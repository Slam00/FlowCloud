package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

type warpConfig struct {
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"peer_public_key"`
	Endpoint     string `json:"endpoint"`
	AddressV4    string `json:"address_v4"`
	AddressV6    string `json:"address_v6"`
	PersistentKA int    `json:"persistent_keepalive"`
}

func parseWarpConfig(value string) (warpConfig, error) {
	var config warpConfig
	if strings.TrimSpace(value) == "" {
		return config, nil
	}
	if err := json.Unmarshal([]byte(value), &config); err != nil {
		return config, fmt.Errorf("decode WARP configuration: %w", err)
	}
	if _, err := decodeKey(config.PrivateKey); err != nil {
		return config, fmt.Errorf("invalid WARP private key: %w", err)
	}
	if _, err := decodeKey(config.PublicKey); err != nil {
		return config, fmt.Errorf("invalid WARP peer key: %w", err)
	}
	if config.Endpoint == "" {
		return config, errors.New("WARP endpoint is missing")
	}
	if config.AddressV4 == "" && config.AddressV6 == "" {
		return config, errors.New("WARP interface address is missing")
	}
	if config.PersistentKA <= 0 {
		config.PersistentKA = 25
	}
	return config, nil
}

func (config warpConfig) available() bool {
	return strings.TrimSpace(config.PrivateKey) != "" &&
		strings.TrimSpace(config.PublicKey) != "" &&
		strings.TrimSpace(config.Endpoint) != "" &&
		(strings.TrimSpace(config.AddressV4) != "" || strings.TrimSpace(config.AddressV6) != "")
}

func decodeKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("key must be 32-byte base64")
	}
	return decoded, nil
}

type warpTunnel struct {
	device   *device.Device
	net      *netstack.Net
	resolver func(context.Context, string) ([]netip.Addr, error)
}

const (
	warpProbeTimeout = 6 * time.Second

	// Mobile AWG 2.0 profile. Junk and CPS packets are client-only decoys. The
	// S/H values below deliberately keep the actual tunnel byte-compatible with
	// Cloudflare's stock WireGuard peer.
	warpJunkCount = 3
	warpJunkMin   = 64
	warpJunkMax   = 128
)

func (t *warpTunnel) close() {
	if t != nil && t.device != nil {
		t.device.Close()
	}
}

func (t *warpTunnel) dialContext(ctx context.Context, target string) (net.Conn, error) {
	return t.dialNetworkContext(ctx, "tcp", target)
}

func (t *warpTunnel) dialNetworkContext(ctx context.Context, network, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || net.ParseIP(host) != nil {
		return t.net.DialContext(ctx, network, target)
	}

	// Android's process is bound to the physical network before the VPN starts.
	// Resolve there first and send only the resulting IP through WARP. Relying on
	// UDP/53 inside WARP stalls on mobile providers that pass WireGuard data but
	// block or impair the WARP DNS addresses.
	var addresses []netip.Addr
	var resolveErr error
	if t.resolver != nil {
		addresses, resolveErr = t.resolver(ctx, host)
	} else {
		addresses, resolveErr = net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	}
	if resolveErr != nil {
		return nil, fmt.Errorf("resolve %s on underlying network: %w", host, resolveErr)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve %s on underlying network: no IPv4 address", host)
	}
	var lastErr error
	for _, address := range addresses {
		connection, dialErr := t.net.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

func openWorkingWarp(
	ctx context.Context,
	config warpConfig,
	probeTarget string,
	resolver func(context.Context, string) ([]netip.Addr, error),
) (*warpTunnel, error) {
	type attemptResult struct {
		endpoint string
		tunnel   *warpTunnel
		err      error
	}

	candidates := endpointCandidates(config.Endpoint)
	if len(candidates) == 0 {
		return nil, errors.New("start WARP route: no endpoint candidates")
	}
	attemptContext, cancelAttempts := context.WithCancel(ctx)
	results := make(chan attemptResult, len(candidates))
	for _, endpoint := range candidates {
		go func(endpoint string) {
			tunnel, err := openWarp(config, endpoint, resolver)
			if err == nil {
				probeContext, cancelProbe := context.WithTimeout(attemptContext, warpProbeTimeout)
				err = probeWarpRoute(probeContext, tunnel, probeTarget)
				cancelProbe()
			}
			if err != nil && tunnel != nil {
				tunnel.close()
				tunnel = nil
			}
			results <- attemptResult{endpoint: endpoint, tunnel: tunnel, err: err}
		}(endpoint)
	}

	var lastErr error
	for completed := 0; completed < len(candidates); completed++ {
		select {
		case result := <-results:
			if result.err == nil && result.tunnel != nil {
				cancelAttempts()
				flowRouterLogf("WARP endpoint selected: %s (YouTube data probe passed)", result.endpoint)
				remaining := len(candidates) - completed - 1
				go func() {
					for index := 0; index < remaining; index++ {
						unused := <-results
						if unused.tunnel != nil {
							unused.tunnel.close()
						}
					}
				}()
				return result.tunnel, nil
			}
			lastErr = result.err
			flowRouterLogf("WARP endpoint rejected: %s: %v", result.endpoint, result.err)
		case <-ctx.Done():
			cancelAttempts()
			flowRouterLogf("WARP endpoint scan timed out after %d/%d results: %v", completed, len(candidates), ctx.Err())
			return nil, fmt.Errorf("start WARP route: %w", ctx.Err())
		}
	}
	cancelAttempts()
	if lastErr == nil {
		lastErr = errors.New("no usable WARP endpoint")
	}
	return nil, fmt.Errorf("start WARP route: %w", lastErr)
}

func probeWarpRoute(ctx context.Context, tunnel *warpTunnel, target string) error {
	connection, err := tunnel.dialContext(ctx, target)
	if err != nil {
		return fmt.Errorf("connect YouTube through tunnel: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	secure := tls.Client(connection, &tls.Config{
		ServerName:         "www.youtube.com",
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // Connectivity probe; the response is not trusted or consumed.
	})
	if err = secure.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("YouTube TLS probe: %w", err)
	}
	if _, err = secure.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: www.youtube.com\r\nConnection: close\r\n\r\n")); err != nil {
		return fmt.Errorf("YouTube HTTP probe write: %w", err)
	}
	status, err := bufio.NewReader(secure).ReadString('\n')
	if err != nil {
		return fmt.Errorf("YouTube HTTP probe read: %w", err)
	}
	if !strings.HasPrefix(status, "HTTP/") {
		return fmt.Errorf("YouTube HTTP probe returned invalid status %q", strings.TrimSpace(status))
	}
	return nil
}

func openWarp(
	config warpConfig,
	endpoint string,
	resolver func(context.Context, string) ([]netip.Addr, error),
) (*warpTunnel, error) {
	privateKey, _ := decodeKey(config.PrivateKey)
	publicKey, _ := decodeKey(config.PublicKey)
	// Android's outer VPN is IPv4-only on mobile data. Keeping the inner WARP
	// interface IPv4-only avoids an unusable IPv6 path winning route selection.
	addresses := make([]netip.Addr, 0, 1)
	for _, value := range []string{config.AddressV4} {
		value = strings.TrimSpace(value)
		if before, _, found := strings.Cut(value, "/"); found {
			value = before
		}
		if value == "" {
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	tunDevice, tunnelNet, err := netstack.CreateNetTUN(
		addresses,
		[]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")},
		1280,
	)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(
		tunDevice,
		conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelSilent, "FlowCloudAuto"),
	)
	uapi := strings.Join([]string{
		"private_key=" + hex.EncodeToString(privateKey),
		"jc=" + strconv.Itoa(warpJunkCount),
		"jmin=" + strconv.Itoa(warpJunkMin),
		"jmax=" + strconv.Itoa(warpJunkMax),
		"s1=0",
		"s2=0",
		"s3=0",
		"s4=0",
		"h1=1",
		"h2=2",
		"h3=3",
		"h4=4",
		"i1=" + warpCPSPacket,
		"replace_peers=true",
		"public_key=" + hex.EncodeToString(publicKey),
		"endpoint=" + endpoint,
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval=" + strconv.Itoa(config.PersistentKA),
	}, "\n") + "\n\n"
	if err = dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, err
	}
	if err = dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &warpTunnel{device: dev, net: tunnelNet, resolver: resolver}, nil
}

func endpointCandidates(value string) []string {
	host, portValue, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return []string{value}
	}
	originalPort, _ := strconv.Atoi(portValue)
	ports := []int{originalPort, 2408, 500, 1701, 4500, 943}
	// WARP anycast addresses can land on different Cloudflare edge nodes. Some
	// nodes pass the WireGuard handshake but filter the requested sites, so use
	// samples from both standard WARP endpoint pools and validate actual data.
	hosts := []string{
		host,
		"162.159.192.5", "162.159.192.1", "162.159.193.10", "162.159.194.20", "162.159.195.30",
		"162.159.196.40", "162.159.197.50", "162.159.198.60", "162.159.199.70",
		"188.114.96.10", "188.114.98.58", "188.114.100.30", "188.114.103.40",
		"188.114.106.50", "188.114.110.60",
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, 24)
	appendCandidate := func(candidateHost string, port int) {
		if port <= 0 || port > 65535 || len(result) >= 24 {
			return
		}
		candidate := net.JoinHostPort(candidateHost, strconv.Itoa(port))
		if _, exists := seen[candidate]; exists {
			return
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}
	for _, port := range ports {
		appendCandidate(host, port)
	}
	for index, candidateHost := range hosts[1:] {
		appendCandidate(candidateHost, 2408)
		appendCandidate(candidateHost, []int{500, 1701, 4500, 943}[index%4])
	}
	return result
}
