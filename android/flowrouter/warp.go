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
	mrand "math/rand"
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
	// Masque is the optional MASQUE device used when WireGuard is blocked.
	Masque *masqueConfig `json:"masque,omitempty"`
	// Probe is a second WARP device used only to test endpoints. With one
	// key, a test handshake that finishes after the winner's takes
	// Cloudflare's session from the live tunnel.
	Probe *warpConfig `json:"probe,omitempty"`
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
	if config.Probe != nil {
		probe := *config.Probe
		probe.Masque, probe.Probe = nil, nil
		if probe.PersistentKA <= 0 {
			probe.PersistentKA = config.PersistentKA
		}
		_, keyErr := decodeKey(probe.PrivateKey)
		_, peerErr := decodeKey(probe.PublicKey)
		if keyErr != nil || peerErr != nil || !probe.available() {
			// Without it selection tests with the main key, as before.
			flowRouterLogf("WARP probe device ignored: incomplete data")
			config.Probe = nil
		} else {
			config.Probe = &probe
		}
	}
	if config.Masque != nil {
		if _, err := config.Masque.tlsConfig(); err != nil || !config.Masque.available() {
			// A broken MASQUE entry must not cost the WireGuard route.
			flowRouterLogf("MASQUE fallback disabled: invalid device data: %v", err)
			config.Masque = nil
		}
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

// warpTunnel is a userspace network reaching the internet through WARP, over
// either AmneziaWG or MASQUE.
type warpTunnel struct {
	net      *netstack.Net
	resolver func(context.Context, string) ([]netip.Addr, error)
	closer   func()
	// endpoint and transport describe the candidate that won selection; set by
	// openWorkingWarp for display.
	endpoint  string
	transport string
	candidate warpCandidate
	// colo is the Cloudflare location the tunnel exits from, "" when unknown.
	colo string
	// AmneziaWG tunnels keep their device, counting bind and peer for the
	// stall detector and reconnect; MASQUE tunnels leave them nil.
	device    *device.Device
	bind      *countingBind
	peerHex   string
	keepalive int
	conns     trackedConns
}

// transportLabel is the user-facing protocol name of a candidate.
func transportLabel(candidate warpCandidate) string {
	switch candidate.transport {
	case transportMasqueH3:
		return "MASQUE H3"
	case transportMasqueH2:
		return "MASQUE H2"
	default:
		return "AmneziaWG"
	}
}


// ping measures the TCP handshake time through the tunnel, the best of a few
// attempts. Each attempt also needs an HTTP answer to count: a tunnel that
// completes handshakes but returns no data is dead.
func (t *warpTunnel) ping(ctx context.Context, attempts int) (time.Duration, error) {
	best := time.Duration(-1)
	var lastErr error
	for index := 0; index < attempts; index++ {
		started := time.Now()
		connection, err := t.net.DialContext(ctx, "tcp", warpDataTarget)
		if err != nil {
			lastErr = err
			continue
		}
		elapsed := time.Since(started)
		err = expectHTTP(ctx, connection)
		_ = connection.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if best < 0 || elapsed < best {
			best = elapsed
		}
	}
	if best < 0 {
		if lastErr == nil {
			lastErr = errors.New("no ping attempts")
		}
		return 0, lastErr
	}
	return best, nil
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
	if t != nil && t.closer != nil {
		t.closer()
	}
}

func (t *warpTunnel) dialContext(ctx context.Context, target string) (net.Conn, error) {
	return t.dialNetworkContext(ctx, "tcp", target)
}

func (t *warpTunnel) dialNetworkContext(ctx context.Context, network, target string) (net.Conn, error) {
	connection, err := t.dialRaw(ctx, network, target)
	if err != nil {
		return nil, err
	}
	return t.conns.wrap(connection), nil
}

// dialRaw dials without tracking (probes and pings).
func (t *warpTunnel) dialRaw(ctx context.Context, network, target string) (net.Conn, error) {
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

// warpSelection carries what openWorkingWarp needs besides the profile: where
// to remember winners and which network they were measured on.
type warpSelection struct {
	cache      *endpointCache
	networkKey string
	rng        *mrand.Rand
}

func describeCandidate(candidate warpCandidate) string {
	if candidate.transport.isMasque() {
		return candidate.transport.String()
	}
	return "awg " + candidate.profile.String()
}

func probeWarpRoute(ctx context.Context, tunnel *warpTunnel, target string) error {
	connection, err := tunnel.dialRaw(ctx, "tcp", target)
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
	profile awgProfile,
	resolver func(context.Context, string) ([]netip.Addr, error),
) (*warpTunnel, error) {
	if err := profile.validate(); err != nil {
		return nil, fmt.Errorf("AmneziaWG profile %s: %w", profile.Name, err)
	}
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
	bind := newCountingBind(conn.NewDefaultBind())
	dev := device.NewDevice(
		tunDevice,
		bind,
		device.NewLogger(device.LogLevelSilent, "FlowCloudAuto"),
	)
	lines := []string{"private_key=" + hex.EncodeToString(privateKey)}
	lines = append(lines, profile.uapi()...)
	lines = append(lines,
		"replace_peers=true",
		"public_key="+hex.EncodeToString(publicKey),
		"endpoint="+endpoint,
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval="+strconv.Itoa(config.PersistentKA),
	)
	uapi := strings.Join(lines, "\n") + "\n\n"
	if err = dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, err
	}
	if err = dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	bindWireGuardSockets(bind)
	return &warpTunnel{
		net: tunnelNet, resolver: resolver, closer: dev.Close,
		device: dev, bind: bind, peerHex: hex.EncodeToString(publicKey), keepalive: config.PersistentKA,
		candidate: warpCandidate{endpoint: endpoint, profile: profile, transport: transportAWG},
	}, nil
}
