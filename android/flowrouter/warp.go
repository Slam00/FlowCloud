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

// warpPingTarget is Cloudflare's resolver, served from the same edge as the
// WARP endpoint, so a TCP handshake to it through the tunnel approximates the
// round trip to the endpoint itself.
const warpPingTarget = "1.1.1.1:443"

// ping measures the TCP handshake time through the tunnel, the best of a few
// attempts.
func (t *warpTunnel) ping(ctx context.Context, attempts int) (time.Duration, error) {
	best := time.Duration(-1)
	var lastErr error
	for index := 0; index < attempts; index++ {
		started := time.Now()
		connection, err := t.net.DialContext(ctx, "tcp", warpPingTarget)
		if err != nil {
			lastErr = err
			continue
		}
		elapsed := time.Since(started)
		_ = connection.Close()
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

func openWorkingWarp(
	ctx context.Context,
	config warpConfig,
	probeTarget string,
	resolver func(context.Context, string) ([]netip.Addr, error),
	selection warpSelection,
) (*warpTunnel, error) {
	type attemptResult struct {
		candidate warpCandidate
		tunnel    *warpTunnel
		latency   time.Duration
		err       error
	}

	rng := selection.rng
	if rng == nil {
		rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	}
	cached := selection.cache.snapshot()
	awgCandidates := buildWarpCandidates(config.Endpoint, cached, selection.networkKey, rng)
	var masqueCandidates []warpCandidate
	if config.Masque.available() {
		masqueCandidates = buildMasqueCandidates(cached, selection.networkKey, rng)
	}
	total := len(awgCandidates) + len(masqueCandidates)
	if total == 0 {
		return nil, errors.New("start WARP route: no endpoint candidates")
	}
	cachedCount := 0
	for _, candidate := range append(append([]warpCandidate(nil), awgCandidates...), masqueCandidates...) {
		if candidate.source == sourceCached {
			cachedCount++
		}
	}
	flowRouterLogf(
		"WARP endpoint round: %d AmneziaWG + %d MASQUE candidates (%d cached), network=%s",
		len(awgCandidates), len(masqueCandidates), cachedCount, selection.networkKey,
	)
	started := time.Now()
	attemptContext, cancelAttempts := context.WithCancel(ctx)
	results := make(chan attemptResult, total)
	attempt := func(candidate warpCandidate) {
		var tunnel *warpTunnel
		var err error
		if candidate.transport.isMasque() {
			tunnel, err = openMasque(attemptContext, config.Masque, candidate.endpoint, candidate.transport, resolver)
		} else {
			tunnel, err = openWarp(config, candidate.endpoint, candidate.profile, resolver)
		}
		if err == nil {
			probeContext, cancelProbe := context.WithTimeout(attemptContext, warpProbeTimeout)
			err = probeWarpRoute(probeContext, tunnel, probeTarget)
			cancelProbe()
		}
		if err != nil && tunnel != nil {
			tunnel.close()
			tunnel = nil
		}
		results <- attemptResult{candidate: candidate, tunnel: tunnel, latency: time.Since(started), err: err}
	}
	for _, candidate := range awgCandidates {
		go attempt(candidate)
	}
	// MASQUE joins after a head start for AmneziaWG, or at once when every
	// AmneziaWG candidate has already failed.
	awgExhausted := make(chan struct{})
	if len(awgCandidates) == 0 {
		close(awgExhausted)
	}
	if len(masqueCandidates) > 0 {
		go func() {
			timer := time.NewTimer(masqueStartDelay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-awgExhausted:
			case <-attemptContext.Done():
				for _, candidate := range masqueCandidates {
					results <- attemptResult{candidate: candidate, err: attemptContext.Err()}
				}
				return
			}
			flowRouterLogf("WARP endpoint round: starting MASQUE candidates after %s", time.Since(started).Round(time.Millisecond))
			for _, candidate := range masqueCandidates {
				go attempt(candidate)
			}
		}()
	}
	// drain closes tunnels that finish after the round is decided.
	drain := func(remaining int, keepBackups bool) {
		go func() {
			for index := 0; index < remaining; index++ {
				unused := <-results
				if unused.tunnel != nil {
					if keepBackups {
						// It passed before the cancel reached it: keep it as a backup.
						selection.cache.remember(selection.networkKey, unused.candidate, unused.latency)
					}
					unused.tunnel.close()
				}
			}
		}()
	}

	var lastErr error
	awgFailed := 0
	for completed := 0; completed < total; completed++ {
		select {
		case result := <-results:
			if result.err == nil && result.tunnel != nil {
				cancelAttempts()
				flowRouterLogf(
					"WARP endpoint selected: %s [%s, %s] in %s (YouTube data probe passed)",
					result.candidate.endpoint, result.candidate.source, describeCandidate(result.candidate),
					result.latency.Round(time.Millisecond),
				)
				selection.cache.remember(selection.networkKey, result.candidate, result.latency)
				drain(total-completed-1, true)
				result.tunnel.endpoint = result.candidate.endpoint
				result.tunnel.transport = transportLabel(result.candidate)
				result.tunnel.candidate = result.candidate
				return result.tunnel, nil
			}
			lastErr = result.err
			if result.candidate.source == sourceCached {
				selection.cache.fail(selection.networkKey, result.candidate)
			}
			if !result.candidate.transport.isMasque() {
				awgFailed++
				if awgFailed == len(awgCandidates) {
					close(awgExhausted)
				}
			}
			flowRouterLogf(
				"WARP endpoint rejected: %s [%s, %s]: %v",
				result.candidate.endpoint, result.candidate.source, describeCandidate(result.candidate), result.err,
			)
		case <-ctx.Done():
			cancelAttempts()
			flowRouterLogf("WARP endpoint scan timed out after %d/%d results: %v", completed, total, ctx.Err())
			drain(total-completed, false)
			return nil, fmt.Errorf("start WARP route: %w", ctx.Err())
		}
	}
	cancelAttempts()
	if lastErr == nil {
		lastErr = errors.New("no usable WARP endpoint")
	}
	return nil, fmt.Errorf("start WARP route: %w", lastErr)
}

func describeCandidate(candidate warpCandidate) string {
	if candidate.transport.isMasque() {
		return candidate.transport.String()
	}
	return "awg " + candidate.profile.String()
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
	bind := conn.NewDefaultBind()
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
	return &warpTunnel{net: tunnelNet, resolver: resolver, closer: dev.Close}, nil
}
