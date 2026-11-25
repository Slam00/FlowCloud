package main

// MASQUE (CONNECT-IP over HTTP/3 or HTTP/2) fallback for networks that block
// WireGuard UDP. The tunnel and the Cloudflare constants follow WARPSCOUT
// (https://github.com/vernette/warpscout, internal/warpscout/masque.go, MIT
// License, Copyright (c) 2026 Nikita S.), which builds on usque
// (https://github.com/Diniboy1123/usque, MIT License).

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	masqueConnectURI = "https://cloudflareaccess.com"
	// The SNI never matches the endpoint address; the peer is pinned by its
	// public key instead of the certificate chain.
	masqueSNI         = "consumer-masque.cloudflareclient.com"
	masqueKeepalive   = 10 * time.Second
	masqueIdleTimeout = 30 * time.Second
	masqueDialTimeout = 5 * time.Second
	masqueMTU         = 1280
	masqueReadBuffer  = masqueMTU + 128
	// Cloudflare never checks the client certificate itself, only the enrolled
	// key it carries.
	masqueCertLifetime = 24 * time.Hour

	// masqueStartDelay gives AmneziaWG a head start: MASQUE only joins the
	// round when WireGuard is slow or has already failed everywhere.
	masqueStartDelay  = 3 * time.Second
	masqueRoundH3     = 8
	masqueRoundH2     = 4
	masqueCachedLimit = 2
)

// QUIC MASQUE is served only from these two addresses on the listed ports; the
// HTTP/2 fallback answers across both /24s.
var (
	masqueH3Hosts = []string{"162.159.198.1", "162.159.198.2"}
	masqueH2Pools = []netip.Prefix{
		netip.MustParsePrefix("162.159.198.0/24"),
		netip.MustParsePrefix("162.159.199.0/24"),
	}
	masquePorts = []int{443, 500, 1701, 4500, 4443, 8443, 8095}
)

type warpTransport string

const (
	transportAWG      warpTransport = ""
	transportMasqueH3 warpTransport = "masque-h3"
	transportMasqueH2 warpTransport = "masque-h2"
)

func (t warpTransport) isMasque() bool {
	return t == transportMasqueH3 || t == transportMasqueH2
}

func (t warpTransport) String() string {
	if t == transportAWG {
		return "awg"
	}
	return string(t)
}

// masqueConfig is the MASQUE device registered next to the WireGuard one.
type masqueConfig struct {
	// PrivateKey is a base64 P-256 key, PKCS#8 (Android) or SEC 1 DER.
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
	AddressV4     string `json:"address_v4"`
	AddressV6     string `json:"address_v6"`
}

func (m *masqueConfig) available() bool {
	return m != nil && strings.TrimSpace(m.PrivateKey) != "" && strings.TrimSpace(m.PeerPublicKey) != "" &&
		(strings.TrimSpace(m.AddressV4) != "" || strings.TrimSpace(m.AddressV6) != "")
}

func parseMasquePrivateKey(value string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("MASQUE private key: %w", err)
	}
	if key, sec1Err := x509.ParseECPrivateKey(der); sec1Err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("MASQUE private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("MASQUE private key is not ECDSA")
	}
	return key, nil
}

func parseMasquePeerKey(value string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, errors.New("MASQUE peer public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("MASQUE peer public key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("MASQUE peer public key is not ECDSA")
	}
	return key, nil
}

func (m *masqueConfig) tlsConfig() (*tls.Config, error) {
	privateKey, err := parseMasquePrivateKey(m.PrivateKey)
	if err != nil {
		return nil, err
	}
	peerKey, err := parseMasquePeerKey(m.PeerPublicKey)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(masqueCertLifetime),
	}, &x509.Certificate{}, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("MASQUE client certificate: %w", err)
	}
	return api.PrepareTlsConfig(privateKey, peerKey, [][]byte{certificate}, masqueSNI, false)
}

// localAddresses returns the IPv4 interface address only, like the AmneziaWG
// path: the outer Android VPN is IPv4-only on mobile data.
func (m *masqueConfig) localAddresses() ([]netip.Addr, error) {
	value := strings.TrimSpace(m.AddressV4)
	if before, _, found := strings.Cut(value, "/"); found {
		value = before
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return nil, errors.New("MASQUE device has no IPv4 interface address")
	}
	return []netip.Addr{address}, nil
}

// quic-go and connect-ip-go write to the standard logger; FlowCloud logs
// through flowRouterLogf only.
var muteLibraryLog sync.Once

func openMasque(
	ctx context.Context,
	config *masqueConfig,
	endpoint string,
	transport warpTransport,
	resolver func(context.Context, string) ([]netip.Addr, error),
) (*warpTunnel, error) {
	muteLibraryLog.Do(func() { log.SetOutput(io.Discard) })
	if !config.available() {
		return nil, errors.New("MASQUE device is not registered")
	}
	tlsConfig, err := config.tlsConfig()
	if err != nil {
		return nil, err
	}
	addresses, err := config.localAddresses()
	if err != nil {
		return nil, err
	}
	var remote net.Addr
	if transport == transportMasqueH2 {
		remote, err = net.ResolveTCPAddr("tcp", endpoint)
	} else {
		remote, err = net.ResolveUDPAddr("udp", endpoint)
	}
	if err != nil {
		return nil, err
	}

	// Over HTTP/2 the CONNECT-IP stream is one long request bound to this
	// context, so it must outlive the dial; only the dial itself is bounded.
	dialContext, cancelDial := context.WithCancel(context.Background())
	dialDeadline := time.AfterFunc(masqueDialTimeout, cancelDial)
	stopParent := context.AfterFunc(ctx, cancelDial)
	udpConn, transportH3, ipConn, _, err := api.ConnectTunnel(
		dialContext,
		tlsConfig,
		&quic.Config{
			EnableDatagrams:      true,
			KeepAlivePeriod:      masqueKeepalive,
			HandshakeIdleTimeout: masqueDialTimeout,
			MaxIdleTimeout:       masqueIdleTimeout,
		},
		masqueConnectURI,
		remote,
		transport == transportMasqueH2,
	)
	dialInTime := dialDeadline.Stop()
	parentAlive := stopParent()
	if err != nil || !dialInTime || !parentAlive {
		cancelDial()
		closeMasqueTransport(udpConn, transportH3, ipConn)
		if err == nil {
			err = errors.New("MASQUE dial timed out")
		}
		return nil, fmt.Errorf("MASQUE %s dial: %w", transport, err)
	}

	tunDevice, tunnelNet, err := netstack.CreateNetTUN(
		addresses,
		[]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")},
		masqueMTU,
	)
	if err != nil {
		cancelDial()
		closeMasqueTransport(udpConn, transportH3, ipConn)
		return nil, err
	}

	pumpContext, cancelPump := context.WithCancel(context.Background())
	go func() {
		// Userspace stack -> MASQUE.
		buffer := make([]byte, masqueReadBuffer)
		buffers := [][]byte{buffer}
		sizes := []int{0}
		for pumpContext.Err() == nil {
			if _, readErr := tunDevice.Read(buffers, sizes, 0); readErr != nil {
				return
			}
			if _, writeErr := ipConn.WritePacket(buffer[:sizes[0]]); writeErr != nil && pumpContext.Err() != nil {
				return
			}
		}
	}()
	go func() {
		// MASQUE -> userspace stack.
		buffer := make([]byte, masqueReadBuffer)
		for pumpContext.Err() == nil {
			count, readErr := ipConn.ReadPacket(buffer, true)
			if readErr != nil {
				return
			}
			if _, writeErr := tunDevice.Write([][]byte{buffer[:count]}, 0); writeErr != nil {
				return
			}
		}
	}()

	var closeOnce sync.Once
	closer := func() {
		closeOnce.Do(func() {
			cancelPump()
			cancelDial()
			closeMasqueTransport(udpConn, transportH3, ipConn)
			_ = tunDevice.Close()
		})
	}
	return &warpTunnel{net: tunnelNet, resolver: resolver, closer: closer}, nil
}

func closeMasqueTransport(udpConn *net.UDPConn, transport *http3.Transport, conn *connectip.Conn) {
	if conn != nil {
		_ = conn.Close()
	}
	if transport != nil {
		_ = transport.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
}

// buildMasqueCandidates returns the MASQUE part of a round: cached MASQUE
// winners, then QUIC endpoints, then a few HTTP/2 ones for networks that block
// UDP entirely.
func buildMasqueCandidates(cached []cachedEndpoint, networkKey string, rng *mrand.Rand) []warpCandidate {
	result := make([]warpCandidate, 0, masqueCachedLimit+masqueRoundH3+masqueRoundH2)
	seen := make(map[string]struct{})
	add := func(candidate warpCandidate) bool {
		key := candidate.transport.String() + "|" + candidate.endpoint
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
		result = append(result, candidate)
		return true
	}
	cachedAdded := 0
	for _, entry := range cached {
		if cachedAdded >= masqueCachedLimit || !entry.Transport.isMasque() || entry.Network != networkKey {
			continue
		}
		if add(warpCandidate{endpoint: entry.Endpoint, transport: entry.Transport, source: sourceCached}) {
			cachedAdded++
		}
	}

	h3 := make([]string, 0, len(masqueH3Hosts)*len(masquePorts))
	for _, host := range masqueH3Hosts {
		for _, port := range masquePorts {
			h3 = append(h3, net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}
	rng.Shuffle(len(h3), func(i, j int) { h3[i], h3[j] = h3[j], h3[i] })
	added := 0
	for _, endpoint := range h3 {
		if added >= masqueRoundH3 {
			break
		}
		if add(warpCandidate{endpoint: endpoint, transport: transportMasqueH3, source: sourcePool}) {
			added++
		}
	}

	added = 0
	for attempts := 0; added < masqueRoundH2 && attempts < masqueRoundH2*8; attempts++ {
		prefix := masqueH2Pools[rng.Intn(len(masqueH2Pools))]
		base := prefix.Masked().Addr().As4()
		base[3] = byte(randRange(rng, 1, 254))
		port := 443
		if rng.Intn(3) == 0 {
			port = masquePorts[rng.Intn(len(masquePorts))]
		}
		endpoint := net.JoinHostPort(netip.AddrFrom4(base).String(), strconv.Itoa(port))
		if add(warpCandidate{endpoint: endpoint, transport: transportMasqueH2, source: sourcePool}) {
			added++
		}
	}
	return result
}
