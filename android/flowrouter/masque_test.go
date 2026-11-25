package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	mrand "math/rand"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

func testMasqueConfig(t *testing.T, pkcs8 bool) *masqueConfig {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var privateDER []byte
	if pkcs8 {
		privateDER, err = x509.MarshalPKCS8PrivateKey(clientKey)
	} else {
		privateDER, err = x509.MarshalECPrivateKey(clientKey)
	}
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerDER, err := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &masqueConfig{
		PrivateKey:    base64.StdEncoding.EncodeToString(privateDER),
		PeerPublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: peerDER})),
		AddressV4:     "172.16.0.2",
		AddressV6:     "2606:4700:110:8a36::2",
	}
}

func TestMasqueTLSConfigAcceptsAndroidAndSEC1Keys(t *testing.T) {
	for _, pkcs8 := range []bool{true, false} {
		config := testMasqueConfig(t, pkcs8)
		tlsConfig, err := config.tlsConfig()
		if err != nil {
			t.Fatalf("pkcs8=%v: %v", pkcs8, err)
		}
		if tlsConfig.ServerName != masqueSNI || len(tlsConfig.Certificates) != 1 {
			t.Fatalf("pkcs8=%v: unexpected TLS config %+v", pkcs8, tlsConfig)
		}
		addresses, err := config.localAddresses()
		if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("172.16.0.2") {
			t.Fatalf("localAddresses() = %v, %v", addresses, err)
		}
	}
}

func TestParseWarpConfigDropsBrokenMasque(t *testing.T) {
	base := map[string]any{
		"private_key":     testKey(t),
		"peer_public_key": testKey(t),
		"endpoint":        "162.159.192.1:2408",
		"address_v4":      "172.16.0.2/32",
	}
	base["masque"] = map[string]string{"private_key": "bm90LWEta2V5", "peer_public_key": "junk", "address_v4": "172.16.0.3"}
	text, _ := json.Marshal(base)
	config, err := parseWarpConfig(string(text))
	if err != nil {
		t.Fatalf("parseWarpConfig() error = %v; a broken MASQUE entry must not fail WireGuard", err)
	}
	if config.Masque != nil {
		t.Fatal("broken MASQUE entry was kept")
	}

	base["masque"] = testMasqueConfig(t, true)
	text, _ = json.Marshal(base)
	config, err = parseWarpConfig(string(text))
	if err != nil || !config.Masque.available() {
		t.Fatalf("valid MASQUE entry: config=%+v err=%v", config.Masque, err)
	}
}

func TestBuildMasqueCandidates(t *testing.T) {
	cached := []cachedEndpoint{
		{Endpoint: "162.159.198.2:8443", Network: "wifi", Transport: transportMasqueH3},
		{Endpoint: "8.6.112.1:2408", Network: "wifi", Profile: defaultAWGProfile()},
	}
	candidates := buildMasqueCandidates(cached, "wifi", mrand.New(mrand.NewSource(4)))
	if len(candidates) == 0 || candidates[0].endpoint != "162.159.198.2:8443" || candidates[0].source != sourceCached {
		t.Fatalf("first candidate = %+v, want the cached MASQUE pair", candidates)
	}
	h3, h2 := 0, 0
	for _, candidate := range candidates {
		host, portText, err := net.SplitHostPort(candidate.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		port, _ := strconv.Atoi(portText)
		if !slices.Contains(masquePorts, port) {
			t.Fatalf("%s uses a non-MASQUE port", candidate.endpoint)
		}
		switch candidate.transport {
		case transportMasqueH3:
			h3++
			if !slices.Contains(masqueH3Hosts, host) {
				t.Fatalf("QUIC candidate %s is not a MASQUE QUIC host", candidate.endpoint)
			}
		case transportMasqueH2:
			h2++
			address := netip.MustParseAddr(host)
			if !masqueH2Pools[0].Contains(address) && !masqueH2Pools[1].Contains(address) {
				t.Fatalf("HTTP/2 candidate %s is outside the MASQUE pools", candidate.endpoint)
			}
		default:
			t.Fatalf("AmneziaWG candidate %s in the MASQUE round", candidate.endpoint)
		}
	}
	if h3 != masqueRoundH3+1 || h2 != masqueRoundH2 {
		t.Fatalf("h3=%d h2=%d, want %d and %d", h3, h2, masqueRoundH3+1, masqueRoundH2)
	}

	// AmneziaWG rounds never pick up MASQUE winners.
	for _, candidate := range buildWarpCandidates("", cached, "wifi", mrand.New(mrand.NewSource(5))) {
		if candidate.transport.isMasque() || candidate.endpoint == "162.159.198.2:8443" {
			t.Fatalf("MASQUE entry %s leaked into the AmneziaWG round", candidate.endpoint)
		}
	}
}

func TestEndpointCacheKeepsTransportsApart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warp-endpoints.json")
	cache := newEndpointCache(path)
	cache.remember("wifi", warpCandidate{endpoint: "162.159.198.1:443", transport: transportMasqueH3}, time.Second)
	cache.remember("wifi", warpCandidate{endpoint: "162.159.198.1:443", transport: transportMasqueH2}, time.Second)
	entries := newEndpointCache(path).snapshot()
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want one per transport", entries)
	}
}
