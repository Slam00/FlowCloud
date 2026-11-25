package main

import (
	"crypto/rand"
	"encoding/base64"
	mrand "math/rand"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func inWarpPools(t *testing.T, host string) bool {
	t.Helper()
	address, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("candidate host %q: %v", host, err)
	}
	for _, prefix := range warpPoolsV4 {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func TestBuildWarpCandidatesOrderAndBounds(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	cached := []cachedEndpoint{
		{Endpoint: "8.6.112.7:4500", Network: "cell:25001", Profile: defaultAWGProfile()},
		{Endpoint: "188.114.97.3:2408", Network: "wifi", Profile: defaultAWGProfile()},
	}
	candidates := buildWarpCandidates("162.159.192.9:0", cached, "cell:25001", rng)
	if len(candidates) != warpRoundSize {
		t.Fatalf("len = %d, want %d", len(candidates), warpRoundSize)
	}
	if candidates[0].endpoint != "8.6.112.7:4500" || candidates[0].source != sourceCached {
		t.Fatalf("first candidate = %+v, want the same-network cached pair", candidates[0])
	}
	if candidates[1].endpoint != "188.114.97.3:2408" || candidates[1].source != sourceCached {
		t.Fatalf("second candidate = %+v, want the other-network cached pair", candidates[1])
	}
	seen := map[string]bool{}
	registered, pool, randomProfiles := 0, 0, 0
	for _, candidate := range candidates {
		if seen[candidate.endpoint] {
			t.Fatalf("duplicate candidate %s", candidate.endpoint)
		}
		seen[candidate.endpoint] = true
		host, portText, err := net.SplitHostPort(candidate.endpoint)
		if err != nil {
			t.Fatalf("candidate %q: %v", candidate.endpoint, err)
		}
		port, _ := strconv.Atoi(portText)
		if port <= 0 || port > 65535 {
			t.Fatalf("candidate %q has port %d", candidate.endpoint, port)
		}
		if err = candidate.profile.validate(); err != nil {
			t.Fatalf("candidate %q profile: %v", candidate.endpoint, err)
		}
		switch candidate.source {
		case sourceRegistered:
			registered++
			if host != "162.159.192.9" {
				t.Fatalf("registered candidate %q uses another host", candidate.endpoint)
			}
		case sourcePool:
			pool++
			if !inWarpPools(t, host) {
				t.Fatalf("pool candidate %q is outside the WARP pools", candidate.endpoint)
			}
			if candidate.profile.Name != defaultAWGProfile().Name {
				randomProfiles++
			}
		}
	}
	// Port 0 from the API is skipped; 2408 and 500 remain.
	if registered != 2 {
		t.Fatalf("registered candidates = %d, want 2", registered)
	}
	if pool == 0 || randomProfiles == 0 {
		t.Fatalf("pool=%d randomProfiles=%d, want both > 0", pool, randomProfiles)
	}
}

func TestEndpointCachePersistsAndEvicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warp-endpoints.json")
	now := time.Unix(1_800_000_000, 0)
	cache := newEndpointCache(path)
	cache.now = func() time.Time { return now }
	good := warpCandidate{endpoint: "8.39.125.10:2408", profile: defaultAWGProfile()}
	other := warpCandidate{endpoint: "8.47.69.20:500", profile: randomAWGProfile(mrand.New(mrand.NewSource(2)))}
	cache.remember("wifi", other, 900*time.Millisecond)
	now = now.Add(time.Minute)
	cache.remember("wifi", good, 300*time.Millisecond)

	reloaded := newEndpointCache(path)
	reloaded.now = func() time.Time { return now }
	entries := reloaded.snapshot()
	if len(entries) != 2 || entries[0].Endpoint != good.endpoint {
		t.Fatalf("reloaded entries = %+v, want the most recent success first", entries)
	}
	if entries[1].Profile.I1 != other.profile.I1 {
		t.Fatal("generated I1 was not persisted verbatim")
	}

	for index := 0; index < endpointCacheMaxFails; index++ {
		reloaded.fail("wifi", good)
	}
	entries = newEndpointCache(path).snapshot()
	if len(entries) != 1 || entries[0].Endpoint != other.endpoint {
		t.Fatalf("entries after failures = %+v, want only %s", entries, other.endpoint)
	}

	expired := newEndpointCache(path)
	expired.now = func() time.Time { return now.Add(endpointCacheTTL + time.Hour) }
	expired.entries = nil
	expired.load()
	if len(expired.entries) != 0 {
		t.Fatalf("expired entries were loaded: %+v", expired.entries)
	}
}

func TestNilEndpointCacheIsSafe(t *testing.T) {
	var cache *endpointCache
	cache.remember("wifi", warpCandidate{endpoint: "8.6.112.1:2408"}, time.Second)
	cache.fail("wifi", warpCandidate{endpoint: "8.6.112.1:2408"})
	if cache.snapshot() != nil {
		t.Fatal("nil cache returned entries")
	}
}

func testKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// Every I1 variant must be accepted by amneziawg-go's own parser, otherwise a
// candidate would fail on IpcSet instead of on the network.
func TestAWGProfilesAreAcceptedByDevice(t *testing.T) {
	config := warpConfig{
		PrivateKey:   testKey(t),
		PublicKey:    testKey(t),
		Endpoint:     "127.0.0.1:9",
		AddressV4:    "172.16.0.2/32",
		PersistentKA: 25,
	}
	rng := mrand.New(mrand.NewSource(3))
	profiles := []awgProfile{defaultAWGProfile()}
	for _, variant := range i1Variants {
		chain, err := variant.generate(rng)
		if err != nil {
			t.Fatalf("%s: %v", variant.name, err)
		}
		profiles = append(profiles, awgProfile{Name: variant.name, Jc: 4, Jmin: 20, Jmax: 90, I1: chain})
	}
	for _, profile := range profiles {
		tunnel, err := openWarp(config, config.Endpoint, profile, nil)
		if err != nil {
			t.Fatalf("profile %s rejected: %v", profile.Name, err)
		}
		tunnel.close()
	}
}

func TestAWGProfileValidate(t *testing.T) {
	bad := []awgProfile{
		{Jc: awgMaxJunkCount + 1},
		{Jc: 3, Jmin: 100, Jmax: 50},
		{Jc: 3, Jmin: 10, Jmax: awgMaxJunkSize + 1},
		{Jc: 3, Jmin: 10, Jmax: 20, I1: "<b 0x00>\nprivate_key=00"},
	}
	for _, profile := range bad {
		if profile.validate() == nil {
			t.Errorf("validate(%+v) = nil, want an error", profile)
		}
	}
}
