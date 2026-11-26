package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestWarpEvaluationRanking(t *testing.T) {
	moscow := warpEvaluation{colo: "DME", sitesOK: 2, sites: 2, latency: 300 * time.Millisecond}
	stockholm := warpEvaluation{colo: "ARN", sitesOK: 2, sites: 2, latency: 500 * time.Millisecond}
	stockholmHalf := warpEvaluation{colo: "ARN", sitesOK: 1, sites: 2, latency: 100 * time.Millisecond}
	if !stockholm.perfect() || moscow.perfect() || stockholmHalf.perfect() {
		t.Fatal("perfect means every site outside the avoided locations")
	}
	if !stockholm.better(moscow) {
		t.Fatal("an exit outside the avoided locations wins when both open every site")
	}
	if !moscow.better(stockholmHalf) {
		t.Fatal("opening more sites outranks the location")
	}
	if best := bestEvaluation([]warpEvaluation{stockholmHalf, moscow, stockholm}); best.colo != "ARN" || best.sitesOK != 2 {
		t.Fatalf("best = %+v", best)
	}
}

func TestStallDetector(t *testing.T) {
	var detector stallDetector
	tunnel := &warpTunnel{}
	start := time.Unix(1000, 0)
	if detector.add(tunnel, start, 500, 1000, 10, 4*time.Second) {
		t.Fatal("one sample is no stall")
	}
	if detector.add(tunnel, start.Add(2*time.Second), 500, 1400, 13, 4*time.Second) {
		t.Fatal("half a window is no stall")
	}
	if !detector.add(tunnel, start.Add(4*time.Second), 500, 1800, 16, 4*time.Second) {
		t.Fatal("sending for a whole window with nothing received is a stall")
	}
	detector.reset()
	detector.add(tunnel, start, 500, 1000, 10, 4*time.Second)
	if detector.add(tunnel, start.Add(4*time.Second), 520, 1800, 16, 4*time.Second) {
		t.Fatal("anything received means the flow is alive")
	}
	detector.reset()
	detector.add(tunnel, start, 500, 1000, 10, 4*time.Second)
	if detector.add(tunnel, start.Add(4*time.Second), 500, 1032, 11, 4*time.Second) {
		t.Fatal("a lone keepalive is no stall")
	}
}

func TestEndpointCacheKeepsLocations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoints.json")
	cache := newEndpointCache(path)
	candidate := warpCandidate{endpoint: "8.39.125.105:1701", profile: defaultAWGProfile(), source: sourcePool, transport: transportAWG}
	cache.rememberEvaluated("wifi:home", candidate, 40*time.Millisecond, "ARN", true)
	cache.noteColo("wifi:home", "8.35.211.176:1701", "DME")

	reloaded := newEndpointCache(path)
	entries := reloaded.snapshot()
	if len(entries) != 1 || entries[0].Colo != "ARN" || !entries[0].Sites {
		t.Fatalf("entries = %+v", entries)
	}
	if reloaded.poolColo("wifi:home", "8.35.211.9:2408") != "DME" || reloaded.poolColo("wifi:home", "8.39.125.1:500") != "ARN" {
		t.Fatal("pool locations must survive a reload")
	}
	if reloaded.poolColo("mobile:x", "8.39.125.1:500") != "" {
		t.Fatal("pool locations are per network")
	}
	reloaded.sitesFailed("wifi:home", candidate)
	if reloaded.snapshot()[0].Sites {
		t.Fatal("a pair that failed with the main key must lose its site flag")
	}
}

func TestParseWarpConfigProbe(t *testing.T) {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	config, err := parseWarpConfig(`{"private_key":"` + key + `","peer_public_key":"` + key + `","endpoint":"162.159.192.1:2408","address_v4":"172.16.0.2",` +
		`"probe":{"private_key":"` + key + `","peer_public_key":"` + key + `","endpoint":"162.159.192.1:2408","address_v4":"172.16.0.2"}}`)
	if err != nil || config.Probe == nil || config.Probe.PersistentKA != 25 {
		t.Fatalf("config = %+v, %v", config, err)
	}
	config, err = parseWarpConfig(`{"private_key":"` + key + `","peer_public_key":"` + key + `","endpoint":"162.159.192.1:2408","address_v4":"172.16.0.2",` +
		`"probe":{"private_key":"bad"}}`)
	if err != nil || config.Probe != nil {
		t.Fatal("a broken probe device must be ignored, not fail the profile")
	}
}
