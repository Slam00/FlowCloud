package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type fakeTunnel struct {
	tunnel *warpTunnel
	closed atomic.Int32
}

func newFakeTunnel(endpoint string) *fakeTunnel {
	fake := &fakeTunnel{}
	fake.tunnel = &warpTunnel{
		endpoint:  endpoint,
		transport: "AmneziaWG",
		candidate: warpCandidate{endpoint: endpoint, profile: defaultAWGProfile()},
		closer:    func() { fake.closed.Add(1) },
	}
	return fake
}

func newHealthTestRouter(t *testing.T) *flowRouter {
	t.Helper()
	warpJSON := fmt.Sprintf(
		`{"private_key":%q,"peer_public_key":%q,"endpoint":"162.159.192.1:2408","address_v4":"172.16.0.2/32"}`,
		testKey(t), testKey(t),
	)
	options := routerOptions{
		EndpointCacheFile: filepath.Join(t.TempDir(), "warp-endpoints.json"),
		NetworkKey:        "wifi",
	}
	router, err := newFlowRouter("127.0.0.1:0", "127.0.0.1:1080", "", "", "", warpJSON, options)
	if err != nil {
		t.Fatal(err)
	}
	router.health = warpHealthSettings{
		interval:                time.Hour,
		pingTimeout:             time.Second,
		pingAttempts:            1,
		recheckDelay:            time.Millisecond,
		dialFailuresBeforeCheck: 3,
		reselectTimeout:         time.Second,
	}
	t.Cleanup(router.close)
	return router
}

func TestDeadWarpTunnelIsReplaced(t *testing.T) {
	router := newHealthTestRouter(t)
	dead := newFakeTunnel("8.6.112.10:2408")
	replacement := newFakeTunnel("188.114.97.20:500")
	router.endpoints.remember("wifi", dead.tunnel.candidate, 100*time.Millisecond)
	router.warp = dead.tunnel
	router.pingWarp = func(_ context.Context, tunnel *warpTunnel) error {
		if tunnel == dead.tunnel {
			return errors.New("timeout")
		}
		return nil
	}
	opened := 0
	router.openWarpRoute = func(context.Context) (*warpTunnel, error) {
		opened++
		if state := router.warpState(); state != "searching" {
			t.Errorf("warpState during replacement = %q, want searching", state)
		}
		return replacement.tunnel, nil
	}

	router.checkWarpOnce()

	if opened != 1 {
		t.Fatalf("selection rounds = %d, want 1", opened)
	}
	if dead.closed.Load() != 1 {
		t.Fatal("dead tunnel was not closed")
	}
	if router.warp != replacement.tunnel || router.warpErr != nil {
		t.Fatalf("router.warp = %v, err = %v; want the replacement", router.warp, router.warpErr)
	}
	for _, entry := range router.endpoints.snapshot() {
		if entry.Endpoint == dead.tunnel.endpoint {
			t.Fatal("dead endpoint stayed in the cache")
		}
	}
	if state := router.warpState(); state != "ok" {
		t.Fatalf("warpState after replacement = %q, want ok", state)
	}
}

func TestHealthyWarpTunnelIsKept(t *testing.T) {
	router := newHealthTestRouter(t)
	healthy := newFakeTunnel("8.6.112.10:2408")
	router.warp = healthy.tunnel
	pings := 0
	router.pingWarp = func(context.Context, *warpTunnel) error {
		pings++
		if pings == 1 {
			return errors.New("one lost ping")
		}
		return nil
	}
	router.openWarpRoute = func(context.Context) (*warpTunnel, error) {
		t.Fatal("a tunnel that answered the second ping was replaced")
		return nil, nil
	}

	router.checkWarpOnce()

	if router.warp != healthy.tunnel || healthy.closed.Load() != 0 {
		t.Fatal("healthy tunnel was dropped")
	}
}

func TestFailedReplacementLeavesRetryableError(t *testing.T) {
	router := newHealthTestRouter(t)
	dead := newFakeTunnel("8.6.112.10:2408")
	router.warp = dead.tunnel
	router.pingWarp = func(context.Context, *warpTunnel) error { return errors.New("timeout") }
	router.openWarpRoute = func(context.Context) (*warpTunnel, error) {
		return nil, errors.New("no usable WARP endpoint")
	}

	router.checkWarpOnce()

	if router.warp != nil || router.warpErr == nil || router.warpReselecting {
		t.Fatalf("warp=%v err=%v reselecting=%v; want no tunnel and a retryable error",
			router.warp, router.warpErr, router.warpReselecting)
	}
	if state := router.warpState(); state != "failed" {
		t.Fatalf("warpState = %q, want failed", state)
	}
}

func TestDialFailuresTriggerCheck(t *testing.T) {
	router := newHealthTestRouter(t)
	tunnel := newFakeTunnel("8.6.112.10:2408").tunnel
	router.warp = tunnel
	failure := errors.New("connect: i/o timeout")

	router.noteWarpDial(tunnel, failure)
	router.noteWarpDial(tunnel, context.Canceled) // caller gave up: not counted
	router.noteWarpDial(tunnel, failure)
	select {
	case <-router.warpCheck:
		t.Fatal("check requested before the threshold")
	default:
	}
	router.noteWarpDial(tunnel, failure)
	select {
	case <-router.warpCheck:
	default:
		t.Fatal("three failed dials did not request a check")
	}

	router.noteWarpDial(tunnel, failure)
	router.noteWarpDial(tunnel, nil) // a success resets the streak
	router.noteWarpDial(tunnel, failure)
	router.noteWarpDial(tunnel, failure)
	select {
	case <-router.warpCheck:
		t.Fatal("streak was not reset by a successful dial")
	default:
	}
}

func TestDialFailsFastWhileReselecting(t *testing.T) {
	router := newHealthTestRouter(t)
	router.warpReselecting = true
	started := time.Now()
	_, err := router.dialWarpNetwork(context.Background(), "tcp", "203.0.113.1:443")
	if !errors.Is(err, errWarpReselecting) {
		t.Fatalf("err = %v, want errWarpReselecting", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("dial took %s while reselecting", elapsed)
	}
}

func TestEndpointCacheDrop(t *testing.T) {
	cache := newEndpointCache(filepath.Join(t.TempDir(), "warp-endpoints.json"))
	keep := warpCandidate{endpoint: "8.6.112.1:2408", profile: defaultAWGProfile()}
	drop := warpCandidate{endpoint: "8.6.112.2:2408", profile: defaultAWGProfile()}
	cache.remember("wifi", keep, time.Second)
	cache.remember("wifi", drop, time.Second)
	cache.drop("wifi", drop)
	entries := cache.snapshot()
	if len(entries) != 1 || entries[0].Endpoint != keep.endpoint {
		t.Fatalf("entries = %+v, want only %s", entries, keep.endpoint)
	}
}
