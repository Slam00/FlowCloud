package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestActiveWarpConfigSwapsIdentities(t *testing.T) {
	masque := &masqueConfig{}
	main := warpConfig{PrivateKey: "main", Masque: masque, Probe: &warpConfig{PrivateKey: "probe"}}
	r := &flowRouter{warpConfig: main}
	if got := r.activeWarpConfigLocked(); got.PrivateKey != "main" || got.Probe.PrivateKey != "probe" {
		t.Fatalf("unswapped: %+v", got)
	}
	r.warpSwapped = true
	got := r.activeWarpConfigLocked()
	if got.PrivateKey != "probe" || got.Probe == nil || got.Probe.PrivateKey != "main" {
		t.Fatalf("swapped: %+v", got)
	}
	if got.Masque != masque || got.Probe.Masque != nil || got.Probe.Probe != nil {
		t.Fatalf("swapped extras: %+v", got)
	}
	if r.warpConfig.PrivateKey != "main" || r.warpConfig.Probe.PrivateKey != "probe" {
		t.Fatalf("stored config changed: %+v", r.warpConfig)
	}
}

func TestDrainWarpClosesReplacedTunnelWhenIdle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := make(chan struct{})
	old := &warpTunnel{endpoint: "old", closer: func() { close(closed) }}
	client, server := net.Pipe()
	defer server.Close()
	connection := old.conns.wrap(client)
	r := &flowRouter{context: ctx, warpDraining: old}
	done := make(chan struct{})
	go func() {
		r.drainWarp(old)
		close(done)
	}()
	select {
	case <-closed:
		t.Fatal("closed with a connection still open")
	case <-time.After(100 * time.Millisecond):
	}
	_ = connection.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("not closed after its last connection")
	}
	select {
	case <-closed:
	default:
		t.Fatal("tunnel not closed")
	}
	if r.warpDraining != nil {
		t.Fatal("draining tunnel still set")
	}
}

func TestUpgradeWaitGrowsUntilFound(t *testing.T) {
	r := &flowRouter{}
	var waits []time.Duration
	for range 5 {
		r.upgradeFound(false)
		waits = append(waits, r.upgradeWaitLocked())
	}
	want := []time.Duration{20 * time.Minute, 40 * time.Minute, time.Hour, time.Hour, time.Hour}
	for index := range want {
		if waits[index] != want[index] {
			t.Fatalf("waits %v, want %v", waits, want)
		}
	}
	r.upgradeFound(true)
	if got := r.upgradeWaitLocked(); got != warpUpgradeEvery {
		t.Fatalf("after success %s, want %s", got, warpUpgradeEvery)
	}
}

func TestDeadWarpSwitchesToBackup(t *testing.T) {
	router := newHealthTestRouter(t)
	dead := newFakeTunnel("8.6.112.10:2408")
	good := newFakeTunnel("162.159.192.7:500")
	router.warp = dead.tunnel
	router.warpBackups = []warpEvaluation{
		{candidate: warpCandidate{endpoint: "8.6.112.99:2408"}, sites: 2, sitesOK: 2},
		{candidate: warpCandidate{endpoint: "162.159.192.7:500"}, colo: "ARN", sites: 2, sitesOK: 2},
		{candidate: warpCandidate{endpoint: "188.114.97.3:4500"}, sites: 2, sitesOK: 1},
	}
	router.pingWarp = func(context.Context, *warpTunnel) error { return errors.New("timeout") }
	var tried []string
	router.openWarpPair = func(_ context.Context, _ warpConfig, candidate warpCandidate, _ string, _ time.Duration) (*warpTunnel, error) {
		tried = append(tried, candidate.endpoint)
		if candidate.endpoint == good.tunnel.endpoint {
			return good.tunnel, nil
		}
		return nil, errors.New("no data")
	}
	router.openWarpRoute = func(context.Context) (*warpTunnel, error) {
		t.Error("selection round started although a backup works")
		return nil, errors.New("unexpected")
	}

	router.checkWarpOnce()

	if router.warp != good.tunnel || router.warpErr != nil || router.warpReselecting {
		t.Fatalf("warp=%v err=%v reselecting=%v; want the second backup", router.warp, router.warpErr, router.warpReselecting)
	}
	if dead.closed.Load() != 1 {
		t.Fatal("dead tunnel was not closed")
	}
	if len(tried) != 2 || len(router.warpBackups) != 1 || router.warpBackups[0].candidate.endpoint != "188.114.97.3:4500" {
		t.Fatalf("tried %v, backups left %v", tried, router.warpBackups)
	}
	if good.tunnel.colo != "ARN" || !good.tunnel.ideal {
		t.Fatalf("backup tunnel colo=%q ideal=%v", good.tunnel.colo, good.tunnel.ideal)
	}
}

func TestDeadWarpWithoutWorkingBackupReselects(t *testing.T) {
	router := newHealthTestRouter(t)
	dead := newFakeTunnel("8.6.112.10:2408")
	replacement := newFakeTunnel("188.114.97.20:500")
	router.warp = dead.tunnel
	router.warpBackups = []warpEvaluation{{candidate: warpCandidate{endpoint: "8.6.112.99:2408"}}}
	router.pingWarp = func(context.Context, *warpTunnel) error { return errors.New("timeout") }
	router.openWarpPair = func(context.Context, warpConfig, warpCandidate, string, time.Duration) (*warpTunnel, error) {
		return nil, errors.New("no data")
	}
	rounds := 0
	router.openWarpRoute = func(context.Context) (*warpTunnel, error) {
		rounds++
		return replacement.tunnel, nil
	}

	router.checkWarpOnce()

	if rounds != 1 || router.warp != replacement.tunnel || dead.closed.Load() != 1 {
		t.Fatalf("rounds=%d warp=%v dead closed=%d", rounds, router.warp, dead.closed.Load())
	}
}
