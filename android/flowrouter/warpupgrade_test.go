package main

import (
	"context"
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
