package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// A second cut soon after a reconnect skips the reconnect only when a backup
// can take over: without one the reconnect (a second or two) beats a full
// selection round (up to half a minute).
func TestRepeatedCutWithoutBackupStillReconnects(t *testing.T) {
	r := &flowRouter{}
	if r.noteWarpCut() {
		t.Fatal("first cut skipped the reconnect")
	}
	if r.noteWarpCut() {
		t.Fatal("repeated cut without backups skipped the reconnect")
	}
	r.warpBackups = []warpEvaluation{{candidate: warpCandidate{endpoint: "162.159.192.7:500"}}}
	if !r.noteWarpCut() {
		t.Fatal("repeated cut with a backup did not go to the backup")
	}
	r.warpLastCut = time.Now().Add(-2 * warpRecentCut)
	if r.noteWarpCut() {
		t.Fatal("a cut long after the last one skipped the reconnect")
	}
}

func newStallingTunnel(endpoint string) (*fakeTunnel, func(context.Context)) {
	fake := newFakeTunnel(endpoint)
	fake.tunnel.bind = newCountingBind(nil)
	// pump sends with nothing received, as over a cut flow.
	pump := func(ctx context.Context) {
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				fake.tunnel.bind.tx.Add(200)
				fake.tunnel.bind.sent.Add(1)
			}
		}
	}
	return fake, pump
}

// Upgrade searches and backup checks run on the watcher for up to half a
// minute; a cut meanwhile must stop them instead of waiting them out.
func TestBackgroundJobStopsOnStall(t *testing.T) {
	router := newHealthTestRouter(t)
	router.health.stallTick = 5 * time.Millisecond
	router.health.stallWindow = 30 * time.Millisecond
	live, pump := newStallingTunnel("8.6.112.10:2408")
	pumpContext, stopPump := context.WithCancel(context.Background())
	defer stopPump()
	go pump(pumpContext)

	started := time.Now()
	var jobErr error
	interrupted := router.runWarpBackground(live.tunnel, func(ctx context.Context) {
		select {
		case <-ctx.Done():
			jobErr = ctx.Err()
		case <-time.After(10 * time.Second):
		}
	})
	if !interrupted || jobErr == nil {
		t.Fatalf("interrupted=%v jobErr=%v; want the job cancelled", interrupted, jobErr)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("stall handled after %s", elapsed)
	}
}

func TestBackgroundJobStopsOnCheckRequest(t *testing.T) {
	router := newHealthTestRouter(t)
	router.health.stallTick = time.Hour
	live := newFakeTunnel("8.6.112.10:2408")
	interrupted := router.runWarpBackground(live.tunnel, func(ctx context.Context) {
		router.requestWarpCheck()
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
			t.Error("check request did not stop the job")
		}
	})
	if !interrupted {
		t.Fatal("not reported as interrupted")
	}
}

func TestBackgroundJobRunsToTheEnd(t *testing.T) {
	router := newHealthTestRouter(t)
	router.health.stallTick = 5 * time.Millisecond
	router.health.stallWindow = 30 * time.Millisecond
	live := newFakeTunnel("8.6.112.10:2408")
	live.tunnel.bind = newCountingBind(nil)
	ran := false
	interrupted := router.runWarpBackground(live.tunnel, func(ctx context.Context) {
		time.Sleep(100 * time.Millisecond)
		ran = ctx.Err() == nil
	})
	if interrupted || !ran {
		t.Fatalf("interrupted=%v ran=%v; an idle tunnel is no stall", interrupted, ran)
	}
}

// A backup check cut short says nothing about the backups.
func TestInterruptedBackupCheckKeepsBackups(t *testing.T) {
	router := newHealthTestRouter(t)
	probe := router.warpConfig
	router.warpConfig.Probe = &probe
	live := newFakeTunnel("8.6.112.10:2408")
	router.warp = live.tunnel
	router.warpBackups = []warpEvaluation{
		{candidate: warpCandidate{endpoint: "162.159.192.7:500"}},
		{candidate: warpCandidate{endpoint: "188.114.97.3:4500"}},
	}
	router.openWarpPair = func(ctx context.Context, _ warpConfig, _ warpCandidate, _ string, _ time.Duration) (*warpTunnel, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	router.checkWarpBackups(ctx, live.tunnel)
	if len(router.warpBackups) != 2 {
		t.Fatalf("backups after an interrupted check: %v", router.warpBackups)
	}
}

// Connections left on a replaced tunnel whose flow the provider cuts are
// closed at once, so apps reconnect over the live tunnel.
func TestDrainingTunnelClosedOnStall(t *testing.T) {
	saved := warpDrainTick
	warpDrainTick = 5 * time.Millisecond
	defer func() { warpDrainTick = saved }()
	router := newHealthTestRouter(t)
	router.health.stallWindow = 30 * time.Millisecond
	router.pingWarp = func(context.Context, *warpTunnel) error { return errors.New("timeout") }
	old, pump := newStallingTunnel("8.6.112.10:2408")
	pumpContext, stopPump := context.WithCancel(context.Background())
	defer stopPump()
	go pump(pumpContext)
	client, server := net.Pipe()
	defer server.Close()
	old.tunnel.conns.wrap(client)
	router.warpDraining = old.tunnel

	done := make(chan struct{})
	go func() {
		router.drainWarp(old.tunnel)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cut draining tunnel kept its connections")
	}
	if old.closed.Load() != 1 || old.tunnel.conns.count() != 0 {
		t.Fatalf("closed=%d connections=%d", old.closed.Load(), old.tunnel.conns.count())
	}
	router.warpMutex.Lock()
	draining := router.warpDraining
	router.warpMutex.Unlock()
	if draining != nil {
		t.Fatal("draining tunnel still set")
	}
}

// A draining tunnel that still answers keeps its connections.
func TestDrainingTunnelKeptWhileAlive(t *testing.T) {
	saved := warpDrainTick
	warpDrainTick = 5 * time.Millisecond
	defer func() { warpDrainTick = saved }()
	router := newHealthTestRouter(t)
	router.health.stallWindow = 30 * time.Millisecond
	router.pingWarp = func(context.Context, *warpTunnel) error { return nil }
	old, pump := newStallingTunnel("8.6.112.10:2408")
	pumpContext, stopPump := context.WithCancel(context.Background())
	defer stopPump()
	go pump(pumpContext)
	client, server := net.Pipe()
	defer server.Close()
	connection := old.tunnel.conns.wrap(client)
	router.warpDraining = old.tunnel

	done := make(chan struct{})
	go func() {
		router.drainWarp(old.tunnel)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("live draining tunnel closed")
	case <-time.After(200 * time.Millisecond):
	}
	_ = connection.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("not closed after its last connection")
	}
}

// After an upgrade the round has usually stopped at its first ideal pair:
// the pairs that passed without being ideal and the old backups stay as
// backups, without the live pair, failures or duplicates.
func TestMergeWarpBackups(t *testing.T) {
	live := warpCandidate{endpoint: "162.159.192.1:2408"}
	fromWinner := []warpEvaluation{{candidate: warpCandidate{endpoint: "162.159.192.2:2408"}, sites: 2, sitesOK: 2}}
	passed := []warpEvaluation{
		{candidate: warpCandidate{endpoint: "162.159.192.3:2408"}, sites: 2, sitesOK: 1, latency: 50 * time.Millisecond},
		{candidate: warpCandidate{endpoint: "162.159.192.4:2408"}, err: errors.New("no data")},
		{candidate: live},
	}
	old := []warpEvaluation{
		{candidate: warpCandidate{endpoint: "162.159.192.3:2408"}, sites: 2, sitesOK: 1},
		{candidate: warpCandidate{endpoint: "162.159.192.5:2408"}, sites: 2, sitesOK: 1, latency: 90 * time.Millisecond},
		{candidate: warpCandidate{endpoint: "162.159.192.6:2408"}, sites: 2, sitesOK: 0},
	}
	got := mergeWarpBackups(live, fromWinner, passed, old)
	want := []string{"162.159.192.2:2408", "162.159.192.3:2408", "162.159.192.5:2408"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for index, endpoint := range want {
		if got[index].candidate.endpoint != endpoint {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
