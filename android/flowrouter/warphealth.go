package main

import (
	"context"
	"errors"
	"net"
	"time"
)

// WARP health watching. After selection an endpoint can stop passing traffic
// (Cloudflare drains a node, the provider starts filtering it, NAT state is
// lost). The router notices that on its own and selects a new endpoint in the
// background, without restarting the VPN service: Auto mode falls back to
// ByeDPI meanwhile and WARP mode fails new connections fast until the new
// tunnel is up.

var errWarpReselecting = errors.New("WARP endpoint is being replaced")

type warpHealthSettings struct {
	// interval between routine liveness checks of the selected tunnel.
	interval time.Duration
	// pingTimeout bounds one liveness ping (several TCP handshake attempts).
	pingTimeout time.Duration
	// pingAttempts is how many handshakes one ping tries before it fails.
	pingAttempts int
	// recheckDelay separates the two pings that must both fail.
	recheckDelay time.Duration
	// dialFailuresBeforeCheck consecutive failed WARP dials trigger an
	// immediate check instead of waiting for the next interval.
	dialFailuresBeforeCheck int
	// reselectTimeout bounds one background selection round.
	reselectTimeout time.Duration
	// Between checks the counters of an AmneziaWG tunnel are read every
	// stallTick; sending for stallWindow with nothing received means the
	// network most likely cut the flow.
	stallTick   time.Duration
	stallWindow time.Duration
}

var defaultWarpHealth = warpHealthSettings{
	interval:                20 * time.Second,
	pingTimeout:             4 * time.Second,
	pingAttempts:            2,
	recheckDelay:            2 * time.Second,
	dialFailuresBeforeCheck: 3,
	reselectTimeout:         30 * time.Second,
	stallTick:               2 * time.Second,
	stallWindow:             4 * time.Second,
}

// A stall needs stallMinPackets packets and stallMinSent bytes sent in the
// window with nothing received: an app's request and its first retransmit
// qualify, a lone keepalive does not.
const (
	stallMinSent    = 100
	stallMinPackets = 2
)

// defaultPingWarp reports whether the tunnel still carries traffic.
func (r *flowRouter) defaultPingWarp(ctx context.Context, tunnel *warpTunnel) error {
	_, err := tunnel.ping(ctx, r.health.pingAttempts)
	return err
}

// defaultOpenWarpRoute runs a full selection round.
func (r *flowRouter) defaultOpenWarpRoute(ctx context.Context) (*warpTunnel, error) {
	r.warpMutex.Lock()
	probeTarget := r.warpProbeTarget
	r.warpMutex.Unlock()
	if probeTarget == "" {
		addresses, err := r.resolveWarpHost(ctx, "www.youtube.com")
		if err != nil {
			return nil, err
		}
		probeTarget = net.JoinHostPort(addresses[0].String(), "443")
		r.warpMutex.Lock()
		r.warpProbeTarget = probeTarget
		r.warpMutex.Unlock()
	}
	return openWorkingWarp(ctx, r.warpConfig, probeTarget, r.resolveWarpHost, r.warpSelection())
}

// requestWarpCheck asks the watcher for an immediate check without blocking.
func (r *flowRouter) requestWarpCheck() {
	select {
	case r.warpCheck <- struct{}{}:
	default:
	}
}

// noteWarpDial records the outcome of a dial through the selected tunnel.
func (r *flowRouter) noteWarpDial(tunnel *warpTunnel, err error) {
	if err != nil && errors.Is(err, context.Canceled) {
		// The caller gave up (another route won); says nothing about WARP.
		return
	}
	r.warpMutex.Lock()
	if r.warp != tunnel {
		r.warpMutex.Unlock()
		return
	}
	if err == nil {
		r.warpDialFailures = 0
		r.warpMutex.Unlock()
		return
	}
	r.warpDialFailures++
	trigger := r.warpDialFailures >= r.health.dialFailuresBeforeCheck
	if trigger {
		r.warpDialFailures = 0
	}
	r.warpMutex.Unlock()
	if trigger {
		r.requestWarpCheck()
	}
}

// watchWarp runs until the router closes: a liveness check every interval
// and, between them, a look at the tunnel's counters every stallTick.
func (r *flowRouter) watchWarp() {
	tick := time.NewTicker(r.health.stallTick)
	defer tick.Stop()
	next := time.Now().Add(r.health.interval)
	var stall stallDetector
	for {
		select {
		case <-r.context.Done():
			return
		case <-r.warpCheck:
			next = time.Now()
		case <-tick.C:
		}
		if !time.Now().Before(next) {
			r.checkWarpOnce()
			next = time.Now().Add(r.health.interval)
			stall.reset()
			continue
		}
		r.warpMutex.Lock()
		tunnel, reselecting := r.warp, r.warpReselecting
		r.warpMutex.Unlock()
		if tunnel == nil || reselecting {
			stall.reset()
			continue
		}
		rx, tx, sent, ok := tunnel.traffic()
		if !ok {
			continue
		}
		if stall.add(tunnel, time.Now(), rx, tx, sent, r.health.stallWindow) && !r.warpAlive(tunnel) {
			r.recoverWarp(tunnel, "the tunnel sends and receives nothing")
			stall.reset()
			next = time.Now().Add(r.health.interval)
		}
	}
}

// stallDetector watches a tunnel's byte counters.
type stallDetector struct {
	tunnel  *warpTunnel
	samples []trafficSample
}

type trafficSample struct {
	at           time.Time
	rx, tx, sent uint64
}

func (d *stallDetector) reset() {
	d.tunnel = nil
	d.samples = d.samples[:0]
}

// add records a sample and reports a suspected stall.
func (d *stallDetector) add(tunnel *warpTunnel, at time.Time, rx, tx, sent uint64, window time.Duration) bool {
	if d.tunnel != tunnel {
		d.reset()
		d.tunnel = tunnel
	}
	d.samples = append(d.samples, trafficSample{at, rx, tx, sent})
	for len(d.samples) > 1 && at.Sub(d.samples[1].at) >= window {
		d.samples = d.samples[1:]
	}
	first := d.samples[0]
	if at.Sub(first.at) < window || rx != first.rx || tx-first.tx < stallMinSent || sent-first.sent < stallMinPackets {
		return false
	}
	d.samples = d.samples[:0]
	return true
}

// recoverWarp handles a tunnel that stopped passing traffic. A dead flow is
// usually the network cutting this UDP flow, not a dead endpoint, so an
// AmneziaWG tunnel first reconnects to the same endpoint from a new source
// port, which takes a second or two instead of a new selection. Connections
// opened over the cut flow cannot come back and are closed, so apps
// reconnect at once. Only when that fails is a new endpoint selected.
func (r *flowRouter) recoverWarp(tunnel *warpTunnel, reason string) {
	if tunnel.device != nil && r.context.Err() == nil {
		if err := tunnel.reconnect(); err == nil {
			ctx, cancel := context.WithTimeout(r.context, 6*time.Second)
			_, pingErr := tunnel.ping(ctx, 4)
			cancel()
			if pingErr == nil {
				closed := tunnel.conns.closeAll()
				r.warpMutex.Lock()
				current := r.warp == tunnel
				if current {
					r.warpReconnects++
					r.warpDialFailures = 0
				}
				r.warpMutex.Unlock()
				if current {
					flowRouterLogf("WARP %s: %s; reconnected from a new source port, closed %d connections from the cut flow",
						tunnel.endpoint, reason, closed)
					return
				}
			} else {
				flowRouterLogf("WARP %s: reconnect from a new source port carried no data: %v", tunnel.endpoint, pingErr)
			}
		}
	}
	r.reselectWarp(tunnel, reason)
}

// checkWarpOnce checks the selected tunnel and replaces it if it is dead, or
// retries selection when there is no tunnel.
func (r *flowRouter) checkWarpOnce() {
	r.warpMutex.Lock()
	tunnel := r.warp
	reselecting := r.warpReselecting
	retryDue := time.Since(r.warpTried) >= warpRetryInterval
	r.warpMutex.Unlock()
	if reselecting || r.context.Err() != nil {
		return
	}
	if tunnel == nil {
		if retryDue {
			r.reselectWarp(nil, "no working WARP endpoint")
		}
		return
	}
	if r.warpAlive(tunnel) {
		return
	}
	select {
	case <-r.context.Done():
		return
	case <-time.After(r.health.recheckDelay):
	}
	if r.warpAlive(tunnel) {
		return
	}
	r.recoverWarp(tunnel, "liveness ping failed twice")
}

func (r *flowRouter) warpAlive(tunnel *warpTunnel) bool {
	ctx, cancel := context.WithTimeout(r.context, r.health.pingTimeout)
	defer cancel()
	err := r.pingWarp(ctx, tunnel)
	if err != nil && r.context.Err() == nil {
		flowRouterLogf("WARP liveness ping through %s failed: %v", tunnel.endpoint, err)
	}
	return err == nil
}

// reselectWarp replaces dead (nil when there is no tunnel) with a freshly
// selected one. Only one replacement runs at a time.
func (r *flowRouter) reselectWarp(dead *warpTunnel, reason string) {
	r.warpMutex.Lock()
	if r.warpReselecting || r.warp != dead {
		r.warpMutex.Unlock()
		return
	}
	r.warp = nil
	r.warpErr = errWarpReselecting
	r.warpReselecting = true
	r.warpDialFailures = 0
	r.warpTried = time.Now()
	r.warpMutex.Unlock()

	if dead != nil {
		flowRouterLogf("WARP endpoint %s (%s) dropped: %s; selecting a new one", dead.endpoint, dead.transport, reason)
		dead.close()
		r.endpoints.drop(r.options.NetworkKey, dead.candidate)
	} else {
		flowRouterLogf("WARP selection retry: %s", reason)
	}

	ctx, cancel := context.WithTimeout(r.context, r.health.reselectTimeout)
	tunnel, err := r.openWarpRoute(ctx)
	cancel()

	r.warpMutex.Lock()
	r.warpReselecting = false
	r.warpTried = time.Now()
	if r.context.Err() != nil {
		r.warpMutex.Unlock()
		if tunnel != nil {
			tunnel.close()
		}
		return
	}
	if err == nil && tunnel == nil {
		err = errors.New("WARP selection returned no tunnel")
	}
	r.warp, r.warpErr = tunnel, err
	r.warpMutex.Unlock()
	if err != nil {
		flowRouterLogf("WARP replacement failed, retrying in %s: %v", warpRetryInterval, err)
		return
	}
	flowRouterLogf("WARP replacement ready: %s (%s)", tunnel.endpoint, tunnel.transport)
}
