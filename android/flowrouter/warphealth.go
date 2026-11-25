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
}

var defaultWarpHealth = warpHealthSettings{
	interval:                20 * time.Second,
	pingTimeout:             4 * time.Second,
	pingAttempts:            2,
	recheckDelay:            2 * time.Second,
	dialFailuresBeforeCheck: 3,
	reselectTimeout:         15 * time.Second,
}

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

// watchWarp runs until the router closes.
func (r *flowRouter) watchWarp() {
	ticker := time.NewTicker(r.health.interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.context.Done():
			return
		case <-ticker.C:
		case <-r.warpCheck:
		}
		r.checkWarpOnce()
	}
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
	r.reselectWarp(tunnel, "liveness ping failed twice")
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
