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
	// Testing runs with the identity a draining tunnel still uses.
	r.closeDrainingWarp()
	r.warpMutex.Lock()
	probeTarget := r.warpProbeTarget
	config := r.activeWarpConfigLocked()
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
	return openWorkingWarp(ctx, config, probeTarget, r.resolveWarpHost, r.warpSelection())
}

// activeWarpConfigLocked is the identity that carries traffic, with the other
// one as its probe; the caller holds warpMutex.
func (r *flowRouter) activeWarpConfigLocked() warpConfig {
	if !r.warpSwapped || r.warpConfig.Probe == nil {
		return r.warpConfig
	}
	active := *r.warpConfig.Probe
	other := r.warpConfig
	other.Probe, other.Masque = nil, nil
	active.Probe = &other
	active.Masque = r.warpConfig.Masque
	return active
}

// closeDrainingWarp ends the tunnel an upgrade replaced, before its identity
// is used for testing again.
func (r *flowRouter) closeDrainingWarp() {
	r.warpMutex.Lock()
	draining := r.warpDraining
	r.warpDraining = nil
	r.warpMutex.Unlock()
	if draining != nil {
		closed := draining.conns.closeAll()
		draining.close()
		flowRouterLogf("WARP %s: replaced tunnel closed with %d connections", draining.endpoint, closed)
	}
}

// drainWarp closes a replaced tunnel once its connections have finished, or
// after warpDrainMax.
func (r *flowRouter) drainWarp(tunnel *warpTunnel) {
	deadline := time.Now().Add(warpDrainMax)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for time.Now().Before(deadline) && tunnel.conns.count() > 0 {
		select {
		case <-r.context.Done():
			return
		case <-tick.C:
		}
	}
	r.warpMutex.Lock()
	current := r.warpDraining == tunnel
	r.warpMutex.Unlock()
	if current {
		r.closeDrainingWarp()
	}
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
		upgradeDue := tunnel != nil && !tunnel.ideal && r.warpConfig.Probe != nil && r.warpDraining == nil &&
			time.Since(tunnel.openedAt) >= warpUpgradeAfter && time.Since(r.warpUpgradeTried) >= r.upgradeWaitLocked()
		r.warpMutex.Unlock()
		if tunnel == nil || reselecting {
			stall.reset()
			continue
		}
		if upgradeDue {
			r.upgradeWarp(tunnel)
			stall.reset()
			next = time.Now().Add(r.health.interval)
			continue
		}
		if r.warpBackupCheckDue(tunnel) {
			r.checkWarpBackups(tunnel)
			stall.reset()
			next = time.Now().Add(r.health.interval)
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

// A tunnel selection settled for (not every test site open outside the
// avoided locations, or no time to test) gets a background search for a
// better pair warpUpgradeAfter after it came up, and again at most every
// warpUpgradeEvery. Only with the probe device: testing with the main key
// would take the session from the live tunnel.
const (
	warpUpgradeAfter = 90 * time.Second
	warpUpgradeEvery = 10 * time.Minute
	// Each search that finds nothing better doubles the pause, up to
	// warpUpgradeMaxWait: on a network without a good pair the search would
	// otherwise cost traffic and battery every 10 minutes. A new network
	// starts a new router, so the pause starts over there.
	warpUpgradeMaxWait = time.Hour
	warpUpgradeTimeout = 30 * time.Second
	// warpDrainMax bounds how long a replaced tunnel keeps its connections
	// (a game or a call). A successful upgrade leaves an ideal tunnel, which
	// is not upgraded again, so only a reselection ends a drain earlier.
	warpDrainMax = time.Hour
)

// upgradeWaitLocked is the pause before the next upgrade search; the caller
// holds warpMutex.
func (r *flowRouter) upgradeWaitLocked() time.Duration {
	if r.warpUpgradeWait < warpUpgradeEvery {
		return warpUpgradeEvery
	}
	return r.warpUpgradeWait
}

// upgradeFound records an upgrade search's outcome for the next pause.
func (r *flowRouter) upgradeFound(found bool) {
	r.warpMutex.Lock()
	defer r.warpMutex.Unlock()
	if found {
		r.warpUpgradeWait = 0
		return
	}
	r.warpUpgradeWait = min(2*r.upgradeWaitLocked(), warpUpgradeMaxWait)
	flowRouterLogf("WARP upgrade: next search in %s", r.warpUpgradeWait)
}

// upgradeWarp looks for an ideal pair with the probe identity and moves new
// connections to it without touching the live tunnel: the new pair opens with
// the probe identity it was just tested with (opening it with the live key
// would take Cloudflare's session from the live tunnel and cut every
// connection), and the identities swap roles. Connections of the old tunnel
// finish there (drainWarp).
func (r *flowRouter) upgradeWarp(current *warpTunnel) {
	r.warpMutex.Lock()
	r.warpUpgradeTried = time.Now()
	probeTarget := r.warpProbeTarget
	config := r.activeWarpConfigLocked()
	r.warpMutex.Unlock()
	if config.Probe == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.context, warpUpgradeTimeout)
	defer cancel()
	found := false
	defer func() { r.upgradeFound(found) }()
	evaluated, err := selectWarpEvaluations(ctx, config, probeTarget, r.resolveWarpHost, r.warpSelection(), current.endpoint)
	if err != nil {
		flowRouterLogf("WARP upgrade: no better pair than %s: %v", current.endpoint, err)
		return
	}
	var ideal []warpEvaluation
	for _, evaluation := range evaluated {
		if evaluation.perfect() {
			ideal = append(ideal, evaluation)
		}
	}
	if len(ideal) == 0 {
		flowRouterLogf("WARP upgrade: no pair opens every test site outside the avoided locations; keeping %s", current.endpoint)
		// They still passed with the probe identity: good backups.
		r.offerWarpBackups(current, evaluated)
		return
	}
	// The probe identity carries the new tunnel; its Probe is the live one,
	// which applyWarpWinner does not use.
	swapped := *config.Probe
	swapped.Masque = config.Masque
	started := time.Now()
	tunnel, err := applyWarpWinner(ctx, swapped, probeTarget, r.resolveWarpHost, r.warpSelection(), ideal, started)
	if err != nil {
		flowRouterLogf("WARP upgrade: %v; keeping %s", err, current.endpoint)
		return
	}
	r.warpMutex.Lock()
	if r.warp != current || r.context.Err() != nil {
		r.warpMutex.Unlock()
		tunnel.close()
		return
	}
	found = true
	r.warp = tunnel
	r.warpBackups = tunnel.backups
	r.warpSwapped = !r.warpSwapped
	r.warpDraining = current
	r.warpDialFailures = 0
	r.warpMutex.Unlock()
	flowRouterLogf("WARP upgrade: %s -> %s (exit %s); %d connections finish on the old tunnel",
		current.endpoint, tunnel.endpoint, orDash(tunnel.colo), current.conns.count())
	r.wait.Add(1)
	go func() {
		defer r.wait.Done()
		r.drainWarp(current)
	}()
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
	// A pair cut again soon after a reconnect is being cut over and over:
	// a backup is the quicker way out.
	r.warpMutex.Lock()
	recent := time.Since(r.warpLastCut) < warpRecentCut
	r.warpLastCut = time.Now()
	r.warpNeededRecovery = time.Now()
	r.warpMutex.Unlock()
	if recent {
		flowRouterLogf("WARP %s: %s again within %s of a reconnect; trying a backup", tunnel.endpoint, reason, warpRecentCut)
	}
	if !recent && tunnel.device != nil && r.context.Err() == nil {
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
	if r.switchWarpBackup(tunnel, reason) {
		return
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
	if tunnel != nil {
		r.warpBackups = tunnel.backups
	}
	r.warpMutex.Unlock()
	if err != nil {
		flowRouterLogf("WARP replacement failed, retrying in %s: %v", warpRetryInterval, err)
		return
	}
	flowRouterLogf("WARP replacement ready: %s (%s)", tunnel.endpoint, tunnel.transport)
}
