package main

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"time"
)

// WARP backups. The live tunnel keeps up to warpBackupsMax pairs from the
// round that picked it. When the provider cuts the tunnel's flow and a
// reconnect from a new source port does not bring it back (or the pair was
// cut again within warpRecentCut), the next backup takes over in a second or
// two instead of a selection round of up to half a minute, during which
// Telegram and every other WARP connection get nothing.
//
// Every warpBackupCheckEvery the probe identity re-tests the first backup and
// drops it when dead. An empty list is refilled by a round with the probe
// identity, at most every warpBackupRefillEvery and only while the network
// keeps cutting the tunnel: mobile data is not spent on a stable network.

const (
	warpBackupsMax        = 3
	warpRecentCut         = 3 * time.Minute
	warpBackupApply       = 4 * time.Second
	warpBackupBudget      = 10 * time.Second
	warpBackupCheckEvery  = 10 * time.Minute
	warpBackupCheckTime   = 6 * time.Second
	warpBackupRefillEvery = 30 * time.Minute
	warpBackupRefillTime  = 30 * time.Second
	// warpRefillWindow: refills happen only this soon after a recovery.
	warpRefillWindow = time.Hour
)

func firstBackups(sorted []warpEvaluation) []warpEvaluation {
	if len(sorted) > warpBackupsMax {
		sorted = sorted[:warpBackupsMax]
	}
	return append([]warpEvaluation(nil), sorted...)
}

// openWarpPair opens a candidate with config and proves data flows within
// timeout.
func openWarpPair(ctx context.Context, config warpConfig, candidate warpCandidate,
	resolver func(context.Context, string) ([]netip.Addr, error), probeTarget string, timeout time.Duration) (*warpTunnel, error) {
	var tunnel *warpTunnel
	var err error
	if candidate.transport.isMasque() {
		tunnel, err = openMasque(ctx, config.Masque, candidate.endpoint, candidate.transport, resolver)
	} else {
		tunnel, err = openWarp(config, candidate.endpoint, candidate.profile, resolver)
	}
	if err != nil {
		return nil, err
	}
	probeContext, cancel := context.WithTimeout(ctx, timeout)
	err = probeWarpRoute(probeContext, tunnel, probeTarget)
	cancel()
	if err != nil {
		tunnel.close()
		return nil, err
	}
	return tunnel, nil
}

// switchWarpBackup replaces dead with the first backup that carries data with
// the live identity. Connections of dead were on the cut flow and are closed.
func (r *flowRouter) switchWarpBackup(dead *warpTunnel, reason string) bool {
	r.warpMutex.Lock()
	if r.warp != dead || r.warpReselecting || len(r.warpBackups) == 0 || r.context.Err() != nil {
		r.warpMutex.Unlock()
		return false
	}
	backups := r.warpBackups
	r.warpBackups = nil
	config := r.activeWarpConfigLocked()
	probeTarget := r.warpProbeTarget
	// Like a reselection: dials fail fast (Auto mode uses ByeDPI) meanwhile.
	r.warp = nil
	r.warpErr = errWarpReselecting
	r.warpReselecting = true
	r.warpMutex.Unlock()

	started := time.Now()
	closed := dead.conns.closeAll()
	dead.close()
	r.endpoints.drop(r.options.NetworkKey, dead.candidate)

	ctx, cancel := context.WithTimeout(r.context, warpBackupBudget)
	defer cancel()
	var tunnel *warpTunnel
	var used warpEvaluation
	remaining := backups
	for len(remaining) > 0 && ctx.Err() == nil {
		evaluation := remaining[0]
		remaining = remaining[1:]
		var err error
		tunnel, err = r.openWarpPair(ctx, config, evaluation.candidate, probeTarget, warpBackupApply)
		if err == nil {
			used = evaluation
			break
		}
		flowRouterLogf("WARP backup %s carried no data: %v", evaluation.candidate.endpoint, err)
	}

	r.warpMutex.Lock()
	r.warpReselecting = false
	if tunnel == nil || r.context.Err() != nil {
		r.warpBackups = nil
		r.warpMutex.Unlock()
		if tunnel != nil {
			tunnel.close()
		}
		if r.context.Err() == nil {
			// The dead pair is closed already: select from nothing.
			r.reselectWarp(nil, reason+"; no backup carried data")
		}
		return true
	}
	tunnel.endpoint = used.candidate.endpoint
	tunnel.transport = transportLabel(used.candidate)
	tunnel.candidate = used.candidate
	tunnel.colo = used.colo
	tunnel.ideal = used.perfect()
	tunnel.openedAt = time.Now()
	r.warp, r.warpErr = tunnel, nil
	r.warpBackups = remaining
	r.warpDialFailures = 0
	r.warpLastCut = time.Time{}
	r.warpMutex.Unlock()
	flowRouterLogf("WARP %s: %s; backup %s (exit %s) took over in %s, closed %d connections from the cut flow, %d backups left",
		dead.endpoint, reason, tunnel.endpoint, orDash(tunnel.colo), time.Since(started).Round(time.Millisecond), closed, len(remaining))
	return true
}

// offerWarpBackups fills an empty backup list from evaluations of a round
// that left current in place.
func (r *flowRouter) offerWarpBackups(current *warpTunnel, evaluated []warpEvaluation) {
	sorted := make([]warpEvaluation, 0, len(evaluated))
	for _, evaluation := range evaluated {
		if evaluation.err == nil && evaluation.candidate.endpoint != current.endpoint {
			sorted = append(sorted, evaluation)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].better(sorted[j]) })
	r.warpMutex.Lock()
	defer r.warpMutex.Unlock()
	if r.warp == current && len(r.warpBackups) == 0 {
		r.warpBackups = firstBackups(sorted)
	}
}

func (r *flowRouter) warpBackupCheckDue(tunnel *warpTunnel) bool {
	r.warpMutex.Lock()
	defer r.warpMutex.Unlock()
	// The probe identity is busy while a replaced tunnel drains on it.
	return r.warp == tunnel && !r.warpReselecting && r.warpConfig.Probe != nil && r.warpDraining == nil &&
		time.Since(tunnel.openedAt) >= time.Minute && time.Since(r.warpBackupChecked) >= warpBackupCheckEvery
}

// checkWarpBackups re-tests the backups with the probe identity until one
// passes, dropping the dead ones, and refills an empty list on a network
// that recently cut the tunnel. parent cancels the check (runWarpBackground);
// a backup whose test was cut short is kept.
func (r *flowRouter) checkWarpBackups(parent context.Context, current *warpTunnel) {
	r.warpMutex.Lock()
	r.warpBackupChecked = time.Now()
	backups := append([]warpEvaluation(nil), r.warpBackups...)
	config := r.activeWarpConfigLocked()
	probeTarget := r.warpProbeTarget
	refillDue := time.Since(r.warpNeededRecovery) < warpRefillWindow && time.Since(r.warpBackupRefilled) >= warpBackupRefillEvery
	r.warpMutex.Unlock()
	if config.Probe == nil {
		return
	}
	probing := *config.Probe
	probing.Masque = config.Masque

	var dead []string
	for _, backup := range backups {
		ctx, cancel := context.WithTimeout(parent, warpBackupCheckTime+2*time.Second)
		tunnel, err := r.openWarpPair(ctx, probing, backup.candidate, probeTarget, warpBackupCheckTime)
		cancel()
		if parent.Err() != nil {
			if tunnel != nil {
				tunnel.close()
			}
			return
		}
		if err == nil {
			tunnel.close()
			break
		}
		flowRouterLogf("WARP backup %s no longer carries data: %v", backup.candidate.endpoint, err)
		dead = append(dead, backup.candidate.endpoint)
	}
	r.warpMutex.Lock()
	kept := make([]warpEvaluation, 0, len(r.warpBackups))
	for _, backup := range r.warpBackups {
		if !containsString(dead, backup.candidate.endpoint) {
			kept = append(kept, backup)
		}
	}
	r.warpBackups = kept
	empty := len(kept) == 0 && r.warp == current
	if empty && refillDue {
		r.warpBackupRefilled = time.Now()
	}
	r.warpMutex.Unlock()
	if !empty || !refillDue {
		return
	}
	ctx, cancel := context.WithTimeout(parent, warpBackupRefillTime)
	evaluated, err := selectWarpEvaluations(ctx, config, probeTarget, r.resolveWarpHost, r.warpSelection(), current.endpoint)
	cancel()
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			flowRouterLogf("WARP backups: none found: %v", err)
		}
		return
	}
	r.offerWarpBackups(current, evaluated)
	r.warpMutex.Lock()
	count := len(r.warpBackups)
	r.warpMutex.Unlock()
	flowRouterLogf("WARP backups: %d ready", count)
}

// mergeWarpBackups is the best warpBackupsMax pairs of lists, without
// failed ones, duplicates or the live pair.
func mergeWarpBackups(live warpCandidate, lists ...[]warpEvaluation) []warpEvaluation {
	key := func(candidate warpCandidate) string { return candidate.endpoint + "|" + candidate.transport.String() }
	seen := map[string]bool{key(live): true}
	var merged []warpEvaluation
	for _, list := range lists {
		for _, evaluation := range list {
			if evaluation.err != nil || seen[key(evaluation.candidate)] {
				continue
			}
			seen[key(evaluation.candidate)] = true
			merged = append(merged, evaluation)
		}
	}
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].better(merged[j]) })
	return firstBackups(merged)
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
