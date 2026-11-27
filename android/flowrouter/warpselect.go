package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WARP endpoint selection, ported from FlowCloud for OpenWrt:
//
//  1. Fast path: up to warpFastPathTries cached pairs that opened every test
//     site last time outside the avoided locations.
//  2. Ping round: every candidate in parallel, as before, but collecting up to
//     warpShortlistSize that pass the YouTube data probe instead of taking the
//     first one. With a probe device the round uses its key, never the main one.
//  3. Site stage: the shortlist one at a time (tunnels with one key take each
//     other's session), pools known to exit outside the avoided locations
//     first: the exit location from cdn-cgi/trace plus YouTube and Telegram.
//     The first pair that opens both outside the avoided locations wins.
//  4. The winner is opened with the main key and must carry data within
//     warpApplyTimeout; if not, the next evaluated pairs are tried.

const (
	warpShortlistSize   = 4
	warpCollectWindow   = time.Second
	warpEvaluateTimeout = 7 * time.Second
	warpApplyTimeout    = 6 * time.Second
	warpFastPathTries   = 2
	warpMaxBackups      = 3
	// warpApplyReserve of the caller's deadline stays for the main-key
	// check; the site stage starts a pair only with warpSiteStageCost left.
	warpApplyReserve  = 5 * time.Second
	warpSiteStageCost = 3 * time.Second
	// warpSiteTimeout bounds one site check: a site the exit blocks must not
	// eat the whole start budget.
	warpSiteTimeout = 3 * time.Second
)

// warpAvoidColos are Cloudflare locations from which WARP traffic leaves
// through Russian networks, so blocked sites stay blocked (seen on the test
// ISP: Telegram failed through Moscow, everything opened through Stockholm
// at the same ping). They are used only when nothing else opens the sites.
var defaultWarpAvoidColos = []string{"DME", "LED"}

// warpAvoidColos is set from the app's settings when a router starts
// (setWarpAvoidColos); one router runs at a time.
var warpAvoidColos atomic.Pointer[[]string]

// setWarpAvoidColos sets the avoided locations; nil restores the default.
func setWarpAvoidColos(colos []string) {
	if colos == nil {
		colos = defaultWarpAvoidColos
	}
	cleaned := make([]string, 0, len(colos))
	for _, colo := range colos {
		if colo = strings.ToUpper(strings.TrimSpace(colo)); colo != "" {
			cleaned = append(cleaned, colo)
		}
	}
	warpAvoidColos.Store(&cleaned)
}

func warpAvoided(colo string) bool {
	colos := defaultWarpAvoidColos
	if stored := warpAvoidColos.Load(); stored != nil {
		colos = *stored
	}
	for _, code := range colos {
		if strings.EqualFold(code, colo) {
			return true
		}
	}
	return false
}

// warpEvaluation is one pair tested by the site stage.
type warpEvaluation struct {
	candidate warpCandidate
	latency   time.Duration
	colo      string
	sitesOK   int
	sites     int
	err       error
}

func (e warpEvaluation) perfect() bool {
	return e.err == nil && e.sitesOK == e.sites && !warpAvoided(e.colo)
}

// better ranks by sites opened, then by an exit outside the avoided
// locations, then by latency.
func (e warpEvaluation) better(other warpEvaluation) bool {
	if e.sitesOK != other.sitesOK {
		return e.sitesOK > other.sitesOK
	}
	if avoidE, avoidO := warpAvoided(e.colo), warpAvoided(other.colo); avoidE != avoidO {
		return avoidO
	}
	return e.latency < other.latency
}

// warpSites are the addresses the site stage needs, resolved once per round on
// the physical network: the probe tunnels have no DNS of their own.
type warpSites struct {
	youtube  string // ip:443 for www.youtube.com
	telegram string // ip:443 for telegram.org, "" when unresolved
}

func (s warpSites) count() int {
	if s.telegram == "" {
		return 1
	}
	return 2
}

func openWorkingWarp(
	ctx context.Context,
	config warpConfig,
	probeTarget string,
	resolver func(context.Context, string) ([]netip.Addr, error),
	selection warpSelection,
) (*warpTunnel, error) {
	started := time.Now()
	evaluated, err := selectWarpEvaluations(ctx, config, probeTarget, resolver, selection, "")
	if err != nil {
		return nil, err
	}
	return applyWarpWinner(ctx, config, probeTarget, resolver, selection, evaluated, started)
}

// selectWarpEvaluations runs the fast path, the ping round and the site stage
// with the probing identity, within a budget: it stops looking for the ideal
// pair warpApplyReserve before ctx's deadline, keeping that time for the
// main-key check. With no pair site-tested by then, the ping round's passes
// come back untested (sites 0), fastest first: the pre-0.2.33 behaviour of
// taking the first pair that carried data. exclude skips one endpoint.
func selectWarpEvaluations(
	ctx context.Context,
	config warpConfig,
	probeTarget string,
	resolver func(context.Context, string) ([]netip.Addr, error),
	selection warpSelection,
	exclude string,
) ([]warpEvaluation, error) {
	probing := config
	if config.Probe != nil {
		probing = *config.Probe
		probing.Masque = config.Masque
	}
	budgetEnd := time.Now().Add(25 * time.Second)
	if deadline, ok := ctx.Deadline(); ok {
		budgetEnd = deadline.Add(-warpApplyReserve)
	}
	budgetContext, cancelBudget := context.WithDeadline(ctx, budgetEnd)
	defer cancelBudget()
	enoughFor := func(need time.Duration) bool { return time.Until(budgetEnd) >= need }

	sites := warpSites{youtube: probeTarget}
	if resolver != nil {
		resolveContext, cancel := context.WithTimeout(budgetContext, 3*time.Second)
		if addresses, err := resolver(resolveContext, "telegram.org"); err == nil && len(addresses) > 0 {
			sites.telegram = net.JoinHostPort(addresses[0].String(), "443")
		}
		cancel()
	}
	network := selection.networkKey
	cache := selection.cache

	var evaluated []warpEvaluation
	record := func(evaluation warpEvaluation) {
		cache.noteColo(network, evaluation.candidate.endpoint, evaluation.colo)
		evaluated = append(evaluated, evaluation)
	}
	done := func() bool {
		for _, evaluation := range evaluated {
			if evaluation.perfect() {
				return true
			}
		}
		return false
	}

	// 1. Fast path.
	tried := map[string]bool{}
	if exclude != "" {
		tried[exclude+"|"+transportAWG.String()] = true
	}
	fast := 0
	for _, entry := range cache.snapshot() {
		if fast == warpFastPathTries || !enoughFor(warpSiteStageCost) {
			break
		}
		if entry.Network != network || !entry.Sites || warpAvoided(entry.Colo) || entry.Endpoint == exclude {
			continue
		}
		fast++
		candidate := warpCandidate{endpoint: entry.Endpoint, profile: entry.Profile, source: sourceCached, transport: entry.Transport}
		tried[candidate.endpoint+"|"+candidate.transport.String()] = true
		evaluation := evaluateWarp(budgetContext, probing, candidate, resolver, sites, false)
		if evaluation.err != nil {
			cache.fail(network, candidate)
			flowRouterLogf("WARP cached pair %s failed: %v", candidate.endpoint, evaluation.err)
			continue
		}
		record(evaluation)
		if done() {
			return evaluated, nil
		}
	}

	// 2. Ping round.
	shortlist, err := warpPingRound(budgetContext, probing, probeTarget, resolver, selection, tried)
	if err != nil {
		if len(evaluated) > 0 {
			return evaluated, nil
		}
		return nil, err
	}
	// 3. Site stage: known good pools first, known avoided ones last.
	rank := func(candidate warpCandidate) int {
		switch colo := cache.poolColo(network, candidate.endpoint); {
		case colo == "":
			return 1
		case warpAvoided(colo):
			return 2
		default:
			return 0
		}
	}
	untested := append([]warpCandidate(nil), shortlist...)
	sort.SliceStable(shortlist, func(i, j int) bool { return rank(shortlist[i]) < rank(shortlist[j]) })
	var deferred []warpCandidate
	for _, candidate := range shortlist {
		if !enoughFor(warpSiteStageCost) {
			flowRouterLogf("WARP selection: out of time for the site stage; taking the best pair so far")
			break
		}
		evaluation := evaluateWarp(budgetContext, probing, candidate, resolver, sites, true)
		if evaluation.err != nil {
			continue
		}
		if evaluation.sites < 0 {
			// Exits in an avoided location: its sites are tested only if
			// nothing else opens them.
			cache.noteColo(network, candidate.endpoint, evaluation.colo)
			deferred = append(deferred, candidate)
			continue
		}
		record(evaluation)
		if done() {
			return evaluated, nil
		}
	}
	for _, candidate := range deferred {
		if !enoughFor(warpSiteStageCost) || len(evaluated) > 0 && bestEvaluation(evaluated).sitesOK == sites.count() {
			break
		}
		if evaluation := evaluateWarp(budgetContext, probing, candidate, resolver, sites, false); evaluation.err == nil {
			record(evaluation)
		}
	}
	if len(evaluated) == 0 {
		// Nothing site-tested in time: the ping round's passes, untested.
		for _, candidate := range untested {
			evaluated = append(evaluated, warpEvaluation{candidate: candidate, colo: cache.poolColo(network, candidate.endpoint)})
		}
	}
	if len(evaluated) == 0 {
		return nil, errors.New("start WARP route: no endpoint passed the site stage")
	}
	return evaluated, nil
}

func bestEvaluation(evaluated []warpEvaluation) warpEvaluation {
	var best warpEvaluation
	for index, evaluation := range evaluated {
		if index == 0 || evaluation.better(best) {
			best = evaluation
		}
	}
	return best
}

// applyWarpWinner opens the best evaluated pair with the main key and keeps it
// if it carries data; the next ones back it up. A pair the probe device just
// passed sometimes carries nothing once on the main key, and trying the next
// pair takes seconds instead of a new round.
func applyWarpWinner(
	ctx context.Context,
	config warpConfig,
	probeTarget string,
	resolver func(context.Context, string) ([]netip.Addr, error),
	selection warpSelection,
	evaluated []warpEvaluation,
	started time.Time,
) (*warpTunnel, error) {
	sorted := append([]warpEvaluation(nil), evaluated...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].better(sorted[j]) })
	ordered := sorted
	if len(ordered) > 1+warpMaxBackups {
		ordered = ordered[:1+warpMaxBackups]
	}
	var lastErr error
	for index, evaluation := range ordered {
		if ctx.Err() != nil {
			break
		}
		candidate := evaluation.candidate
		var tunnel *warpTunnel
		var err error
		if candidate.transport.isMasque() {
			tunnel, err = openMasque(ctx, config.Masque, candidate.endpoint, candidate.transport, resolver)
		} else {
			tunnel, err = openWarp(config, candidate.endpoint, candidate.profile, resolver)
		}
		if err == nil {
			applyContext, cancel := context.WithTimeout(ctx, warpApplyTimeout)
			err = probeWarpRoute(applyContext, tunnel, probeTarget)
			cancel()
		}
		if err != nil {
			if tunnel != nil {
				tunnel.close()
			}
			lastErr = err
			selection.cache.sitesFailed(selection.networkKey, candidate)
			flowRouterLogf("WARP pair %s carried no data with the main key: %v; trying the next one", candidate.endpoint, err)
			continue
		}
		tunnel.endpoint = candidate.endpoint
		tunnel.transport = transportLabel(candidate)
		tunnel.candidate = candidate
		tunnel.colo = evaluation.colo
		tunnel.ideal = evaluation.perfect()
		tunnel.openedAt = time.Now()
		tunnel.backups = firstBackups(sorted[index+1:])
		selection.cache.rememberEvaluated(selection.networkKey, candidate, evaluation.latency, evaluation.colo,
			evaluation.sites > 0 && evaluation.sitesOK == evaluation.sites)
		backup := ""
		if index > 0 {
			backup = fmt.Sprintf(", backup %d", index)
		}
		flowRouterLogf("WARP endpoint selected: %s [%s, %s] exit %s, sites %d/%d, in %s%s",
			candidate.endpoint, candidate.source, describeCandidate(candidate), orDash(evaluation.colo),
			evaluation.sitesOK, evaluation.sites, time.Since(started).Round(time.Millisecond), backup)
		return tunnel, nil
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	if lastErr == nil {
		lastErr = errors.New("no usable WARP endpoint")
	}
	return nil, fmt.Errorf("start WARP route: %w", lastErr)
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// evaluateWarp opens one pair with the probing identity and runs the site
// stage through it; the tunnel is closed afterwards. YouTube must open. With
// deferAvoided, a pair exiting in an avoided location returns right after the
// location check with sites set to -1.
func evaluateWarp(
	ctx context.Context,
	probing warpConfig,
	candidate warpCandidate,
	resolver func(context.Context, string) ([]netip.Addr, error),
	sites warpSites,
	deferAvoided bool,
) warpEvaluation {
	evaluation := warpEvaluation{candidate: candidate, sites: sites.count()}
	evaluateContext, cancel := context.WithTimeout(ctx, warpEvaluateTimeout)
	defer cancel()
	started := time.Now()
	var tunnel *warpTunnel
	var err error
	if candidate.transport.isMasque() {
		tunnel, err = openMasque(evaluateContext, probing.Masque, candidate.endpoint, candidate.transport, resolver)
	} else {
		tunnel, err = openWarp(probing, candidate.endpoint, candidate.profile, resolver)
	}
	if err != nil {
		evaluation.err = err
		return evaluation
	}
	defer tunnel.close()
	youtubeContext, cancelYouTube := context.WithTimeout(evaluateContext, warpSiteTimeout+time.Second)
	err = probeWarpRoute(youtubeContext, tunnel, sites.youtube)
	cancelYouTube()
	if err != nil {
		evaluation.err = err
		return evaluation
	}
	evaluation.latency = time.Since(started)
	traceContext, cancelTrace := context.WithTimeout(evaluateContext, 2*time.Second)
	evaluation.colo = warpTraceColo(traceContext, tunnel)
	cancelTrace()
	if deferAvoided && warpAvoided(evaluation.colo) {
		evaluation.sites = -1
		return evaluation
	}
	evaluation.sitesOK = 1 // YouTube
	if sites.telegram != "" {
		telegramContext, cancelTelegram := context.WithTimeout(evaluateContext, warpSiteTimeout)
		if err := httpsCheck(telegramContext, tunnel, sites.telegram, "telegram.org", "/"); err == nil {
			evaluation.sitesOK++
		}
		cancelTelegram()
	}
	return evaluation
}

// warpTraceColo reads the Cloudflare location the tunnel exits from.
func warpTraceColo(ctx context.Context, tunnel *warpTunnel) string {
	connection, err := tunnel.dialRaw(ctx, "tcp", warpDataTarget)
	if err != nil {
		return ""
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err = io.WriteString(connection, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"); err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(connection, 4096))
	for _, line := range strings.Split(string(body), "\n") {
		if colo, ok := strings.CutPrefix(strings.TrimSpace(line), "colo="); ok {
			return colo
		}
	}
	return ""
}

// httpsCheck opens host through the tunnel at address and waits for an HTTP
// status line; any status counts, a stalled or reset connection does not.
func httpsCheck(ctx context.Context, tunnel *warpTunnel, address, host, path string) error {
	connection, err := tunnel.dialRaw(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	secure := tls.Client(connection, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // Connectivity probe; the response is not trusted or consumed.
	})
	if err = secure.HandshakeContext(ctx); err != nil {
		return err
	}
	if _, err = fmt.Fprintf(secure, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host); err != nil {
		return err
	}
	status, err := bufio.NewReader(secure).ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(status, "HTTP/") {
		return fmt.Errorf("invalid status %q", strings.TrimSpace(status))
	}
	return nil
}

// warpPingRound tests every candidate in parallel with the probing identity
// and returns up to warpShortlistSize that passed, fastest first. It waits
// warpCollectWindow after the first pass for more, then cancels the rest and
// waits for their tunnels to close, so none of them can take the session of
// a site-stage tunnel that uses the same key.
func warpPingRound(
	ctx context.Context,
	probing warpConfig,
	probeTarget string,
	resolver func(context.Context, string) ([]netip.Addr, error),
	selection warpSelection,
	skip map[string]bool,
) ([]warpCandidate, error) {
	type attemptResult struct {
		candidate warpCandidate
		latency   time.Duration
		err       error
	}
	rng := selection.rng
	if rng == nil {
		rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	}
	cached := selection.cache.snapshot()
	var awgCandidates, masqueCandidates []warpCandidate
	for _, candidate := range buildWarpCandidates(probing.Endpoint, cached, selection.networkKey, rng) {
		if !skip[candidate.endpoint+"|"+candidate.transport.String()] {
			awgCandidates = append(awgCandidates, candidate)
		}
	}
	// Pools known to exit outside the avoided locations go first among the
	// sampled ones; cached pairs keep their lead.
	rank := func(candidate warpCandidate) int {
		if candidate.source == sourceCached {
			return 0
		}
		switch colo := selection.cache.poolColo(selection.networkKey, candidate.endpoint); {
		case colo == "":
			return 2
		case warpAvoided(colo):
			return 3
		default:
			return 1
		}
	}
	sort.SliceStable(awgCandidates, func(i, j int) bool { return rank(awgCandidates[i]) < rank(awgCandidates[j]) })
	if probing.Masque.available() {
		for _, candidate := range buildMasqueCandidates(cached, selection.networkKey, rng) {
			if !skip[candidate.endpoint+"|"+candidate.transport.String()] {
				masqueCandidates = append(masqueCandidates, candidate)
			}
		}
	}
	total := len(awgCandidates) + len(masqueCandidates)
	if total == 0 {
		return nil, errors.New("start WARP route: no endpoint candidates")
	}
	flowRouterLogf("WARP endpoint round: %d AmneziaWG + %d MASQUE candidates, network=%s",
		len(awgCandidates), len(masqueCandidates), selection.networkKey)
	started := time.Now()
	attemptContext, cancelAttempts := context.WithCancel(ctx)
	defer cancelAttempts()
	results := make(chan attemptResult, total)
	var workers sync.WaitGroup
	attempt := func(candidate warpCandidate) {
		defer workers.Done()
		var tunnel *warpTunnel
		var err error
		if candidate.transport.isMasque() {
			tunnel, err = openMasque(attemptContext, probing.Masque, candidate.endpoint, candidate.transport, resolver)
		} else {
			tunnel, err = openWarp(probing, candidate.endpoint, candidate.profile, resolver)
		}
		if err == nil {
			probeContext, cancelProbe := context.WithTimeout(attemptContext, warpProbeTimeout)
			err = probeWarpRoute(probeContext, tunnel, probeTarget)
			cancelProbe()
		}
		if tunnel != nil {
			tunnel.close()
		}
		results <- attemptResult{candidate: candidate, latency: time.Since(started), err: err}
	}
	workers.Add(len(awgCandidates))
	for _, candidate := range awgCandidates {
		go attempt(candidate)
	}
	awgExhausted := make(chan struct{})
	var exhaustOnce sync.Once
	if len(awgCandidates) == 0 {
		exhaustOnce.Do(func() { close(awgExhausted) })
	}
	if len(masqueCandidates) > 0 {
		workers.Add(len(masqueCandidates))
		go func() {
			timer := time.NewTimer(masqueStartDelay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-awgExhausted:
			case <-attemptContext.Done():
				for range masqueCandidates {
					results <- attemptResult{err: attemptContext.Err()}
					workers.Done()
				}
				return
			}
			for _, candidate := range masqueCandidates {
				go attempt(candidate)
			}
		}()
	}

	type passed struct {
		candidate warpCandidate
		latency   time.Duration
	}
	var shortlist []passed
	var lastErr error
	var window <-chan time.Time
	awgFailed := 0
collect:
	for completed := 0; completed < total; completed++ {
		select {
		case result := <-results:
			if result.err == nil {
				shortlist = append(shortlist, passed{result.candidate, result.latency})
				if len(shortlist) >= warpShortlistSize {
					break collect
				}
				if window == nil {
					window = time.After(warpCollectWindow)
				}
				continue
			}
			if attemptContext.Err() != nil {
				continue
			}
			lastErr = result.err
			if result.candidate.source == sourceCached {
				selection.cache.fail(selection.networkKey, result.candidate)
			}
			if result.candidate.endpoint != "" && !result.candidate.transport.isMasque() {
				awgFailed++
				if awgFailed == len(awgCandidates) {
					exhaustOnce.Do(func() { close(awgExhausted) })
				}
			}
		case <-window:
			break collect
		case <-ctx.Done():
			break collect
		}
	}
	cancelAttempts()
	workers.Wait()
	if len(shortlist) == 0 {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("start WARP route: %w", ctx.Err())
		}
		if lastErr == nil {
			lastErr = errors.New("no usable WARP endpoint")
		}
		return nil, fmt.Errorf("start WARP route: %w", lastErr)
	}
	sort.SliceStable(shortlist, func(i, j int) bool { return shortlist[i].latency < shortlist[j].latency })
	result := make([]warpCandidate, len(shortlist))
	for index, entry := range shortlist {
		result[index] = entry.candidate
	}
	flowRouterLogf("WARP ping round: %d of %d passed in %s", len(result), total, time.Since(started).Round(time.Millisecond))
	return result, nil
}
