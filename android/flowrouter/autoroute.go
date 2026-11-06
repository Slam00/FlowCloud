package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// routerOptions are set by the app before the router starts (see FlowRouterSetOptions).
type routerOptions struct {
	// AutoFallback enables per-destination failover between direct, ByeDPI and
	// WARP with a learned, expiring per-host choice. It is only meant for the
	// app's Auto transport mode.
	AutoFallback bool `json:"auto_fallback"`
	// StateFile persists learned routes across router restarts.
	StateFile string `json:"state_file"`
	// LearnTTLSeconds is how long a learned route is used before the default
	// order is probed again.
	LearnTTLSeconds int64 `json:"learn_ttl_seconds"`
}

func parseRouterOptions(text string) (routerOptions, error) {
	var options routerOptions
	if strings.TrimSpace(text) == "" {
		return options, nil
	}
	if err := json.Unmarshal([]byte(text), &options); err != nil {
		return routerOptions{}, fmt.Errorf("invalid router options: %w", err)
	}
	if options.LearnTTLSeconds < 0 {
		options.LearnTTLSeconds = 0
	}
	return options, nil
}

// autoTimings bound how long Auto mode spends on failing upstreams. Every
// attempt except the last one has a single deadline covering both the dial
// and the wait for the first response; the last attempt is never judged, so
// the worst-case extra latency is about probeBudget.
type autoTimings struct {
	attempt     map[routeKind]time.Duration
	probeBudget time.Duration
	lastDial    map[routeKind]time.Duration
}

var defaultAutoTimings = autoTimings{
	attempt: map[routeKind]time.Duration{
		routeDirect: 5 * time.Second,
		// ByeDPI may itself reconnect with its next desync group (-A) before it
		// answers, so it gets a little longer than the others.
		routeByeDPI: 7 * time.Second,
		routeWarp:   5 * time.Second,
	},
	probeBudget: 12 * time.Second,
	lastDial: map[routeKind]time.Duration{
		routeDirect: 10 * time.Second,
		routeByeDPI: 15 * time.Second,
		routeWarp:   8 * time.Second,
	},
}

// baseRouteOrder is the order of upstreams for a destination before any
// learned preference is applied.
func baseRouteOrder(useWarp, useByeDPI, autoFallback bool) []routeKind {
	if !autoFallback {
		switch {
		case useWarp && useByeDPI:
			return []routeKind{routeWarp, routeByeDPI}
		case useWarp:
			return []routeKind{routeWarp}
		case useByeDPI:
			return []routeKind{routeByeDPI}
		default:
			return []routeKind{routeDirect}
		}
	}
	switch {
	case useWarp:
		// WARP rules include user split-tunnel choices; never leak those to a
		// plain direct connection, but ByeDPI is an acceptable last resort.
		return []routeKind{routeWarp, routeByeDPI}
	case useByeDPI:
		return []routeKind{routeByeDPI, routeWarp}
	default:
		return []routeKind{routeDirect, routeByeDPI, routeWarp}
	}
}

// orderRoutes moves a learned route to the front if it is one of the allowed
// candidates and drops unavailable upstreams.
func orderRoutes(base []routeKind, learned routeKind, hasLearned bool, available func(routeKind) bool) []routeKind {
	result := make([]routeKind, 0, len(base))
	if hasLearned {
		for _, route := range base {
			if route == learned && (available == nil || available(route)) {
				result = append(result, route)
				break
			}
		}
	}
	for _, route := range base {
		if hasLearned && route == learned {
			continue
		}
		if available == nil || available(route) {
			result = append(result, route)
		}
	}
	return result
}

type initialKind uint8

const (
	initialOpaque initialKind = iota // unknown or non-replayable data
	initialTLS                       // TLS ClientHello without 0-RTT data
	initialHTTP                      // idempotent HTTP/1 request
)

// classifyInitial decides whether the first client flight may be replayed to
// another upstream. Only data that has no side effects on the server qualifies:
// a TLS ClientHello without early data, or a GET/HEAD/OPTIONS request.
func classifyInitial(data []byte) initialKind {
	if len(data) == 0 {
		return initialOpaque
	}
	if data[0] == 0x16 {
		if !isTLSClientHello(data) || tlsClientHelloHasExtension(data, tlsExtensionEarlyData) {
			return initialOpaque
		}
		if len(data) != 5+int(binary.BigEndian.Uint16(data[3:5])) {
			// Anything after the ClientHello record (e.g. 0-RTT application data)
			// must not be replayed.
			return initialOpaque
		}
		return initialTLS
	}
	for _, method := range [][]byte{[]byte("GET "), []byte("HEAD "), []byte("OPTIONS ")} {
		if bytes.HasPrefix(data, method) && bytes.Contains(data, []byte("\r\n\r\n")) {
			return initialHTTP
		}
	}
	return initialOpaque
}

var errProbeRejected = errors.New("unexpected first response")

// probeFirstResponse waits for the server's first bytes after the replayable
// initial flight was written. It returns the bytes read so they can be relayed.
func probeFirstResponse(connection net.Conn, kind initialKind, deadline time.Time) ([]byte, error) {
	_ = connection.SetReadDeadline(deadline)
	defer connection.SetReadDeadline(time.Time{})
	need := 1
	if kind == initialTLS {
		need = 6 // record header + handshake type
	}
	buffer := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for len(buffer) < need {
		count, err := connection.Read(chunk)
		buffer = append(buffer, chunk[:count]...)
		if kind == initialTLS && len(buffer) > 0 && buffer[0] != 0x16 {
			if buffer[0] == 0x15 {
				return buffer, fmt.Errorf("%w: TLS alert", errProbeRejected)
			}
			return buffer, fmt.Errorf("%w: not a TLS handshake (0x%02x)", errProbeRejected, buffer[0])
		}
		if err != nil {
			if len(buffer) >= need {
				break
			}
			if errors.Is(err, io.EOF) {
				return buffer, errors.New("closed before response")
			}
			return buffer, err
		}
	}
	if kind == initialTLS && buffer[5] != 0x02 {
		return buffer, fmt.Errorf("%w: no ServerHello (handshake type %d)", errProbeRejected, buffer[5])
	}
	return buffer, nil
}

type routeDialer func(ctx context.Context, route routeKind, target socksTarget) (net.Conn, error)

func (r *flowRouter) dialRouteDefault(ctx context.Context, route routeKind, target socksTarget) (net.Conn, error) {
	switch route {
	case routeWarp:
		return r.dialWarp(ctx, target.address())
	case routeByeDPI:
		return dialSocks(ctx, r.byeDPIAddress, target)
	default:
		// Bind to the physical network the VPN service chose (see netbind.go).
		return physicalDialer().DialContext(ctx, "tcp", target.address())
	}
}

type routeAttempt struct {
	route routeKind
	err   error
}

type routeResult struct {
	upstream net.Conn
	route    routeKind
	// response holds upstream bytes already read by the probe.
	response []byte
	// initialSent reports whether the initial client flight was written.
	initialSent bool
	attempts    []routeAttempt
}

// connectWithFallback tries the routes in order. A route is abandoned on a
// dial error, or, when the initial flight is replayable, on RST/EOF/timeout or
// a non-TLS answer before the first response. The last route is never judged.
func (r *flowRouter) connectWithFallback(
	target socksTarget,
	initial []byte,
	order []routeKind,
	probe bool,
	timings autoTimings,
	dial routeDialer,
) (routeResult, error) {
	result := routeResult{}
	if len(order) == 0 {
		return result, errors.New("no route available")
	}
	kind := initialOpaque
	if probe {
		kind = classifyInitial(initial)
	}
	start := time.Now()
	for index, route := range order {
		last := index == len(order)-1 || time.Since(start) >= timings.probeBudget
		if last && index != len(order)-1 {
			// Out of budget: go straight to the final route.
			route = order[len(order)-1]
		}
		var timeout time.Duration
		if last {
			timeout = timings.lastDial[route]
		} else {
			timeout = timings.attempt[route]
		}
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		attemptDeadline := time.Now().Add(timeout)
		ctx, cancel := context.WithDeadline(r.context, attemptDeadline)
		upstream, err := dial(ctx, route, target)
		cancel()
		if err == nil && !last && kind != initialOpaque {
			if _, err = upstream.Write(initial); err == nil {
				var response []byte
				response, err = probeFirstResponse(upstream, kind, attemptDeadline)
				if err == nil {
					result.upstream = upstream
					result.route = route
					result.response = response
					result.initialSent = true
					return result, nil
				}
			}
			_ = upstream.Close()
		}
		if err == nil {
			result.upstream = upstream
			result.route = route
			return result, nil
		}
		result.attempts = append(result.attempts, routeAttempt{route: route, err: err})
		if last {
			break
		}
		if r.context.Err() != nil {
			break
		}
	}
	return result, errors.New("all routes failed")
}

func (r *flowRouter) routeAvailable(route routeKind) bool {
	if route == routeWarp {
		return r.warpConfig.available()
	}
	return true
}

func routeKey(host string, target socksTarget) string {
	if host != "" {
		return normalizeHost(host)
	}
	return normalizeHost(target.host)
}

func formatAttempts(attempts []routeAttempt) string {
	var buffer bytes.Buffer
	for index, attempt := range attempts {
		if index > 0 {
			buffer.WriteString("; ")
		}
		fmt.Fprintf(&buffer, "%s: %v", attempt.route, attempt.err)
	}
	return buffer.String()
}

// learnFromResult updates the per-host cache after a connection decision.
// base is the default order for the destination (without the learned route
// moved to the front); base[0] is the route used when nothing is learned.
func (r *flowRouter) learnFromResult(key string, base []routeKind, learned routeKind, hasLearned bool, result routeResult, err error) {
	if r.routes == nil || key == "" || len(base) == 0 {
		return
	}
	if err != nil {
		if hasLearned {
			r.routes.forget(key)
		}
		flowRouterLogf("Auto route exhausted: host=%s tried=[%s]", key, formatAttempts(result.attempts))
		return
	}
	if len(result.attempts) > 0 {
		flowRouterLogf("Auto route fallback: host=%s via=%s after [%s]", key, result.route, formatAttempts(result.attempts))
	}
	switch {
	case hasLearned && result.route == learned:
		// Keep the original expiry so the default order is re-probed later.
	case result.route == base[0]:
		if hasLearned {
			r.routes.forget(key)
			flowRouterLogf("Auto route forgotten: host=%s default %s works again", key, result.route)
		}
	default:
		r.routes.remember(key, result.route)
		flowRouterLogf("Auto route learned: host=%s via=%s ttl=%s", key, result.route, r.routes.ttl)
	}
}

// learnedWarp reports whether TCP learned that this destination needs WARP,
// so QUIC to it follows the same upstream.
func (r *flowRouter) learnedWarp(hosts ...string) bool {
	if r.routes == nil {
		return false
	}
	for _, host := range hosts {
		if route, ok := r.routes.lookup(host); ok && route == routeWarp {
			return true
		}
	}
	return false
}
