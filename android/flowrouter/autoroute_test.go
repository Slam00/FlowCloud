package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestBaseRouteOrder(t *testing.T) {
	tests := []struct {
		name               string
		warp, byeDPI, auto bool
		want               []routeKind
	}{
		{"legacy direct", false, false, false, []routeKind{routeDirect}},
		{"legacy warp", true, false, false, []routeKind{routeWarp}},
		{"legacy warp+byedpi", true, true, false, []routeKind{routeWarp, routeByeDPI}},
		{"legacy byedpi", false, true, false, []routeKind{routeByeDPI}},
		{"auto unknown host", false, false, true, []routeKind{routeDirect, routeByeDPI, routeWarp}},
		{"auto byedpi rule", false, true, true, []routeKind{routeByeDPI, routeWarp}},
		{"auto warp rule never goes direct", true, false, true, []routeKind{routeWarp, routeByeDPI}},
		{"auto warp wins over byedpi", true, true, true, []routeKind{routeWarp, routeByeDPI}},
	}
	for _, test := range tests {
		if got := baseRouteOrder(test.warp, test.byeDPI, test.auto); !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: got %v, want %v", test.name, got, test.want)
		}
	}
}

func TestOrderRoutesLearnedAndAvailability(t *testing.T) {
	base := []routeKind{routeDirect, routeByeDPI, routeWarp}
	all := func(routeKind) bool { return true }
	noWarp := func(route routeKind) bool { return route != routeWarp }

	if got := orderRoutes(base, routeWarp, true, all); !reflect.DeepEqual(got, []routeKind{routeWarp, routeDirect, routeByeDPI}) {
		t.Errorf("learned warp first: got %v", got)
	}
	if got := orderRoutes(base, routeByeDPI, true, noWarp); !reflect.DeepEqual(got, []routeKind{routeByeDPI, routeDirect}) {
		t.Errorf("learned byedpi without warp: got %v", got)
	}
	// A learned route that is not allowed for this destination is ignored.
	if got := orderRoutes([]routeKind{routeWarp, routeByeDPI}, routeDirect, true, all); !reflect.DeepEqual(got, []routeKind{routeWarp, routeByeDPI}) {
		t.Errorf("learned direct for warp rule: got %v", got)
	}
	// An unavailable learned route is skipped.
	if got := orderRoutes(base, routeWarp, true, noWarp); !reflect.DeepEqual(got, []routeKind{routeDirect, routeByeDPI}) {
		t.Errorf("learned but unavailable warp: got %v", got)
	}
}

// clientHello builds a minimal TLS ClientHello record with the given extensions.
func clientHello(extensions ...[]byte) []byte {
	var extensionBlock []byte
	for _, extension := range extensions {
		extensionBlock = append(extensionBlock, extension...)
	}
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id
	body = append(body, 0, 2, 0x13, 0x01)    // cipher suites
	body = append(body, 1, 0)                // compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensionBlock)))
	body = append(body, extensionBlock...)
	handshake := []byte{0x01, 0, byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x01}
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	return append(record, handshake...)
}

func sniExtension(host string) []byte {
	name := []byte{0}
	name = binary.BigEndian.AppendUint16(name, uint16(len(host)))
	name = append(name, host...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(name)))
	list = append(list, name...)
	extension := binary.BigEndian.AppendUint16(nil, tlsExtensionServerName)
	extension = binary.BigEndian.AppendUint16(extension, uint16(len(list)))
	return append(extension, list...)
}

func earlyDataExtension() []byte {
	return []byte{0, tlsExtensionEarlyData, 0, 0}
}

func TestSniffTLSHostAfterRefactor(t *testing.T) {
	if got := sniffHost(clientHello(sniExtension("Example.COM"))); got != "example.com" {
		t.Fatalf("sniffHost() = %q", got)
	}
}

func TestClassifyInitial(t *testing.T) {
	hello := clientHello(sniExtension("example.com"))
	tests := map[string]struct {
		data []byte
		want initialKind
	}{
		"empty":            {nil, initialOpaque},
		"client hello":     {hello, initialTLS},
		"0-rtt hello":      {clientHello(sniExtension("example.com"), earlyDataExtension()), initialOpaque},
		"hello plus data":  {append(append([]byte(nil), hello...), 0x17, 3, 3, 0, 1, 0), initialOpaque},
		"truncated hello":  {hello[:len(hello)-3], initialOpaque},
		"http get":         {[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), initialHTTP},
		"http head":        {[]byte("HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"), initialHTTP},
		"http post":        {[]byte("POST /pay HTTP/1.1\r\nHost: example.com\r\n\r\n"), initialOpaque},
		"partial http get": {[]byte("GET / HTTP/1.1\r\nHost: exa"), initialOpaque},
		"opaque":           {[]byte{0xef, 1, 2, 3}, initialOpaque},
	}
	for name, test := range tests {
		if got := classifyInitial(test.data); got != test.want {
			t.Errorf("%s: classifyInitial() = %d, want %d", name, got, test.want)
		}
	}
}

// fakeServer answers on one side of a pipe according to behaviour.
type fakeBehaviour int

const (
	serveServerHello fakeBehaviour = iota
	serveReset
	serveSilence
	serveAlert
	serveHTTP
)

type recordingConn struct {
	net.Conn
	mutex   sync.Mutex
	written []byte
}

func (c *recordingConn) Write(data []byte) (int, error) {
	c.mutex.Lock()
	c.written = append(c.written, data...)
	c.mutex.Unlock()
	return c.Conn.Write(data)
}

func fakeUpstream(t *testing.T, behaviour fakeBehaviour) (*recordingConn, net.Conn) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	go func() {
		buffer := make([]byte, 65535)
		_, err := serverSide.Read(buffer)
		if err != nil {
			return
		}
		switch behaviour {
		case serveServerHello:
			_, _ = serverSide.Write([]byte{0x16, 3, 3, 0, 4, 0x02, 0, 0, 0})
			_, _ = io.Copy(io.Discard, serverSide)
		case serveAlert:
			_, _ = serverSide.Write([]byte{0x15, 3, 3, 0, 2, 2, 40})
			_ = serverSide.Close()
		case serveHTTP:
			_, _ = serverSide.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			_, _ = io.Copy(io.Discard, serverSide)
		case serveReset:
			_ = serverSide.Close()
		case serveSilence:
			_, _ = io.Copy(io.Discard, serverSide)
		}
	}()
	t.Cleanup(func() { _ = serverSide.Close(); _ = clientSide.Close() })
	return &recordingConn{Conn: clientSide}, serverSide
}

type scriptedDialer struct {
	t         *testing.T
	mutex     sync.Mutex
	dialErr   map[routeKind]error
	behaviour map[routeKind]fakeBehaviour
	dialed    []routeKind
	conns     map[routeKind]*recordingConn
}

func (d *scriptedDialer) dial(_ context.Context, route routeKind, _ socksTarget) (net.Conn, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.dialed = append(d.dialed, route)
	if err := d.dialErr[route]; err != nil {
		return nil, err
	}
	connection, _ := fakeUpstream(d.t, d.behaviour[route])
	if d.conns == nil {
		d.conns = make(map[routeKind]*recordingConn)
	}
	d.conns[route] = connection
	return connection, nil
}

var fastTimings = autoTimings{
	attempt: map[routeKind]time.Duration{
		routeDirect: 200 * time.Millisecond, routeByeDPI: 200 * time.Millisecond, routeWarp: 200 * time.Millisecond,
	},
	probeBudget: 2 * time.Second,
	lastDial: map[routeKind]time.Duration{
		routeDirect: time.Second, routeByeDPI: time.Second, routeWarp: time.Second,
	},
}

func testRouter(t *testing.T, statePath string) *flowRouter {
	t.Helper()
	router, err := newFlowRouter("127.0.0.1:0", "127.0.0.1:1", "", "", "", "",
		routerOptions{AutoFallback: true, StateFile: statePath, LearnTTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.close)
	return router
}

func TestConnectWithFallbackOrdering(t *testing.T) {
	hello := clientHello(sniExtension("blocked.example"))
	order := []routeKind{routeDirect, routeByeDPI, routeWarp}
	tests := []struct {
		name       string
		dialErr    map[routeKind]error
		behaviour  map[routeKind]fakeBehaviour
		initial    []byte
		wantRoute  routeKind
		wantDialed []routeKind
		wantSent   bool
	}{
		{
			name:       "direct works",
			behaviour:  map[routeKind]fakeBehaviour{routeDirect: serveServerHello},
			initial:    hello,
			wantRoute:  routeDirect,
			wantDialed: []routeKind{routeDirect},
			wantSent:   true,
		},
		{
			name:       "direct reset then byedpi",
			behaviour:  map[routeKind]fakeBehaviour{routeDirect: serveReset, routeByeDPI: serveServerHello},
			initial:    hello,
			wantRoute:  routeByeDPI,
			wantDialed: []routeKind{routeDirect, routeByeDPI},
			wantSent:   true,
		},
		{
			name:       "silence and alert then warp unjudged",
			behaviour:  map[routeKind]fakeBehaviour{routeDirect: serveSilence, routeByeDPI: serveAlert, routeWarp: serveSilence},
			initial:    hello,
			wantRoute:  routeWarp,
			wantDialed: []routeKind{routeDirect, routeByeDPI, routeWarp},
			wantSent:   false,
		},
		{
			name:       "dial errors fail over even for opaque data",
			dialErr:    map[routeKind]error{routeDirect: errors.New("refused"), routeByeDPI: errors.New("socks 5")},
			initial:    []byte("POST / HTTP/1.1\r\n\r\n"),
			wantRoute:  routeWarp,
			wantDialed: []routeKind{routeDirect, routeByeDPI, routeWarp},
		},
		{
			name:       "non-idempotent data is never replayed",
			behaviour:  map[routeKind]fakeBehaviour{routeDirect: serveReset},
			initial:    []byte("POST / HTTP/1.1\r\n\r\n"),
			wantRoute:  routeDirect,
			wantDialed: []routeKind{routeDirect},
		},
		{
			name:       "idempotent http probes",
			behaviour:  map[routeKind]fakeBehaviour{routeDirect: serveReset, routeByeDPI: serveHTTP},
			initial:    []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
			wantRoute:  routeByeDPI,
			wantDialed: []routeKind{routeDirect, routeByeDPI},
			wantSent:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := testRouter(t, "")
			dialer := &scriptedDialer{t: t, dialErr: test.dialErr, behaviour: test.behaviour}
			result, err := router.connectWithFallback(socksTarget{host: "203.0.113.1", port: 443}, test.initial, order, true, fastTimings, dialer.dial)
			if err != nil {
				t.Fatalf("connectWithFallback() error = %v", err)
			}
			defer result.upstream.Close()
			if result.route != test.wantRoute {
				t.Errorf("route = %s, want %s", result.route, test.wantRoute)
			}
			if !reflect.DeepEqual(dialer.dialed, test.wantDialed) {
				t.Errorf("dialed = %v, want %v", dialer.dialed, test.wantDialed)
			}
			if result.initialSent != test.wantSent {
				t.Errorf("initialSent = %v, want %v", result.initialSent, test.wantSent)
			}
			if test.wantSent && len(result.response) == 0 {
				t.Errorf("probe response was not kept for relaying")
			}
			// Opaque data must never have been written to an abandoned upstream.
			if classifyInitial(test.initial) == initialOpaque {
				for route, connection := range dialer.conns {
					if len(connection.written) > 0 {
						t.Errorf("opaque data written to %s during routing", route)
					}
				}
			}
		})
	}
}

func TestConnectWithFallbackAllFail(t *testing.T) {
	router := testRouter(t, "")
	dialer := &scriptedDialer{t: t, dialErr: map[routeKind]error{
		routeDirect: errors.New("a"), routeByeDPI: errors.New("b"), routeWarp: errors.New("c"),
	}}
	result, err := router.connectWithFallback(socksTarget{host: "203.0.113.1", port: 443}, nil,
		[]routeKind{routeDirect, routeByeDPI, routeWarp}, true, fastTimings, dialer.dial)
	if err == nil {
		t.Fatal("expected failure")
	}
	if len(result.attempts) != 3 {
		t.Fatalf("attempts = %d, want 3", len(result.attempts))
	}
}

func TestConnectWithFallbackBudgetJumpsToLastRoute(t *testing.T) {
	router := testRouter(t, "")
	dialer := &scriptedDialer{t: t, behaviour: map[routeKind]fakeBehaviour{
		routeDirect: serveSilence, routeByeDPI: serveSilence, routeWarp: serveSilence,
	}}
	timings := fastTimings
	timings.probeBudget = 150 * time.Millisecond
	started := time.Now()
	result, err := router.connectWithFallback(socksTarget{host: "203.0.113.1", port: 443},
		clientHello(sniExtension("a.example")), []routeKind{routeDirect, routeByeDPI, routeWarp}, true, timings, dialer.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer result.upstream.Close()
	if !reflect.DeepEqual(dialer.dialed, []routeKind{routeDirect, routeWarp}) {
		t.Errorf("dialed = %v, want direct then warp", dialer.dialed)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("routing took %s", elapsed)
	}
}

func TestLearnFromResult(t *testing.T) {
	router := testRouter(t, "")
	base := []routeKind{routeDirect, routeByeDPI, routeWarp}
	failed := []routeAttempt{{route: routeDirect, err: errors.New("reset")}}

	router.learnFromResult("a.example", base, 0, false, routeResult{route: routeDirect}, nil)
	if _, ok := router.routes.lookup("a.example"); ok {
		t.Fatal("default route must not be stored")
	}
	router.learnFromResult("a.example", base, 0, false, routeResult{route: routeByeDPI, attempts: failed}, nil)
	if route, ok := router.routes.lookup("a.example"); !ok || route != routeByeDPI {
		t.Fatalf("learned = %v %v, want byedpi", route, ok)
	}
	// The learned route failing and the default working again forgets it.
	router.learnFromResult("a.example", base, routeByeDPI, true,
		routeResult{route: routeDirect, attempts: []routeAttempt{{route: routeByeDPI, err: errors.New("x")}}}, nil)
	if _, ok := router.routes.lookup("a.example"); ok {
		t.Fatal("learned route should be forgotten when the default works")
	}
	// Learned byedpi failing over to WARP replaces it.
	router.routes.remember("b.example", routeByeDPI)
	router.learnFromResult("b.example", base, routeByeDPI, true,
		routeResult{route: routeWarp, attempts: []routeAttempt{{routeByeDPI, errors.New("x")}, {routeDirect, errors.New("y")}}}, nil)
	if route, _ := router.routes.lookup("b.example"); route != routeWarp {
		t.Fatalf("learned = %v, want warp", route)
	}
	// Everything failing drops the entry.
	router.learnFromResult("b.example", base, routeWarp, true, routeResult{attempts: failed}, errors.New("all routes failed"))
	if _, ok := router.routes.lookup("b.example"); ok {
		t.Fatal("entry should be dropped when every route fails")
	}
}

func TestRouteCacheTTLAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	now := time.Unix(1_800_000_000, 0)
	cache := newRouteCache(path, time.Hour)
	cache.now = func() time.Time { return now }
	cache.remember("Blocked.Example.", routeWarp)
	cache.remember("203.0.113.7", routeByeDPI)
	cache.close()

	reloaded := newRouteCacheAt(path, time.Hour, now.Add(30*time.Minute))
	if route, ok := reloaded.lookup("blocked.example"); !ok || route != routeWarp {
		t.Fatalf("reloaded host = %v %v", route, ok)
	}
	if route, ok := reloaded.lookup("203.0.113.7"); !ok || route != routeByeDPI {
		t.Fatalf("reloaded ip = %v %v", route, ok)
	}
	reloaded.now = func() time.Time { return now.Add(61 * time.Minute) }
	if _, ok := reloaded.lookup("blocked.example"); ok {
		t.Fatal("entry must expire after the TTL")
	}

	expired := newRouteCacheAt(path, time.Hour, now.Add(2*time.Hour))
	if expired.size() != 0 {
		t.Fatalf("expired entries loaded: %d", expired.size())
	}
	// A shorter configured TTL caps stored expiries.
	shorter := newRouteCacheAt(path, time.Minute, now.Add(30*time.Minute))
	shorter.now = func() time.Time { return now.Add(32 * time.Minute) }
	if _, ok := shorter.lookup("blocked.example"); ok {
		t.Fatal("stored expiry must be capped by the configured TTL")
	}
}

func TestRouteCacheCorruptFileIsIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := writeFileAtomic(path, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if cache := newRouteCache(path, time.Hour); cache.size() != 0 {
		t.Fatal("corrupt cache should load empty")
	}
}

func TestRouteCacheEviction(t *testing.T) {
	cache := newRouteCache("", time.Hour)
	for index := 0; index < routeCacheMaxEntries+10; index++ {
		cache.remember(net.IPv4(10, byte(index>>16), byte(index>>8), byte(index)).String(), routeByeDPI)
	}
	if size := cache.size(); size > routeCacheMaxEntries {
		t.Fatalf("cache size %d exceeds limit", size)
	}
}

func TestParseRouterOptions(t *testing.T) {
	options, err := parseRouterOptions(`{"auto_fallback":true,"state_file":"/data/x.json","learn_ttl_seconds":600}`)
	if err != nil || !options.AutoFallback || options.StateFile != "/data/x.json" || options.LearnTTLSeconds != 600 {
		t.Fatalf("parseRouterOptions() = %+v, %v", options, err)
	}
	if options, err = parseRouterOptions(""); err != nil || options.AutoFallback {
		t.Fatalf("empty options = %+v, %v", options, err)
	}
	if _, err = parseRouterOptions("{"); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// newRouteCacheAt loads a cache as if the current time were now.
func newRouteCacheAt(path string, ttl time.Duration, now time.Time) *routeCache {
	cache := &routeCache{entries: make(map[string]learnedRoute), ttl: ttl, path: path,
		now: func() time.Time { return now }}
	cache.load()
	return cache
}
