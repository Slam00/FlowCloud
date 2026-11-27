package main

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// YouTube in Auto mode. UDP that no WARP rule claims goes through ByeDPI,
// which relays it untouched, so the YouTube app's QUIC reached the video
// servers directly. Russian providers let such a flow deliver the first
// megabytes and then stop it: videos froze after 10-15 seconds in Auto mode
// and played in WARP mode. QUIC to YouTube is therefore dropped in Auto mode:
// the app switches to TCP, which ByeDPI handles, and the video comes directly
// at full speed. If TCP to a video server stalls too on a network, YouTube
// goes through WARP for the route cache TTL.

// youTubeSuffixes are YouTube's hosts; videoSuffixes the video servers among
// them, whose TCP is watched for stalls.
var (
	youTubeSuffixes = []string{
		"googlevideo.com",
		"youtube.com",
		"ytimg.com",
		"ggpht.com",
		"youtubei.googleapis.com",
		"youtube-nocookie.com",
	}
	videoSuffixes = []string{"googlevideo.com"}
)

func hostHasSuffix(host string, suffixes []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false
	}
	for _, suffix := range suffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func isYouTubeHost(host string) bool { return hostHasSuffix(host, youTubeSuffixes) }

func isVideoHost(host string) bool { return hostHasSuffix(host, videoSuffixes) }

// videoStallSilence: a video server that sends nothing this long while a
// request is pending is stalled. Video servers hold no long polls.
const videoStallSilence = 8 * time.Second

// youtubeViaWarp reports whether YouTube currently goes through WARP.
func (r *flowRouter) youtubeViaWarp() bool {
	r.warpMutex.Lock()
	defer r.warpMutex.Unlock()
	return time.Now().Before(r.youtubeWarpUntil)
}

// markYouTubeViaWarp records that a video stalled over TCP through route.
func (r *flowRouter) markYouTubeViaWarp(host string, route routeKind) {
	ttl := 6 * time.Hour
	if r.routes != nil && r.routes.ttl > 0 {
		ttl = r.routes.ttl
	}
	r.warpMutex.Lock()
	r.youtubeWarpUntil = time.Now().Add(ttl)
	r.warpMutex.Unlock()
	flowRouterLogf("YouTube video stalled over TCP through %s: host=%s; YouTube goes through WARP for %s", route, host, ttl)
}

// stallWatchedConn records when data last came from the server and when the
// client last sent, for the video stall watcher.
type stallWatchedConn struct {
	net.Conn
	lastDown atomic.Int64
	lastUp   atomic.Int64
}

func newStallWatchedConn(connection net.Conn) *stallWatchedConn {
	watched := &stallWatchedConn{Conn: connection}
	watched.lastDown.Store(time.Now().UnixNano())
	return watched
}

func (c *stallWatchedConn) Read(buffer []byte) (int, error) {
	count, err := c.Conn.Read(buffer)
	if count > 0 {
		c.lastDown.Store(time.Now().UnixNano())
	}
	return count, err
}

func (c *stallWatchedConn) Write(buffer []byte) (int, error) {
	count, err := c.Conn.Write(buffer)
	if count > 0 {
		c.lastUp.Store(time.Now().UnixNano())
	}
	return count, err
}

// CloseWrite keeps relayTCP's half-close working through the wrapper.
func (c *stallWatchedConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return nil
}

// stalled reports a request pending (the client sent after the last server
// data) with the server silent for at least silence.
func (c *stallWatchedConn) stalled(now time.Time, silence time.Duration) bool {
	down, up := c.lastDown.Load(), c.lastUp.Load()
	return up > down && now.UnixNano()-down >= int64(silence)
}

// watch calls onStall once if the connection stalls; stop ends the watch.
func (c *stallWatchedConn) watch(silence time.Duration, onStall func()) (stop func()) {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				if c.stalled(now, silence) {
					onStall()
					return
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// A QUIC flow stalls when the server sends nothing for quicStallSilence while
// the client keeps sending (quicStallPackets packets): QUIC acknowledges in
// both directions all the time, so a live flow, even an idle long poll, is
// never silent on one side only.
const (
	quicStallSilence = 5 * time.Second
	quicStallPackets = 6
	// quicFlowForget drops flow records nobody used for this long.
	quicFlowForget = 2 * time.Minute
)

type quicFlow struct {
	received      bool
	lastDown      time.Time
	lastUse       time.Time
	upSinceDown   int
	stallReported bool
}

// quicStallTracker watches the QUIC flows of one UDP association that go
// through ByeDPI.
type quicStallTracker struct {
	mutex  sync.Mutex
	flows  map[string]*quicFlow
	now    func() time.Time
	pruned time.Time
}

func newQuicStallTracker() *quicStallTracker {
	return &quicStallTracker{flows: map[string]*quicFlow{}, now: time.Now}
}

// down records a packet from the server of target.
func (t *quicStallTracker) down(target string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	now := t.now()
	flow := t.flows[target]
	if flow == nil {
		flow = &quicFlow{}
		t.flows[target] = flow
	}
	flow.received = true
	flow.lastDown = now
	flow.lastUse = now
	flow.upSinceDown = 0
	flow.stallReported = false
}

// up records a client packet to target and reports a stall once per silence.
func (t *quicStallTracker) up(target string) bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	now := t.now()
	if now.Sub(t.pruned) > quicFlowForget {
		for key, flow := range t.flows {
			if now.Sub(flow.lastUse) > quicFlowForget {
				delete(t.flows, key)
			}
		}
		t.pruned = now
	}
	flow := t.flows[target]
	if flow == nil {
		flow = &quicFlow{}
		t.flows[target] = flow
	}
	flow.lastUse = now
	flow.upSinceDown++
	if !flow.received || flow.stallReported || flow.upSinceDown < quicStallPackets || now.Sub(flow.lastDown) < quicStallSilence {
		return false
	}
	flow.stallReported = true
	return true
}
