package main

import (
	"strings"
	"sync"
	"time"
)

// QUIC in Auto mode. UDP that no WARP rule claims goes through ByeDPI, which
// relays it untouched, so QUIC reaches the server directly. Russian providers
// let a direct QUIC flow to YouTube's video servers deliver the first
// megabytes and then stop it: videos froze after 10-15 seconds in Auto mode
// and played in WARP mode.

// quicViaWarpSuffixes are hosts whose QUIC goes through WARP in Auto mode from
// the first packet. Their TCP keeps the normal Auto order.
var quicViaWarpSuffixes = []string{
	"googlevideo.com",
	"youtube.com",
	"ytimg.com",
	"ggpht.com",
	"youtubei.googleapis.com",
	"youtube-nocookie.com",
}

func quicPrefersWarp(hosts ...string) bool {
	for _, host := range hosts {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if host == "" {
			continue
		}
		for _, suffix := range quicViaWarpSuffixes {
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				return true
			}
		}
	}
	return false
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
