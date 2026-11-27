package main

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"strings"
)

// AmneziaWG 3 client-side parameters, after warp-awg-gen
// (https://github.com/Skiro1/warp-awg-gen, MIT). Only the ones a Cloudflare
// WARP server accepts are used: it is a plain WireGuard peer, so S1-S4, H1-H4
// and header protection must stay at stock values. Checked on 2026-11-27
// against two WARP endpoints with FlowCloud for OpenWrt's probe device: every
// line below completed the handshake and carried data. Whether they help
// against providers that cut long WARP flows is not proven yet.
//
//   - I2-I5: 1-3 short random decoys each, sent after I1 before every
//     handshake, like the junk packets.
//   - content_padding_addition: 10-100 extra bytes of padding inside the
//     encrypted data packets, so their sizes stop looking like WireGuard's.
//   - random_trailers: random bytes after handshake packets, so the
//     initiation is no longer exactly 148 bytes.
//   - timings: rekey and keepalive intervals vary instead of the fixed
//     WireGuard ones; the persistent keepalive becomes a range too.
var awg3TimingLines = []string{
	"content_padding_addition=10-100",
	"random_trailers=true",
	"rekey_after_time=100-120",
	"rekey_timeout=3-7",
	"reject_after_time=150-180",
	"keepalive_timeout=5-15",
	"max_handshake_attempts=15-20",
}

// awg3DeviceLines returns the device-level IpcSet lines, with fresh decoys.
func awg3DeviceLines(rng *mrand.Rand) []string {
	lines := make([]string, 0, 4+len(awg3TimingLines))
	for index := 2; index <= 5; index++ {
		lines = append(lines, fmt.Sprintf("i%d=%s", index, randomDecoys(rng)))
	}
	return append(lines, awg3TimingLines...)
}

// randomDecoys is 1-3 static-byte tags of 16-63 random bytes each.
func randomDecoys(rng *mrand.Rand) string {
	var builder strings.Builder
	count := rng.Intn(3) + 1
	for index := 0; index < count; index++ {
		buffer := make([]byte, rng.Intn(48)+16)
		_, _ = rand.Read(buffer)
		fmt.Fprintf(&builder, "<b 0x%x>", buffer)
	}
	return builder.String()
}

// keepaliveRange spreads the persistent keepalive over ten seconds.
func keepaliveRange(seconds int) string {
	return fmt.Sprintf("%d-%d", seconds, seconds+10)
}
