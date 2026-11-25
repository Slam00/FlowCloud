package main

import (
	"fmt"
	mrand "math/rand"
	"strconv"
	"strings"
)

// awgProfile is the client-side AmneziaWG obfuscation used for one WARP
// attempt. Junk packets and I1 are decoys sent before the stock WireGuard
// handshake; S1-S4 and H1-H4 stay at stock values because the Cloudflare peer
// is a plain WireGuard server.
type awgProfile struct {
	Name string `json:"name"`
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	I1   string `json:"i1,omitempty"`
}

const (
	awgMaxJunkCount = 10
	awgMaxJunkSize  = 1280
	awgMaxI1Length  = 16 * 1024

	// Ranges WARPSCOUT samples for its junk search.
	awgJunkCountMin = 3
	awgJunkCountMax = 6
	awgJunkSizeMin  = 10
	awgJunkSizeMax  = 64
	awgJunkSpanMin  = 20
	awgJunkSpanMax  = 100
)

// defaultAWGProfile is the profile FlowCloud shipped with before adaptive
// selection. It stays first in every round so a working network keeps working.
func defaultAWGProfile() awgProfile {
	return awgProfile{
		Name: "cps-quic",
		Jc:   warpJunkCount,
		Jmin: warpJunkMin,
		Jmax: warpJunkMax,
		I1:   warpCPSPacket,
	}
}

type i1Variant struct {
	name     string
	generate func(*mrand.Rand) (string, error)
}

func staticI1(chain string) func(*mrand.Rand) (string, error) {
	return func(*mrand.Rand) (string, error) { return chain, nil }
}

func hostI1(generator func(*mrand.Rand, string) (string, error)) func(*mrand.Rand) (string, error) {
	return func(rng *mrand.Rand) (string, error) {
		return generator(rng, i1Hosts[rng.Intn(len(i1Hosts))])
	}
}

// i1Variants are the alternatives tried when the default profile does not get
// through. Order does not matter: candidates pick one at random.
var i1Variants = []i1Variant{
	{"quic-alt", staticI1(warpI1QUICAlt)},
	{"quic-alt2", staticI1(warpI1QUICAlt2)},
	{"quic-gen", hostI1(genQUICI1)},
	{"dns", hostI1(genDNSI1)},
	{"stun", hostI1(genSTUNI1)},
	{"sip", hostI1(genSIPI1)},
	{"none", staticI1("")},
}

// randomAWGProfile returns a fresh junk set with a random I1 variant.
func randomAWGProfile(rng *mrand.Rand) awgProfile {
	jmin := randRange(rng, awgJunkSizeMin, awgJunkSizeMax)
	profile := awgProfile{
		Jc:   randRange(rng, awgJunkCountMin, awgJunkCountMax),
		Jmin: jmin,
		Jmax: jmin + randRange(rng, awgJunkSpanMin, awgJunkSpanMax),
	}
	for attempt := 0; attempt < len(i1Variants); attempt++ {
		variant := i1Variants[rng.Intn(len(i1Variants))]
		chain, err := variant.generate(rng)
		if err != nil {
			continue
		}
		profile.Name = variant.name
		profile.I1 = chain
		return profile
	}
	profile.Name = "none"
	return profile
}

// validate rejects values a corrupted or hand-edited cache file could carry.
func (p awgProfile) validate() error {
	if p.Jc < 0 || p.Jc > awgMaxJunkCount {
		return fmt.Errorf("jc %d out of range", p.Jc)
	}
	if p.Jmin < 0 || p.Jmax < p.Jmin || p.Jmax > awgMaxJunkSize {
		return fmt.Errorf("junk size %d-%d out of range", p.Jmin, p.Jmax)
	}
	if len(p.I1) > awgMaxI1Length {
		return fmt.Errorf("I1 is %d bytes", len(p.I1))
	}
	if strings.ContainsAny(p.I1, "\n\r") {
		return fmt.Errorf("I1 contains a line break")
	}
	return nil
}

func (p awgProfile) String() string {
	return fmt.Sprintf("%s jc=%d jmin=%d jmax=%d", p.Name, p.Jc, p.Jmin, p.Jmax)
}

// uapi returns the interface-level IpcSet lines for this profile.
func (p awgProfile) uapi() []string {
	lines := []string{
		"jc=" + strconv.Itoa(p.Jc),
		"jmin=" + strconv.Itoa(p.Jmin),
		"jmax=" + strconv.Itoa(p.Jmax),
		"s1=0",
		"s2=0",
		"s3=0",
		"s4=0",
		"h1=1",
		"h2=2",
		"h3=3",
		"h4=4",
	}
	if p.I1 != "" {
		lines = append(lines, "i1="+p.I1)
	}
	return lines
}
