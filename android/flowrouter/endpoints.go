package main

import (
	"encoding/json"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WARP WireGuard anycast pools and ports. Source: WARPSCOUT
// (https://github.com/vernette/warpscout, internal/warpscout/pools.go and
// warp.go, MIT License, Copyright (c) 2026 Nikita S.). MASQUE lives on
// 162.159.198.0/23 and is deliberately not part of these pools.
var warpPoolsV4 = []netip.Prefix{
	netip.MustParsePrefix("8.6.112.0/24"),
	netip.MustParsePrefix("8.34.70.0/24"),
	netip.MustParsePrefix("8.34.146.0/24"),
	netip.MustParsePrefix("8.35.211.0/24"),
	netip.MustParsePrefix("8.39.125.0/24"),
	netip.MustParsePrefix("8.39.204.0/24"),
	netip.MustParsePrefix("8.39.214.0/24"),
	netip.MustParsePrefix("8.47.69.0/24"),
	netip.MustParsePrefix("162.159.192.0/24"),
	netip.MustParsePrefix("162.159.195.0/24"),
	netip.MustParsePrefix("188.114.96.0/24"),
	netip.MustParsePrefix("188.114.97.0/24"),
	netip.MustParsePrefix("188.114.98.0/24"),
	netip.MustParsePrefix("188.114.99.0/24"),
}

// legacyWarpHosts were FlowCloud's fixed candidates before pool sampling. A few
// are still mixed into every round so networks where they worked keep a path.
var legacyWarpHosts = []string{
	"162.159.192.5", "162.159.192.1", "162.159.193.10", "162.159.194.20", "162.159.195.30",
	"162.159.196.40", "162.159.197.50", "162.159.198.60", "162.159.199.70",
	"188.114.96.10", "188.114.98.58", "188.114.100.30", "188.114.103.40",
	"188.114.106.50", "188.114.110.60",
}

var (
	primaryWarpPorts  = []int{2408, 500, 1701, 4500}
	extendedWarpPorts = []int{
		854, 859, 864, 878, 880, 890, 891, 894, 903, 908,
		928, 934, 939, 942, 943, 945, 946, 955, 968, 987,
		988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843,
		2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279,
		5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}
)

const (
	// warpRoundSize bounds how many AmneziaWG devices one selection round runs
	// in parallel. FlowCloud ran 24 fixed candidates before.
	warpRoundSize = 24
	// warpDefaultProfileShare is how many sampled endpoints keep the default
	// profile; the rest try random junk/I1 sets.
	warpDefaultProfileShare = 10
	warpLegacyPerRound      = 3
	warpCachedSameNetwork   = 4
	warpCachedOtherNetwork  = 2
)

type candidateSource string

const (
	sourceCached     candidateSource = "cached"
	sourceRegistered candidateSource = "registered"
	sourcePool       candidateSource = "pool"
	sourceLegacy     candidateSource = "legacy"
)

type warpCandidate struct {
	endpoint  string
	profile   awgProfile
	source    candidateSource
	transport warpTransport
}

// randomPoolAddress picks a host address inside a random WARP pool, avoiding
// the network and broadcast addresses of the /24.
func randomPoolAddress(rng *mrand.Rand) netip.Addr {
	prefix := warpPoolsV4[rng.Intn(len(warpPoolsV4))]
	base := prefix.Masked().Addr().As4()
	base[3] = byte(randRange(rng, 1, 254))
	return netip.AddrFrom4(base)
}

func randomWarpPort(rng *mrand.Rand) int {
	// Mostly the four ports every client uses; sometimes an alternate port for
	// networks that filter those.
	if rng.Intn(4) == 0 {
		return extendedWarpPorts[rng.Intn(len(extendedWarpPorts))]
	}
	return primaryWarpPorts[rng.Intn(len(primaryWarpPorts))]
}

// buildWarpCandidates assembles one selection round: endpoints that worked
// before first, then the endpoint from the registration, then random samples
// from the WARP pools. Profiles are mixed so a round explores both the address
// and the obfuscation dimension.
func buildWarpCandidates(registered string, cached []cachedEndpoint, networkKey string, rng *mrand.Rand) []warpCandidate {
	result := make([]warpCandidate, 0, warpRoundSize)
	seen := make(map[string]struct{})
	add := func(candidate warpCandidate) bool {
		if len(result) >= warpRoundSize {
			return false
		}
		host, portText, err := net.SplitHostPort(candidate.endpoint)
		if err != nil || host == "" {
			return false
		}
		if port, convErr := strconv.Atoi(portText); convErr != nil || port <= 0 || port > 65535 {
			return false
		}
		if _, exists := seen[candidate.endpoint]; exists {
			return false
		}
		seen[candidate.endpoint] = struct{}{}
		result = append(result, candidate)
		return true
	}

	same, other := 0, 0
	for _, entry := range cached {
		if entry.Transport.isMasque() {
			continue
		}
		candidate := warpCandidate{endpoint: entry.Endpoint, profile: entry.Profile, source: sourceCached}
		if entry.Network == networkKey {
			if same < warpCachedSameNetwork && add(candidate) {
				same++
			}
		} else if other < warpCachedOtherNetwork && add(candidate) {
			other++
		}
	}

	if host, portText, err := net.SplitHostPort(strings.TrimSpace(registered)); err == nil && host != "" {
		ports := []string{portText}
		for _, port := range primaryWarpPorts {
			ports = append(ports, strconv.Itoa(port))
		}
		for _, port := range ports[:3] {
			add(warpCandidate{endpoint: net.JoinHostPort(host, port), profile: defaultAWGProfile(), source: sourceRegistered})
		}
	}

	for _, index := range rng.Perm(len(legacyWarpHosts))[:warpLegacyPerRound] {
		port := primaryWarpPorts[rng.Intn(len(primaryWarpPorts))]
		add(warpCandidate{
			endpoint: net.JoinHostPort(legacyWarpHosts[index], strconv.Itoa(port)),
			profile:  defaultAWGProfile(),
			source:   sourceLegacy,
		})
	}

	sampled := 0
	for attempts := 0; len(result) < warpRoundSize && attempts < warpRoundSize*8; attempts++ {
		profile := defaultAWGProfile()
		if sampled >= warpDefaultProfileShare {
			profile = randomAWGProfile(rng)
		}
		endpoint := net.JoinHostPort(randomPoolAddress(rng).String(), strconv.Itoa(randomWarpPort(rng)))
		if add(warpCandidate{endpoint: endpoint, profile: profile, source: sourcePool}) {
			sampled++
		}
	}
	return result
}

// cachedEndpoint is an endpoint+profile pair that passed the data probe.
type cachedEndpoint struct {
	Endpoint  string        `json:"endpoint"`
	Network   string        `json:"network"`
	Transport warpTransport `json:"transport,omitempty"`
	Profile   awgProfile    `json:"profile"`
	LatencyMs int64         `json:"latency_ms"`
	OKAt      int64         `json:"ok_at"`
	Fails     int           `json:"fails"`
	// Colo is the Cloudflare location the pair exits from; Sites is true
	// when every test site opened through it. Such pairs are tried first,
	// before the parallel round.
	Colo  string `json:"colo,omitempty"`
	Sites bool   `json:"sites,omitempty"`
}

func (e cachedEndpoint) key() string {
	return cacheKey(e.Network, e.Transport, e.Endpoint)
}

func cacheKey(network string, transport warpTransport, endpoint string) string {
	return network + "|" + transport.String() + "|" + endpoint
}

const (
	endpointCacheVersion   = 1
	endpointCacheMax       = 12
	endpointCacheTTL       = 14 * 24 * time.Hour
	endpointCacheMaxFails  = 3
	endpointCacheFileLimit = 1 << 20
)

type endpointCacheFile struct {
	Version int              `json:"version"`
	Entries []cachedEndpoint `json:"entries"`
	// Colos maps "network|pool /24" to the location that pool was last seen
	// exiting from: one network reaches a /24 through one location, so the
	// site stage can try likely good pools first.
	Colos map[string]string `json:"colos,omitempty"`
}

// poolColosMax bounds the remembered pool locations.
const poolColosMax = 512

// endpointCache persists working WARP endpoints across router restarts so the
// next start probes known-good pairs first. A nil cache is valid and stores
// nothing.
type endpointCache struct {
	path    string
	mutex   sync.Mutex
	entries []cachedEndpoint
	colos   map[string]string
	now     func() time.Time
}

func poolColoKey(network, endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Is4() {
		return ""
	}
	prefix, _ := address.Prefix(24)
	return network + "|" + prefix.String()
}

// poolColo returns the location last seen for the endpoint's /24 on network.
func (c *endpointCache) poolColo(network, endpoint string) string {
	if c == nil {
		return ""
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.colos[poolColoKey(network, endpoint)]
}

// noteColo remembers where an endpoint's /24 exits on network.
func (c *endpointCache) noteColo(network, endpoint, colo string) {
	key := poolColoKey(network, endpoint)
	if c == nil || key == "" || colo == "" {
		return
	}
	c.mutex.Lock()
	if c.colos == nil {
		c.colos = map[string]string{}
	}
	previous, known := c.colos[key]
	changed := previous != colo && (known || len(c.colos) < poolColosMax)
	if changed {
		c.colos[key] = colo
	}
	c.mutex.Unlock()
	if changed {
		c.save()
	}
}

// rememberEvaluated stores a pair with its location and site result.
func (c *endpointCache) rememberEvaluated(network string, candidate warpCandidate, latency time.Duration, colo string, sites bool) {
	if c == nil {
		return
	}
	c.remember(network, candidate, latency)
	c.mutex.Lock()
	key := cacheKey(network, candidate.transport, candidate.endpoint)
	for index := range c.entries {
		if c.entries[index].key() == key {
			c.entries[index].Colo = colo
			c.entries[index].Sites = sites
		}
	}
	c.mutex.Unlock()
	c.save()
	c.noteColo(network, candidate.endpoint, colo)
}

// sitesFailed clears the site flag of a pair that did not carry traffic for
// the tunnel's own account, so it is not tried first again.
func (c *endpointCache) sitesFailed(network string, candidate warpCandidate) {
	if c == nil {
		return
	}
	c.mutex.Lock()
	key := cacheKey(network, candidate.transport, candidate.endpoint)
	changed := false
	for index := range c.entries {
		if c.entries[index].key() == key && c.entries[index].Sites {
			c.entries[index].Sites = false
			changed = true
		}
	}
	c.mutex.Unlock()
	if changed {
		c.save()
	}
}

func newEndpointCache(path string) *endpointCache {
	cache := &endpointCache{path: path, now: time.Now}
	cache.load()
	return cache
}

func (c *endpointCache) load() {
	if c.path == "" {
		return
	}
	info, err := os.Stat(c.path)
	if err != nil || info.Size() > endpointCacheFileLimit {
		return
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var file endpointCacheFile
	if json.Unmarshal(data, &file) != nil || file.Version != endpointCacheVersion {
		return
	}
	for key, colo := range file.Colos {
		if len(c.colos) >= poolColosMax || len(colo) > 8 || !strings.Contains(key, "|") {
			continue
		}
		if c.colos == nil {
			c.colos = map[string]string{}
		}
		c.colos[key] = colo
	}
	now := c.now()
	for _, entry := range file.Entries {
		if entry.Fails >= endpointCacheMaxFails {
			continue
		}
		if entry.Transport != transportAWG && !entry.Transport.isMasque() {
			continue
		}
		if !entry.Transport.isMasque() && entry.Profile.validate() != nil {
			continue
		}
		if _, _, splitErr := net.SplitHostPort(entry.Endpoint); splitErr != nil {
			continue
		}
		if now.Sub(time.Unix(entry.OKAt, 0)) > endpointCacheTTL {
			continue
		}
		c.entries = append(c.entries, entry)
	}
	c.sortLocked()
}

// snapshot returns the entries, best first.
func (c *endpointCache) snapshot() []cachedEndpoint {
	if c == nil {
		return nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]cachedEndpoint(nil), c.entries...)
}

// sortLocked orders by fewest recent failures, then most recent success, then
// latency.
func (c *endpointCache) sortLocked() {
	sort.SliceStable(c.entries, func(i, j int) bool {
		a, b := c.entries[i], c.entries[j]
		if a.Fails != b.Fails {
			return a.Fails < b.Fails
		}
		if a.OKAt != b.OKAt {
			return a.OKAt > b.OKAt
		}
		return a.LatencyMs < b.LatencyMs
	})
}

func (c *endpointCache) remember(network string, candidate warpCandidate, latency time.Duration) {
	if c == nil {
		return
	}
	c.mutex.Lock()
	entry := cachedEndpoint{
		Endpoint:  candidate.endpoint,
		Network:   network,
		Transport: candidate.transport,
		Profile:   candidate.profile,
		LatencyMs: latency.Milliseconds(),
		OKAt:      c.now().Unix(),
	}
	replaced := false
	for index := range c.entries {
		if c.entries[index].key() == entry.key() {
			c.entries[index] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		c.entries = append(c.entries, entry)
	}
	c.sortLocked()
	if len(c.entries) > endpointCacheMax {
		c.entries = c.entries[:endpointCacheMax]
	}
	c.mutex.Unlock()
	c.save()
}

// fail counts a failed probe of a cached pair; repeated failures evict it.
func (c *endpointCache) fail(network string, candidate warpCandidate) {
	if c == nil {
		return
	}
	c.mutex.Lock()
	key := cacheKey(network, candidate.transport, candidate.endpoint)
	changed := false
	kept := c.entries[:0]
	for _, entry := range c.entries {
		if entry.key() == key {
			entry.Fails++
			changed = true
			if entry.Fails >= endpointCacheMaxFails {
				continue
			}
		}
		kept = append(kept, entry)
	}
	c.entries = kept
	c.sortLocked()
	c.mutex.Unlock()
	if changed {
		c.save()
	}
}

// drop evicts a pair that stopped passing traffic after it was selected.
func (c *endpointCache) drop(network string, candidate warpCandidate) {
	if c == nil {
		return
	}
	c.mutex.Lock()
	key := cacheKey(network, candidate.transport, candidate.endpoint)
	changed := false
	kept := c.entries[:0]
	for _, entry := range c.entries {
		if entry.key() == key {
			changed = true
			continue
		}
		kept = append(kept, entry)
	}
	c.entries = kept
	c.mutex.Unlock()
	if changed {
		c.save()
	}
}

func (c *endpointCache) save() {
	if c == nil || c.path == "" {
		return
	}
	c.mutex.Lock()
	data, err := json.Marshal(endpointCacheFile{Version: endpointCacheVersion, Entries: c.entries, Colos: c.colos})
	c.mutex.Unlock()
	if err != nil {
		return
	}
	if err = writeFileAtomic(c.path, data); err != nil {
		flowRouterLogf("WARP endpoint cache not saved: %v", err)
	}
}
