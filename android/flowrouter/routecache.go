package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// routeKind is an upstream the router can use for one TCP connection.
type routeKind uint8

const (
	routeDirect routeKind = iota
	routeByeDPI
	routeWarp
)

func (k routeKind) String() string {
	switch k {
	case routeDirect:
		return "direct"
	case routeByeDPI:
		return "byedpi"
	case routeWarp:
		return "warp"
	}
	return "unknown"
}

func parseRouteKind(value string) (routeKind, bool) {
	switch value {
	case "direct":
		return routeDirect, true
	case "byedpi":
		return routeByeDPI, true
	case "warp":
		return routeWarp, true
	}
	return 0, false
}

const (
	defaultRouteCacheTTL   = 6 * time.Hour
	routeCacheMaxEntries   = 2048
	routeCacheSaveInterval = 5 * time.Second
)

type learnedRoute struct {
	route     routeKind
	expiresAt time.Time
}

// routeCache remembers which upstream worked for a destination (host name, or
// the IP when no name is known). Entries expire so that a route learned on one
// network or during a temporary outage is re-probed later.
type routeCache struct {
	mutex   sync.Mutex
	entries map[string]learnedRoute
	ttl     time.Duration
	path    string
	now     func() time.Time

	dirty      bool
	saveTimer  *time.Timer
	saveMutex  sync.Mutex
	closed     bool
	afterWrite func() // test hook
}

func newRouteCache(path string, ttl time.Duration) *routeCache {
	if ttl <= 0 {
		ttl = defaultRouteCacheTTL
	}
	cache := &routeCache{
		entries: make(map[string]learnedRoute),
		ttl:     ttl,
		path:    path,
		now:     time.Now,
	}
	cache.load()
	return cache
}

type routeCacheFileEntry struct {
	Host    string `json:"host"`
	Route   string `json:"route"`
	Expires int64  `json:"expires"`
}

type routeCacheFile struct {
	Version int                   `json:"version"`
	Entries []routeCacheFileEntry `json:"entries"`
}

func (c *routeCache) load() {
	if c.path == "" {
		return
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var file routeCacheFile
	if json.Unmarshal(data, &file) != nil || file.Version != 1 {
		return
	}
	now := c.now()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for _, entry := range file.Entries {
		route, ok := parseRouteKind(entry.Route)
		expires := time.Unix(entry.Expires, 0)
		host := normalizeHost(entry.Host)
		if !ok || host == "" || !expires.After(now) {
			continue
		}
		// Never trust a stored expiry further away than the configured TTL.
		if limit := now.Add(c.ttl); expires.After(limit) {
			expires = limit
		}
		c.entries[host] = learnedRoute{route: route, expiresAt: expires}
	}
}

func (c *routeCache) lookup(host string) (routeKind, bool) {
	host = normalizeHost(host)
	if host == "" {
		return 0, false
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	entry, ok := c.entries[host]
	if !ok {
		return 0, false
	}
	if !entry.expiresAt.After(c.now()) {
		delete(c.entries, host)
		c.dirty = true
		return 0, false
	}
	return entry.route, true
}

func (c *routeCache) remember(host string, route routeKind) {
	host = normalizeHost(host)
	if host == "" {
		return
	}
	c.mutex.Lock()
	now := c.now()
	if len(c.entries) >= routeCacheMaxEntries {
		c.evictLocked(now)
	}
	c.entries[host] = learnedRoute{route: route, expiresAt: now.Add(c.ttl)}
	c.dirty = true
	c.mutex.Unlock()
	c.scheduleSave()
}

func (c *routeCache) forget(host string) {
	host = normalizeHost(host)
	c.mutex.Lock()
	_, existed := c.entries[host]
	delete(c.entries, host)
	if existed {
		c.dirty = true
	}
	c.mutex.Unlock()
	if existed {
		c.scheduleSave()
	}
}

// evictLocked drops expired entries and, if still full, the ones closest to expiry.
func (c *routeCache) evictLocked(now time.Time) {
	for host, entry := range c.entries {
		if !entry.expiresAt.After(now) {
			delete(c.entries, host)
		}
	}
	if len(c.entries) < routeCacheMaxEntries {
		return
	}
	hosts := make([]string, 0, len(c.entries))
	for host := range c.entries {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool {
		return c.entries[hosts[i]].expiresAt.Before(c.entries[hosts[j]].expiresAt)
	})
	for _, host := range hosts[:len(hosts)-routeCacheMaxEntries/2] {
		delete(c.entries, host)
	}
}

func (c *routeCache) scheduleSave() {
	if c.path == "" {
		return
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.closed || c.saveTimer != nil {
		return
	}
	c.saveTimer = time.AfterFunc(routeCacheSaveInterval, func() {
		c.mutex.Lock()
		c.saveTimer = nil
		c.mutex.Unlock()
		c.flush()
	})
}

// flush writes the cache atomically if it changed since the last write.
func (c *routeCache) flush() {
	if c.path == "" {
		return
	}
	c.saveMutex.Lock()
	defer c.saveMutex.Unlock()
	c.mutex.Lock()
	if !c.dirty {
		c.mutex.Unlock()
		return
	}
	now := c.now()
	file := routeCacheFile{Version: 1, Entries: make([]routeCacheFileEntry, 0, len(c.entries))}
	for host, entry := range c.entries {
		if entry.expiresAt.After(now) {
			file.Entries = append(file.Entries, routeCacheFileEntry{
				Host: host, Route: entry.route.String(), Expires: entry.expiresAt.Unix(),
			})
		}
	}
	c.dirty = false
	c.mutex.Unlock()
	sort.Slice(file.Entries, func(i, j int) bool { return file.Entries[i].Host < file.Entries[j].Host })
	data, err := json.Marshal(file)
	if err == nil {
		err = writeFileAtomic(c.path, data)
	}
	if err != nil {
		flowRouterLogf("Auto route cache save failed: %v", err)
		c.mutex.Lock()
		c.dirty = true
		c.mutex.Unlock()
	}
	if c.afterWrite != nil {
		c.afterWrite()
	}
}

func (c *routeCache) close() {
	c.mutex.Lock()
	c.closed = true
	if c.saveTimer != nil {
		c.saveTimer.Stop()
		c.saveTimer = nil
	}
	c.mutex.Unlock()
	c.flush()
}

func (c *routeCache) size() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return len(c.entries)
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
