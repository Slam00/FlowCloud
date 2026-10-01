package main

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type domainRules struct {
	rules    map[string]struct{}
	prefixes []netip.Prefix
	all      bool
}

func parseDomainRules(text string) domainRules {
	rules := make(map[string]struct{})
	prefixes := make([]netip.Prefix, 0)
	all := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "*" {
			all = true
			continue
		}
		if prefix, err := netip.ParsePrefix(line); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		line = strings.TrimPrefix(line, ".")
		line = normalizeHost(line)
		if line != "" {
			rules[line] = struct{}{}
		}
	}
	return domainRules{rules: rules, prefixes: prefixes, all: all}
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	value = strings.ToLower(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.Trim(value, "[]")
}

func (r domainRules) matches(host string) bool {
	if r.all {
		return true
	}
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		for _, prefix := range r.prefixes {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	for {
		if _, ok := r.rules[host]; ok {
			return true
		}
		dot := strings.IndexByte(host, '.')
		if dot < 0 {
			return false
		}
		host = host[dot+1:]
	}
}

type cachedDomain struct {
	host      string
	expiresAt time.Time
}

type dnsCache struct {
	mutex   sync.Mutex
	byIP    map[string]cachedDomain
	queries map[uint16]string
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		byIP:    make(map[string]cachedDomain),
		queries: make(map[uint16]string),
	}
}

func (c *dnsCache) rememberQuery(id uint16, host string) {
	host = normalizeHost(host)
	if host == "" {
		return
	}
	c.mutex.Lock()
	c.queries[id] = host
	c.mutex.Unlock()
}

func (c *dnsCache) rememberAnswers(id uint16, addresses []string, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	host := c.queries[id]
	delete(c.queries, id)
	if host == "" {
		return
	}
	c.rememberResolvedLocked(host, addresses, ttl)
}

func (c *dnsCache) rememberResolved(host string, addresses []string, ttl time.Duration) {
	host = normalizeHost(host)
	if host == "" {
		return
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.rememberResolvedLocked(host, addresses, ttl)
}

func (c *dnsCache) rememberResolvedLocked(host string, addresses []string, ttl time.Duration) {
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 10 * time.Minute
	}
	entry := cachedDomain{host: host, expiresAt: time.Now().Add(ttl)}
	for _, address := range addresses {
		c.byIP[address] = entry
	}
}

func (c *dnsCache) lookup(address string) string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	entry, ok := c.byIP[normalizeHost(address)]
	if !ok {
		return ""
	}
	if time.Now().After(entry.expiresAt) {
		delete(c.byIP, normalizeHost(address))
		return ""
	}
	return entry.host
}
