package main

import (
	"testing"
	"time"
)

func TestDomainRulesMatchSuffixAndCIDR(t *testing.T) {
	rules := parseDomainRules("telegram.org\n149.154.160.0/20\n2001:b28:f23f::/48\n")
	tests := map[string]bool{
		"telegram.org":      true,
		"api.telegram.org":  true,
		"149.154.167.91":    true,
		"2001:b28:f23f::42": true,
		"nottelegram.org":   false,
		"149.154.159.255":   false,
		"example.com":       false,
	}
	for value, expected := range tests {
		if actual := rules.matches(value); actual != expected {
			t.Errorf("matches(%q) = %v, want %v", value, actual, expected)
		}
	}
}

func TestDomainRulesWildcardMatchesEverything(t *testing.T) {
	rules := parseDomainRules("*")
	for _, value := range []string{"example.com", "149.154.167.91", "2001:db8::1"} {
		if !rules.matches(value) {
			t.Errorf("wildcard does not match %q", value)
		}
	}
}

func TestSniffHTTPHost(t *testing.T) {
	packet := []byte("GET / HTTP/1.1\r\nHost: api.telegram.org:443\r\n\r\n")
	if actual := sniffHost(packet); actual != "api.telegram.org" {
		t.Fatalf("sniffHost() = %q", actual)
	}
}

func TestDNSCacheRememberResolved(t *testing.T) {
	cache := newDNSCache()
	cache.rememberResolved("SpeedTest.NET.", []string{"203.0.113.8"}, time.Minute)
	if actual := cache.lookup("203.0.113.8"); actual != "speedtest.net" {
		t.Fatalf("lookup() = %q, want speedtest.net", actual)
	}
}

func TestWarpEndpointCandidatesIncludeMobileFallbacks(t *testing.T) {
	candidates := endpointCandidates("162.159.192.9:2408")
	wanted := map[string]bool{
		"162.159.192.9:2408": false,
		"162.159.192.9:500":  false,
		"162.159.192.1:2408": false,
		"162.159.192.5:500":  false,
	}
	for _, candidate := range candidates {
		if _, exists := wanted[candidate]; exists {
			wanted[candidate] = true
		}
	}
	for candidate, found := range wanted {
		if !found {
			t.Errorf("endpointCandidates() does not contain %s", candidate)
		}
	}
}
