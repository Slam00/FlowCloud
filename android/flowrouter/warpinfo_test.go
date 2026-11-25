package main

import (
	"encoding/json"
	"testing"
)

func TestTransportLabel(t *testing.T) {
	cases := map[warpTransport]string{
		transportAWG:      "AmneziaWG",
		transportMasqueH3: "MASQUE H3",
		transportMasqueH2: "MASQUE H2",
	}
	for transport, want := range cases {
		if got := transportLabel(warpCandidate{transport: transport}); got != want {
			t.Errorf("transportLabel(%q) = %q, want %q", transport, got, want)
		}
	}
}

func TestWarpInfoWithoutProfile(t *testing.T) {
	router, err := newFlowRouter("127.0.0.1:0", "127.0.0.1:1080", "", "", "", "", routerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer router.close()
	payload, err := json.Marshal(router.warpInfo(true))
	if err != nil {
		t.Fatal(err)
	}
	var info warpInfo
	if err = json.Unmarshal(payload, &info); err != nil {
		t.Fatal(err)
	}
	if info.State != "unavailable" || info.PingMs != -1 || info.Endpoint != "" {
		t.Fatalf("info = %+v, want unavailable without endpoint or ping", info)
	}
}
