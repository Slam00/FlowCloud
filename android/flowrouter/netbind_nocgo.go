//go:build !cgo

package main

import "net"

// Host builds without a C compiler (e.g. `go test ./...` on Windows) cannot call
// android_setsocknetwork; sockets simply follow the system default network.

func physicalDialer() *net.Dialer {
	return &net.Dialer{}
}

func bindWireGuardSockets(_ interface{}) {}
