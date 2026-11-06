package main

/*
#cgo android LDFLAGS: -landroid
#ifdef __ANDROID__
#include <android/multinetwork.h>
static int flow_bind_socket_to_network(long long handle, int fd) {
	return android_setsocknetwork((net_handle_t) handle, fd);
}
#else
static int flow_bind_socket_to_network(long long handle, int fd) {
	(void) handle;
	(void) fd;
	return 0;
}
#endif
*/
import "C"

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
)

// physicalNetworkHandle is the Android net_handle_t (Network.getNetworkHandle()) of
// the physical network the VPN service chose. ConnectivityManager.bindProcessToNetwork
// only affects sockets created through bionic's libc, while Go issues raw syscalls,
// so Go sockets must be bound explicitly or they follow the system default network,
// which can differ from the one ByeDPI uses during a network switch.
var physicalNetworkHandle atomic.Int64

//export FlowRouterSetPhysicalNetwork
func FlowRouterSetPhysicalNetwork(handle C.longlong) {
	physicalNetworkHandle.Store(int64(handle))
	if handle == 0 {
		flowRouterLogf("Physical network binding cleared; using the system default network")
	} else {
		flowRouterLogf("Outbound sockets bound to physical network handle %d", int64(handle))
	}
}

func bindFdToPhysicalNetwork(fd int) error {
	handle := physicalNetworkHandle.Load()
	if handle == 0 {
		return nil
	}
	result, err := C.flow_bind_socket_to_network(C.longlong(handle), C.int(fd))
	if result != 0 {
		return fmt.Errorf("bind socket to network %d: %w", handle, err)
	}
	return nil
}

// physicalNetworkControl is a net.Dialer / net.ListenConfig Control hook. Loopback
// destinations (ByeDPI, the DNS relay) are left alone: binding them to a physical
// network would make 127.0.0.1 unreachable.
func physicalNetworkControl(_ string, address string, raw syscall.RawConn) error {
	if host, _, err := net.SplitHostPort(address); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		bindErr = bindFdToPhysicalNetwork(int(fd))
	}); err != nil {
		return err
	}
	return bindErr
}

// physicalDialer returns a dialer whose sockets use the chosen physical network.
func physicalDialer() *net.Dialer {
	return &net.Dialer{Control: physicalNetworkControl}
}

// bindWireGuardSockets binds the WireGuard UDP sockets (created by conn.StdNetBind)
// to the chosen physical network. It is best effort: a socket that cannot be peeked
// keeps working on the system default network.
func bindWireGuardSockets(bind interface{}) {
	peeker, ok := bind.(interface {
		PeekLookAtSocketFd4() (int, error)
		PeekLookAtSocketFd6() (int, error)
	})
	if !ok || physicalNetworkHandle.Load() == 0 {
		return
	}
	for family, peek := range map[string]func() (int, error){
		"IPv4": peeker.PeekLookAtSocketFd4,
		"IPv6": peeker.PeekLookAtSocketFd6,
	} {
		fd, err := peek()
		if err != nil || fd < 0 {
			continue
		}
		if err = bindFdToPhysicalNetwork(fd); err != nil {
			flowRouterLogf("WARP %s socket stays on the default network: %v", family, err)
		}
	}
}
