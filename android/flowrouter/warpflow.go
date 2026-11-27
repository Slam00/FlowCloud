package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// Lessons from FlowCloud for OpenWrt and WindseekerTunnel on the same kind of
// network: the provider cuts long WARP UDP flows (after a couple of minutes or
// a few MB) while the handshake keeps working, and the same endpoint answers
// again from a new source port with a new handshake. Connections opened over
// the cut flow do not come back, so they are closed at once and apps
// reconnect over the revived tunnel instead of waiting for TCP to give up.

// countingBind wraps the WireGuard bind and counts the bytes it receives and
// sends, for the stall detector.
type countingBind struct {
	conn.Bind
	rx   atomic.Uint64
	tx   atomic.Uint64
	sent atomic.Uint64
}

func newCountingBind(inner conn.Bind) *countingBind { return &countingBind{Bind: inner} }

func (b *countingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	functions, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, actual, err
	}
	wrapped := make([]conn.ReceiveFunc, len(functions))
	for index, receive := range functions {
		receive := receive
		wrapped[index] = func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			count, err := receive(packets, sizes, endpoints)
			for packet := 0; packet < count; packet++ {
				b.rx.Add(uint64(sizes[packet]))
			}
			return count, err
		}
	}
	return wrapped, actual, nil
}

func (b *countingBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	err := b.Bind.Send(packets, endpoint)
	if err == nil {
		for _, packet := range packets {
			b.tx.Add(uint64(len(packet)))
		}
		b.sent.Add(uint64(len(packets)))
	}
	return err
}

// PeekLookAtSocketFd4 and PeekLookAtSocketFd6 let bindWireGuardSockets reach
// the sockets of the wrapped StdNetBind.
func (b *countingBind) PeekLookAtSocketFd4() (int, error) {
	if peeker, ok := b.Bind.(interface{ PeekLookAtSocketFd4() (int, error) }); ok {
		return peeker.PeekLookAtSocketFd4()
	}
	return -1, errors.ErrUnsupported
}

func (b *countingBind) PeekLookAtSocketFd6() (int, error) {
	if peeker, ok := b.Bind.(interface{ PeekLookAtSocketFd6() (int, error) }); ok {
		return peeker.PeekLookAtSocketFd6()
	}
	return -1, errors.ErrUnsupported
}

// traffic returns the WireGuard bytes received and sent and the packets sent.
func (t *warpTunnel) traffic() (rx, tx, sent uint64, ok bool) {
	if t == nil || t.bind == nil {
		return 0, 0, 0, false
	}
	return t.bind.rx.Load(), t.bind.tx.Load(), t.bind.sent.Load(), true
}

// reconnect moves an AmneziaWG tunnel to a new random source port with a new
// handshake to the same endpoint, keeping its userspace network. Cloudflare
// does not move a session to a new port by itself, so the peer is removed
// and added again; its persistent keepalive sends the handshake at once.
func (t *warpTunnel) reconnect() error {
	if t == nil || t.device == nil || t.peerHex == "" {
		return errors.New("tunnel cannot reconnect")
	}
	lines := []string{
		"listen_port=0",
		"public_key=" + t.peerHex,
		"remove=true",
		"public_key=" + t.peerHex,
		"endpoint=" + t.candidate.endpoint,
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval=" + keepaliveRange(t.keepalive),
	}
	if err := t.device.IpcSet(strings.Join(lines, "\n") + "\n\n"); err != nil {
		return fmt.Errorf("reconnect to %s: %w", t.candidate.endpoint, err)
	}
	// The new sockets must follow the chosen physical network too.
	bindWireGuardSockets(t.bind)
	return nil
}

// trackedConns are the connections dialed through one tunnel.
type trackedConns struct {
	mutex sync.Mutex
	conns map[*trackedConn]struct{}
}

type trackedConn struct {
	net.Conn
	owner *trackedConns
	once  sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.owner.remove(c) })
	return c.Conn.Close()
}

func (t *trackedConns) wrap(connection net.Conn) net.Conn {
	wrapped := &trackedConn{Conn: connection, owner: t}
	t.mutex.Lock()
	if t.conns == nil {
		t.conns = map[*trackedConn]struct{}{}
	}
	t.conns[wrapped] = struct{}{}
	t.mutex.Unlock()
	return wrapped
}

func (t *trackedConns) remove(connection *trackedConn) {
	t.mutex.Lock()
	delete(t.conns, connection)
	t.mutex.Unlock()
}

// count is the number of open tracked connections.
func (t *trackedConns) count() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return len(t.conns)
}

// closeAll closes every tracked connection and reports how many there were.
func (t *trackedConns) closeAll() int {
	t.mutex.Lock()
	conns := make([]*trackedConn, 0, len(t.conns))
	for connection := range t.conns {
		conns = append(conns, connection)
	}
	t.mutex.Unlock()
	for _, connection := range conns {
		_ = connection.Close()
	}
	return len(conns)
}

// warpDataTarget answers a plain HTTP request from the same Cloudflare edge as
// the WARP endpoint.
const warpDataTarget = "1.1.1.1:80"

// expectHTTP sends a HEAD and waits for the start of the response: a tunnel
// that completes TCP handshakes but returns no data has been seen, so a
// handshake alone is no proof of life.
func expectHTTP(ctx context.Context, connection net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := io.WriteString(connection, "HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"); err != nil {
		return fmt.Errorf("send through tunnel: %w", err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(connection, reply); err != nil {
		return fmt.Errorf("no data through tunnel: %w", err)
	}
	if !strings.HasPrefix(string(reply), "HTTP/1.") {
		return errors.New("unexpected reply through tunnel")
	}
	return nil
}
