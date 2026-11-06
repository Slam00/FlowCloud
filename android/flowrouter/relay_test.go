package main

import (
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	dialed, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return dialed, <-accepted
}

func TestRelayTCPForwardsAndPropagatesEOF(t *testing.T) {
	client, relayLeft := tcpPair(t)
	relayRight, server := tcpPair(t)
	defer client.Close()
	defer server.Close()

	finished := make(chan struct{})
	go func() {
		relayTCP(relayLeft, relayRight, []byte("hello "))
		relayLeft.Close()
		relayRight.Close()
		close(finished)
	}()

	_, _ = client.Write([]byte("world"))
	_ = client.(*net.TCPConn).CloseWrite()
	received, err := io.ReadAll(server)
	if err != nil || string(received) != "hello world" {
		t.Fatalf("server got %q, %v", received, err)
	}
	_, _ = server.Write([]byte("bye"))
	_ = server.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(client)
	if err != nil || string(reply) != "bye" {
		t.Fatalf("client got %q, %v", reply, err)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not finish after both sides closed")
	}
}

func TestRelayTCPDoesNotHangOnSilentPeer(t *testing.T) {
	previous := relayHalfCloseIdle
	relayHalfCloseIdle = 300 * time.Millisecond
	defer func() { relayHalfCloseIdle = previous }()

	client, relayLeft := tcpPair(t)
	relayRight, server := tcpPair(t)
	defer client.Close()
	defer server.Close() // never writes or closes: a vanished upstream

	finished := make(chan struct{})
	go func() {
		relayTCP(relayLeft, relayRight, nil)
		close(finished)
	}()

	// The client goes away; the upstream never answers.
	_ = client.Close()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("relay leaked: it is still waiting for a silent upstream")
	}
}
