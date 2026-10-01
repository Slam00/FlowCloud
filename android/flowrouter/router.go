package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

type flowRouter struct {
	listenAddress string
	byeDPIAddress string
	dnsRelay      *net.UDPAddr
	warpRules     domainRules
	byeDPIRules   domainRules
	dns           *dnsCache
	warpConfig    warpConfig

	context context.Context
	cancel  context.CancelFunc
	listen  net.Listener

	warpMutex       sync.Mutex
	warp            *warpTunnel
	warpErr         error
	warpTried       time.Time
	warpProbeTarget string
	closeOnce       sync.Once
	wait            sync.WaitGroup
}

const warpRetryInterval = 30 * time.Second

func newFlowRouter(listenAddress, byeDPIAddress, dnsRelayAddress, warpRulesText, byeDPIRulesText, warpJSON string) (*flowRouter, error) {
	if _, err := net.ResolveTCPAddr("tcp", listenAddress); err != nil {
		return nil, fmt.Errorf("invalid router address: %w", err)
	}
	if _, err := net.ResolveTCPAddr("tcp", byeDPIAddress); err != nil {
		return nil, fmt.Errorf("invalid ByeDPI address: %w", err)
	}
	var dnsRelay *net.UDPAddr
	if dnsRelayAddress != "" {
		var err error
		dnsRelay, err = net.ResolveUDPAddr("udp4", dnsRelayAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS relay address: %w", err)
		}
	}
	config, err := parseWarpConfig(warpJSON)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &flowRouter{
		listenAddress: listenAddress,
		byeDPIAddress: byeDPIAddress,
		dnsRelay:      dnsRelay,
		warpRules:     parseDomainRules(warpRulesText),
		byeDPIRules:   parseDomainRules(byeDPIRulesText),
		dns:           newDNSCache(),
		warpConfig:    config,
		context:       ctx,
		cancel:        cancel,
	}, nil
}

func (r *flowRouter) exchangeDNSViaRelay(query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(r.context, 9*time.Second)
	defer cancel()
	return r.exchangeDNSViaRelayContext(ctx, query)
}

func (r *flowRouter) exchangeDNSViaRelayContext(ctx context.Context, query []byte) ([]byte, error) {
	if r.dnsRelay == nil {
		return nil, errors.New("DNS relay is unavailable")
	}
	connection, err := net.DialUDP("udp4", nil, r.dnsRelay)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	deadline := time.Now().Add(9 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	if _, err = connection.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	count, err := connection.Read(response)
	if err != nil {
		return nil, err
	}
	if count < 12 || response[0] != query[0] || response[1] != query[1] || response[2]&0x80 == 0 {
		return nil, errors.New("invalid response from DNS relay")
	}
	return append([]byte(nil), response[:count]...), nil
}

func (r *flowRouter) resolveWarpHost(ctx context.Context, host string) ([]netip.Addr, error) {
	query, ok := buildDNSQuery(host)
	if !ok {
		return nil, fmt.Errorf("invalid DNS name %q", host)
	}
	response, err := r.exchangeDNSViaRelayContext(ctx, query)
	if err != nil {
		return nil, err
	}
	message, ok := parseDNSMessage(response)
	if !ok || !message.response {
		return nil, errors.New("invalid DNS relay response")
	}
	addresses := make([]netip.Addr, 0, len(message.addresses))
	for _, value := range message.addresses {
		address, parseErr := netip.ParseAddr(value)
		if parseErr == nil && address.Is4() {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("DNS relay returned no IPv4 address for %s", host)
	}
	return addresses, nil
}

func (r *flowRouter) start() error {
	listener, err := net.Listen("tcp4", r.listenAddress)
	if err != nil {
		return fmt.Errorf("listen for tun2socks: %w", err)
	}
	r.listen = listener
	flowRouterLogf(
		"Router started: WARP domains=%d, WARP networks=%d, ByeDPI domains=%d, ByeDPI networks=%d",
		len(r.warpRules.rules), len(r.warpRules.prefixes), len(r.byeDPIRules.rules), len(r.byeDPIRules.prefixes),
	)
	if r.warpRules.all && !r.warpConfig.available() {
		_ = listener.Close()
		return errors.New("WARP mode requires a registered WARP profile")
	}
	if r.warpConfig.available() {
		probeContext, cancelProbe := context.WithTimeout(r.context, 9*time.Second)
		probeAddresses, resolveErr := r.resolveWarpHost(probeContext, "www.youtube.com")
		r.warpMutex.Lock()
		r.warpTried = time.Now()
		if resolveErr != nil {
			r.warpErr = fmt.Errorf("resolve WARP data probe through encrypted DNS: %w", resolveErr)
		} else {
			r.warpProbeTarget = net.JoinHostPort(probeAddresses[0].String(), "443")
			flowRouterLogf("WARP data probe resolved through encrypted DNS: %s", r.warpProbeTarget)
			r.warp, r.warpErr = openWorkingWarp(
				probeContext,
				r.warpConfig,
				r.warpProbeTarget,
				r.resolveWarpHost,
			)
		}
		r.warpMutex.Unlock()
		cancelProbe()
		if r.warpErr != nil {
			flowRouterLogf("WARP preflight failed: %v", r.warpErr)
			if r.warpRules.all {
				_ = listener.Close()
				return r.warpErr
			}
		}
	}
	r.wait.Add(1)
	go func() {
		defer r.wait.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				if r.context.Err() != nil {
					return
				}
				continue
			}
			r.wait.Add(1)
			go func() {
				defer r.wait.Done()
				r.handle(connection)
			}()
		}
	}()
	return nil
}

func (r *flowRouter) close() {
	r.closeOnce.Do(func() {
		r.cancel()
		if r.listen != nil {
			_ = r.listen.Close()
		}
		warpClosed := make(chan struct{})
		go func() {
			r.warpMutex.Lock()
			if r.warp != nil {
				r.warp.close()
				r.warp = nil
			}
			r.warpMutex.Unlock()
			close(warpClosed)
		}()
		select {
		case <-warpClosed:
		case <-time.After(2 * time.Second):
		}
	})
	finished := make(chan struct{})
	go func() {
		r.wait.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
	}
}

func (r *flowRouter) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	command, target, err := negotiateSocks(connection)
	if err != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	switch command {
	case socksConnect:
		r.handleConnect(connection, target)
	case socksUDP:
		r.handleUDP(connection)
	default:
		_ = writeSocksReply(connection, 7, nil)
	}
}

func (r *flowRouter) handleConnect(client net.Conn, target socksTarget) {
	// tun2socks only releases application data after a successful SOCKS reply.
	// A provisional success lets us inspect TLS SNI/HTTP Host before choosing
	// ByeDPI or WARP inside this single Android VPN service.
	if writeSocksReply(client, 0, nil) != nil {
		return
	}
	// Telegram and other IP/CIDR rules can be selected immediately. Waiting for
	// an SNI that will never exist delays native protocols and can make clients
	// abandon an otherwise healthy connection.
	targetWarp := r.warpRules.matches(target.host)
	targetByeDPI := r.byeDPIRules.matches(target.host)
	var initial []byte
	var host string
	if !targetWarp && !targetByeDPI {
		initial = readInitialPayload(client)
		host = sniffHost(initial)
	}
	if host == "" {
		host = r.dns.lookup(target.host)
	}
	if host == "" && net.ParseIP(target.host) == nil {
		host = target.host
	}

	var upstream net.Conn
	var err error
	useWarp := r.warpRules.matches(host) || targetWarp
	useByeDPI := r.byeDPIRules.matches(host) || targetByeDPI
	routedViaWarp := false
	if useWarp {
		flowRouterLogf("TCP route WARP: host=%s target=%s", host, target.address())
		warpTimeout := 4 * time.Second
		if r.warpRules.all {
			warpTimeout = 8 * time.Second
		}
		warpContext, cancelWarp := context.WithTimeout(r.context, warpTimeout)
		upstream, err = r.dialWarp(warpContext, target.address())
		cancelWarp()
		if err != nil {
			flowRouterLogf("TCP route WARP failed: host=%s target=%s: %v", host, target.address(), err)
			if useByeDPI {
				flowRouterLogf("TCP route ByeDPI fallback: host=%s target=%s", host, target.address())
				fallbackContext, cancelFallback := context.WithTimeout(r.context, 15*time.Second)
				upstream, err = dialSocks(fallbackContext, r.byeDPIAddress, target)
				cancelFallback()
			}
		} else {
			routedViaWarp = true
		}
	} else if useByeDPI {
		flowRouterLogf("TCP route ByeDPI: host=%s target=%s", host, target.address())
		fallbackContext, cancelFallback := context.WithTimeout(r.context, 15*time.Second)
		upstream, err = dialSocks(fallbackContext, r.byeDPIAddress, target)
		cancelFallback()
	} else {
		directContext, cancelDirect := context.WithTimeout(r.context, 10*time.Second)
		upstream, err = (&net.Dialer{}).DialContext(directContext, "tcp", target.address())
		cancelDirect()
	}
	if err != nil {
		return
	}
	if routedViaWarp {
		flowRouterLogf("TCP route WARP connected: host=%s target=%s", host, target.address())
	}
	defer upstream.Close()
	relayTCP(client, upstream, initial)
}

func (r *flowRouter) dialWarp(ctx context.Context, target string) (net.Conn, error) {
	return r.dialWarpNetwork(ctx, "tcp", target)
}

func (r *flowRouter) dialWarpNetwork(ctx context.Context, network, target string) (net.Conn, error) {
	r.warpMutex.Lock()
	defer r.warpMutex.Unlock()
	if !r.warpConfig.available() {
		return nil, errors.New("WARP configuration is unavailable")
	}
	if r.warpErr != nil && time.Since(r.warpTried) >= warpRetryInterval {
		r.warpErr = nil
	}
	if r.warp == nil && r.warpErr == nil {
		r.warpTried = time.Now()
		if r.warpProbeTarget == "" {
			addresses, resolveErr := r.resolveWarpHost(ctx, "www.youtube.com")
			if resolveErr != nil {
				r.warpErr = resolveErr
			} else {
				r.warpProbeTarget = net.JoinHostPort(addresses[0].String(), "443")
			}
		}
		if r.warpErr == nil {
			r.warp, r.warpErr = openWorkingWarp(
				ctx,
				r.warpConfig,
				r.warpProbeTarget,
				r.resolveWarpHost,
			)
		}
	}
	if r.warpErr != nil {
		return nil, r.warpErr
	}
	if r.warp == nil {
		return nil, errors.New("WARP is unavailable")
	}
	return r.warp.dialNetworkContext(ctx, network, target)
}

func (r *flowRouter) exchangeDNSOverWarp(target socksTarget, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(r.context, 6*time.Second)
	defer cancel()
	connection, err := r.dialWarpNetwork(ctx, "tcp", target.address())
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(6 * time.Second))
	packet := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(packet[:2], uint16(len(query)))
	copy(packet[2:], query)
	if _, err = connection.Write(packet); err != nil {
		return nil, err
	}
	header := make([]byte, 2)
	if _, err = io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header))
	if length < 12 || length > 65535 {
		return nil, errors.New("invalid DNS-over-TCP response size")
	}
	response := make([]byte, length)
	if _, err = io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (r *flowRouter) handleUDP(control net.Conn) {
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		_ = writeSocksReply(control, 1, nil)
		return
	}
	defer local.Close()
	if writeSocksReply(control, 0, local.LocalAddr()) != nil {
		return
	}
	upstream, err := openUpstreamUDP(r.byeDPIAddress)
	if err != nil {
		return
	}
	defer upstream.close()

	clientState := &udpClientState{}
	type pendingWarpPacket struct {
		payload  []byte
		original []byte
	}
	type warpUDPState struct {
		connection net.Conn
		opening    bool
		pending    []pendingWarpPacket
	}
	warpConnections := make(map[string]*warpUDPState)
	var warpConnectionsMutex sync.Mutex
	udpClosed := false
	sendViaByeDPI := func(packet []byte) {
		_, _ = upstream.socket.WriteToUDP(packet, upstream.target)
	}
	defer func() {
		warpConnectionsMutex.Lock()
		udpClosed = true
		for _, state := range warpConnections {
			if state.connection != nil {
				_ = state.connection.Close()
			}
		}
		warpConnections = make(map[string]*warpUDPState)
		warpConnectionsMutex.Unlock()
	}()
	done := make(chan struct{})
	go func() {
		buffer := make([]byte, 65535)
		for {
			count, _, err := upstream.socket.ReadFromUDP(buffer)
			if err != nil {
				close(done)
				return
			}
			packet := append([]byte(nil), buffer[:count]...)
			if frame, parseErr := parseUDPFrame(packet); parseErr == nil && frame.target.port == 53 {
				if message, ok := parseDNSMessage(frame.payload); ok && message.response {
					r.dns.rememberAnswers(message.id, message.addresses, message.ttl)
				}
			}
			clientState.mutex.Lock()
			clientAddress := clientState.address
			clientState.mutex.Unlock()
			if clientAddress != nil {
				_, _ = local.WriteToUDP(packet, clientAddress)
			}
		}
	}()

	r.wait.Add(1)
	go func() {
		defer r.wait.Done()
		_, _ = io.Copy(io.Discard, control)
		_ = local.Close()
		_ = upstream.socket.Close()
	}()

	buffer := make([]byte, 65535)
	for {
		count, clientAddress, err := local.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		clientState.mutex.Lock()
		clientState.address = clientAddress
		clientState.mutex.Unlock()
		packet := append([]byte(nil), buffer[:count]...)
		frame, parseErr := parseUDPFrame(packet)
		if parseErr == nil {
			if frame.target.port == 53 {
				message, validQuery := parseDNSMessage(frame.payload)
				if validQuery && !message.response {
					r.dns.rememberQuery(message.id, message.question)
				}
				question := message.question
				query := append([]byte(nil), frame.payload...)
				originalPacket := append([]byte(nil), packet...)
				target := frame.target
				clientCopy := *clientAddress
				r.wait.Add(1)
				go func() {
					defer r.wait.Done()
					response, dnsErr := r.exchangeDNSViaRelay(query)
					if dnsErr != nil {
						response, dnsErr = r.exchangeDNSOverWarp(target, query)
					}
					if dnsErr != nil {
						_, _ = upstream.socket.WriteToUDP(originalPacket, upstream.target)
						return
					}
					if answer, ok := parseDNSMessage(response); ok && answer.response {
						r.dns.rememberResolved(question, answer.addresses, answer.ttl)
					}
					responsePacket := []byte{0, 0, 0}
					responsePacket = append(responsePacket, target.raw...)
					responsePacket = append(responsePacket, response...)
					_, _ = local.WriteToUDP(responsePacket, &clientCopy)
				}()
				continue
			}
			host := r.dns.lookup(frame.target.host)
			// The DNS cache lets IP-based QUIC packets follow the same WARP rules as
			// TCP. Unknown UDP/443 must not be forced through WARP: doing that stalls
			// ordinary sites on mobile providers that impair WireGuard UDP.
			if r.warpRules.matches(host) || r.warpRules.matches(frame.target.host) {
				key := frame.target.address()
				queued := pendingWarpPacket{
					payload:  append([]byte(nil), frame.payload...),
					original: append([]byte(nil), packet...),
				}
				warpConnectionsMutex.Lock()
				state := warpConnections[key]
				if state == nil {
					state = &warpUDPState{opening: true, pending: []pendingWarpPacket{queued}}
					warpConnections[key] = state
					target := frame.target
					warpTimeout := 4 * time.Second
					if r.warpRules.all {
						warpTimeout = 8 * time.Second
					}
					r.wait.Add(1)
					go func() {
						defer r.wait.Done()
						ctx, cancel := context.WithTimeout(r.context, warpTimeout)
						connection, dialErr := r.dialWarpNetwork(ctx, "udp", key)
						cancel()
						if dialErr != nil {
							warpConnectionsMutex.Lock()
							if warpConnections[key] != state {
								warpConnectionsMutex.Unlock()
								return
							}
							delete(warpConnections, key)
							pending := state.pending
							warpConnectionsMutex.Unlock()
							for _, queuedPacket := range pending {
								sendViaByeDPI(queuedPacket.original)
							}
							return
						}

						// Packets can arrive while WARP is connecting. Drain the queue
						// before exposing the connection so writes stay ordered.
						for {
							warpConnectionsMutex.Lock()
							if udpClosed || warpConnections[key] != state {
								warpConnectionsMutex.Unlock()
								_ = connection.Close()
								return
							}
							pending := state.pending
							state.pending = nil
							if len(pending) == 0 {
								state.connection = connection
								state.opening = false
								warpConnectionsMutex.Unlock()
								break
							}
							warpConnectionsMutex.Unlock()

							for index, queuedPacket := range pending {
								if _, writeErr := connection.Write(queuedPacket.payload); writeErr != nil {
									warpConnectionsMutex.Lock()
									if warpConnections[key] == state {
										delete(warpConnections, key)
									}
									remainder := append([]pendingWarpPacket(nil), pending[index:]...)
									remainder = append(remainder, state.pending...)
									state.pending = nil
									warpConnectionsMutex.Unlock()
									_ = connection.Close()
									for _, fallbackPacket := range remainder {
										sendViaByeDPI(fallbackPacket.original)
									}
									return
								}
							}
						}

						relayWarpUDP(connection, target, local, clientState)
						warpConnectionsMutex.Lock()
						if warpConnections[key] == state {
							delete(warpConnections, key)
						}
						warpConnectionsMutex.Unlock()
						_ = connection.Close()
					}()
					warpConnectionsMutex.Unlock()
					continue
				}

				if state.opening {
					if len(state.pending) < 64 {
						state.pending = append(state.pending, queued)
						warpConnectionsMutex.Unlock()
						continue
					}
					warpConnectionsMutex.Unlock()
					sendViaByeDPI(packet)
					continue
				}

				connection := state.connection
				warpConnectionsMutex.Unlock()
				if connection != nil {
					if _, writeErr := connection.Write(frame.payload); writeErr == nil {
						continue
					}
					warpConnectionsMutex.Lock()
					if warpConnections[key] == state {
						delete(warpConnections, key)
					}
					warpConnectionsMutex.Unlock()
					_ = connection.Close()
				}
				sendViaByeDPI(packet)
				continue
			}
		}
		if _, err = upstream.socket.WriteToUDP(packet, upstream.target); err != nil {
			return
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func relayWarpUDP(connection net.Conn, target socksTarget, local *net.UDPConn, client *udpClientState) {
	buffer := make([]byte, 65535)
	for {
		count, err := connection.Read(buffer)
		if err != nil {
			return
		}
		packet := []byte{0, 0, 0}
		packet = append(packet, target.raw...)
		packet = append(packet, buffer[:count]...)
		client.mutex.Lock()
		address := client.address
		client.mutex.Unlock()
		if address != nil {
			_, _ = local.WriteToUDP(packet, address)
		}
	}
}
