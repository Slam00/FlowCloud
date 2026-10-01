package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	socksVersion5 = 5
	socksConnect  = 1
	socksUDP      = 3
	addressIPv4   = 1
	addressDomain = 3
	addressIPv6   = 4
)

type socksTarget struct {
	host string
	port uint16
	raw  []byte
}

func (t socksTarget) address() string {
	return net.JoinHostPort(t.host, strconv.Itoa(int(t.port)))
}

func readSocksTarget(reader io.Reader) (socksTarget, error) {
	atyp := []byte{0}
	if _, err := io.ReadFull(reader, atyp); err != nil {
		return socksTarget{}, err
	}
	raw := []byte{atyp[0]}
	var host string
	switch atyp[0] {
	case addressIPv4:
		address := make([]byte, 4)
		if _, err := io.ReadFull(reader, address); err != nil {
			return socksTarget{}, err
		}
		raw = append(raw, address...)
		host = net.IP(address).String()
	case addressIPv6:
		address := make([]byte, 16)
		if _, err := io.ReadFull(reader, address); err != nil {
			return socksTarget{}, err
		}
		raw = append(raw, address...)
		host = net.IP(address).String()
	case addressDomain:
		length := []byte{0}
		if _, err := io.ReadFull(reader, length); err != nil {
			return socksTarget{}, err
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, name); err != nil {
			return socksTarget{}, err
		}
		raw = append(raw, length[0])
		raw = append(raw, name...)
		host = string(name)
	default:
		return socksTarget{}, fmt.Errorf("unsupported SOCKS address type %d", atyp[0])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return socksTarget{}, err
	}
	raw = append(raw, portBytes...)
	return socksTarget{host: normalizeHost(host), port: binary.BigEndian.Uint16(portBytes), raw: raw}, nil
}

func writeSocksReply(writer io.Writer, code byte, address net.Addr) error {
	host := net.IPv4zero
	port := 0
	if udp, ok := address.(*net.UDPAddr); ok {
		host = udp.IP
		port = udp.Port
	} else if tcp, ok := address.(*net.TCPAddr); ok {
		host = tcp.IP
		port = tcp.Port
	}
	if host == nil || host.To4() == nil {
		host = net.IPv4zero
	}
	reply := []byte{socksVersion5, code, 0, addressIPv4}
	reply = append(reply, host.To4()...)
	reply = binary.BigEndian.AppendUint16(reply, uint16(port))
	_, err := writer.Write(reply)
	return err
}

func negotiateSocks(connection net.Conn) (byte, socksTarget, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return 0, socksTarget{}, err
	}
	if header[0] != socksVersion5 || header[1] == 0 {
		return 0, socksTarget{}, errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return 0, socksTarget{}, err
	}
	found := false
	for _, method := range methods {
		found = found || method == 0
	}
	if !found {
		_, _ = connection.Write([]byte{socksVersion5, 0xff})
		return 0, socksTarget{}, errors.New("SOCKS client does not support no-auth")
	}
	if _, err := connection.Write([]byte{socksVersion5, 0}); err != nil {
		return 0, socksTarget{}, err
	}
	request := make([]byte, 3)
	if _, err := io.ReadFull(connection, request); err != nil {
		return 0, socksTarget{}, err
	}
	if request[0] != socksVersion5 || request[2] != 0 {
		return 0, socksTarget{}, errors.New("invalid SOCKS request")
	}
	target, err := readSocksTarget(connection)
	return request[1], target, err
}

func dialSocks(ctx context.Context, upstream string, target socksTarget) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (net.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	if _, err = connection.Write([]byte{socksVersion5, 1, 0}); err != nil {
		return closeOnError(err)
	}
	response := make([]byte, 2)
	if _, err = io.ReadFull(connection, response); err != nil {
		return closeOnError(err)
	}
	if response[0] != socksVersion5 || response[1] != 0 {
		return closeOnError(errors.New("ByeDPI rejected SOCKS authentication"))
	}
	request := []byte{socksVersion5, socksConnect, 0}
	request = append(request, target.raw...)
	if _, err = connection.Write(request); err != nil {
		return closeOnError(err)
	}
	replyHeader := make([]byte, 3)
	if _, err = io.ReadFull(connection, replyHeader); err != nil {
		return closeOnError(err)
	}
	if replyHeader[0] != socksVersion5 || replyHeader[1] != 0 {
		return closeOnError(fmt.Errorf("ByeDPI SOCKS error %d", replyHeader[1]))
	}
	if _, err = readSocksTarget(connection); err != nil {
		return closeOnError(err)
	}
	return connection, nil
}

func relayTCP(left, right net.Conn, initial []byte) {
	if len(initial) > 0 {
		if _, err := right.Write(initial); err != nil {
			return
		}
	}
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(right, left)
		if tcp, ok := right.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(left, right)
	if tcp, ok := left.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-done
}

func readInitialPayload(connection net.Conn) []byte {
	const maximum = 64 * 1024
	buffer := make([]byte, 0, 4096)
	temporary := make([]byte, 4096)
	_ = connection.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	defer connection.SetReadDeadline(time.Time{})
	for len(buffer) < maximum {
		count, err := connection.Read(temporary)
		if count > 0 {
			buffer = append(buffer, temporary[:count]...)
			if sniffHost(buffer) != "" || looksCompleteInitial(buffer) {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return buffer
}

func looksCompleteInitial(data []byte) bool {
	if len(data) >= 5 && data[0] == 0x16 {
		return len(data) >= 5+int(binary.BigEndian.Uint16(data[3:5]))
	}
	return len(data) >= 8192
}

type udpFrame struct {
	target  socksTarget
	payload []byte
}

func parseUDPFrame(packet []byte) (udpFrame, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return udpFrame{}, errors.New("invalid SOCKS UDP frame")
	}
	reader := &byteReader{data: packet[3:]}
	target, err := readSocksTarget(reader)
	if err != nil {
		return udpFrame{}, err
	}
	return udpFrame{target: target, payload: reader.remaining()}, nil
}

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(destination []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	count := copy(destination, r.data[r.pos:])
	r.pos += count
	return count, nil
}

func (r *byteReader) remaining() []byte {
	return r.data[r.pos:]
}

type upstreamUDP struct {
	control net.Conn
	socket  *net.UDPConn
	target  *net.UDPAddr
}

func openUpstreamUDP(upstream string) (*upstreamUDP, error) {
	connection, err := net.DialTimeout("tcp", upstream, 10*time.Second)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*upstreamUDP, error) {
		_ = connection.Close()
		return nil, err
	}
	if _, err = connection.Write([]byte{socksVersion5, 1, 0}); err != nil {
		return fail(err)
	}
	auth := make([]byte, 2)
	if _, err = io.ReadFull(connection, auth); err != nil || auth[1] != 0 {
		if err == nil {
			err = errors.New("ByeDPI rejected UDP authentication")
		}
		return fail(err)
	}
	if _, err = connection.Write([]byte{socksVersion5, socksUDP, 0, addressIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	reply := make([]byte, 3)
	if _, err = io.ReadFull(connection, reply); err != nil || reply[1] != 0 {
		if err == nil {
			err = fmt.Errorf("ByeDPI UDP associate error %d", reply[1])
		}
		return fail(err)
	}
	target, err := readSocksTarget(connection)
	if err != nil {
		return fail(err)
	}
	address, err := net.ResolveUDPAddr("udp", target.address())
	if err != nil {
		return fail(err)
	}
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fail(err)
	}
	return &upstreamUDP{control: connection, socket: socket, target: address}, nil
}

func (u *upstreamUDP) close() {
	_ = u.socket.Close()
	_ = u.control.Close()
}

type udpClientState struct {
	mutex   sync.Mutex
	address *net.UDPAddr
}
