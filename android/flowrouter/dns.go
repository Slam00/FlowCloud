package main

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

type dnsMessage struct {
	id        uint16
	response  bool
	question  string
	addresses []string
	ttl       time.Duration
}

func buildDNSQuery(host string) ([]byte, bool) {
	host = normalizeHost(host)
	if host == "" || len(host) > 253 {
		return nil, false
	}
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], uint16(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(packet[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, false
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 1, 0, 1) // root, A, IN
	return packet, true
}

func parseDNSMessage(packet []byte) (dnsMessage, bool) {
	if len(packet) < 12 {
		return dnsMessage{}, false
	}
	message := dnsMessage{
		id:       binary.BigEndian.Uint16(packet[0:2]),
		response: packet[2]&0x80 != 0,
	}
	questionCount := int(binary.BigEndian.Uint16(packet[4:6]))
	answerCount := int(binary.BigEndian.Uint16(packet[6:8]))
	position := 12
	for i := 0; i < questionCount; i++ {
		name, next, ok := readDNSName(packet, position, 0)
		if !ok || next+4 > len(packet) {
			return dnsMessage{}, false
		}
		if message.question == "" {
			message.question = normalizeHost(name)
		}
		position = next + 4
	}
	minimumTTL := uint32(0)
	for i := 0; i < answerCount; i++ {
		_, next, ok := readDNSName(packet, position, 0)
		if !ok || next+10 > len(packet) {
			return dnsMessage{}, false
		}
		typeID := binary.BigEndian.Uint16(packet[next : next+2])
		classID := binary.BigEndian.Uint16(packet[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(packet[next+4 : next+8])
		length := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
		position = next + 10
		if position+length > len(packet) {
			return dnsMessage{}, false
		}
		if classID == 1 {
			var address net.IP
			switch {
			case typeID == 1 && length == 4:
				address = net.IP(packet[position : position+4])
			case typeID == 28 && length == 16:
				address = net.IP(packet[position : position+16])
			}
			if address != nil {
				message.addresses = append(message.addresses, address.String())
				if minimumTTL == 0 || ttl < minimumTTL {
					minimumTTL = ttl
				}
			}
		}
		position += length
	}
	message.ttl = time.Duration(minimumTTL) * time.Second
	return message, message.question != "" || len(message.addresses) > 0
}

func readDNSName(packet []byte, position, depth int) (string, int, bool) {
	if depth > 12 || position < 0 || position >= len(packet) {
		return "", position, false
	}
	labels := make([]string, 0, 4)
	next := position
	jumped := false
	for {
		if position >= len(packet) {
			return "", next, false
		}
		length := int(packet[position])
		if length&0xc0 == 0xc0 {
			if position+1 >= len(packet) {
				return "", next, false
			}
			pointer := ((length & 0x3f) << 8) | int(packet[position+1])
			name, _, ok := readDNSName(packet, pointer, depth+1)
			if !ok {
				return "", next, false
			}
			if name != "" {
				labels = append(labels, name)
			}
			if !jumped {
				next = position + 2
			}
			return strings.Join(labels, "."), next, true
		}
		if length == 0 {
			if !jumped {
				next = position + 1
			}
			return strings.Join(labels, "."), next, true
		}
		if length > 63 || position+1+length > len(packet) {
			return "", next, false
		}
		labels = append(labels, string(packet[position+1:position+1+length]))
		position += 1 + length
		if !jumped {
			next = position
		}
	}
}
