package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

func sniffHost(data []byte) string {
	if host := sniffTLSHost(data); host != "" {
		return normalizeHost(host)
	}
	return normalizeHost(sniffHTTPHost(data))
}

func sniffHTTPHost(data []byte) string {
	if len(data) < 8 {
		return ""
	}
	upper := bytes.ToUpper(data[:min(len(data), 12)])
	valid := false
	for _, method := range [][]byte{
		[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
		[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	} {
		if bytes.HasPrefix(upper, method) {
			valid = true
			break
		}
	}
	if !valid {
		return ""
	}
	for _, line := range strings.Split(string(data), "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sniffTLSHost(data []byte) string {
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLength < 4 || len(data) < 5+recordLength {
		return ""
	}
	handshake := data[5 : 5+recordLength]
	if len(handshake) < 42 || handshake[0] != 0x01 {
		return ""
	}
	pos := 4 + 2 + 32
	if pos >= len(handshake) {
		return ""
	}
	sessionLength := int(handshake[pos])
	pos += 1 + sessionLength
	if pos+2 > len(handshake) {
		return ""
	}
	cipherLength := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2 + cipherLength
	if pos >= len(handshake) {
		return ""
	}
	compressionLength := int(handshake[pos])
	pos += 1 + compressionLength
	if pos+2 > len(handshake) {
		return ""
	}
	extensionsLength := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2
	end := min(len(handshake), pos+extensionsLength)
	for pos+4 <= end {
		typeID := binary.BigEndian.Uint16(handshake[pos : pos+2])
		length := int(binary.BigEndian.Uint16(handshake[pos+2 : pos+4]))
		pos += 4
		if pos+length > end {
			return ""
		}
		if typeID == 0 && length >= 5 {
			extension := handshake[pos : pos+length]
			listLength := int(binary.BigEndian.Uint16(extension[:2]))
			for item := 2; item+3 <= len(extension) && item < 2+listLength; {
				nameType := extension[item]
				nameLength := int(binary.BigEndian.Uint16(extension[item+1 : item+3]))
				item += 3
				if item+nameLength > len(extension) {
					return ""
				}
				if nameType == 0 {
					return string(extension[item : item+nameLength])
				}
				item += nameLength
			}
		}
		pos += length
	}
	return ""
}
