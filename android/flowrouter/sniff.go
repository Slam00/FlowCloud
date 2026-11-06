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

const (
	tlsExtensionServerName = 0
	tlsExtensionEarlyData  = 42
)

// tlsClientHelloExtensions returns the extensions block of a complete
// ClientHello record, or ok=false when data is not one.
func tlsClientHelloExtensions(data []byte) ([]byte, bool) {
	if len(data) < 5 || data[0] != 0x16 {
		return nil, false
	}
	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLength < 4 || len(data) < 5+recordLength {
		return nil, false
	}
	handshake := data[5 : 5+recordLength]
	if len(handshake) < 42 || handshake[0] != 0x01 {
		return nil, false
	}
	pos := 4 + 2 + 32
	if pos >= len(handshake) {
		return nil, false
	}
	sessionLength := int(handshake[pos])
	pos += 1 + sessionLength
	if pos+2 > len(handshake) {
		return nil, false
	}
	cipherLength := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2 + cipherLength
	if pos >= len(handshake) {
		return nil, false
	}
	compressionLength := int(handshake[pos])
	pos += 1 + compressionLength
	if pos+2 > len(handshake) {
		// A ClientHello without extensions is still a ClientHello.
		return nil, pos <= len(handshake)
	}
	extensionsLength := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2
	end := min(len(handshake), pos+extensionsLength)
	return handshake[pos:end], true
}

// forEachTLSExtension calls visit for every well-formed extension until visit
// returns false. It returns false if the block is malformed.
func forEachTLSExtension(extensions []byte, visit func(typeID uint16, body []byte) bool) bool {
	pos := 0
	for pos+4 <= len(extensions) {
		typeID := binary.BigEndian.Uint16(extensions[pos : pos+2])
		length := int(binary.BigEndian.Uint16(extensions[pos+2 : pos+4]))
		pos += 4
		if pos+length > len(extensions) {
			return false
		}
		if !visit(typeID, extensions[pos:pos+length]) {
			return true
		}
		pos += length
	}
	return true
}

func isTLSClientHello(data []byte) bool {
	_, ok := tlsClientHelloExtensions(data)
	return ok
}

func tlsClientHelloHasExtension(data []byte, wanted uint16) bool {
	extensions, ok := tlsClientHelloExtensions(data)
	if !ok {
		return false
	}
	found := false
	forEachTLSExtension(extensions, func(typeID uint16, _ []byte) bool {
		found = typeID == wanted
		return !found
	})
	return found
}

func sniffTLSHost(data []byte) string {
	extensions, ok := tlsClientHelloExtensions(data)
	if !ok {
		return ""
	}
	host := ""
	valid := forEachTLSExtension(extensions, func(typeID uint16, extension []byte) bool {
		if typeID != tlsExtensionServerName || len(extension) < 5 {
			return true
		}
		listLength := int(binary.BigEndian.Uint16(extension[:2]))
		for item := 2; item+3 <= len(extension) && item < 2+listLength; {
			nameType := extension[item]
			nameLength := int(binary.BigEndian.Uint16(extension[item+1 : item+3]))
			item += 3
			if item+nameLength > len(extension) {
				return false
			}
			if nameType == 0 {
				host = string(extension[item : item+nameLength])
				return false
			}
			item += nameLength
		}
		return true
	})
	if !valid {
		return ""
	}
	return host
}
