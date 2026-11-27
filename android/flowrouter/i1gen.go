package main

// AmneziaWG I1 (CPS) generators. Ported from WARPSCOUT
// (https://github.com/vernette/warpscout, internal/warpscout/i1gen.go and
// quic.go, MIT License, Copyright (c) 2026 Nikita S.).
//
// Every generator returns a CPS chain: <b 0x..> keeps bytes as they are,
// <r N>/<rc N>/<rd N> are filled by amneziawg-go with fresh random bytes,
// letters or digits for every handshake, so one chain yields a different
// datagram each time while keeping the protocol framing intact.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"strings"
)

// Hosts used as the visible name inside generated decoys. They only need to be
// names every network already sees in bulk.
var i1Hosts = []string{
	"www.apple.com",
	"www.google.com",
	"www.microsoft.com",
	"cdn.jsdelivr.net",
}

type cpsChain struct {
	sb strings.Builder
}

func (c *cpsChain) bytes(b []byte) {
	if len(b) > 0 {
		fmt.Fprintf(&c.sb, "<b 0x%x>", b)
	}
}

func (c *cpsChain) text(s string) {
	c.bytes([]byte(s))
}

func (c *cpsChain) tag(name string, n int) {
	fmt.Fprintf(&c.sb, "<%s %d>", name, n)
}

func (c *cpsChain) String() string {
	return c.sb.String()
}

func randRange(rng *mrand.Rand, lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + rng.Intn(hi-lo+1)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return b
}

const (
	dnsLabelMax     = 63
	dnsPadMin       = 60
	dnsPadMax       = 180
	stunSoftwareMin = 16
	stunSoftwareMax = 32
)

// genDNSI1 builds a standard A query plus an EDNS0 OPT record whose padding
// option (RFC 7830) carries the random bytes, so the packet stays well formed.
func genDNSI1(rng *mrand.Rand, host string) (string, error) {
	qname, err := dnsName(host)
	if err != nil {
		return "", err
	}
	question := append(qname, 0, 1, 0, 1)

	padLen := randRange(rng, dnsPadMin, dnsPadMax)
	opt := []byte{0}                               // root name
	opt = binary.BigEndian.AppendUint16(opt, 41)   // OPT
	opt = binary.BigEndian.AppendUint16(opt, 4096) // UDP payload size
	opt = append(opt, 0, 0, 0, 0)                  // extended rcode and flags
	opt = binary.BigEndian.AppendUint16(opt, uint16(padLen+4))
	opt = binary.BigEndian.AppendUint16(opt, 12) // padding option
	opt = binary.BigEndian.AppendUint16(opt, uint16(padLen))

	c := &cpsChain{}
	c.tag("r", 2) // transaction id
	c.bytes([]byte{0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1})
	c.bytes(question)
	c.bytes(opt)
	c.tag("r", padLen)
	return c.String(), nil
}

const (
	dnsAnswersMax = 4
	dnsTTLMin     = 60
	dnsTTLMax     = 3600
)

// genDNSAnswerI1 builds a DNS response to an A query for host: one to
// dnsAnswersMax A records, each pointing back at the question name, with
// addresses and the transaction id random for every handshake. A response
// is the other half of the most common UDP exchange there is (the idea comes
// from Amnezia VPN's default I1, a DNS answer).
func genDNSAnswerI1(rng *mrand.Rand, host string) (string, error) {
	qname, err := dnsName(host)
	if err != nil {
		return "", err
	}
	answers := randRange(rng, 1, dnsAnswersMax)
	header := []byte{0x81, 0x80, 0, 1} // response, recursion desired and available; one question
	header = binary.BigEndian.AppendUint16(header, uint16(answers))
	header = append(header, 0, 0, 0, 0)

	c := &cpsChain{}
	c.tag("r", 2) // transaction id
	c.bytes(header)
	c.bytes(append(qname, 0, 1, 0, 1))
	ttl := uint32(randRange(rng, dnsTTLMin, dnsTTLMax))
	for range answers {
		record := []byte{0xc0, 0x0c, 0, 1, 0, 1} // name pointer to the question, A, IN
		record = binary.BigEndian.AppendUint32(record, ttl)
		record = binary.BigEndian.AppendUint16(record, 4)
		c.bytes(record)
		c.tag("r", 4) // address
	}
	return c.String(), nil
}

func dnsName(host string) ([]byte, error) {
	var out []byte
	for _, label := range strings.Split(strings.Trim(host, "."), ".") {
		if label == "" || len(label) > dnsLabelMax {
			return nil, fmt.Errorf("bad DNS label %q in %q", label, host)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

func genSIPI1(rng *mrand.Rand, host string) (string, error) {
	c := &cpsChain{}
	c.text("OPTIONS sip:" + host + " SIP/2.0\r\n")
	c.text(fmt.Sprintf("Via: SIP/2.0/UDP 192.168.%d.%d:5060;branch=z9hG4bK", randRange(rng, 0, 255), randRange(rng, 2, 254)))
	c.tag("rc", 10)
	c.text("\r\nFrom: <sip:")
	c.tag("rc", 8)
	c.text("@" + host + ">;tag=")
	c.tag("rd", 6)
	c.text("\r\nTo: <sip:" + host + ">\r\nCall-ID: ")
	c.tag("rc", 16)
	c.text("@" + host + "\r\nCSeq: ")
	c.tag("rd", 4)
	c.text(" OPTIONS\r\nMax-Forwards: 70\r\nUser-Agent: PJSIP/2.13\r\nContent-Length: 0\r\n\r\n")
	return c.String(), nil
}

func genSTUNI1(rng *mrand.Rand, _ string) (string, error) {
	softwareLen := randRange(rng, stunSoftwareMin/4, stunSoftwareMax/4) * 4
	attrLen := 4 + softwareLen

	c := &cpsChain{}
	header := binary.BigEndian.AppendUint16(nil, 0x0001) // Binding Request
	header = binary.BigEndian.AppendUint16(header, uint16(attrLen))
	header = binary.BigEndian.AppendUint32(header, 0x2112A442) // magic cookie
	c.bytes(header)
	c.tag("r", 12) // transaction id
	software := binary.BigEndian.AppendUint16(nil, 0x8022)
	software = binary.BigEndian.AppendUint16(software, uint16(softwareLen))
	c.bytes(software)
	c.tag("rc", softwareLen)
	return c.String(), nil
}

const (
	quicVersion1     = 1
	quicTagLen       = 16
	quicHelloRandLen = 32
	quicSampleEnd    = 20
	tlsHandshakeHead = 6
)

var quicInitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// genQUICI1 builds a real, correctly protected QUIC v1 Initial carrying a TLS
// ClientHello for sni, then marks the ClientHello random and the AEAD tag as
// random so every handshake sends a fresh-looking Initial.
func genQUICI1(_ *mrand.Rand, sni string) (string, error) {
	dcid := randomBytes(1)
	pkn := []byte{0}
	hello := tlsClientHello(sni)
	payload := quicCryptoFrame(hello)

	packet, headerLen, err := quicInitialPacket(dcid, pkn, payload)
	if err != nil {
		return "", err
	}
	parts := quicCutParts(len(payload)-len(hello), len(hello), len(pkn), headerLen)
	return quicToCPS(packet, parts), nil
}

func quicInitialPacket(dcid, pkn, payload []byte) ([]byte, int, error) {
	header := []byte{0xC0 | byte(len(pkn)-1)}
	header = binary.BigEndian.AppendUint32(header, quicVersion1)
	header = append(header, quicStr8(dcid)...)
	header = append(header, 0, 0) // empty SCID, empty token
	header = append(header, quicVarint(len(pkn)+len(payload)+quicTagLen)...)
	header = append(header, pkn...)
	headerLen := len(header)

	key, iv, hp := quicInitialKeys(dcid)
	for i := range pkn {
		iv[len(iv)-len(pkn)+i] ^= pkn[i]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	ciphertext := gcm.Seal(nil, iv, payload, header)

	mask, err := quicHeaderMask(hp, ciphertext[4-len(pkn):quicSampleEnd-len(pkn)])
	if err != nil {
		return nil, 0, err
	}
	header[0] ^= mask[0] & 0x0f
	for i := range pkn {
		header[headerLen-len(pkn)+i] ^= mask[1+i]
	}
	return append(header, ciphertext...), headerLen, nil
}

func quicInitialKeys(dcid []byte) (key, iv, hp []byte) {
	initial := quicHMAC(quicInitialSalt, dcid)
	client := quicExpandLabel(initial, "client in", sha256.Size)
	return quicExpandLabel(client, "quic key", 16),
		quicExpandLabel(client, "quic iv", 12),
		quicExpandLabel(client, "quic hp", 16)
}

// quicExpandLabel is HKDF-Expand-Label truncated to one HMAC block; every QUIC
// Initial secret fits in it.
func quicExpandLabel(secret []byte, label string, length int) []byte {
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, quicStr8([]byte("tls13 "+label))...)
	info = append(info, 0, 1)
	return quicHMAC(secret, info)[:length]
}

func quicHMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func quicHeaderMask(hp, sample []byte) ([]byte, error) {
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, aes.BlockSize)
	block.Encrypt(mask, sample)
	return mask, nil
}

func quicCryptoFrame(data []byte) []byte {
	frame := []byte{0x06}
	frame = append(frame, quicVarint(0)...)
	frame = append(frame, quicVarint(len(data))...)
	return append(frame, data...)
}

func tlsClientHello(sni string) []byte {
	name := []byte(sni)
	serverName := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
	serverName = append(serverName, 0)
	serverName = binary.BigEndian.AppendUint16(serverName, uint16(len(name)))
	serverName = append(serverName, name...)

	ext := binary.BigEndian.AppendUint16(nil, 0) // server_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(serverName)))
	ext = append(ext, serverName...)

	body := []byte{0x03, 0x03}
	body = append(body, randomBytes(quicHelloRandLen)...)
	body = append(body, 0, 0, 0, 0) // no session id, no cipher suites, no compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hello := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hello, body...)
}

// quicCutParts returns alternating keep/randomize byte counts over the finished
// packet. The static prefix must cover the header protection sample, so the
// first cut never starts before ciphertext byte 20-len(pkn).
func quicCutParts(frameHeaderLen, helloLen, pknLen, headerLen int) []int {
	keep := frameHeaderLen + tlsHandshakeHead
	randomized := quicHelloRandLen
	if short := quicSampleEnd - pknLen - keep; short > 0 {
		keep += short
		randomized -= short
	}
	return []int{headerLen + keep, randomized, helloLen - tlsHandshakeHead - quicHelloRandLen, quicTagLen}
}

func quicToCPS(packet []byte, parts []int) string {
	c := &cpsChain{}
	offset, keep := 0, true
	for _, n := range parts {
		if n > 0 && keep {
			c.bytes(packet[offset : offset+n])
		} else if n > 0 {
			c.tag("r", n)
		}
		offset += n
		keep = !keep
	}
	return c.String()
}

func quicVarint(x int) []byte {
	switch {
	case x < 0x40:
		return []byte{byte(x)}
	case x < 0x4000:
		b := binary.BigEndian.AppendUint16(nil, uint16(x))
		b[0] |= 0x40
		return b
	default:
		b := binary.BigEndian.AppendUint32(nil, uint32(x))
		b[0] |= 0x80
		return b
	}
}

func quicStr8(b []byte) []byte {
	return append([]byte{byte(len(b))}, b...)
}
