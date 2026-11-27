package main

import (
	"encoding/hex"
	mrand "math/rand"
	"regexp"
	"strconv"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// expandCPS fills a CPS chain the way amneziawg-go does, with zero bytes in
// place of the random tags.
func expandCPS(t *testing.T, chain string) []byte {
	t.Helper()
	var out []byte
	for _, tag := range regexp.MustCompile(`<(b 0x[0-9a-f]*|r \d+|rc \d+|rd \d+)>`).FindAllStringSubmatch(chain, -1) {
		switch value := tag[1]; {
		case value[0] == 'b':
			decoded, err := hex.DecodeString(value[4:])
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, decoded...)
		default:
			_, count, _ := cutSpace(value)
			n, err := strconv.Atoi(count)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, make([]byte, n)...)
		}
	}
	return out
}

func cutSpace(s string) (string, string, bool) {
	for i := range s {
		if s[i] == ' ' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func TestDNSAnswerI1IsAValidResponse(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	for range 50 {
		chain, err := genDNSAnswerI1(rng, "www.apple.com")
		if err != nil {
			t.Fatal(err)
		}
		var parser dnsmessage.Parser
		header, err := parser.Start(expandCPS(t, chain))
		if err != nil {
			t.Fatal(err)
		}
		if !header.Response || header.RCode != dnsmessage.RCodeSuccess {
			t.Fatalf("header %+v", header)
		}
		question, err := parser.Question()
		if err != nil || question.Name.String() != "www.apple.com." || question.Type != dnsmessage.TypeA {
			t.Fatalf("question %+v: %v", question, err)
		}
		_ = parser.SkipAllQuestions()
		answers, err := parser.AllAnswers()
		if err != nil || len(answers) < 1 || len(answers) > dnsAnswersMax {
			t.Fatalf("%d answers: %v", len(answers), err)
		}
		for _, answer := range answers {
			if answer.Header.Type != dnsmessage.TypeA || answer.Header.Name.String() != "www.apple.com." {
				t.Fatalf("answer %+v", answer.Header)
			}
		}
	}
}
