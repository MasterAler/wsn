package protocol

import (
	"bytes"
	"net"
	"testing"
)

func TestHelloRoundTrip(t *testing.T) {
	message, err := MarshalHello("alice.example")
	if err != nil {
		t.Fatal(err)
	}
	id, err := ParseHello(message)
	if err != nil {
		t.Fatal(err)
	}
	if id != "alice.example" {
		t.Fatalf("got %q", id)
	}
}

func TestProofBindsIdentityChallengeAndMAC(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	challenge := bytes.Repeat([]byte{2}, ChallengeSize)
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	proof, err := Proof(key, challenge, "alice", mac)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyProof(key, challenge, "alice", mac, proof) {
		t.Fatal("valid proof rejected")
	}
	if VerifyProof(key, challenge, "bob", mac, proof) {
		t.Fatal("proof accepted for another identity")
	}
	otherMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	if VerifyProof(key, challenge, "alice", otherMAC, proof) {
		t.Fatal("proof accepted for another MAC")
	}
	challenge[0]++
	if VerifyProof(key, challenge, "alice", mac, proof) {
		t.Fatal("replayed proof accepted for another challenge")
	}
}

func TestParseHelloRejectsMalformedInput(t *testing.T) {
	for _, input := range [][]byte{nil, {Version}, {1, 0, 1, 'a'}, {Version, 0, 2, 'a'}} {
		if _, err := ParseHello(input); err == nil {
			t.Fatalf("accepted %v", input)
		}
	}
}
