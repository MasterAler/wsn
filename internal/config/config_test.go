package config

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRelayRejectsDuplicateIdentityAndMAC(t *testing.T) {
	key := EncodeKey(bytes.Repeat([]byte{7}, 32))
	tests := []Relay{
		{Clients: []RelayClient{{ID: "a", Key: key, MAC: "02:00:00:00:00:01"}, {ID: "a", Key: key, MAC: "02:00:00:00:00:02"}}},
		{Clients: []RelayClient{{ID: "a", Key: key, MAC: "02:00:00:00:00:01"}, {ID: "b", Key: key, MAC: "02:00:00:00:00:01"}}},
	}
	for _, cfg := range tests {
		path := filepath.Join(t.TempDir(), "relay.json")
		if err := SaveJSON(path, cfg, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRelay(path); err == nil {
			t.Fatal("invalid duplicate configuration accepted")
		}
	}
}

func TestClientRejectsRouteOverlappingOverlay(t *testing.T) {
	directory := t.TempDir()
	cfg := Client{
		Server: "wss://203.0.113.1/wsn", CAFile: "/etc/wsn/ca.crt", KeyFile: "/etc/wsn/key",
		ID: "alice", Device: "wsn0", MAC: "02:00:00:00:00:01", Address: "100.96.1.2/24",
		Gateway: "100.96.1.1", Routes: []string{"100.96.1.128/25"},
	}
	path := filepath.Join(directory, "client.json")
	if err := SaveJSON(path, cfg, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClient(path); err == nil {
		t.Fatal("overlapping route accepted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// NTFS does not carry Unix permission bits, so Windows always reports 0666
	// here. The mode still matters on the platforms that enforce it.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected mode %o", info.Mode().Perm())
	}
}
