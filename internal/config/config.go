package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const DefaultMaxFrameSize = 2048

type RelayClient struct {
	ID  string `json:"id"`
	Key string `json:"key"`
	MAC string `json:"mac"`
}

type Relay struct {
	Listen               string        `json:"listen"`
	Path                 string        `json:"path"`
	HealthPath           string        `json:"health_path"`
	MaxFrameSize         int           `json:"max_frame_size"`
	ClientQueueSize      int           `json:"client_queue_size"`
	HandshakeTimeoutMS   int           `json:"handshake_timeout_ms"`
	IdleTimeoutMS        int           `json:"idle_timeout_ms"`
	MaxPendingHandshakes int           `json:"max_pending_handshakes"`
	Clients              []RelayClient `json:"clients"`
}

type Client struct {
	Server       string   `json:"server"`
	CAFile       string   `json:"ca_file"`
	ID           string   `json:"id"`
	KeyFile      string   `json:"key_file"`
	Device       string   `json:"device"`
	MAC          string   `json:"mac"`
	Address      string   `json:"address"`
	Gateway      string   `json:"gateway"`
	Routes       []string `json:"routes"`
	MaxFrameSize int      `json:"max_frame_size"`
}

func LoadRelay(path string) (Relay, error) {
	var cfg Relay
	if err := loadJSON(path, &cfg); err != nil {
		return Relay{}, err
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}
	if cfg.Path == "" {
		cfg.Path = "/wsn"
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = "/healthz"
	}
	if cfg.MaxFrameSize == 0 {
		cfg.MaxFrameSize = DefaultMaxFrameSize
	}
	if cfg.ClientQueueSize == 0 {
		cfg.ClientQueueSize = 256
	}
	if cfg.HandshakeTimeoutMS == 0 {
		cfg.HandshakeTimeoutMS = 10000
	}
	if cfg.IdleTimeoutMS == 0 {
		cfg.IdleTimeoutMS = 90000
	}
	if cfg.MaxPendingHandshakes == 0 {
		cfg.MaxPendingHandshakes = 32
	}
	if !strings.HasPrefix(cfg.Path, "/") || !strings.HasPrefix(cfg.HealthPath, "/") {
		return Relay{}, errors.New("relay paths must begin with /")
	}
	if cfg.Path == cfg.HealthPath {
		return Relay{}, errors.New("relay path and health path must differ")
	}
	if cfg.MaxFrameSize < 64 || cfg.MaxFrameSize > 65535 {
		return Relay{}, errors.New("max_frame_size must be between 64 and 65535")
	}
	if cfg.ClientQueueSize < 1 || cfg.ClientQueueSize > 65536 {
		return Relay{}, errors.New("client_queue_size must be between 1 and 65536")
	}
	if cfg.MaxPendingHandshakes < 1 || cfg.MaxPendingHandshakes > 4096 {
		return Relay{}, errors.New("max_pending_handshakes must be between 1 and 4096")
	}
	if cfg.HandshakeTimeoutMS < 1000 || cfg.HandshakeTimeoutMS > 60000 {
		return Relay{}, errors.New("handshake_timeout_ms must be between 1000 and 60000")
	}
	if cfg.IdleTimeoutMS < 10000 || cfg.IdleTimeoutMS > 3600000 {
		return Relay{}, errors.New("idle_timeout_ms must be between 10000 and 3600000")
	}
	ids := make(map[string]struct{}, len(cfg.Clients))
	macs := make(map[string]struct{}, len(cfg.Clients))
	for i := range cfg.Clients {
		client := &cfg.Clients[i]
		if err := ValidateID(client.ID); err != nil {
			return Relay{}, fmt.Errorf("clients[%d]: %w", i, err)
		}
		if _, exists := ids[client.ID]; exists {
			return Relay{}, fmt.Errorf("duplicate client id %q", client.ID)
		}
		ids[client.ID] = struct{}{}
		if _, err := DecodeKey(client.Key); err != nil {
			return Relay{}, fmt.Errorf("client %q: %w", client.ID, err)
		}
		mac, err := ParseMAC(client.MAC)
		if err != nil {
			return Relay{}, fmt.Errorf("client %q: %w", client.ID, err)
		}
		normalized := mac.String()
		if _, exists := macs[normalized]; exists {
			return Relay{}, fmt.Errorf("duplicate client mac %q", normalized)
		}
		macs[normalized] = struct{}{}
		client.MAC = normalized
	}
	return cfg, nil
}

func LoadClient(path string) (Client, error) {
	var cfg Client
	if err := loadJSON(path, &cfg); err != nil {
		return Client{}, err
	}
	if err := ValidateID(cfg.ID); err != nil {
		return Client{}, err
	}
	if cfg.Server == "" || !strings.HasPrefix(cfg.Server, "wss://") {
		return Client{}, errors.New("server must use wss://")
	}
	if cfg.CAFile == "" || cfg.KeyFile == "" || cfg.Device == "" {
		return Client{}, errors.New("ca_file, key_file, and device are required")
	}
	if !filepath.IsAbs(cfg.CAFile) || !filepath.IsAbs(cfg.KeyFile) {
		return Client{}, errors.New("ca_file and key_file must be absolute paths")
	}
	mac, err := ParseMAC(cfg.MAC)
	if err != nil {
		return Client{}, err
	}
	cfg.MAC = mac.String()
	address, err := netip.ParsePrefix(cfg.Address)
	if err != nil || !address.Addr().Is4() {
		return Client{}, errors.New("address must be an IPv4 prefix")
	}
	gateway, err := netip.ParseAddr(cfg.Gateway)
	if err != nil || !gateway.Is4() {
		return Client{}, errors.New("gateway must be an IPv4 address")
	}
	if !address.Masked().Contains(gateway) {
		return Client{}, errors.New("gateway must be inside the overlay prefix")
	}
	for _, route := range cfg.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil || !prefix.Addr().Is4() {
			return Client{}, fmt.Errorf("invalid IPv4 route %q", route)
		}
		if prefixesOverlap(address.Masked(), prefix.Masked()) {
			return Client{}, fmt.Errorf("route %q overlaps overlay %q", route, address.Masked())
		}
	}
	if cfg.MaxFrameSize == 0 {
		cfg.MaxFrameSize = DefaultMaxFrameSize
	}
	if cfg.MaxFrameSize < 64 || cfg.MaxFrameSize > 65535 {
		return Client{}, errors.New("max_frame_size must be between 64 and 65535")
	}
	return cfg, nil
}

func LoadKey(path string) ([]byte, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeKey(strings.TrimSpace(string(contents)))
}

func DecodeKey(value string) ([]byte, error) {
	key, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, errors.New("key must be unpadded base64")
	}
	if len(key) != 32 {
		return nil, errors.New("key must decode to exactly 32 bytes")
	}
	return key, nil
}

func EncodeKey(key []byte) string { return base64.RawStdEncoding.EncodeToString(key) }

func ValidateID(id string) error {
	if len(id) < 1 || len(id) > 64 {
		return errors.New("client id must contain 1-64 characters")
	}
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return errors.New("client id may contain only letters, digits, '.', '-', and '_'")
	}
	return nil
}

func ParseMAC(value string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return nil, errors.New("mac must be a six-byte Ethernet address")
	}
	if mac[0]&1 != 0 {
		return nil, errors.New("mac must be unicast")
	}
	return mac, nil
}

func SaveJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".wsn-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func loadJSON(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("decode %s: trailing data", path)
	}
	return nil
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}
