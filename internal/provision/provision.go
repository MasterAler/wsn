package provision

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MasterAler/wsn/internal/config"
)

//go:embed assets/*
var assets embed.FS

type State struct {
	Version  int                 `json:"version"`
	PublicIP string              `json:"public_ip"`
	Overlay  string              `json:"overlay"`
	Gateway  string              `json:"gateway"`
	DNS      string              `json:"dns,omitempty"`
	Search   []string            `json:"search,omitempty"`
	Clients  []ProvisionedClient `json:"clients"`
}

type ProvisionedClient struct {
	ID      string   `json:"id"`
	OS      string   `json:"os"`
	Role    string   `json:"role"`
	Address string   `json:"address"`
	MAC     string   `json:"mac"`
	Key     string   `json:"key"`
	Device  string   `json:"device"`
	Routes  []string `json:"routes"`
	Egress  string   `json:"egress,omitempty"`
}

type InitOptions struct {
	Directory string
	PublicIP  string
	Overlay   string
	Gateway   string
	DNS       string
	Search    []string
}

type AddOptions struct {
	Directory string
	ID        string
	OS        string
	Role      string
	Address   string
	Device    string
	Routes    []string
	Egress    string
}

type BundleOptions struct {
	Directory    string
	ID           string
	ClientBinary string
	TapInstaller string
	Tapctl       string
	Output       string
}

func Init(options InitOptions) error {
	if _, err := os.Stat(filepath.Join(options.Directory, "state.json")); err == nil {
		return errors.New("deployment state already exists")
	}
	publicIP, err := netip.ParseAddr(options.PublicIP)
	if err != nil || !publicIP.Is4() {
		return errors.New("public-ip must be an IPv4 address")
	}
	overlay, err := netip.ParsePrefix(options.Overlay)
	if err != nil || !overlay.Addr().Is4() || overlay != overlay.Masked() || overlay.Bits() > 30 {
		return errors.New("overlay must be a canonical IPv4 prefix with at least two usable addresses")
	}
	gateway, err := netip.ParseAddr(options.Gateway)
	if err != nil || !usableAddress(overlay, gateway) {
		return errors.New("gateway must be a usable address inside overlay")
	}
	dns, search, err := normalizeResolver(options.DNS, options.Search, overlay)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(options.Directory, 0700); err != nil {
		return err
	}
	state := State{
		Version: 1, PublicIP: publicIP.String(), Overlay: overlay.String(),
		Gateway: gateway.String(), DNS: dns, Search: search,
	}
	if err := config.SaveJSON(filepath.Join(options.Directory, "state.json"), state, 0600); err != nil {
		return err
	}
	if err := generateCertificates(options.Directory, publicIP); err != nil {
		return err
	}
	return writeRelayConfig(options.Directory, state)
}

func AddClient(options AddOptions) (ProvisionedClient, error) {
	state, err := loadState(options.Directory)
	if err != nil {
		return ProvisionedClient{}, err
	}
	if err := config.ValidateID(options.ID); err != nil {
		return ProvisionedClient{}, err
	}
	if options.OS != "linux" && options.OS != "windows" {
		return ProvisionedClient{}, errors.New("os must be linux or windows")
	}
	if options.Role == "" {
		options.Role = "client"
	}
	if options.Role != "client" && options.Role != "gateway" {
		return ProvisionedClient{}, errors.New("role must be client or gateway")
	}
	if options.Role == "gateway" && options.OS != "linux" {
		return ProvisionedClient{}, errors.New("gateway role requires linux")
	}
	if options.Role == "gateway" && options.Egress == "" {
		return ProvisionedClient{}, errors.New("gateway role requires egress interface")
	}
	overlay, _ := netip.ParsePrefix(state.Overlay)
	address, err := normalizeAddress(options.Address, overlay)
	if err != nil {
		return ProvisionedClient{}, err
	}
	for _, existing := range state.Clients {
		if existing.ID == options.ID {
			return ProvisionedClient{}, fmt.Errorf("client %q already exists", options.ID)
		}
		if existing.Address == address.String() {
			return ProvisionedClient{}, fmt.Errorf("address %q is already assigned", address)
		}
		if options.Role == "gateway" && existing.Role == "gateway" {
			return ProvisionedClient{}, errors.New("deployment already has a gateway client")
		}
	}
	gatewayAddress, _ := netip.ParseAddr(state.Gateway)
	if options.Role == "gateway" && address.Addr() != gatewayAddress {
		return ProvisionedClient{}, errors.New("gateway client must use the configured gateway address")
	}
	if options.Role != "gateway" && address.Addr() == gatewayAddress {
		return ProvisionedClient{}, errors.New("regular client cannot use the configured gateway address")
	}
	routes, err := normalizeRoutes(options.Routes, overlay)
	if err != nil {
		return ProvisionedClient{}, err
	}
	if options.Role == "gateway" && len(routes) == 0 {
		return ProvisionedClient{}, errors.New("gateway requires at least one corporate destination route")
	}
	// A resolver that no route reaches would silently break name resolution
	// for this client instead of failing at provisioning time. The gateway is
	// exempt: it sits on the corporate network and keeps its own resolver.
	if state.DNS != "" && options.Role != "gateway" {
		resolver, _ := netip.ParseAddr(state.DNS)
		reachable := false
		for _, route := range routes {
			prefix, _ := netip.ParsePrefix(route)
			if prefix.Contains(resolver) {
				reachable = true
				break
			}
		}
		if !reachable {
			return ProvisionedClient{}, fmt.Errorf(
				"corporate DNS server %s is not inside any route of this client; add the CIDR containing it to -routes", state.DNS)
		}
	}
	if options.Device == "" {
		if options.OS == "windows" {
			options.Device = "WSN-" + options.ID
		} else {
			options.Device = "wsn0"
		}
	}
	if !safeInterfaceName(options.Device) {
		return ProvisionedClient{}, errors.New("device contains unsupported characters")
	}
	if options.OS == "linux" && len(options.Device) >= 16 {
		return ProvisionedClient{}, errors.New("Linux TAP device name must be shorter than 16 bytes")
	}
	if options.Egress != "" && !safeInterfaceName(options.Egress) {
		return ProvisionedClient{}, errors.New("egress contains unsupported characters")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return ProvisionedClient{}, err
	}
	mac, err := randomMAC()
	if err != nil {
		return ProvisionedClient{}, err
	}
	client := ProvisionedClient{
		ID: options.ID, OS: options.OS, Role: options.Role,
		Address: address.String(), MAC: mac.String(), Key: config.EncodeKey(key),
		Device: options.Device, Routes: routes, Egress: options.Egress,
	}
	state.Clients = append(state.Clients, client)
	sort.Slice(state.Clients, func(i, j int) bool { return state.Clients[i].ID < state.Clients[j].ID })
	if err := saveState(options.Directory, state); err != nil {
		return ProvisionedClient{}, err
	}
	if err := writeRelayConfig(options.Directory, state); err != nil {
		return ProvisionedClient{}, err
	}
	return client, nil
}

func RevokeClient(directory, id string) error {
	state, err := loadState(directory)
	if err != nil {
		return err
	}
	result := state.Clients[:0]
	found := false
	for _, client := range state.Clients {
		if client.ID == id {
			found = true
			continue
		}
		result = append(result, client)
	}
	if !found {
		return fmt.Errorf("client %q does not exist", id)
	}
	state.Clients = result
	if err := saveState(directory, state); err != nil {
		return err
	}
	return writeRelayConfig(directory, state)
}

func List(directory string) ([]ProvisionedClient, error) {
	state, err := loadState(directory)
	return state.Clients, err
}

func Bundle(options BundleOptions) (string, error) {
	state, err := loadState(options.Directory)
	if err != nil {
		return "", err
	}
	var selected *ProvisionedClient
	for i := range state.Clients {
		if state.Clients[i].ID == options.ID {
			selected = &state.Clients[i]
			break
		}
	}
	if selected == nil {
		return "", fmt.Errorf("client %q does not exist", options.ID)
	}
	if options.ClientBinary == "" {
		return "", errors.New("client-binary is required")
	}
	if selected.OS == "windows" && (options.TapInstaller == "" || options.Tapctl == "") {
		return "", errors.New("Windows bundles require tap-installer and tapctl")
	}
	if err := verifyClientBinary(options.ClientBinary, selected.OS); err != nil {
		return "", err
	}
	temp, err := os.MkdirTemp("", "wsn-bundle-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temp)
	if err := renderBundle(temp, state, *selected, options); err != nil {
		return "", err
	}
	if options.Output == "" {
		if selected.OS == "windows" {
			options.Output = selected.ID + "-windows.zip"
		} else {
			options.Output = selected.ID + "-linux.tar.gz"
		}
	}
	if selected.OS == "windows" {
		err = zipDirectory(temp, options.Output)
	} else {
		err = tarDirectory(temp, options.Output)
	}
	if err != nil {
		return "", err
	}
	return options.Output, nil
}

type EnrollOptions struct {
	AddOptions
	ClientBinary string
	TapInstaller string
	Tapctl       string
	Output       string
	ServerOutput string
}

type EnrollResult struct {
	Client       ProvisionedClient
	ClientBundle string
	ServerBundle string
}

// Enroll adds a client, builds its private bundle, and refreshes the server
// bundle in one step, so the three artefacts can never drift apart. A client
// whose bundle cannot be built is rolled back out of the deployment state
// rather than left half-provisioned.
func Enroll(options EnrollOptions) (EnrollResult, error) {
	client, err := AddClient(options.AddOptions)
	if err != nil {
		return EnrollResult{}, err
	}
	clientBundle, err := Bundle(BundleOptions{
		Directory: options.Directory, ID: client.ID, ClientBinary: options.ClientBinary,
		TapInstaller: options.TapInstaller, Tapctl: options.Tapctl, Output: options.Output,
	})
	if err != nil {
		if revokeErr := RevokeClient(options.Directory, client.ID); revokeErr != nil {
			return EnrollResult{}, fmt.Errorf("%w (rolling back %s also failed: %v)", err, client.ID, revokeErr)
		}
		return EnrollResult{}, err
	}
	serverBundle, err := ServerBundle(options.Directory, options.ServerOutput)
	if err != nil {
		return EnrollResult{}, err
	}
	return EnrollResult{Client: client, ClientBundle: clientBundle, ServerBundle: serverBundle}, nil
}

func ServerBundle(directory, output string) (string, error) {
	if _, err := loadState(directory); err != nil {
		return "", err
	}
	if output == "" {
		output = "wsn-server-private.tar.gz"
	}
	temp, err := os.MkdirTemp("", "wsn-server-bundle-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temp)
	for _, file := range []struct {
		name string
		mode os.FileMode
	}{{"server.json", 0600}, {"relay.crt", 0644}, {"relay.key", 0600}} {
		if err := copyFile(filepath.Join(directory, file.name), filepath.Join(temp, file.name), file.mode); err != nil {
			return "", err
		}
	}
	if err := tarDirectory(temp, output); err != nil {
		return "", err
	}
	return output, nil
}

func RotateCertificate(directory string) error {
	state, err := loadState(directory)
	if err != nil {
		return err
	}
	publicIP, err := netip.ParseAddr(state.PublicIP)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(filepath.Join(directory, "relay-ca.crt"))
	if err != nil {
		return err
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return errors.New("invalid relay CA certificate")
	}
	caCertificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(directory, "relay-ca.key"))
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("invalid relay CA private key")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	caPrivate, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return errors.New("unsupported relay CA private key type")
	}
	return generateLeafCertificate(directory, publicIP, caCertificate, caPrivate)
}

func renderBundle(directory string, state State, client ProvisionedClient, options BundleOptions) error {
	ca, err := os.ReadFile(filepath.Join(options.Directory, "relay-ca.crt"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "relay-ca.crt"), ca, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "client.key"), []byte(client.Key+"\n"), 0600); err != nil {
		return err
	}
	// These paths name locations on the target host, so they must use the
	// target's separator. filepath.Join uses the separator of whichever machine
	// wsnctl runs on, so a Linux bundle built on Windows got \etc\wsn\... which
	// LoadClient then rejects on the client as a relative path.
	configPath := "/etc/wsn"
	separator := "/"
	binaryName := "wsn-client"
	if client.OS == "windows" {
		configPath = `C:\ProgramData\WSN`
		separator = `\`
		binaryName += ".exe"
	}
	clientConfig := config.Client{
		Server: "wss://" + state.PublicIP + "/wsn",
		CAFile: configPath + separator + "relay-ca.crt",
		ID:     client.ID, KeyFile: configPath + separator + "client.key", Device: client.Device,
		MAC: client.MAC, Address: client.Address, Gateway: state.Gateway, Routes: client.Routes,
		MaxFrameSize: config.DefaultMaxFrameSize,
	}
	if err := config.SaveJSON(filepath.Join(directory, "client.json"), clientConfig, 0600); err != nil {
		return err
	}
	clientHash, err := fileSHA256(options.ClientBinary)
	if err != nil {
		return err
	}
	caFingerprint, err := Fingerprint(filepath.Join(options.Directory, "relay-ca.crt"))
	if err != nil {
		return err
	}
	// The gateway already sits on the corporate network and resolves through
	// its own resolver; pointing it at the corporate DNS server across the
	// overlay would route replies back through itself.
	resolver := state.DNS
	searchDomains := state.Search
	if client.Role == "gateway" {
		resolver = ""
		searchDomains = nil
	}
	meta := map[string]any{
		"id": client.ID, "role": client.Role, "device": client.Device, "mac": client.MAC,
		"address": client.Address, "gateway": state.Gateway, "overlay": state.Overlay,
		"routes": client.Routes, "egress": client.Egress, "client_sha256": clientHash,
		"dns": resolver, "search": searchDomains, "ca_sha256": caFingerprint,
	}
	if client.OS == "windows" {
		tapHash, err := fileSHA256(options.TapInstaller)
		if err != nil {
			return err
		}
		tapctlHash, err := fileSHA256(options.Tapctl)
		if err != nil {
			return err
		}
		meta["tap_driver_sha256"] = tapHash
		meta["tapctl_sha256"] = tapctlHash
	}
	if err := config.SaveJSON(filepath.Join(directory, "bundle.json"), meta, 0644); err != nil {
		return err
	}
	networkRoutes := client.Routes
	if client.Role == "gateway" {
		networkRoutes = nil
	}
	networkEnvironment := fmt.Sprintf(
		"WSN_DEVICE='%s'\nWSN_MAC='%s'\nWSN_ADDRESS='%s'\nWSN_GATEWAY='%s'\nWSN_ROUTES='%s'\nWSN_DNS='%s'\nWSN_SEARCH='%s'\n",
		client.Device, client.MAC, client.Address, state.Gateway,
		strings.Join(networkRoutes, " "), resolver, strings.Join(searchDomains, " "))
	if err := os.WriteFile(filepath.Join(directory, "network.env"), []byte(networkEnvironment), 0644); err != nil {
		return err
	}
	// Shipped as plain text so the Linux installer can display it without a
	// JSON parser; the recipient compares it with the value wsnctl init
	// printed on the administrator machine.
	if err := os.WriteFile(filepath.Join(directory, "ca-fingerprint.txt"), []byte(caFingerprint+"\n"), 0644); err != nil {
		return err
	}
	if client.Role == "gateway" {
		gatewayEnvironment := fmt.Sprintf("WSN_DEVICE='%s'\nWSN_OVERLAY='%s'\nWSN_EGRESS='%s'\nWSN_DESTINATIONS='%s'\n",
			client.Device, state.Overlay, client.Egress, strings.Join(client.Routes, " "))
		if err := os.WriteFile(filepath.Join(directory, "gateway.env"), []byte(gatewayEnvironment), 0644); err != nil {
			return err
		}
	}
	if err := copyFile(options.ClientBinary, filepath.Join(directory, binaryName), 0755); err != nil {
		return err
	}
	assetNames := []string{"install-linux.sh", "uninstall-linux.sh", "upgrade-linux.sh", "rollback-linux.sh", "wsn-net.sh", "wsn-client.service", "wsn-net.service"}
	if client.OS == "windows" {
		assetNames = []string{"install-windows.ps1", "uninstall-windows.ps1", "upgrade-windows.ps1", "rollback-windows.ps1", "wsn-toggle.ps1"}
		if err := copyFile(options.TapInstaller, filepath.Join(directory, "tap-driver.exe"), 0644); err != nil {
			return err
		}
		if err := copyFile(options.Tapctl, filepath.Join(directory, "tapctl.exe"), 0755); err != nil {
			return err
		}
	}
	if client.Role == "gateway" {
		assetNames = append(assetNames, "wsn-gateway.sh", "wsn-gateway.service")
	}
	for _, name := range assetNames {
		contents, err := assets.ReadFile("assets/" + name)
		if err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".ps1") {
			mode = 0755
		}
		if !strings.HasSuffix(name, ".ps1") {
			contents = toUnixNewlines(contents)
		}
		if err := os.WriteFile(filepath.Join(directory, name), contents, mode); err != nil {
			return err
		}
	}
	return nil
}

// toUnixNewlines strips CR so scripts and unit files run on the target. go:embed
// captures the working tree byte for byte, so a Windows checkout with
// core.autocrlf=true embeds CRLF, and "#!/bin/sh\r" makes Linux report the
// interpreter as missing. .gitattributes pins LF; this keeps a bundle correct
// even when it is built from a tree that was checked out some other way.
func toUnixNewlines(contents []byte) []byte {
	return bytes.ReplaceAll(contents, []byte("\r\n"), []byte("\n"))
}

func generateCertificates(directory string, publicIP netip.Addr) error {
	now := time.Now().Add(-5 * time.Minute)
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caSerial, err := randomSerial()
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial, Subject: pkix.Name{CommonName: "WSN deployment CA"},
		NotBefore: now, NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(directory, "relay-ca.crt"), "CERTIFICATE", caDER, 0644); err != nil {
		return err
	}
	caKey, err := x509.MarshalPKCS8PrivateKey(caPrivate)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(directory, "relay-ca.key"), "PRIVATE KEY", caKey, 0600); err != nil {
		return err
	}
	return generateLeafCertificate(directory, publicIP, caTemplate, caPrivate)
}

func generateLeafCertificate(directory string, publicIP netip.Addr, caCertificate *x509.Certificate, caPrivate ed25519.PrivateKey) error {
	now := time.Now().Add(-5 * time.Minute)
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	leafSerial, err := randomSerial()
	if err != nil {
		return err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "WSN relay"},
		NotBefore: now, NotAfter: now.AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP(publicIP.String())},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, leafPublic, caPrivate)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(directory, "relay.crt"), "CERTIFICATE", leafDER, 0644); err != nil {
		return err
	}
	leafKey, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		return err
	}
	return writePEM(filepath.Join(directory, "relay.key"), "PRIVATE KEY", leafKey, 0600)
}

func writeRelayConfig(directory string, state State) error {
	clients := make([]config.RelayClient, 0, len(state.Clients))
	for _, client := range state.Clients {
		clients = append(clients, config.RelayClient{ID: client.ID, Key: client.Key, MAC: client.MAC})
	}
	relay := config.Relay{
		Listen: "0.0.0.0:8080", Path: "/wsn", HealthPath: "/healthz",
		MaxFrameSize: config.DefaultMaxFrameSize, ClientQueueSize: 256,
		HandshakeTimeoutMS: 10000, IdleTimeoutMS: 90000, MaxPendingHandshakes: 32, Clients: clients,
	}
	return config.SaveJSON(filepath.Join(directory, "server.json"), relay, 0600)
}

func normalizeAddress(value string, overlay netip.Prefix) (netip.Prefix, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !usableAddress(overlay, address) {
		return netip.Prefix{}, errors.New("address must be a usable IPv4 address inside overlay")
	}
	return netip.PrefixFrom(address, overlay.Bits()), nil
}

func usableAddress(prefix netip.Prefix, address netip.Addr) bool {
	if !address.Is4() || !prefix.Contains(address) || address == prefix.Addr() {
		return false
	}
	addressBytes := address.As4()
	networkBytes := prefix.Addr().As4()
	addressValue := binary.BigEndian.Uint32(addressBytes[:])
	networkValue := binary.BigEndian.Uint32(networkBytes[:])
	mask := uint32(0)
	if prefix.Bits() > 0 {
		mask = ^uint32(0) << (32 - prefix.Bits())
	}
	broadcast := networkValue | ^mask
	return addressValue != broadcast
}

// normalizeResolver validates the optional corporate DNS server and its search
// domains. Both are required together: a resolver without routing domains has
// no well-defined split-DNS behaviour on either platform.
func normalizeResolver(value string, domains []string, overlay netip.Prefix) (string, []string, error) {
	resolver := strings.TrimSpace(value)
	search, err := normalizeSearchDomains(domains)
	if err != nil {
		return "", nil, err
	}
	if resolver == "" {
		if len(search) > 0 {
			return "", nil, errors.New("search domains require a dns server")
		}
		return "", nil, nil
	}
	address, err := netip.ParseAddr(resolver)
	if err != nil || !address.Is4() {
		return "", nil, errors.New("dns must be an IPv4 address")
	}
	if overlay.Contains(address) {
		return "", nil, errors.New("dns must be a corporate address outside the overlay")
	}
	if len(search) == 0 {
		return "", nil, errors.New("dns requires at least one search domain")
	}
	return address.String(), search, nil
}

func normalizeSearchDomains(values []string) ([]string, error) {
	unique := make(map[string]struct{})
	for _, value := range values {
		domain := strings.Trim(strings.TrimSpace(value), ".")
		if domain == "" {
			continue
		}
		if !safeDomainName(domain) {
			return nil, fmt.Errorf("invalid DNS search domain %q", value)
		}
		unique[strings.ToLower(domain)] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for domain := range unique {
		result = append(result, domain)
	}
	sort.Strings(result)
	return result, nil
}

func safeDomainName(value string) bool {
	if len(value) < 1 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// verifyClientBinary rejects a client binary built for the wrong operating
// system. The installers only compare SHA-256 hashes, so a mismatched binary
// installs cleanly and then fails when the service starts, with an error that
// points nowhere near the actual mistake.
func verifyClientBinary(path, operatingSystem string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	header := make([]byte, 4)
	if _, err := io.ReadFull(file, header); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	switch operatingSystem {
	case "linux":
		if !bytes.Equal(header, []byte{0x7f, 'E', 'L', 'F'}) {
			return fmt.Errorf("%s is not a Linux ELF binary", path)
		}
	case "windows":
		if header[0] != 'M' || header[1] != 'Z' {
			return fmt.Errorf("%s is not a Windows PE binary", path)
		}
	}
	return nil
}

func normalizeRoutes(values []string, overlay netip.Prefix) ([]string, error) {
	unique := make(map[string]struct{})
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return nil, fmt.Errorf("invalid canonical IPv4 route %q", value)
		}
		if prefixesOverlap(prefix, overlay) {
			return nil, fmt.Errorf("route %q overlaps overlay %q", prefix, overlay)
		}
		unique[prefix.String()] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for route := range unique {
		result = append(result, route)
	}
	sort.Strings(result)
	return result, nil
}

func randomMAC() (net.HardwareAddr, error) {
	mac := make(net.HardwareAddr, 6)
	if _, err := rand.Read(mac); err != nil {
		return nil, err
	}
	mac[0] = (mac[0] | 2) & 0xfe
	return mac, nil
}

func randomSerial() (*big.Int, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	serial := new(big.Int).SetBytes(value)
	if serial.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return serial, nil
}

func loadState(directory string) (State, error) {
	var state State
	data, err := os.ReadFile(filepath.Join(directory, "state.json"))
	if err != nil {
		return State{}, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	if state.Version != 1 {
		return State{}, errors.New("unsupported deployment state version")
	}
	return state, nil
}

func saveState(directory string, state State) error {
	return config.SaveJSON(filepath.Join(directory, "state.json"), state, 0600)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), mode)
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func zipDirectory(directory, output string) error {
	file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	archive := zip.NewWriter(file)
	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		header := &zip.FileHeader{Name: entry.Name(), Method: zip.Deflate}
		header.SetMode(0600)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := writer.Write(data); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	return file.Close()
}

func tarDirectory(directory, output string) error {
	file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(file)
	archive := tar.NewWriter(gz)
	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		header, _ := tar.FileInfoHeader(info, "")
		header.Name = entry.Name()
		// The bundle targets Linux even when wsnctl is running on Windows, where
		// staged files do not retain POSIX execute or owner-only permission bits.
		// Set target permissions from the bundle contract rather than copying
		// host filesystem metadata into the archive.
		header.Mode = linuxArchiveMode(entry.Name())
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		if _, err := archive.Write(data); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return file.Close()
}

func linuxArchiveMode(name string) int64 {
	if name == "wsn-client" || strings.HasSuffix(name, ".sh") {
		return 0755
	}
	switch name {
	case "client.json", "client.key", "server.json", "relay.key":
		return 0600
	default:
		return 0644
	}
}

func prefixesOverlap(a, b netip.Prefix) bool { return a.Contains(b.Addr()) || b.Contains(a.Addr()) }

func safeInterfaceName(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func Fingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("invalid PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}
