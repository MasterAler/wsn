package provision

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Bundle inspects the leading magic bytes, so fixtures must look like real
// executables for the platform they claim to target.
var (
	elfBinary = []byte("\x7fELF placeholder linux client")
	peBinary  = []byte("MZ placeholder windows client")
)

// A Linux bundle must carry POSIX paths no matter which OS wsnctl runs on. When
// these were built with filepath.Join, a bundle produced on a Windows
// administrator machine shipped "\etc\wsn\relay-ca.crt" and every Linux client
// refused to start with "ca_file and key_file must be absolute paths".
func TestLinuxBundleUsesPOSIXConfigPaths(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddClient(AddOptions{Directory: directory, ID: "bob", OS: "linux", Address: "100.96.42.3", Routes: []string{"10.5.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "wsn-client")
	if err := os.WriteFile(binary, elfBinary, 0755); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bob.tar.gz")
	if _, err := Bundle(BundleOptions{Directory: directory, ID: "bob", ClientBinary: binary, Output: output}); err != nil {
		t.Fatal(err)
	}
	clientJSON := readTarEntry(t, output, "client.json")
	if strings.Contains(clientJSON, `\\`) {
		t.Errorf("Linux client.json contains Windows separators:\n%s", clientJSON)
	}
	for _, want := range []string{`"ca_file": "/etc/wsn/relay-ca.crt"`, `"key_file": "/etc/wsn/client.key"`} {
		if !strings.Contains(clientJSON, want) {
			t.Errorf("Linux client.json missing %s:\n%s", want, clientJSON)
		}
	}
}

func readTarEntry(t *testing.T, archivePath, name string) string {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err != nil {
			t.Fatalf("%s not found in %s", name, archivePath)
		}
		if header.Name == name {
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		}
	}
}

func TestTarDirectorySetsLinuxModesIndependentOfHost(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"wsn-client", "install-linux.sh", "client.json", "client.key", "relay-ca.crt"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0666); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := tarDirectory(directory, output); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{
		"wsn-client": 0755, "install-linux.sh": 0755,
		"client.json": 0600, "client.key": 0600, "relay-ca.crt": 0644,
	}
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Mode != want[header.Name] {
			t.Errorf("%s mode = %#o, want %#o", header.Name, header.Mode, want[header.Name])
		}
		delete(want, header.Name)
	}
	for name := range want {
		t.Errorf("archive missing %s", name)
	}
}

// Bundled scripts and units must be LF whatever the build host did to the
// working tree: "#!/bin/sh\r" fails on Linux with "required file not found", so
// a CRLF install-linux.sh cannot even start.
func TestLinuxBundleShipsUnixNewlines(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddClient(AddOptions{
		Directory: directory, ID: "gw", OS: "linux", Role: "gateway", Address: "100.96.42.1",
		Egress: "eth0", Routes: []string{"10.5.0.0/16"},
	}); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "wsn-client")
	if err := os.WriteFile(binary, elfBinary, 0755); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "gw.tar.gz")
	if _, err := Bundle(BundleOptions{Directory: directory, ID: "gw", ClientBinary: binary, Output: output}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"install-linux.sh", "uninstall-linux.sh", "upgrade-linux.sh", "rollback-linux.sh",
		"wsn-net.sh", "wsn-gateway.sh",
		"wsn-client.service", "wsn-net.service", "wsn-gateway.service",
	} {
		contents := readTarEntry(t, output, name)
		if strings.Contains(contents, "\r") {
			t.Errorf("%s contains CR; it would not execute on Linux", name)
		}
	}
	if shebang := readTarEntry(t, output, "install-linux.sh"); !strings.HasPrefix(shebang, "#!/bin/sh\n") {
		t.Errorf("install-linux.sh has a broken shebang line: %q", firstLine(shebang))
	}
}

func firstLine(value string) string {
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		return value[:index+1]
	}
	return value
}

func TestProvisionDeploymentAndLinuxBundle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	client, err := AddClient(AddOptions{
		Directory: directory, ID: "alice", OS: "linux", Address: "100.96.42.2",
		Routes: []string{"10.5.0.0/16", "172.19.102.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.Address != "100.96.42.2/24" || client.MAC == "" || client.Key == "" {
		t.Fatalf("invalid client: %+v", client)
	}
	binary := filepath.Join(t.TempDir(), "wsn-client")
	if err := os.WriteFile(binary, elfBinary, 0755); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "alice.tar.gz")
	if _, err := Bundle(BundleOptions{Directory: directory, ID: "alice", ClientBinary: binary, Output: output}); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(gz)
	found := map[string]bool{}
	for {
		header, err := archive.Next()
		if err != nil {
			break
		}
		found[header.Name] = true
	}
	for _, name := range []string{"wsn-client", "client.json", "client.key", "relay-ca.crt", "install-linux.sh", "ca-fingerprint.txt"} {
		if !found[name] {
			t.Errorf("bundle missing %s", name)
		}
	}
}

func TestGatewayRequiresDestinations(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	_, err := AddClient(AddOptions{Directory: directory, ID: "gateway", OS: "linux", Role: "gateway", Address: "100.96.42.1", Egress: "eth0"})
	if err == nil {
		t.Fatal("gateway without destinations accepted")
	}
}

func TestGatewayMustUseReservedAddress(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	_, err := AddClient(AddOptions{
		Directory: directory, ID: "gateway", OS: "linux", Role: "gateway", Address: "100.96.42.2",
		Egress: "eth0", Routes: []string{"10.5.0.0/16"},
	})
	if err == nil {
		t.Fatal("gateway accepted a non-reserved address")
	}
}

func TestWindowsAndServerBundlesArePrivate(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddClient(AddOptions{Directory: directory, ID: "alice", OS: "windows", Address: "100.96.42.2", Routes: []string{"10.5.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	asset := filepath.Join(t.TempDir(), "asset.exe")
	if err := os.WriteFile(asset, peBinary, 0755); err != nil {
		t.Fatal(err)
	}
	windowsBundle := filepath.Join(t.TempDir(), "alice.zip")
	if _, err := Bundle(BundleOptions{Directory: directory, ID: "alice", ClientBinary: asset, TapInstaller: asset, Tapctl: asset, Output: windowsBundle}); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(windowsBundle)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	foundInstaller := false
	for _, file := range archive.File {
		if file.Name == "install-windows.ps1" {
			foundInstaller = true
		}
	}
	if !foundInstaller {
		t.Fatal("Windows bundle missing installer")
	}
	serverBundle := filepath.Join(t.TempDir(), "server.tar.gz")
	if _, err := ServerBundle(directory, serverBundle); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{windowsBundle, serverBundle} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		// NTFS does not carry Unix permission bits, so Windows always reports
		// 0666 here. The mode still matters on the platforms that enforce it.
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatalf("private bundle %s has mode %o", path, info.Mode().Perm())
		}
	}
}

func TestBundleRejectsBinaryBuiltForAnotherOS(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddClient(AddOptions{Directory: directory, ID: "alice", OS: "windows", Address: "100.96.42.2", Routes: []string{"10.5.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	linux := filepath.Join(t.TempDir(), "wsn-client")
	if err := os.WriteFile(linux, elfBinary, 0755); err != nil {
		t.Fatal(err)
	}
	_, err := Bundle(BundleOptions{
		Directory: directory, ID: "alice", ClientBinary: linux,
		TapInstaller: linux, Tapctl: linux, Output: filepath.Join(t.TempDir(), "alice.zip"),
	})
	if err == nil {
		t.Fatal("a Linux binary was accepted for a Windows client")
	}
}

func TestClientRoutesMustReachCorporateDNS(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{
		Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24",
		Gateway: "100.96.42.1", DNS: "10.0.0.53", Search: []string{"corp.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddClient(AddOptions{
		Directory: directory, ID: "unreachable", OS: "linux", Address: "100.96.42.2",
		Routes: []string{"10.5.0.0/16"},
	}); err == nil {
		t.Fatal("client whose routes exclude the DNS server was accepted")
	}
	if _, err := AddClient(AddOptions{
		Directory: directory, ID: "reachable", OS: "linux", Address: "100.96.42.3",
		Routes: []string{"10.0.0.0/16", "10.5.0.0/16"},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResolverRequiresSearchDomains(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	err := Init(InitOptions{
		Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24",
		Gateway: "100.96.42.1", DNS: "10.0.0.53",
	})
	if err == nil {
		t.Fatal("resolver without search domains accepted")
	}
}

func TestGatewayBundleOmitsOverlayResolver(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{
		Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24",
		Gateway: "100.96.42.1", DNS: "10.0.0.53", Search: []string{"corp.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddClient(AddOptions{
		Directory: directory, ID: "gateway", OS: "linux", Role: "gateway", Address: "100.96.42.1",
		Egress: "eth0", Routes: []string{"10.0.0.0/16"},
	}); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "wsn-client")
	if err := os.WriteFile(binary, elfBinary, 0755); err != nil {
		t.Fatal(err)
	}
	staging := t.TempDir()
	state, err := loadState(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := renderBundle(staging, state, state.Clients[0], BundleOptions{Directory: directory, ClientBinary: binary}); err != nil {
		t.Fatal(err)
	}
	environment, err := os.ReadFile(filepath.Join(staging, "network.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(environment), "WSN_DNS=''") {
		t.Fatalf("gateway network.env should not carry a resolver:\n%s", environment)
	}
}

func TestEnrollProducesClientAndServerBundles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "wsn-client")
	if err := os.WriteFile(binary, elfBinary, 0755); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	result, err := Enroll(EnrollOptions{
		AddOptions: AddOptions{
			Directory: directory, ID: "bob", OS: "linux", Address: "100.96.42.3",
			Routes: []string{"10.5.0.0/16"},
		},
		ClientBinary: binary,
		Output:       filepath.Join(output, "bob.tar.gz"),
		ServerOutput: filepath.Join(output, "server.tar.gz"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{result.ClientBundle, result.ServerBundle} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("enroll did not produce %s: %v", path, err)
		}
	}
}

func TestEnrollRollsBackAFailedBundle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(t.TempDir(), "wsn-client")
	if err := os.WriteFile(wrong, peBinary, 0755); err != nil {
		t.Fatal(err)
	}
	_, err := Enroll(EnrollOptions{
		AddOptions: AddOptions{
			Directory: directory, ID: "bob", OS: "linux", Address: "100.96.42.3",
			Routes: []string{"10.5.0.0/16"},
		},
		ClientBinary: wrong,
		Output:       filepath.Join(t.TempDir(), "bob.tar.gz"),
		ServerOutput: filepath.Join(t.TempDir(), "server.tar.gz"),
	})
	if err == nil {
		t.Fatal("enroll accepted a Windows binary for a Linux client")
	}
	clients, err := List(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 0 {
		t.Fatalf("failed enrolment left %d clients provisioned", len(clients))
	}
}

func TestRotateCertificateKeepsCAAndChangesLeaf(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Init(InitOptions{Directory: directory, PublicIP: "203.0.113.10", Overlay: "100.96.42.0/24", Gateway: "100.96.42.1"}); err != nil {
		t.Fatal(err)
	}
	caBefore, _ := os.ReadFile(filepath.Join(directory, "relay-ca.crt"))
	leafBefore, _ := os.ReadFile(filepath.Join(directory, "relay.crt"))
	time.Sleep(time.Millisecond)
	if err := RotateCertificate(directory); err != nil {
		t.Fatal(err)
	}
	caAfter, _ := os.ReadFile(filepath.Join(directory, "relay-ca.crt"))
	leafAfter, _ := os.ReadFile(filepath.Join(directory, "relay.crt"))
	if string(caBefore) != string(caAfter) {
		t.Fatal("CA changed during leaf rotation")
	}
	if string(leafBefore) == string(leafAfter) {
		t.Fatal("leaf certificate did not rotate")
	}
}
