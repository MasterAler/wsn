package provision

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
	if err := os.WriteFile(binary, []byte("test binary"), 0755); err != nil {
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
	for _, name := range []string{"wsn-client", "client.json", "client.key", "relay-ca.crt", "install-linux.sh"} {
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
	if err := os.WriteFile(asset, []byte("test asset"), 0755); err != nil {
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
		if info.Mode().Perm() != 0600 {
			t.Fatalf("private bundle %s has mode %o", path, info.Mode().Perm())
		}
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
