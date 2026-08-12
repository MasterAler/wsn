package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MasterAler/wsn/internal/provision"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "init":
		initDeployment(os.Args[2:])
	case "add-client":
		addClient(os.Args[2:])
	case "revoke-client":
		revokeClient(os.Args[2:])
	case "list-clients":
		listClients(os.Args[2:])
	case "bundle":
		bundle(os.Args[2:])
	case "server-bundle":
		serverBundle(os.Args[2:])
	case "rotate-certificate":
		rotateCertificate(os.Args[2:])
	default:
		usage()
	}
}

func serverBundle(args []string) {
	flags := flag.NewFlagSet("server-bundle", flag.ExitOnError)
	directory := flags.String("state", "./wsn-state", "private deployment state directory")
	output := flags.String("output", "", "output .tar.gz")
	_ = flags.Parse(args)
	path, err := provision.ServerBundle(*directory, *output)
	must(err)
	fmt.Println("created private server bundle", path)
}

func rotateCertificate(args []string) {
	flags := flag.NewFlagSet("rotate-certificate", flag.ExitOnError)
	directory := flags.String("state", "./wsn-state", "private deployment state directory")
	_ = flags.Parse(args)
	must(provision.RotateCertificate(*directory))
	fmt.Println("rotated relay certificate; regenerate and deploy the server bundle")
}

func initDeployment(args []string) {
	flags := flag.NewFlagSet("init", flag.ExitOnError)
	directory := flags.String("state", "./wsn-state", "private deployment state directory")
	publicIP := flags.String("public-ip", "", "static relay IPv4 address")
	overlay := flags.String("overlay", "", "non-overlapping overlay IPv4 CIDR")
	gateway := flags.String("gateway", "", "gateway address inside the overlay")
	_ = flags.Parse(args)
	must(provision.Init(provision.InitOptions{Directory: *directory, PublicIP: *publicIP, Overlay: *overlay, Gateway: *gateway}))
	fingerprint, err := provision.Fingerprint(*directory + "/relay-ca.crt")
	must(err)
	fmt.Printf("initialized %s\nrelay CA public-key fingerprint: %s\n", *directory, fingerprint)
}

func addClient(args []string) {
	flags := flag.NewFlagSet("add-client", flag.ExitOnError)
	directory := flags.String("state", "./wsn-state", "private deployment state directory")
	id := flags.String("id", "", "unique client identity")
	osName := flags.String("os", "linux", "linux or windows")
	role := flags.String("role", "client", "client or gateway")
	address := flags.String("address", "", "overlay IPv4 address without prefix")
	device := flags.String("device", "", "TAP device name")
	routes := flags.String("routes", "", "comma-separated corporate destination CIDRs")
	egress := flags.String("egress", "", "gateway corporate egress interface")
	_ = flags.Parse(args)
	client, err := provision.AddClient(provision.AddOptions{
		Directory: *directory, ID: *id, OS: *osName, Role: *role, Address: *address,
		Device: *device, Routes: splitList(*routes), Egress: *egress,
	})
	must(err)
	fmt.Printf("added %s (%s, %s, %s)\n", client.ID, client.OS, client.Address, client.MAC)
}

func revokeClient(args []string) {
	flags := flag.NewFlagSet("revoke-client", flag.ExitOnError)
	directory := flags.String("state", "./wsn-state", "private deployment state directory")
	id := flags.String("id", "", "client identity")
	_ = flags.Parse(args)
	must(provision.RevokeClient(*directory, *id))
	fmt.Println("revoked", *id)
}

func listClients(args []string) {
	flags := flag.NewFlagSet("list-clients", flag.ExitOnError)
	directory := flags.String("state", "./wsn-state", "private deployment state directory")
	_ = flags.Parse(args)
	clients, err := provision.List(*directory)
	must(err)
	for _, client := range clients {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", client.ID, client.OS, client.Role, client.Address, client.MAC)
	}
}

func bundle(args []string) {
	flags := flag.NewFlagSet("bundle", flag.ExitOnError)
	directory := flags.String("state", "./wsn-state", "private deployment state directory")
	id := flags.String("id", "", "client identity")
	binary := flags.String("client-binary", "", "matching wsn-client release binary")
	tapInstaller := flags.String("tap-installer", "", "official signed TAP-Windows installer")
	tapctl := flags.String("tapctl", "", "official tapctl.exe")
	output := flags.String("output", "", "output .zip or .tar.gz")
	_ = flags.Parse(args)
	path, err := provision.Bundle(provision.BundleOptions{
		Directory: *directory, ID: *id, ClientBinary: *binary,
		TapInstaller: *tapInstaller, Tapctl: *tapctl, Output: *output,
	})
	must(err)
	fmt.Println("created private bundle", path)
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wsnctl <init|add-client|revoke-client|list-clients|bundle|server-bundle|rotate-certificate> [options]")
	os.Exit(2)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "wsnctl:", err)
		os.Exit(1)
	}
}
