//go:build linux

package netcheck

import (
	"net/netip"
	"testing"

	"github.com/MasterAler/wsn/internal/config"
)

func TestGatewayRejectsHistoricalRangeOverlappingDocker(t *testing.T) {
	cfg := config.Client{
		Device: "wsn0", Routes: []string{"172.16.0.0/12"},
	}
	routes := []systemRoute{
		{prefix: netip.MustParsePrefix("0.0.0.0/0"), interfaceName: "eth0"},
		{prefix: netip.MustParsePrefix("172.19.102.0/24"), interfaceName: "eth0"},
		{prefix: netip.MustParsePrefix("172.17.0.0/16"), interfaceName: "docker0"},
	}
	if err := gatewayWithRoutes(cfg, "eth0", routes); err == nil {
		t.Fatal("gateway accepted a destination range overlapping docker0")
	}
	cfg.Routes = []string{"172.19.102.0/24"}
	if err := gatewayWithRoutes(cfg, "eth0", routes); err != nil {
		t.Fatalf("gateway rejected corporate route on expected egress: %v", err)
	}
}

func TestClientRejectsOverlayOverlappingHomeLAN(t *testing.T) {
	cfg := config.Client{Device: "wsn0", Address: "192.168.1.2/24"}
	routes := []systemRoute{{prefix: netip.MustParsePrefix("192.168.1.0/24"), interfaceName: "wlan0"}}
	if err := clientWithRoutes(cfg, routes); err == nil {
		t.Fatal("client accepted overlay overlapping local LAN")
	}
}

func TestNetMaskBits(t *testing.T) {
	if got := netMaskBits([4]byte{255, 255, 0, 0}); got != 16 {
		t.Fatalf("got %d", got)
	}
	if got := netMaskBits([4]byte{255, 0, 255, 0}); got != -1 {
		t.Fatalf("non-contiguous mask accepted: %d", got)
	}
}
