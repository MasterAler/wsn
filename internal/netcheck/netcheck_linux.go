//go:build linux

package netcheck

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/MasterAler/wsn/internal/config"
)

type systemRoute struct {
	prefix        netip.Prefix
	interfaceName string
}

func Client(cfg config.Client) error {
	routes, err := systemRoutes()
	if err != nil {
		return err
	}
	return clientWithRoutes(cfg, routes)
}

func clientWithRoutes(cfg config.Client, routes []systemRoute) error {
	address, _ := netip.ParsePrefix(cfg.Address)
	targets := []netip.Prefix{address.Masked()}
	for _, value := range cfg.Routes {
		prefix, _ := netip.ParsePrefix(value)
		targets = append(targets, prefix.Masked())
	}
	for _, target := range targets {
		for _, existing := range routes {
			if existing.prefix.Bits() == 0 || existing.interfaceName == cfg.Device {
				continue
			}
			if overlap(target, existing.prefix) {
				return fmt.Errorf("configured network %s overlaps existing route %s on %s", target, existing.prefix, existing.interfaceName)
			}
		}
	}
	return nil
}

func Gateway(cfg config.Client, egress string) error {
	routes, err := systemRoutes()
	if err != nil {
		return err
	}
	return gatewayWithRoutes(cfg, egress, routes)
}

func gatewayWithRoutes(cfg config.Client, egress string, routes []systemRoute) error {
	overlay, _ := netip.ParsePrefix(cfg.Address)
	overlay = overlay.Masked()
	for _, existing := range routes {
		if existing.prefix.Bits() == 0 || existing.interfaceName == cfg.Device {
			continue
		}
		if overlap(overlay, existing.prefix) {
			return fmt.Errorf("configured network %s overlaps existing route %s on %s", overlay, existing.prefix, existing.interfaceName)
		}
	}
	for _, value := range cfg.Routes {
		target, _ := netip.ParsePrefix(value)
		for _, existing := range routes {
			if existing.prefix.Bits() == 0 || existing.interfaceName == egress || existing.interfaceName == cfg.Device {
				continue
			}
			if overlap(target, existing.prefix) {
				return fmt.Errorf("gateway destination %s overlaps route %s on %s instead of %s", target, existing.prefix, existing.interfaceName, egress)
			}
		}
	}
	return nil
}

func systemRoutes() ([]systemRoute, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		// Header.
	}
	var result []systemRoute
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		destination, err1 := strconv.ParseUint(fields[1], 16, 32)
		mask, err2 := strconv.ParseUint(fields[7], 16, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		addressBytes := [4]byte{}
		maskBytes := [4]byte{}
		binary.LittleEndian.PutUint32(addressBytes[:], uint32(destination))
		binary.LittleEndian.PutUint32(maskBytes[:], uint32(mask))
		bits := netMaskBits(maskBytes)
		if bits < 0 {
			continue
		}
		prefix := netip.PrefixFrom(netip.AddrFrom4(addressBytes), bits).Masked()
		result = append(result, systemRoute{prefix: prefix, interfaceName: fields[0]})
	}
	return result, scanner.Err()
}

func netMaskBits(mask [4]byte) int {
	bits := 0
	zeroSeen := false
	for _, value := range mask {
		for bit := 7; bit >= 0; bit-- {
			set := value&(1<<bit) != 0
			if zeroSeen && set {
				return -1
			}
			if set {
				bits++
			} else {
				zeroSeen = true
			}
		}
	}
	return bits
}

func overlap(a, b netip.Prefix) bool { return a.Contains(b.Addr()) || b.Contains(a.Addr()) }
