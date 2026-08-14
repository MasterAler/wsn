//go:build windows

package tap

import "testing"

func TestIsTapComponent(t *testing.T) {
	// tapctl registers a root-enumerated adapter; the driver's own installer
	// registers a PnP one. Both must be recognized.
	for _, value := range []string{"tap0901", "TAP0901", `root\tap0901`, `ROOT\TAP0901`} {
		if !isTapComponent(value) {
			t.Errorf("isTapComponent(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"", "ovpn-dco", "wintun", "tap0801", `root\wintun`, `root\`} {
		if isTapComponent(value) {
			t.Errorf("isTapComponent(%q) = true, want false", value)
		}
	}
}
