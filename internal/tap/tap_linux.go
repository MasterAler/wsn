//go:build linux

package tap

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type linuxDevice struct {
	*os.File
	name string
}

func (d *linuxDevice) Name() string { return d.name }

func open(name string) (Device, error) {
	if len(name) == 0 || len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("invalid TAP interface name %q", name)
	}
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var ifreq [unix.IFNAMSIZ + 64]byte
	copy(ifreq[:unix.IFNAMSIZ], name)
	*(*uint16)(unsafe.Pointer(&ifreq[unix.IFNAMSIZ])) = unix.IFF_TAP | unix.IFF_NO_PI
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifreq[0])))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("attach TAP %s: %w", name, errno)
	}
	return &linuxDevice{File: file, name: name}, nil
}
