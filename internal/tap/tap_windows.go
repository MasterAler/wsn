//go:build windows

package tap

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	networkClassID  = "{4d36e972-e325-11ce-bfc1-08002be10318}"
	networkClassKey = `SYSTEM\CurrentControlSet\Control\Class\` + networkClassID
	networkKey      = `SYSTEM\CurrentControlSet\Control\Network\` + networkClassID
	tapComponentID  = "tap0901"
	tapSetMedia     = uint32((0x22 << 16) | (6 << 2))
)

type windowsDevice struct {
	file *os.File
	name string
}

func (d *windowsDevice) Name() string                { return d.name }
func (d *windowsDevice) Read(p []byte) (int, error)  { return d.file.Read(p) }
func (d *windowsDevice) Write(p []byte) (int, error) { return d.file.Write(p) }
func (d *windowsDevice) Close() error                { return d.file.Close() }

func open(name string) (Device, error) {
	guid, err := findAdapter(name)
	if err != nil {
		return nil, err
	}
	path, err := windows.UTF16PtrFromString(`\\.\Global\` + guid + `.tap`)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_SYSTEM, 0)
	if err != nil {
		return nil, fmt.Errorf("open TAP adapter %s: %w", name, err)
	}
	status := uint32(1)
	var returned uint32
	if err := windows.DeviceIoControl(handle, tapSetMedia, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), nil, 0, &returned, nil); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("enable TAP media: %w", err)
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap TAP adapter handle")
	}
	return &windowsDevice{file: file, name: name}, nil
}

func findAdapter(wanted string) (string, error) {
	class, err := registry.OpenKey(registry.LOCAL_MACHINE, networkClassKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("open network adapter registry: %w", err)
	}
	defer class.Close()
	names, err := class.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}
	for _, subkeyName := range names {
		subkey, err := registry.OpenKey(class, subkeyName, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		componentID, _, _ := subkey.GetStringValue("ComponentId")
		guid, _, _ := subkey.GetStringValue("NetCfgInstanceId")
		subkey.Close()
		if !strings.EqualFold(componentID, tapComponentID) || guid == "" {
			continue
		}
		connection, err := registry.OpenKey(registry.LOCAL_MACHINE, networkKey+`\`+guid+`\Connection`, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		friendlyName, _, _ := connection.GetStringValue("Name")
		connection.Close()
		if strings.EqualFold(wanted, friendlyName) || strings.EqualFold(wanted, guid) {
			return guid, nil
		}
	}
	return "", fmt.Errorf("TAP-Windows adapter %q not found", wanted)
}
