//go:build windows

package tap

import (
	"errors"
	"fmt"
	"strings"
	"sync"
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

// windowsDevice drives the TAP handle with overlapped I/O, which is a
// correctness requirement rather than a tuning choice. The I/O manager
// serializes every operation on a file object opened for synchronous I/O, and
// the client runs two pumps against this one device: one blocked in Read
// waiting for the machine to transmit, one writing frames arriving from the
// relay. Synchronously, the pending read holds the file object for as long as
// nothing is being sent, so inbound frames are delivered only as fast as this
// machine happens to produce outbound ones. Overlapped, the two run
// independently.
type windowsDevice struct {
	handle windows.Handle
	name   string

	readMu  sync.Mutex
	read    operation
	writeMu sync.Mutex
	write   operation

	closeOnce sync.Once
}

// operation holds the OVERLAPPED for one direction. Each direction has a single
// pump goroutine and reuses its structure, so only one request per direction is
// ever in flight; the mutexes make that a guarantee rather than an assumption.
type operation struct {
	overlapped windows.Overlapped
}

func (o *operation) init() error {
	// Manual reset and initially unsignaled. The two directions must not share
	// an event, or a completed read would release a write that is still pending.
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("create TAP completion event: %w", err)
	}
	o.overlapped.HEvent = event
	return nil
}

func (o *operation) close() {
	if o.overlapped.HEvent != 0 {
		windows.CloseHandle(o.overlapped.HEvent)
		o.overlapped.HEvent = 0
	}
}

func (d *windowsDevice) Name() string { return d.name }

// await runs one overlapped request to completion. The buffer and the
// OVERLAPPED stay live for the whole call, so the request may pend safely.
func (d *windowsDevice) await(op *operation, start func(*windows.Overlapped, *uint32) error) (int, error) {
	if err := windows.ResetEvent(op.overlapped.HEvent); err != nil {
		return 0, err
	}
	var done uint32
	err := start(&op.overlapped, &done)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		err = windows.GetOverlappedResult(d.handle, &op.overlapped, &done, true)
	}
	if err != nil {
		return int(done), err
	}
	return int(done), nil
}

func (d *windowsDevice) Read(p []byte) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	return d.await(&d.read, func(overlapped *windows.Overlapped, done *uint32) error {
		return windows.ReadFile(d.handle, p, done, overlapped)
	})
}

func (d *windowsDevice) Write(p []byte) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.await(&d.write, func(overlapped *windows.Overlapped, done *uint32) error {
		return windows.WriteFile(d.handle, p, done, overlapped)
	})
}

func (d *windowsDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		// Cancel before taking the locks. A read waiting for the next outbound
		// frame holds readMu until the driver completes it, which may never
		// happen on an idle machine; CancelIoEx completes it as aborted and
		// releases the pump. Only then is it safe to close what it was using.
		windows.CancelIoEx(d.handle, nil)
		d.readMu.Lock()
		defer d.readMu.Unlock()
		d.writeMu.Lock()
		defer d.writeMu.Unlock()
		err = windows.CloseHandle(d.handle)
		d.read.close()
		d.write.close()
	})
	return err
}

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
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_SYSTEM|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, fmt.Errorf("open TAP adapter %s: %w", name, err)
	}
	device := &windowsDevice{handle: handle, name: name}
	if err := device.read.init(); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	if err := device.write.init(); err != nil {
		device.read.close()
		windows.CloseHandle(handle)
		return nil, err
	}
	// An overlapped handle needs an OVERLAPPED here too: given none, the I/O
	// manager may report a control request complete before the driver has
	// finished it.
	status := uint32(1)
	if _, err := device.await(&device.write, func(overlapped *windows.Overlapped, done *uint32) error {
		return windows.DeviceIoControl(handle, tapSetMedia,
			(*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), nil, 0, done, overlapped)
	}); err != nil {
		device.Close()
		return nil, fmt.Errorf("enable TAP media: %w", err)
	}
	return device, nil
}

// isTapComponent recognizes both spellings of the TAP-Windows component. An
// adapter created by tapctl is root-enumerated and registers as "root\tap0901",
// while the driver's own installer registers a plain "tap0901". Bundles always
// create theirs with tapctl, so matching only the latter finds no adapter at all.
func isTapComponent(componentID string) bool {
	return strings.TrimPrefix(strings.ToLower(componentID), `root\`) == tapComponentID
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
		if !isTapComponent(componentID) || guid == "" {
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
