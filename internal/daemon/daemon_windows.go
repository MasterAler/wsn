//go:build windows

package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/windows/svc"
)

// maxLogBytes caps a generation of the log file. A healthy session logs a
// handful of lines, but a client that cannot reach its relay retries for as
// long as it runs, so the file needs a ceiling.
const maxLogBytes = 4 << 20

// LogOutput reports where this daemon's logs belong. Under the service control
// manager the process has no console and everything written to stdout is
// discarded, which leaves a service that misbehaves with no record of why. A
// service therefore logs beside its configuration; a foreground run keeps
// stdout, so an operator watching it sees the session directly.
// The boolean result identifies a dedicated service log, allowing startup
// diagnostics to be copied there without contaminating interactive stdout.
func LogOutput(dir string) (io.WriteCloser, bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return nil, false, fmt.Errorf("detect Windows service for logging: %w", err)
	}
	if !isService {
		return nopWriteCloser{os.Stdout}, false, nil
	}
	file, err := openRotatingFile(filepath.Join(dir, "client.log"), maxLogBytes)
	if err != nil {
		return nil, false, fmt.Errorf("open service log: %w", err)
	}
	return file, true, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// rotatingFile keeps one previous generation and starts a new one once the
// current generation reaches its limit.
type rotatingFile struct {
	mu    sync.Mutex
	path  string
	limit int64
	file  *os.File
	size  int64
}

func openRotatingFile(path string, limit int64) (*rotatingFile, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &rotatingFile{path: path, limit: limit, file: file, size: info.Size()}, nil
}

func (f *rotatingFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return 0, os.ErrClosed
	}
	if f.size > 0 && f.size+int64(len(p)) > f.limit {
		// Rotation is best-effort. A viewer can temporarily prevent Windows
		// from renaming a generation; rotate still restores an active handle.
		rotateErr := f.rotate()
		if f.file == nil {
			return 0, rotateErr
		}
	}
	n, err := f.file.Write(p)
	f.size += int64(n)
	return n, err
}

// rotate replaces the previous generation with the current one. Windows will
// not rename a file that is still open, so the handle is closed first.
func (f *rotatingFile) rotate() (err error) {
	active := f.file
	f.file = nil
	// Whatever fails below, restore a writable active generation.
	defer func() {
		file, reopenErr := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if reopenErr != nil {
			if err == nil {
				err = reopenErr
			}
			return
		}
		f.file = file
		if info, statErr := file.Stat(); statErr == nil {
			f.size = info.Size()
		} else if err == nil {
			err = statErr
		}
	}()
	if err := active.Close(); err != nil {
		return err
	}
	_ = os.Remove(f.path + ".1")
	if err := os.Rename(f.path, f.path+".1"); err != nil {
		return err
	}
	return nil
}

func (f *rotatingFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return nil
	}
	err := f.file.Close()
	f.file = nil
	return err
}

func Run(name string, run func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		ctx, stop := signal.NotifyContext(context.Background(), osInterruptSignals()...)
		defer stop()
		return run(ctx)
	}
	h := &handler{run: run}
	if err := svc.Run(name, h); err != nil {
		return fmt.Errorf("run Windows service: %w", err)
	}
	return h.err
}

func osInterruptSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }

type handler struct {
	run func(context.Context) error
	err error
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	status <- svc.Status{State: svc.StartPending}
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			h.err = err
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				h.err = <-done
				return false, 0
			}
		}
	}
}
