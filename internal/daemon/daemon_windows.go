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

const (
	maxLogSize = 10 << 20
	logBackups = 3
)

// LogOutput uses stdout for an interactive client and a rotating file next to
// the executable for a client launched by the Windows service manager.
func LogOutput(name string) (io.WriteCloser, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return nil, fmt.Errorf("detect Windows service for logging: %w", err)
	}
	if !isService {
		return nopWriteCloser{os.Stdout}, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate executable for logging: %w", err)
	}
	return openRotatingFile(filepath.Join(filepath.Dir(executable), name), maxLogSize, logBackups)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

type rotatingFile struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	size    int64
	maxSize int64
	backups int
}

func openRotatingFile(path string, maxSize int64, backups int) (*rotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open service log: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat service log: %w", err)
	}
	return &rotatingFile{path: path, file: f, size: info.Size(), maxSize: maxSize, backups: backups}, nil
}

func (f *rotatingFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return 0, os.ErrClosed
	}
	if f.maxSize > 0 && f.size > 0 && f.size+int64(len(p)) > f.maxSize {
		// Rotation is best-effort. In particular, a log viewer on Windows may
		// temporarily deny a rename. rotate always restores a writable active
		// file, so the current record and later records must not be lost.
		rotateErr := f.rotate()
		if f.file == nil {
			return 0, rotateErr
		}
	}
	n, err := f.file.Write(p)
	f.size += int64(n)
	return n, err
}

func (f *rotatingFile) rotate() (err error) {
	// Whatever fails below, reopen the active generation before returning.
	defer func() {
		reopen, reopenErr := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if reopenErr != nil {
			if err == nil {
				err = reopenErr
			}
			return
		}
		f.file = reopen
		if info, statErr := reopen.Stat(); statErr == nil {
			f.size = info.Size()
		} else if err == nil {
			err = statErr
		}
	}()
	active := f.file
	f.file = nil
	if err := active.Close(); err != nil {
		return err
	}

	if f.backups > 0 {
		_ = os.Remove(fmt.Sprintf("%s.%d", f.path, f.backups))
		for generation := f.backups - 1; generation >= 1; generation-- {
			oldPath := fmt.Sprintf("%s.%d", f.path, generation)
			newPath := fmt.Sprintf("%s.%d", f.path, generation+1)
			if renameErr := os.Rename(oldPath, newPath); renameErr != nil && !os.IsNotExist(renameErr) {
				return renameErr
			}
		}
		if err := os.Rename(f.path, f.path+".1"); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
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
