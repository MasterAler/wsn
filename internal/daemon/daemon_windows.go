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

// LogWriter reports where this daemon's logs belong. Under the service control
// manager the process has no console and everything written to stdout is
// discarded, which leaves a service that misbehaves with no record of why. A
// service therefore logs beside its configuration; a foreground run keeps
// stdout, so an operator watching it sees the session directly.
func LogWriter(dir string) io.Writer {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return os.Stdout
	}
	file, err := openRotatingFile(filepath.Join(dir, "client.log"), maxLogBytes)
	if err != nil {
		// Being unable to record the logs is not a reason to refuse to run.
		return os.Stdout
	}
	return file
}

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
	if f.size+int64(len(p)) > f.limit {
		if err := f.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := f.file.Write(p)
	f.size += int64(n)
	return n, err
}

// rotate replaces the previous generation with the current one. Windows will
// not rename a file that is still open, so the handle is closed first.
func (f *rotatingFile) rotate() error {
	if err := f.file.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.path, f.path+".1"); err != nil {
		return err
	}
	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	f.file = file
	f.size = 0
	return nil
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
