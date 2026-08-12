//go:build windows

package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows/svc"
)

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
