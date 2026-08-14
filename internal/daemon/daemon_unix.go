//go:build !windows

package daemon

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func Run(_ string, run func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}

// LogWriter reports where this daemon's logs belong. systemd captures stdout
// into the journal, so there is nothing to arrange.
func LogWriter(_ string) io.Writer { return os.Stdout }
