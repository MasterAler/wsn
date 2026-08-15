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

// LogOutput reports where this daemon's logs belong. The false result marks
// stdout as an interactive stream rather than a dedicated service log.
func LogOutput(_ string) (io.WriteCloser, bool, error) {
	return nopWriteCloser{os.Stdout}, false, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
