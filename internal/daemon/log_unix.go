//go:build !windows

package daemon

import (
	"io"
	"os"
)

// LogOutput returns the normal process output outside Windows services.
func LogOutput(_ string) (io.WriteCloser, error) {
	return nopWriteCloser{os.Stdout}, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
