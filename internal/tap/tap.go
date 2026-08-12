package tap

import "io"

type Device interface {
	io.ReadWriteCloser
	Name() string
}

func Open(name string) (Device, error) { return open(name) }
