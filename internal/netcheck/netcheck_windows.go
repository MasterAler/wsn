//go:build windows

package netcheck

import (
	"errors"

	"github.com/MasterAler/wsn/internal/config"
)

func Client(config.Client) error {
	return errors.New("Windows route validation is performed by install-windows.ps1")
}

func Gateway(config.Client, string) error {
	return errors.New("Windows cannot be provisioned as a WSN gateway")
}
