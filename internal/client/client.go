package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/MasterAler/wsn/internal/config"
	"github.com/MasterAler/wsn/internal/protocol"
	"github.com/MasterAler/wsn/internal/tap"
	"github.com/gorilla/websocket"
)

type Runner struct {
	cfg    config.Client
	key    []byte
	mac    net.HardwareAddr
	dialer websocket.Dialer
	log    *slog.Logger
}

func New(cfg config.Client, logger *slog.Logger) (*Runner, error) {
	key, err := config.LoadKey(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client key: %w", err)
	}
	mac, err := config.ParseMAC(cfg.MAC)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("load relay CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("relay CA file contains no valid certificate")
	}
	return &Runner{
		cfg: cfg,
		key: key,
		mac: mac,
		log: logger,
		dialer: websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 10 * time.Second,
			Subprotocols:     []string{protocol.Subprotocol},
			ReadBufferSize:   cfg.MaxFrameSize,
			WriteBufferSize:  cfg.MaxFrameSize,
			TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
		},
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		err := r.runSession(ctx)
		if ctx.Err() != nil {
			return nil
		}
		r.log.Warn("session ended; reconnecting", "error", err, "delay", backoff)
		jitter := time.Duration(rand.Int63n(int64(backoff/2 + 1)))
		timer := time.NewTimer(backoff + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (r *Runner) runSession(ctx context.Context) error {
	device, err := tap.Open(r.cfg.Device)
	if err != nil {
		return err
	}
	defer device.Close()
	conn, response, err := r.dialer.DialContext(ctx, r.cfg.Server, nil)
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("connect relay: %w", err)
	}
	defer conn.Close()
	if conn.Subprotocol() != protocol.Subprotocol {
		return errors.New("relay did not negotiate wsn-v2")
	}
	if err := r.authenticate(conn); err != nil {
		return err
	}
	r.log.Info("session connected", "server", r.cfg.Server, "id", r.cfg.ID, "device", device.Name(), "mac", r.mac.String())
	conn.SetReadLimit(int64(r.cfg.MaxFrameSize))
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	})
	errCh := make(chan error, 3)
	go r.tapToWebSocket(device, conn, errCh)
	go r.webSocketToTap(conn, device, errCh)
	go pingLoop(conn, errCh)
	select {
	case <-ctx.Done():
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "service stopping"),
			time.Now().Add(time.Second))
		return nil
	case err := <-errCh:
		return err
	}
}

func (r *Runner) authenticate(conn *websocket.Conn) error {
	hello, err := protocol.MarshalHello(r.cfg.ID)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteMessage(websocket.BinaryMessage, hello); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	messageType, challenge, err := conn.ReadMessage()
	if err != nil || messageType != websocket.BinaryMessage || len(challenge) != protocol.ChallengeSize {
		return errors.New("invalid relay challenge")
	}
	proof, err := protocol.Proof(r.key, challenge, r.cfg.ID, r.mac)
	if err != nil {
		return err
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, proof); err != nil {
		return fmt.Errorf("write proof: %w", err)
	}
	messageType, result, err := conn.ReadMessage()
	if err != nil || messageType != websocket.BinaryMessage || len(result) != 1 || result[0] != protocol.AuthOK {
		return errors.New("relay rejected authentication")
	}
	_ = conn.SetWriteDeadline(time.Time{})
	return nil
}

func (r *Runner) tapToWebSocket(device tap.Device, conn *websocket.Conn, errCh chan<- error) {
	buffer := make([]byte, r.cfg.MaxFrameSize+1)
	for {
		n, err := device.Read(buffer)
		if err != nil {
			errCh <- fmt.Errorf("read TAP: %w", err)
			return
		}
		if n < protocol.MinimumFrameSize || n > r.cfg.MaxFrameSize {
			errCh <- fmt.Errorf("invalid TAP frame size %d", n)
			return
		}
		if !equalMAC(protocol.SourceMAC(buffer[:n]), r.mac) {
			errCh <- fmt.Errorf("TAP source MAC differs from configured MAC")
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(websocket.BinaryMessage, buffer[:n]); err != nil {
			errCh <- fmt.Errorf("write relay: %w", err)
			return
		}
	}
}

func (r *Runner) webSocketToTap(conn *websocket.Conn, device tap.Device, errCh chan<- error) {
	for {
		messageType, frame, err := conn.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("read relay: %w", err)
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		if messageType != websocket.BinaryMessage || len(frame) < protocol.MinimumFrameSize || len(frame) > r.cfg.MaxFrameSize {
			errCh <- fmt.Errorf("invalid relay frame")
			return
		}
		if err := writeFull(device, frame); err != nil {
			errCh <- fmt.Errorf("write TAP: %w", err)
			return
		}
	}
}

func pingLoop(conn *websocket.Conn, errCh chan<- error) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
			errCh <- fmt.Errorf("relay ping: %w", err)
			return
		}
	}
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}

func equalMAC(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}
