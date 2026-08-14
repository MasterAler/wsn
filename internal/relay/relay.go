package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MasterAler/wsn/internal/config"
	"github.com/MasterAler/wsn/internal/protocol"
	"github.com/gorilla/websocket"
)

type authorizedClient struct {
	id  string
	key []byte
	mac net.HardwareAddr
}

type Server struct {
	cfg       config.Relay
	log       *slog.Logger
	mu        sync.RWMutex
	clients   map[string]authorizedClient
	hub       *hub
	upgrader  websocket.Upgrader
	handshake time.Duration
	idle      time.Duration
	authSlots chan struct{}
}

func authorizedClients(cfg config.Relay) (map[string]authorizedClient, error) {
	clients := make(map[string]authorizedClient, len(cfg.Clients))
	for _, item := range cfg.Clients {
		key, err := config.DecodeKey(item.Key)
		if err != nil {
			return nil, err
		}
		mac, err := config.ParseMAC(item.MAC)
		if err != nil {
			return nil, err
		}
		clients[item.ID] = authorizedClient{id: item.ID, key: key, mac: mac}
	}
	return clients, nil
}

func New(cfg config.Relay, logger *slog.Logger) (*Server, error) {
	maxPendingHandshakes := cfg.MaxPendingHandshakes
	if maxPendingHandshakes == 0 {
		maxPendingHandshakes = 32
	}
	clients, err := authorizedClients(cfg)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:       cfg,
		log:       logger,
		clients:   clients,
		hub:       newHub(logger),
		handshake: time.Duration(cfg.HandshakeTimeoutMS) * time.Millisecond,
		idle:      time.Duration(cfg.IdleTimeoutMS) * time.Millisecond,
		authSlots: make(chan struct{}, maxPendingHandshakes),
		upgrader: websocket.Upgrader{
			Subprotocols:    []string{protocol.Subprotocol},
			ReadBufferSize:  cfg.MaxFrameSize,
			WriteBufferSize: cfg.MaxFrameSize,
			CheckOrigin: func(r *http.Request) bool {
				return r.Header.Get("Origin") == ""
			},
		},
	}, nil
}

// Reload swaps the set of authorized clients and disconnects any established
// session whose identity has been revoked or whose virtual MAC has changed, so
// a revocation takes effect immediately instead of at the next relay restart.
// Transport settings (listen address, paths, timeouts, queue sizes) are fixed
// at startup and are deliberately not re-applied; changing those still needs a
// restart.
func (s *Server) Reload(cfg config.Relay) error {
	clients, err := authorizedClients(cfg)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.clients = clients
	s.mu.Unlock()
	disconnected := s.hub.retainAuthorized(clients)
	s.log.Info("relay configuration reloaded",
		"configured_clients", len(clients), "disconnected_clients", disconnected)
	return nil
}

func (s *Server) authorized(id string) (authorizedClient, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, exists := s.clients[id]
	return client, exists
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.HealthPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc(s.cfg.Path, s.handleWebSocket)
	return mux
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	authSlotReleased := false
	select {
	case s.authSlots <- struct{}{}:
		defer func() {
			if !authSlotReleased {
				<-s.authSlots
			}
		}()
	default:
		http.Error(w, "too many pending handshakes", http.StatusServiceUnavailable)
		return
	}
	remote := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		remote = forwarded
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Warn("websocket upgrade failed", "remote", remote, "error", err)
		return
	}
	if conn.Subprotocol() != protocol.Subprotocol {
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseProtocolError, "wsn-v2 subprotocol required"),
			time.Now().Add(time.Second))
		_ = conn.Close()
		return
	}
	authorized, err := s.authenticate(conn)
	if err != nil {
		s.log.Warn("authentication failed", "remote", remote, "error", err)
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "authentication failed"),
			time.Now().Add(time.Second))
		_ = conn.Close()
		return
	}
	<-s.authSlots
	authSlotReleased = true
	peer := &peer{
		id:   authorized.id,
		mac:  append(net.HardwareAddr(nil), authorized.mac...),
		conn: conn,
		send: make(chan []byte, s.cfg.ClientQueueSize),
		done: make(chan struct{}),
		log:  s.log,
		idle: s.idle,
	}
	s.hub.add(peer)
	// A reload that ran between authentication and registration could not have
	// seen this peer, so re-check now: otherwise a revoked client that happens
	// to be mid-handshake keeps its session.
	if current, stillAuthorized := s.authorized(peer.id); !stillAuthorized || !bytes.Equal(current.mac, peer.mac) {
		s.hub.remove(peer)
		peer.stop()
		s.log.Warn("client revoked during handshake", "id", peer.id, "remote", remote)
		return
	}
	s.log.Info("client connected", "id", peer.id, "mac", peer.mac.String(), "remote", remote)
	go peer.writeLoop()
	peer.readLoop(s.cfg.MaxFrameSize, s.hub)
	s.hub.remove(peer)
	peer.stop()
	s.log.Info("client disconnected", "id", peer.id, "mac", peer.mac.String(), "remote", remote,
		"dropped", peer.dropped.Load())
}

func (s *Server) authenticate(conn *websocket.Conn) (authorizedClient, error) {
	deadline := time.Now().Add(s.handshake)
	_ = conn.SetReadDeadline(deadline)
	_ = conn.SetWriteDeadline(deadline)
	conn.SetReadLimit(protocol.MaxHelloSize)
	messageType, hello, err := conn.ReadMessage()
	if err != nil || messageType != websocket.BinaryMessage {
		return authorizedClient{}, errors.New("invalid hello")
	}
	id, err := protocol.ParseHello(hello)
	if err != nil {
		return authorizedClient{}, err
	}
	client, exists := s.authorized(id)
	if !exists {
		return authorizedClient{}, errors.New("unknown client")
	}
	challenge := make([]byte, protocol.ChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return authorizedClient{}, fmt.Errorf("generate challenge: %w", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, challenge); err != nil {
		return authorizedClient{}, errors.New("write challenge")
	}
	messageType, proof, err := conn.ReadMessage()
	if err != nil || messageType != websocket.BinaryMessage || !protocol.VerifyProof(client.key, challenge, id, client.mac, proof) {
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte{protocol.AuthFailed})
		return authorizedClient{}, errors.New("invalid proof")
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte{protocol.AuthOK}); err != nil {
		return authorizedClient{}, errors.New("write authentication result")
	}
	conn.SetReadLimit(int64(s.cfg.MaxFrameSize))
	_ = conn.SetWriteDeadline(time.Time{})
	_ = conn.SetReadDeadline(time.Now().Add(s.idle))
	return client, nil
}

type hub struct {
	mu    sync.RWMutex
	byID  map[string]*peer
	byMAC map[uint64]*peer
	log   *slog.Logger
}

func newHub(logger *slog.Logger) *hub {
	return &hub{byID: make(map[string]*peer), byMAC: make(map[uint64]*peer), log: logger}
}

func (h *hub) add(p *peer) {
	h.mu.Lock()
	oldByID := h.byID[p.id]
	oldByMAC := h.byMAC[protocol.MACKey(p.mac)]
	h.byID[p.id] = p
	h.byMAC[protocol.MACKey(p.mac)] = p
	h.mu.Unlock()
	if oldByID != nil && oldByID != p {
		oldByID.stop()
	}
	if oldByMAC != nil && oldByMAC != p && oldByMAC != oldByID {
		oldByMAC.stop()
	}
}

func (h *hub) remove(p *peer) {
	h.mu.Lock()
	if h.byID[p.id] == p {
		delete(h.byID, p.id)
	}
	key := protocol.MACKey(p.mac)
	if h.byMAC[key] == p {
		delete(h.byMAC, key)
	}
	h.mu.Unlock()
}

// retainAuthorized disconnects every peer that the supplied client set no
// longer authorizes, and reports how many were dropped.
func (h *hub) retainAuthorized(clients map[string]authorizedClient) int {
	h.mu.RLock()
	stale := make([]*peer, 0)
	for id, p := range h.byID {
		client, exists := clients[id]
		if !exists || !bytes.Equal(client.mac, p.mac) {
			stale = append(stale, p)
		}
	}
	h.mu.RUnlock()
	for _, p := range stale {
		h.log.Info("disconnecting revoked client", "id", p.id, "mac", p.mac.String())
		p.stop()
	}
	return len(stale)
}

func (h *hub) forward(sender *peer, frame []byte) {
	destination := protocol.DestinationMAC(frame)
	h.mu.RLock()
	recipients := make([]*peer, 0, len(h.byID))
	knownDestination := false
	if !protocol.IsGroupMAC(destination) {
		if target := h.byMAC[protocol.MACKey(destination)]; target != nil {
			knownDestination = true
			if target != sender {
				recipients = append(recipients, target)
			}
		}
	}
	if protocol.IsGroupMAC(destination) || !knownDestination {
		for _, target := range h.byID {
			if target != sender {
				recipients = append(recipients, target)
			}
		}
	}
	h.mu.RUnlock()
	for _, target := range recipients {
		copyOfFrame := append([]byte(nil), frame...)
		select {
		case target.send <- copyOfFrame:
		default:
			// The overlay is Ethernet, which is permitted to lose a frame, and
			// losing one is what makes the sender's TCP back off. Disconnecting
			// the peer instead tore down every connection it held: a burst large
			// enough to fill the queue is ordinary traffic, not a broken client.
			target.noteDrop(h.log)
		}
	}
}

// dropReportInterval bounds how often a peer that cannot keep up is reported.
// A saturated peer discards far too many frames to log a line for each.
const dropReportInterval = 30 * time.Second

type peer struct {
	id       string
	mac      net.HardwareAddr
	conn     *websocket.Conn
	send     chan []byte
	done     chan struct{}
	stopOnce sync.Once
	log      *slog.Logger
	idle     time.Duration

	dropped        atomic.Uint64
	lastDropReport atomic.Int64
}

// noteDrop counts a discarded frame and reports the running total at most once
// per dropReportInterval, so a peer that cannot keep up stays visible in the log
// without drowning it.
func (p *peer) noteDrop(log *slog.Logger) {
	total := p.dropped.Add(1)
	now := time.Now().UnixNano()
	last := p.lastDropReport.Load()
	if now-last < int64(dropReportInterval) {
		return
	}
	if !p.lastDropReport.CompareAndSwap(last, now) {
		return
	}
	log.Warn("dropping frames for a client that cannot keep up",
		"id", p.id, "mac", p.mac.String(), "dropped", total)
}

func (p *peer) stop() {
	p.stopOnce.Do(func() {
		close(p.done)
		_ = p.conn.Close()
	})
}

func (p *peer) readLoop(maxFrameSize int, h *hub) {
	p.conn.SetReadLimit(int64(maxFrameSize))
	p.conn.SetPongHandler(func(string) error {
		return p.conn.SetReadDeadline(time.Now().Add(p.idle))
	})
	for {
		messageType, frame, err := p.conn.ReadMessage()
		if err != nil {
			return
		}
		_ = p.conn.SetReadDeadline(time.Now().Add(p.idle))
		if messageType != websocket.BinaryMessage || len(frame) < protocol.MinimumFrameSize || len(frame) > maxFrameSize {
			p.log.Warn("invalid frame", "id", p.id, "size", len(frame))
			return
		}
		if !bytes.Equal(protocol.SourceMAC(frame), p.mac) {
			p.log.Warn("source mac mismatch", "id", p.id)
			return
		}
		h.forward(p, frame)
	}
}

func (p *peer) writeLoop() {
	pingEvery := p.idle / 3
	if pingEvery < 10*time.Second {
		pingEvery = 10 * time.Second
	}
	ticker := time.NewTicker(pingEvery)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case frame := <-p.send:
			_ = p.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := p.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				p.stop()
				return
			}
		case <-ticker.C:
			if err := p.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				p.stop()
				return
			}
		}
	}
}

// ListenAndServe runs the relay until ctx is cancelled. Every configuration
// received on reload is applied to the running server without interrupting
// sessions that remain authorized; a nil channel disables reloading.
func ListenAndServe(ctx context.Context, cfg config.Relay, reload <-chan config.Relay, logger *slog.Logger) error {
	relay, err := New(cfg, logger)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           relay.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    8192,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()
	for {
		select {
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case updated := <-reload:
			if err := relay.Reload(updated); err != nil {
				logger.Error("reload rejected; keeping the running configuration", "error", err)
			}
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return httpServer.Shutdown(shutdownCtx)
		}
	}
}
