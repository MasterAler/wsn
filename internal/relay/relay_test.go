package relay

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MasterAler/wsn/internal/config"
	"github.com/MasterAler/wsn/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestAuthenticatedClientsForwardFrames(t *testing.T) {
	keyA := bytes.Repeat([]byte{1}, 32)
	keyB := bytes.Repeat([]byte{2}, 32)
	macA, _ := net.ParseMAC("02:00:00:00:00:01")
	macB, _ := net.ParseMAC("02:00:00:00:00:02")
	cfg := config.Relay{
		Path: "/wsn", HealthPath: "/healthz", MaxFrameSize: 2048, ClientQueueSize: 4,
		HandshakeTimeoutMS: 1000, IdleTimeoutMS: 5000,
		Clients: []config.RelayClient{
			{ID: "alice", Key: config.EncodeKey(keyA), MAC: macA.String()},
			{ID: "bob", Key: config.EncodeKey(keyB), MAC: macB.String()},
		},
	}
	server, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	url := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/wsn"
	a := dialAuthenticated(t, url, "alice", keyA, macA)
	defer a.Close()
	b := dialAuthenticated(t, url, "bob", keyB, macB)
	defer b.Close()
	frame := make([]byte, 60)
	copy(frame[0:6], macB)
	copy(frame[6:12], macA)
	if err := a.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	messageType, received, err := b.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.BinaryMessage || !bytes.Equal(received, frame) {
		t.Fatal("forwarded frame differs")
	}
	copy(frame[0:6], macA)
	if err := a.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := b.ReadMessage(); err == nil {
		t.Fatal("frame addressed to sender was flooded to another client")
	}
}

func TestSourceMACSpoofDisconnectsClient(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	mac, _ := net.ParseMAC("02:00:00:00:00:03")
	cfg := config.Relay{
		Path: "/wsn", HealthPath: "/healthz", MaxFrameSize: 2048, ClientQueueSize: 4,
		HandshakeTimeoutMS: 1000, IdleTimeoutMS: 5000,
		Clients: []config.RelayClient{{ID: "alice", Key: config.EncodeKey(key), MAC: mac.String()}},
	}
	server, _ := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	conn := dialAuthenticated(t, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/wsn", "alice", key, mac)
	defer conn.Close()
	frame := make([]byte, 60)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{2, 9, 9, 9, 9, 9})
	if err := conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("spoofing client was not disconnected")
	}
}

func dialAuthenticated(t *testing.T, url, id string, key []byte, mac net.HardwareAddr) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{Subprotocols: []string{protocol.Subprotocol}}
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	hello, _ := protocol.MarshalHello(id)
	if err := conn.WriteMessage(websocket.BinaryMessage, hello); err != nil {
		t.Fatal(err)
	}
	_, challenge, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := protocol.Proof(key, challenge, id, mac)
	if err := conn.WriteMessage(websocket.BinaryMessage, proof); err != nil {
		t.Fatal(err)
	}
	_, result, err := conn.ReadMessage()
	if err != nil || len(result) != 1 || result[0] != protocol.AuthOK {
		t.Fatalf("authentication failed: %v %v", result, err)
	}
	return conn
}
