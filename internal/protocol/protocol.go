package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	Version          = byte(2)
	Subprotocol      = "wsn-v2"
	ChallengeSize    = 32
	ProofSize        = sha256.Size
	MinimumFrameSize = 14
	AuthOK           = byte(0)
	AuthFailed       = byte(1)
	MaxClientIDSize  = 64
	MaxHelloSize     = 3 + MaxClientIDSize
)

var authContext = []byte("WSN-AUTH-v2\x00")

func MarshalHello(id string) ([]byte, error) {
	if len(id) == 0 || len(id) > MaxClientIDSize {
		return nil, errors.New("invalid client id length")
	}
	message := make([]byte, 3+len(id))
	message[0] = Version
	binary.BigEndian.PutUint16(message[1:3], uint16(len(id)))
	copy(message[3:], id)
	return message, nil
}

func ParseHello(message []byte) (string, error) {
	if len(message) < 3 || message[0] != Version {
		return "", errors.New("unsupported protocol hello")
	}
	size := int(binary.BigEndian.Uint16(message[1:3]))
	if size < 1 || size > MaxClientIDSize || len(message) != size+3 {
		return "", errors.New("invalid protocol hello")
	}
	return string(message[3:]), nil
}

func Proof(key, challenge []byte, id string, mac net.HardwareAddr) ([]byte, error) {
	if len(key) != 32 || len(challenge) != ChallengeSize || len(mac) != 6 {
		return nil, fmt.Errorf("invalid proof inputs")
	}
	h := hmac.New(sha256.New, key)
	h.Write(authContext)
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write(challenge)
	h.Write(mac)
	return h.Sum(nil), nil
}

func VerifyProof(key, challenge []byte, id string, mac net.HardwareAddr, proof []byte) bool {
	expected, err := Proof(key, challenge, id, mac)
	return err == nil && hmac.Equal(expected, proof)
}

func SourceMAC(frame []byte) net.HardwareAddr {
	if len(frame) < MinimumFrameSize {
		return nil
	}
	return net.HardwareAddr(frame[6:12])
}

func DestinationMAC(frame []byte) net.HardwareAddr {
	if len(frame) < MinimumFrameSize {
		return nil
	}
	return net.HardwareAddr(frame[0:6])
}

func MACKey(mac net.HardwareAddr) uint64 {
	return uint64(mac[0])<<40 | uint64(mac[1])<<32 | uint64(mac[2])<<24 |
		uint64(mac[3])<<16 | uint64(mac[4])<<8 | uint64(mac[5])
}

func IsGroupMAC(mac net.HardwareAddr) bool { return len(mac) == 6 && mac[0]&1 != 0 }
