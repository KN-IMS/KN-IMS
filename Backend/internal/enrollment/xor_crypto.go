package enrollment

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	nonceSize      = 32
	protectedMACSz = sha256.Size
)

type SessionKeys struct {
	session [32]byte
	enc     [32]byte
	mac     [32]byte
}

func DeriveSessionKeys(xorKey []byte, enrollmentID string, clientNonce, serverNonce []byte) (SessionKeys, error) {
	if len(xorKey) == 0 || enrollmentID == "" || len(clientNonce) != nonceSize || len(serverNonce) != nonceSize {
		return SessionKeys{}, fmt.Errorf("invalid enrollment key material")
	}
	var keys SessionKeys
	h := hmac.New(sha256.New, xorKey)
	h.Write([]byte("knig enrollment v2 session"))
	h.Write([]byte{0})
	h.Write([]byte(enrollmentID))
	h.Write([]byte{0})
	h.Write(clientNonce)
	h.Write(serverNonce)
	copy(keys.session[:], h.Sum(nil))
	copy(keys.enc[:], hmacBytes(keys.session[:], []byte("knig enrollment enc")))
	copy(keys.mac[:], hmacBytes(keys.session[:], []byte("knig enrollment mac")))
	return keys, nil
}

func ServerProof(keys *SessionKeys, enrollmentID string, clientNonce, serverNonce []byte) []byte {
	h := hmac.New(sha256.New, keys.mac[:])
	h.Write([]byte("knig enrollment server proof"))
	h.Write([]byte{0})
	h.Write([]byte(enrollmentID))
	h.Write([]byte{0})
	h.Write(clientNonce)
	h.Write(serverNonce)
	return h.Sum(nil)
}

func SealProtected(msgTyp uint8, seqNum uint32, plaintext []byte, keys *SessionKeys) ([]byte, error) {
	ciphertext := make([]byte, len(plaintext))
	xorKeystream(ciphertext, plaintext, keys.enc[:], seqNum)
	mac := frameMAC(keys.mac[:], msgTyp, seqNum, ciphertext)
	out := make([]byte, 0, len(mac)+len(ciphertext))
	out = append(out, mac...)
	out = append(out, ciphertext...)
	return out, nil
}

func OpenProtected(msgTyp uint8, seqNum uint32, payload []byte, keys *SessionKeys) ([]byte, error) {
	if len(payload) < protectedMACSz {
		return nil, fmt.Errorf("protected payload too short")
	}
	got := payload[:protectedMACSz]
	ciphertext := payload[protectedMACSz:]
	want := frameMAC(keys.mac[:], msgTyp, seqNum, ciphertext)
	if !hmac.Equal(got, want) {
		return nil, fmt.Errorf("protected frame mac mismatch")
	}
	plaintext := make([]byte, len(ciphertext))
	xorKeystream(plaintext, ciphertext, keys.enc[:], seqNum)
	return plaintext, nil
}

func (k *SessionKeys) Clear() {
	if k == nil {
		return
	}
	ZeroBytes(k.session[:])
	ZeroBytes(k.enc[:])
	ZeroBytes(k.mac[:])
}

func hmacBytes(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func frameMAC(macKey []byte, msgTyp uint8, seqNum uint32, ciphertext []byte) []byte {
	h := hmac.New(sha256.New, macKey)
	var seq [4]byte
	binary.BigEndian.PutUint32(seq[:], seqNum)
	h.Write([]byte{msgTyp})
	h.Write(seq[:])
	h.Write(ciphertext)
	return h.Sum(nil)
}

func xorKeystream(dst, src, encKey []byte, seqNum uint32) {
	var blockInput [8]byte
	binary.BigEndian.PutUint32(blockInput[0:4], seqNum)
	for offset, counter := 0, uint32(0); offset < len(src); counter++ {
		binary.BigEndian.PutUint32(blockInput[4:8], counter)
		block := hmacBytes(encKey, blockInput[:])
		for i := 0; i < len(block) && offset < len(src); i++ {
			dst[offset] = src[offset] ^ block[i]
			offset++
		}
		ZeroBytes(block)
	}
}
