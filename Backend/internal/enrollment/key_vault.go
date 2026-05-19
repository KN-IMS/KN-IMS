package enrollment

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

// KeyVault encrypts physically delivered XOR keys before DB persistence.
type KeyVault struct {
	key [32]byte
}

func NewKeyVaultFromEnv(envName string) (*KeyVault, error) {
	raw := os.Getenv(envName)
	if raw == "" {
		return nil, fmt.Errorf("%s 환경변수가 필요합니다", envName)
	}
	return NewKeyVault([]byte(raw))
}

func NewKeyVault(raw []byte) (*KeyVault, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty key encryption key")
	}
	var material []byte
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if decoded, err := enc.DecodeString(string(raw)); err == nil && len(decoded) == 32 {
			material = decoded
			break
		}
	}
	if material == nil {
		sum := sha256.Sum256(raw)
		material = sum[:]
	}

	v := &KeyVault{}
	copy(v.key[:], material)
	ZeroBytes(material)
	return v, nil
}

func (v *KeyVault) Encrypt(plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(v.key[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func (v *KeyVault) Decrypt(ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid enrollment key nonce size")
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (v *KeyVault) Close() {
	if v != nil {
		ZeroBytes(v.key[:])
	}
}
