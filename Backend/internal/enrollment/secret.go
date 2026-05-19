package enrollment

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateID : enrollment row 조회에 사용할 공개 ID 생성
func GenerateID() (string, error) {
	return randomToken(16)
}

// GenerateXORKey : 물리 전달용 최초 등록 XOR key 생성.
//
// 반환값은 운영자가 직접 입력하기 쉬운 base64url 텍스트 바이트다.
// 호출자는 사용 후 ZeroBytes로 지운다.
func GenerateXORKey() ([]byte, error) {
	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	return []byte(token), nil
}

// HashXORKey : DB 저장/검증용 HMAC-SHA256
func HashXORKey(enrollmentID string, xorKey []byte, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(enrollmentID))
	mac.Write([]byte(":"))
	mac.Write(xorKey)
	return hex.EncodeToString(mac.Sum(nil))
}

// ZeroBytes clears sensitive byte slices. Go cannot guarantee clearing string
// copies, so secrets should stay in []byte where possible.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random token 생성 실패: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
