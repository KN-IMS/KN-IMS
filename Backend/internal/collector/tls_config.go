package collector

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// NewTLSConfig : mTLS 서버 설정 생성
// caCert : ca.crt 경로 -> 에이전트 인증서 검증용
// serverCert : server.crt 경로
// serverKey : server.key 경로
func NewTLSConfig(caCert, serverCert, serverKey string) (*tls.Config, error) {
	// CA 인증서 로드 -> 에이전트 인증서 검증 풀
	caPEM, err := os.ReadFile(caCert)
	if err != nil {
		return nil, fmt.Errorf("CA 인증서 로드 실패: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA 인증서 파싱 실패")
	}

	// 서버 인증서 + 개인키 로드
	cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf("서버 인증서 로드 실패: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // mTLS -> 에이전트 인증서 필수
		// 구형 OpenSSL(예: CentOS 7 / OpenSSL 1.0.x) 에이전트도 붙을 수 있게
		// 최소 버전은 TLS 1.2로 두고, 최신 클라이언트는 TLS 1.3으로 협상한다.
		MinVersion: tls.VersionTLS12,
	}, nil
}

// ExtractCN : TLS 연결에서 에이전트 인증서 CN 추출
func ExtractCN(conn *tls.Conn) (string, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("에이전트 인증서 없음")
	}
	return state.PeerCertificates[0].Subject.CommonName, nil
}

// ExtractPeerIdentity : SAN URI 우선, 없으면 CN을 사용해 에이전트 인증서 identity 추출
func ExtractPeerIdentity(conn *tls.Conn) (string, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("에이전트 인증서 없음")
	}
	return peerIdentityFromCert(state.PeerCertificates[0])
}

// ExtractPeerFingerprint : 에이전트 인증서 DER 바이트의 SHA-256 fingerprint
func ExtractPeerFingerprint(conn *tls.Conn) (string, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("에이전트 인증서 없음")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

// ExtractPeerValidity : 에이전트 인증서 유효 기간 추출
func ExtractPeerValidity(conn *tls.Conn) (time.Time, time.Time, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("에이전트 인증서 없음")
	}
	cert := state.PeerCertificates[0]
	return cert.NotBefore, cert.NotAfter, nil
}

// SubjectHash : 인증서 identity 문자열의 SHA-256 해시 반환
func SubjectHash(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

func peerIdentityFromCert(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("에이전트 인증서 없음")
	}
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String(), nil
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}
	return "", fmt.Errorf("에이전트 인증서에 SAN URI 또는 CN이 없음")
}
