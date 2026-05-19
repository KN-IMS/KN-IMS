package enrollment

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"
)

// IssuedCertificate : CSR 서명 결과
type IssuedCertificate struct {
	CertPEM         []byte
	KeyPEM          []byte
	CertSubjectHash string
	CertFingerprint string
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

// CertIssuer : Agent client certificate 발급기
type CertIssuer struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	ttl    time.Duration
}

// NewCertIssuer : Agent CA 인증서/키로 발급기 생성
func NewCertIssuer(caCertPath, caKeyPath string, ttl time.Duration) (*CertIssuer, error) {
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("Agent CA 인증서 로드 실패: %w", err)
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, fmt.Errorf("Agent CA 인증서 PEM 파싱 실패")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Agent CA 인증서 파싱 실패: %w", err)
	}

	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("Agent CA 개인키 로드 실패: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("Agent CA 개인키 PEM 파싱 실패")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}

	return &CertIssuer{caCert: caCert, caKey: key, ttl: ttl}, nil
}

// SignCSR : Agent CSR을 client-auth 인증서로 서명
func (i *CertIssuer) SignCSR(csrPEM []byte, agentIdentity string) (IssuedCertificate, error) {
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		return IssuedCertificate{}, fmt.Errorf("CSR PEM 파싱 실패")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("CSR 파싱 실패: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return IssuedCertificate{}, fmt.Errorf("CSR 서명 검증 실패: %w", err)
	}

	uri, err := url.Parse(agentIdentity)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("Agent identity URI 파싱 실패: %w", err)
	}

	now := time.Now().UTC()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("인증서 serial 생성 실패: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: agentIdentity,
		},
		URIs:                  []*url.URL{uri},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(i.ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.caCert, csr.PublicKey, i.caKey)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("Agent 인증서 발급 실패: %w", err)
	}

	fingerprint := sha256.Sum256(der)
	subjectHash := sha256.Sum256([]byte(agentIdentity))
	return IssuedCertificate{
		CertPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}),
		CertSubjectHash: hex.EncodeToString(subjectHash[:]),
		CertFingerprint: hex.EncodeToString(fingerprint[:]),
		IssuedAt:        tmpl.NotBefore,
		ExpiresAt:       tmpl.NotAfter,
	}, nil
}

// IssueAgentCertificate generates an Agent private key in Backend memory and
// returns the issued client-auth certificate plus private key PEM. The caller
// must send KeyPEM once and clear it after writing the response.
func (i *CertIssuer) IssueAgentCertificate(agentIdentity string) (IssuedCertificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("Agent 개인키 생성 실패: %w", err)
	}

	uri, err := url.Parse(agentIdentity)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("Agent identity URI 파싱 실패: %w", err)
	}

	now := time.Now().UTC()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("인증서 serial 생성 실패: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: agentIdentity,
		},
		URIs:                  []*url.URL{uri},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(i.ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.caCert, &key.PublicKey, i.caKey)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("Agent 인증서 발급 실패: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("Agent 개인키 marshal 실패: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	ZeroBytes(keyDER)

	fingerprint := sha256.Sum256(der)
	subjectHash := sha256.Sum256([]byte(agentIdentity))
	return IssuedCertificate{
		CertPEM:         certPEM,
		KeyPEM:          keyPEM,
		CertSubjectHash: hex.EncodeToString(subjectHash[:]),
		CertFingerprint: hex.EncodeToString(fingerprint[:]),
		IssuedAt:        tmpl.NotBefore,
		ExpiresAt:       tmpl.NotAfter,
	}, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("지원하지 않는 PKCS#8 개인키 타입")
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}
	return nil, fmt.Errorf("Agent CA 개인키 파싱 실패")
}
