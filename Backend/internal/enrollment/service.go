package enrollment

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/KN-IG/KN-IG/Backend/internal"
	"github.com/KN-IG/KN-IG/Backend/internal/collector"
)

// Service : XOR bootstrap 검증 이후 Agent cert/key 발급 orchestration
type Service struct {
	agents      internal.AgentStore
	enrollments internal.EnrollmentStore
	issuer      *CertIssuer
	caCertPEM   []byte
}

func NewService(
	agents internal.AgentStore,
	enrollments internal.EnrollmentStore,
	issuer *CertIssuer,
	caCertPEM []byte,
) *Service {
	return &Service{
		agents:      agents,
		enrollments: enrollments,
		issuer:      issuer,
		caCertPEM:   caCertPEM,
	}
}

// Enroll : 신규 Agent 최초 등록 수행. 요청은 이미 XOR 보호 채널에서 인증/복호화된 상태다.
func (s *Service) Enroll(ctx context.Context, enrollmentID string, req Request) (Response, error) {
	if enrollmentID == "" || req.Hostname == "" || req.IP == "" {
		return Response{}, internal.ErrInvalidInput
	}

	ip := net.ParseIP(req.IP)
	if ip == nil {
		return Response{}, fmt.Errorf("%w: invalid ip", internal.ErrInvalidInput)
	}

	agentNum := collector.GenerateAgentID(req.Hostname, ip)
	agentID := strconv.FormatUint(agentNum, 10)

	identity := fmt.Sprintf("spiffe://kn-ig/agent/%s", agentID)
	issued, err := s.issuer.IssueAgentCertificate(identity)
	if err != nil {
		return Response{}, err
	}

	payload := internal.RegisterPayload{
		Hostname:    req.Hostname,
		IP:          req.IP,
		OS:          req.OS,
		MonitorType: collector.MonitorTypeName(req.MonitorType),
	}
	if err := s.agents.EnsureAgent(ctx, agentID, payload); err != nil {
		return Response{}, err
	}
	cert := internal.AgentCertificate{
		AgentID:         agentID,
		CertSubjectHash: issued.CertSubjectHash,
		CertFingerprint: issued.CertFingerprint,
		IssuedAt:        issued.IssuedAt,
		ExpiresAt:       issued.ExpiresAt,
	}
	if err := s.agents.EnsureAgentCertificate(ctx, agentID, cert); err != nil {
		return Response{}, err
	}
	if err := s.enrollments.MarkEnrollmentIssued(ctx, enrollmentID, agentID, time.Now().UTC()); err != nil {
		return Response{}, err
	}

	return Response{
		AgentID:      agentID,
		AgentCertPEM: issued.CertPEM,
		AgentKeyPEM:  issued.KeyPEM,
		CACertPEM:    s.caCertPEM,
		ExpiresAt:    issued.ExpiresAt,
	}, nil
}
