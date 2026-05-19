package internal

import "errors"

// errors.Is()로 판별해서 오류를 정확히 매핑
var (
	ErrAgentNotFound            = errors.New("agent not found")
	ErrAgentOffline             = errors.New("agent offline")
	ErrAgentCertificateMismatch = errors.New("agent certificate mismatch")
	ErrAlertNotFound            = errors.New("alert not found")
	ErrInvalidInput             = errors.New("invalid input")
	ErrEnrollmentNotFound       = errors.New("enrollment not found")
	ErrEnrollmentExpired        = errors.New("enrollment expired")
	ErrEnrollmentUsed           = errors.New("enrollment already used")
	ErrEnrollmentSecretMismatch = errors.New("enrollment secret mismatch")
	ErrEnrollmentRevoked        = errors.New("enrollment revoked")
)
