package internal

import "errors"

// errors.Is()로 판별해서 오류를 정확히 매핑
var (
	ErrAgentNotFound = errors.New("agent not found")
	ErrAgentOffline = errors.New("agent offline")
	ErrAlertNotFound = errors.New("alert not found")
	ErrInvalidInput = errors.New("invalid input")
)
