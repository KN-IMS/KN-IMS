package internal

import (
	"context"
	"time"
)

// 심각도 상수

const (
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
	SeverityLow    = "LOW"
)

// 페이로드 타입

// RegisterPayload : 에이전트 -> 서버 등록 정보
type RegisterPayload struct {
	Hostname    string
	IP          string
	OS          string
	MonitorType string // lkm, ebpf
}

// FileEventPayload : 에이전트 -> 서버 파일 변경 이벤트
type FileEventPayload struct {
	AgentID        string
	EventType      string // CREATE, MODIFY, DELETE, ATTRIB, MOVE
	FilePath       string
	FileName       string
	FilePermission string // "0644"
	DetectedBy     string // lkm, ebpf
	Pid            int
	Timestamp      int64
}

// Agent 도메인

// Agent : DB에 저장되는 에이전트 정보
type Agent struct {
	AgentID      string
	Hostname     string
	IP           string
	Version      string
	OS           string
	MonitorType  string // lkm, ebpf
	Status       string // online, offline
	RegisteredAt time.Time
	LastSeen     time.Time
}

// AgentStore : 에이전트 등록/조회/상태 관리
// 구현 : internal/store/agent_store.go
type AgentStore interface {
	// RegisterAgent : 0x01 REGISTER 수신 -> agent_id 발급 후 DB 저장
	RegisterAgent(ctx context.Context, agentID string, payload RegisterPayload) error
	// UpdateHeartbeat : 0x02 HEARTBEAT 수신 -> last_seen 갱신
	UpdateHeartbeat(ctx context.Context, agentID string, t time.Time) error
	// SetOffline : TCP 연결 종료 -> status offline
	SetOffline(ctx context.Context, agentID string) error
	// ListAgents : GET /api/agents -> 전체 에이전트 목록
	ListAgents(ctx context.Context) ([]Agent, error)
	// GetAgent : GET /api/agents/:id -> 단일 에이전트 조회
	GetAgent(ctx context.Context, agentID string) (Agent, error)
	// DeleteAgent : DELETE /api/agents/:id -> 에이전트 삭제
	DeleteAgent(ctx context.Context, agentID string) error
	// UpdateStatus : PUT /api/agents/:id/status -> 상태 수동 변경
	UpdateStatus(ctx context.Context, agentID string, status string) error
}

// FileEvent 도메인

// FileEvent : DB에 저장되는 파일 이벤트
type FileEvent struct {
	ID             int64
	AgentID        string
	EventType      string // CREATE, MODIFY, DELETE, ATTRIB, MOVE
	FilePath       string
	FileName       string
	FilePermission string // "0644"
	DetectedBy     string // lkm, ebpf
	Pid            int    // PID를 제공하지 않는 이벤트는 0
	OccurredAt     time.Time
	ReceivedAt     time.Time
}

// EventFilter : GET /api/events 쿼리 파라미터
type EventFilter struct {
	AgentID   string
	EventType string
	From      time.Time
	To        time.Time
	Limit     int
	Offset    int
}

// EventStore : 파일 이벤트 저장/조회
// 구현 : internal/store/event_store.go
type EventStore interface {
	// SaveEvent : 0x03 FILE_EVENT 수신 -> DB 저장
	SaveEvent(ctx context.Context, payload FileEventPayload) error
	// QueryEvents : GET /api/events -> 필터 기반 조회
	QueryEvents(ctx context.Context, filter EventFilter) ([]FileEvent, error)
}

// EventPublisher : FILE_EVENT 실시간 SSE 전달 채널
// 구현 : internal/api/sse.go
// 호출 : internal/collector/agent_session.go
type EventPublisher interface {
	// Publish : 0x03 FILE_EVENT 수신 -> SSE로 즉시 push
	Publish(event FileEvent)
	// Subscribe : SSE 핸들러가 구독 채널 획득
	Subscribe() <-chan FileEvent
}

// Alert 도메인

// Alert : engine 이상 감지 시 생성되는 알림
type Alert struct {
	ID        int64
	AgentID   string
	Severity  string // HIGH, MEDIUM, LOW
	Message   string
	Resolved  bool
	CreatedAt time.Time
}

// AlertFilter : GET /api/alerts 쿼리 파라미터
type AlertFilter struct {
	AgentID  string
	Severity string
	Resolved *bool // nil=전체, true=해결, false=미해결
	From     time.Time
	Limit    int
	Offset   int
}

// AlertStore : 알림 생성/조회/해결
// 구현 : internal/store/alert_store.go
type AlertStore interface {
	// CreateAlert : engine 이상 감지 -> 알림 생성
	CreateAlert(ctx context.Context, agentID string, severity string, message string) error
	// ListAlerts : GET /api/alerts -> 필터 기반 조회
	ListAlerts(ctx context.Context, filter AlertFilter) ([]Alert, error)
	// ResolveAlert : PATCH /api/alerts/:id/resolve -> 알림 해결 처리
	ResolveAlert(ctx context.Context, alertID int64) error
}
