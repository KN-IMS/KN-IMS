package internal

import (
	"context"
	"fmt"
	"time"
)

// ── User 도메인 ─────────────────────────────────────────────────

type User struct {
	UserID    int64
	Username  string
	Password  string
	CreatedAt time.Time
}

type UserStore interface {
	CreateUser(ctx context.Context, username string, password string) error
	GetUserByUsername(ctx context.Context, username string) (User, error)
}

// ── Agent 도메인 ────────────────────────────────────────────────

type RegisterPayload struct {
	Hostname string
	IP       string
	OS       string
	Version  string
}

type Agent struct {
	AgentID      string
	Hostname     string
	IP           string
	OS           string
	Version      string
	Status       int
	RegisteredAt time.Time
	LastSeenAt   time.Time
}

type AgentStore interface {
	RegisterAgent(ctx context.Context, agentID string, payload RegisterPayload) error
	UpdateHeartbeat(ctx context.Context, agentID string, t time.Time) error
	SetOffline(ctx context.Context, agentID string) error
	ListAgents(ctx context.Context) ([]Agent, error)
	GetAgent(ctx context.Context, agentID string) (Agent, error)
	DeleteAgent(ctx context.Context, agentID string) error
	UpdateStatus(ctx context.Context, agentID string, status int) error
}

// ── EventPublisher 도메인 ───────────────────────────────────────

// EventPublisher : 실시간 이벤트 SSE 전달
type EventPublisher interface {
	Publish(event Alert)
	Subscribe() <-chan Alert
}

// ── File 도메인 (베이스라인) ─────────────────────────────────────

type File struct {
	AgentID        string
	FilePathHash   string
	FilePath       string
	FileHash       string
	FilePermission string
	ModTime        time.Time
	UpdatedAt      time.Time
}

type FileStore interface {
	SaveBaseline(ctx context.Context, file File) error
	GetBaseline(ctx context.Context, agentID string, filePathHash string) (File, error)
	ListBaselines(ctx context.Context, agentID string) ([]File, error)
	DeleteBaseline(ctx context.Context, agentID string, filePathHash string) error
	DeleteAllBaselines(ctx context.Context, agentID string) error
}

// ── Alert 도메인 ────────────────────────────────────────────────

type Alert struct {
	AlertID    int64
	AgentID    string
	FilePath   string
	EventType  string
	DetectedAt time.Time
}

type AlertFilter struct {
	AgentID   string
	EventType string
	From      time.Time
	To        time.Time
	Limit     int
	Offset    int
}

type AlertStore interface {
	CreateAlert(ctx context.Context, agentID string, filePath string, eventType string) error
	ListAlerts(ctx context.Context, filter AlertFilter) ([]Alert, error)
}

// ── Command 도메인 ──────────────────────────────────────────────

type CommandSender interface {
	SendCreateBaseline(ctx context.Context, agentID string, path string) error
	SendIntegrityScan(ctx context.Context, agentID string, path string) error
}

// ── Error 정의 ──────────────────────────────────────────────────

var (
	ErrAgentNotFound = fmt.Errorf("agent not found")
	ErrUserNotFound  = fmt.Errorf("user not found")
	ErrAlertNotFound = fmt.Errorf("alert not found")
	ErrFileNotFound  = fmt.Errorf("file not found")
)