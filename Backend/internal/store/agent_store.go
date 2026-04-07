package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/KGU-FIMS/Backend/internal"
)

// MySQLAgentStore : AgentStore 인터페이스의 MySQL 구현체
type MySQLAgentStore struct {
	db *sql.DB
}

// NewMySQLAgentStore : MySQLAgentStore 생성
func NewMySQLAgentStore(db *sql.DB) internal.AgentStore {
	return &MySQLAgentStore{db: db}
}

// RegisterAgent : 에이전트 등록, 이미 존재하면 last_seen 업데이트
func (s *MySQLAgentStore) RegisterAgent(ctx context.Context, agentID string, p internal.RegisterPayload) error {
	query := `
		INSERT INTO agents (agent_id, hostname, ip, version, os, monitor_type, status, registered_at, last_seen)
		VALUES (?, ?, ?, '', ?, ?, 'online', NOW(), NOW())
		ON DUPLICATE KEY UPDATE last_seen = NOW(), status = 'online'`

	_, err := s.db.ExecContext(ctx, query, agentID, p.Hostname, p.IP, p.OS, p.MonitorType)
	return err
}

// UpdateHeartbeat : last_seen 갱신 + status online
func (s *MySQLAgentStore) UpdateHeartbeat(ctx context.Context, agentID string, t time.Time) error {
	query := `UPDATE agents SET last_seen = ?, status = 'online' WHERE agent_id = ?`
	_, err := s.db.ExecContext(ctx, query, t, agentID)
	return err
}

// SetOffline : status를 offline으로 변경
func (s *MySQLAgentStore) SetOffline(ctx context.Context, agentID string) error {
	query := `UPDATE agents SET status = 'offline' WHERE agent_id = ?`
	_, err := s.db.ExecContext(ctx, query, agentID)
	return err
}

// ListAgents : 전체 에이전트 목록 조회
func (s *MySQLAgentStore) ListAgents(ctx context.Context) ([]internal.Agent, error) {
	query := `SELECT agent_id, hostname, ip, version, os, monitor_type, status, registered_at, COALESCE(last_seen, registered_at) FROM agents`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []internal.Agent
	for rows.Next() {
		var a internal.Agent
		err := rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.Version, &a.OS, &a.MonitorType, &a.Status, &a.RegisteredAt, &a.LastSeen)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// GetAgent : 단일 에이전트 조회
func (s *MySQLAgentStore) GetAgent(ctx context.Context, agentID string) (internal.Agent, error) {
	query := `SELECT agent_id, hostname, ip, version, os, monitor_type, status, registered_at, COALESCE(last_seen, registered_at) FROM agents WHERE agent_id = ?`
	var a internal.Agent
	err := s.db.QueryRowContext(ctx, query, agentID).Scan(&a.AgentID, &a.Hostname, &a.IP, &a.Version, &a.OS, &a.MonitorType, &a.Status, &a.RegisteredAt, &a.LastSeen)
	if err == sql.ErrNoRows {
		return internal.Agent{}, internal.ErrAgentNotFound
	}
	return a, err
}

// DeleteAgent : 에이전트 삭제 (CASCADE로 관련 데이터도 삭제)
func (s *MySQLAgentStore) DeleteAgent(ctx context.Context, agentID string) error {
	query := `DELETE FROM agents WHERE agent_id = ?`
	_, err := s.db.ExecContext(ctx, query, agentID)
	return err
}

// UpdateStatus : 에이전트 상태 수동 변경
func (s *MySQLAgentStore) UpdateStatus(ctx context.Context, agentID string, status string) error {
	query := `UPDATE agents SET status = ? WHERE agent_id = ?`
	_, err := s.db.ExecContext(ctx, query, status, agentID)
	return err
}