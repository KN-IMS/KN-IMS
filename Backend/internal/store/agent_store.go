package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// MySQLAgentStore : AgentStore 인터페이스의 MySQL 구현체
// agent 테이블의 CRUD 작업을 담당
type MySQLAgentStore struct {
	db *sql.DB
}

// NewMySQLAgentStore : MySQLAgentStore 생성자
// db: db.go에서 생성한 MySQL 커넥션을 받아서 저장
func NewMySQLAgentStore(db *sql.DB) internal.AgentStore {
	return &MySQLAgentStore{db: db}
}

// RegisterAgent : 에이전트 최초 등록
// collector가 0x01 REGISTER 메시지 수신 시 호출
// ON DUPLICATE KEY UPDATE → 이미 같은 agent_id가 있으면 INSERT 대신 last_seen_at과 status만 갱신
// status = 1 (online)으로 설정
func (s *MySQLAgentStore) RegisterAgent(ctx context.Context, agentID string, p internal.RegisterPayload) error {
	query := `
		INSERT INTO agent (agent_id, hostname, ip, os, version, status, registered_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW())
		ON DUPLICATE KEY UPDATE last_seen_at = NOW(), status = 1`
	_, err := s.db.ExecContext(ctx, query, agentID, p.Hostname, p.IP, p.OS, p.Version)
	return err
}

// UpdateHeartbeat : 에이전트 하트비트 수신 시 last_seen_at 갱신
// collector가 0x02 HEARTBEAT 메시지를 30초마다 수신할 때 호출
// last_seen_at을 현재 시각으로, status를 1(online)으로 갱신
func (s *MySQLAgentStore) UpdateHeartbeat(ctx context.Context, agentID string, t time.Time) error {
	query := `UPDATE agent SET last_seen_at = ?, status = 1 WHERE agent_id = ?`
	_, err := s.db.ExecContext(ctx, query, t, agentID)
	return err
}

// SetOffline : 에이전트 오프라인 처리
// collector가 TCP 연결 끊김을 감지했을 때 호출
// status를 0(offline)으로 변경
func (s *MySQLAgentStore) SetOffline(ctx context.Context, agentID string) error {
	query := `UPDATE agent SET status = 0 WHERE agent_id = ?`
	_, err := s.db.ExecContext(ctx, query, agentID)
	return err
}

// ListAgents : 전체 에이전트 목록 조회
// GET /api/agents 핸들러에서 호출
// agent 테이블의 모든 행을 조회하여 Agent 구조체 슬라이스로 반환
func (s *MySQLAgentStore) ListAgents(ctx context.Context) ([]internal.Agent, error) {
	query := `SELECT agent_id, hostname, ip, os, version, status, registered_at, last_seen_at FROM agent`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []internal.Agent
	for rows.Next() {
		var a internal.Agent
		err := rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.OS, &a.Version, &a.Status, &a.RegisteredAt, &a.LastSeenAt)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// GetAgent : 단일 에이전트 상세 조회
// GET /api/agents/:id 핸들러에서 호출
// 해당 agent_id가 없으면 ErrAgentNotFound 에러 반환
func (s *MySQLAgentStore) GetAgent(ctx context.Context, agentID string) (internal.Agent, error) {
	query := `SELECT agent_id, hostname, ip, os, version, status, registered_at, last_seen_at FROM agent WHERE agent_id = ?`
	var a internal.Agent
	err := s.db.QueryRowContext(ctx, query, agentID).Scan(&a.AgentID, &a.Hostname, &a.IP, &a.OS, &a.Version, &a.Status, &a.RegisteredAt, &a.LastSeenAt)
	if err == sql.ErrNoRows {
		return internal.Agent{}, internal.ErrAgentNotFound
	}
	return a, err
}

// DeleteAgent : 에이전트 삭제
// DELETE /api/agents/:id 핸들러에서 호출
// ON DELETE CASCADE로 관련 file, alert 데이터도 자동 삭제
func (s *MySQLAgentStore) DeleteAgent(ctx context.Context, agentID string) error {
	query := `DELETE FROM agent WHERE agent_id = ?`
	_, err := s.db.ExecContext(ctx, query, agentID)
	return err
}

// UpdateStatus : 에이전트 상태 수동 변경
// PUT /api/agents/:id/status 핸들러에서 호출
// 관리자가 웹 대시보드에서 직접 상태를 변경할 때 사용
// status: 1 = online, 0 = offline
func (s *MySQLAgentStore) UpdateStatus(ctx context.Context, agentID string, status int) error {
	query := `UPDATE agent SET status = ? WHERE agent_id = ?`
	_, err := s.db.ExecContext(ctx, query, status, agentID)
	return err
}