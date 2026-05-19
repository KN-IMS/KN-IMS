package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/KN-IG/KN-IG/Backend/internal"
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
		ON DUPLICATE KEY UPDATE
			hostname = VALUES(hostname),
			ip = VALUES(ip),
			os = VALUES(os),
			monitor_type = VALUES(monitor_type),
			last_seen = NOW(),
			status = 'online'`

	_, err := s.db.ExecContext(ctx, query, agentID, p.Hostname, p.IP, p.OS, p.MonitorType)
	return err
}

// RegisterAgentWithCertificate : Agent 등록과 인증서 binding 검증을 하나의 트랜잭션으로 처리
func (s *MySQLAgentStore) RegisterAgentWithCertificate(ctx context.Context, agentID string, p internal.RegisterPayload, cert internal.AgentCertificate) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO agents (agent_id, hostname, ip, version, os, monitor_type, status, registered_at, last_seen)
		VALUES (?, ?, ?, '', ?, ?, 'online', NOW(), NOW())
		ON DUPLICATE KEY UPDATE
			hostname = VALUES(hostname),
			ip = VALUES(ip),
			os = VALUES(os),
			monitor_type = VALUES(monitor_type),
			last_seen = NOW(),
			status = 'online'`

	if _, err := tx.ExecContext(ctx, query, agentID, p.Hostname, p.IP, p.OS, p.MonitorType); err != nil {
		return err
	}
	if err := ensureActiveCertificateTx(ctx, tx, agentID, cert); err != nil {
		return err
	}
	return tx.Commit()
}

// EnsureAgent : enrollment 단계에서 FK용 Agent row를 만들되 online 상태로 표시하지 않는다.
func (s *MySQLAgentStore) EnsureAgent(ctx context.Context, agentID string, p internal.RegisterPayload) error {
	query := `
		INSERT INTO agents (agent_id, hostname, ip, version, os, monitor_type, status, registered_at, last_seen)
		VALUES (?, ?, ?, '', ?, ?, 'offline', NOW(), NULL)
		ON DUPLICATE KEY UPDATE
			hostname = VALUES(hostname),
			ip = VALUES(ip),
			os = VALUES(os),
			monitor_type = VALUES(monitor_type)`

	_, err := s.db.ExecContext(ctx, query, agentID, p.Hostname, p.IP, p.OS, p.MonitorType)
	return err
}

// EnsureAgentCertificate : Agent에 active 인증서가 없으면 최초 binding하고, 있으면 fingerprint를 검증한다.
func (s *MySQLAgentStore) EnsureAgentCertificate(ctx context.Context, agentID string, cert internal.AgentCertificate) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := ensureActiveCertificateTx(ctx, tx, agentID, cert); err != nil {
		return err
	}
	return tx.Commit()
}

func ensureActiveCertificateTx(ctx context.Context, tx *sql.Tx, agentID string, cert internal.AgentCertificate) error {
	// Agent row를 잠가 동일 agent_id의 최초 인증서 binding 경쟁을 직렬화한다.
	var lockedAgentID string
	if err := tx.QueryRowContext(ctx, `SELECT agent_id FROM agents WHERE agent_id = ? FOR UPDATE`, agentID).Scan(&lockedAgentID); err != nil {
		return err
	}

	var storedSubjectHash string
	var storedFingerprint string
	query := `
		SELECT cert_subject_hash, cert_fingerprint
		FROM agent_certificates
		WHERE agent_id = ? AND status = 'active'
		ORDER BY bound_at DESC
		LIMIT 1
		FOR UPDATE`

	err := tx.QueryRowContext(ctx, query, agentID).Scan(&storedSubjectHash, &storedFingerprint)
	switch {
	case err == nil:
		if storedSubjectHash != cert.CertSubjectHash || storedFingerprint != cert.CertFingerprint {
			return internal.ErrAgentCertificateMismatch
		}
		return nil
	case errors.Is(err, sql.ErrNoRows):
		insert := `
			INSERT INTO agent_certificates
				(agent_id, cert_subject_hash, cert_fingerprint, status, issued_at, expires_at, bound_at)
			VALUES (?, ?, ?, 'active', ?, ?, NOW())`
		_, err = tx.ExecContext(ctx, insert,
			agentID,
			cert.CertSubjectHash,
			cert.CertFingerprint,
			nullTime(cert.IssuedAt),
			nullTime(cert.ExpiresAt),
		)
		return err
	default:
		return err
	}
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
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
