package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/KN-IG/KN-IG/Backend/internal"
)

// MySQLEnrollmentStore : EnrollmentStore 인터페이스의 MySQL 구현체
type MySQLEnrollmentStore struct {
	db *sql.DB
}

// NewMySQLEnrollmentStore : MySQLEnrollmentStore 생성
func NewMySQLEnrollmentStore(db *sql.DB) internal.EnrollmentStore {
	return &MySQLEnrollmentStore{db: db}
}

// CreateEnrollment : 신규 Agent 최초 등록 XOR key metadata 저장
func (s *MySQLEnrollmentStore) CreateEnrollment(ctx context.Context, e internal.Enrollment) error {
	query := `
		INSERT INTO agent_enrollments
			(enrollment_id, agent_id, secret_hash, key_ciphertext, key_nonce, status, expires_at, created_at)
		VALUES (?, NULLIF(?, ''), ?, ?, ?, 'pending', ?, NOW())`
	_, err := s.db.ExecContext(ctx, query, e.EnrollmentID, e.AgentID, e.SecretHash, e.KeyCiphertext, e.KeyNonce, e.ExpiresAt)
	return err
}

// GetPendingEnrollment : XOR bootstrap 세션 시작 전 pending enrollment 조회
func (s *MySQLEnrollmentStore) GetPendingEnrollment(ctx context.Context, enrollmentID string, now time.Time) (internal.Enrollment, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return internal.Enrollment{}, err
	}
	defer tx.Rollback()

	var row internal.Enrollment
	var storedAgentID sql.NullString
	query := `
		SELECT agent_id, secret_hash, key_ciphertext, key_nonce, status, expires_at, created_at
		FROM agent_enrollments
		WHERE enrollment_id = ?
		FOR UPDATE`
	err = tx.QueryRowContext(ctx, query, enrollmentID).Scan(
		&storedAgentID,
		&row.SecretHash,
		&row.KeyCiphertext,
		&row.KeyNonce,
		&row.Status,
		&row.ExpiresAt,
		&row.CreatedAt,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return internal.Enrollment{}, internal.ErrEnrollmentNotFound
	case err != nil:
		return internal.Enrollment{}, err
	}
	row.EnrollmentID = enrollmentID
	if storedAgentID.Valid {
		row.AgentID = storedAgentID.String
	}

	switch row.Status {
	case "pending":
	case "used", "issued":
		return internal.Enrollment{}, internal.ErrEnrollmentUsed
	case "revoked":
		return internal.Enrollment{}, internal.ErrEnrollmentRevoked
	default:
		return internal.Enrollment{}, internal.ErrInvalidInput
	}

	if !now.Before(row.ExpiresAt) {
		return internal.Enrollment{}, internal.ErrEnrollmentExpired
	}

	update := `
		UPDATE agent_enrollments
		SET attempt_count = attempt_count + 1, last_attempt_at = ?
		WHERE enrollment_id = ?`
	if _, err := tx.ExecContext(ctx, update, now, enrollmentID); err != nil {
		return internal.Enrollment{}, err
	}
	if err := tx.Commit(); err != nil {
		return internal.Enrollment{}, err
	}
	return row, nil
}

// MarkEnrollmentIssued : Backend가 Agent cert/key 응답을 생성한 뒤 재사용을 막는다.
func (s *MySQLEnrollmentStore) MarkEnrollmentIssued(ctx context.Context, enrollmentID string, agentID string, now time.Time) error {
	query := `
		UPDATE agent_enrollments
		SET status = 'issued', issued_at = ?, agent_id = ?
		WHERE enrollment_id = ? AND status = 'pending' AND expires_at > ?`
	res, err := s.db.ExecContext(ctx, query, now, agentID, enrollmentID, now)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return internal.ErrEnrollmentUsed
	}
	return nil
}

// MarkEnrollmentUsed : Agent가 protected ACK를 보낸 뒤 완료 처리한다.
func (s *MySQLEnrollmentStore) MarkEnrollmentUsed(ctx context.Context, enrollmentID string, agentID string, now time.Time) error {
	query := `
		UPDATE agent_enrollments
		SET status = 'used', used_at = ?, agent_id = ?
		WHERE enrollment_id = ? AND status IN ('issued', 'pending')`
	res, err := s.db.ExecContext(ctx, query, now, agentID, enrollmentID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return internal.ErrEnrollmentUsed
	}
	return nil
}
