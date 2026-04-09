package store

import (
	"context"
	"database/sql"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// MySQLAlertStore : AlertStore 인터페이스의 MySQL 구현체
type MySQLAlertStore struct {
	db *sql.DB
}

// NewMySQLAlertStore : MySQLAlertStore 생성
func NewMySQLAlertStore(db *sql.DB) internal.AlertStore {
	return &MySQLAlertStore{db: db}
}

// CreateAlert : 알림 생성
func (s *MySQLAlertStore) CreateAlert(ctx context.Context, agentID string, severity string, message string) error {
	query := `INSERT INTO alerts (agent_id, severity, message) VALUES (?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, agentID, severity, message)
	return err
}

// ListAlerts : 필터 기반 알림 목록 조회
func (s *MySQLAlertStore) ListAlerts(ctx context.Context, f internal.AlertFilter) ([]internal.Alert, error) {
	query := `SELECT id, agent_id, severity, message, resolved, created_at FROM alerts WHERE 1=1`
	args := []interface{}{}

	if f.AgentID != "" {
		query += " AND agent_id = ?"
		args = append(args, f.AgentID)
	}
	if f.Severity != "" {
		query += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.Resolved != nil {
		query += " AND resolved = ?"
		args = append(args, *f.Resolved)
	}
	if !f.From.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, f.From)
	}

	query += " ORDER BY created_at DESC"

	if f.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, f.Limit)
	}
	if f.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, f.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []internal.Alert
	for rows.Next() {
		var a internal.Alert
		err := rows.Scan(&a.ID, &a.AgentID, &a.Severity, &a.Message, &a.Resolved, &a.CreatedAt)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// ResolveAlert : 알림 해결 처리
func (s *MySQLAlertStore) ResolveAlert(ctx context.Context, alertID int64) error {
	query := `UPDATE alerts SET resolved = TRUE WHERE id = ?`
	result, err := s.db.ExecContext(ctx, query, alertID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return internal.ErrAlertNotFound
	}
	return nil
}
