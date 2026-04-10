package store

import (
	"context"
	"database/sql"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// MySQLAlertStore : AlertStore 인터페이스의 MySQL 구현체
// alert 테이블의 생성/조회 작업을 담당
type MySQLAlertStore struct {
	db *sql.DB
}

// NewMySQLAlertStore : MySQLAlertStore 생성자
func NewMySQLAlertStore(db *sql.DB) internal.AlertStore {
	return &MySQLAlertStore{db: db}
}


func (s *MySQLAlertStore) CreateAlert(ctx context.Context, agentID string, filePath string, eventType string) error {
	query := `INSERT INTO alert (agent_id, file_path, event_type) VALUES (?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, agentID, filePath, eventType)
	return err
}

func (s *MySQLAlertStore) ListAlerts(ctx context.Context, f internal.AlertFilter) ([]internal.Alert, error) {
	query := `SELECT alert_id, agent_id, file_path, event_type, detected_at FROM alert WHERE 1=1`
	args := []interface{}{}

	if f.AgentID != "" {
		query += " AND agent_id = ?"
		args = append(args, f.AgentID)
	}
	if f.EventType != "" {
		query += " AND event_type = ?"
		args = append(args, f.EventType)
	}
	if !f.From.IsZero() {
		query += " AND detected_at >= ?"
		args = append(args, f.From)
	}
	if !f.To.IsZero() {
		query += " AND detected_at <= ?"
		args = append(args, f.To)
	}

	query += " ORDER BY detected_at DESC"

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
		err := rows.Scan(&a.AlertID, &a.AgentID, &a.FilePath, &a.EventType, &a.DetectedAt)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, nil
}