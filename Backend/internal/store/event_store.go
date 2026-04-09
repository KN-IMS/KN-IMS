package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// MySQLEventStore : EventStore 인터페이스의 MySQL 구현체
type MySQLEventStore struct {
	db *sql.DB
}

// NewMySQLEventStore : MySQLEventStore 생성
func NewMySQLEventStore(db *sql.DB) internal.EventStore {
	return &MySQLEventStore{db: db}
}

// SaveEvent : 파일 이벤트 DB 저장
func (s *MySQLEventStore) SaveEvent(ctx context.Context, p internal.FileEventPayload) error {
	query := `
		INSERT INTO file_events (agent_id, event_type, file_path, file_name, file_permission, detected_by, pid, occurred_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		p.AgentID, p.EventType, p.FilePath, p.FileName,
		p.FilePermission, p.DetectedBy, p.Pid,
		time.Unix(p.Timestamp, 0),
	)
	return err
}

// QueryEvents : 필터 기반 이벤트 조회
func (s *MySQLEventStore) QueryEvents(ctx context.Context, f internal.EventFilter) ([]internal.FileEvent, error) {
	query := `SELECT id, agent_id, event_type, file_path, file_name, file_permission, detected_by, pid, occurred_at, received_at FROM file_events WHERE 1=1`
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
		query += " AND occurred_at >= ?"
		args = append(args, f.From)
	}
	if !f.To.IsZero() {
		query += " AND occurred_at <= ?"
		args = append(args, f.To)
	}

	query += " ORDER BY occurred_at DESC"

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

	var events []internal.FileEvent
	for rows.Next() {
		var e internal.FileEvent
		err := rows.Scan(&e.ID, &e.AgentID, &e.EventType, &e.FilePath, &e.FileName, &e.FilePermission, &e.DetectedBy, &e.Pid, &e.OccurredAt, &e.ReceivedAt)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}
