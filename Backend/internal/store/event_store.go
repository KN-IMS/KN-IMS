package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/KN-IG/KN-IG/Backend/internal"
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO file_events (
			agent_id, event_type, file_path, file_name, file_permission, detected_by, pid,
			target_dev, target_ino, blocked,
			actor_pid, actor_ppid, actor_uid, actor_euid, actor_sid, actor_tty,
			actor_comm, actor_exe, actor_cmdline, actor_start_time_ns,
			chain_depth, chain_truncated, occurred_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	res, err := tx.ExecContext(ctx, query,
		p.AgentID, p.EventType, p.FilePath, p.FileName,
		p.FilePermission, p.DetectedBy, p.Pid,
		p.TargetDev, p.TargetIno, p.Blocked,
		p.ActorPID, p.ActorPPID, p.ActorUID, p.ActorEUID, p.ActorSID, p.ActorTTY,
		p.ActorComm, p.ActorExe, p.ActorCmdline, p.ActorStartTimeNS,
		p.ChainDepth, p.ChainTruncated,
		time.Unix(p.Timestamp, 0),
	)
	if err != nil {
		return err
	}

	eventID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if len(p.Chain) > 0 {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO file_event_process_chain (
				event_id, depth_index, pid, ppid, uid, euid, sid,
				tty, comm, exe, cmdline, start_time_ns
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for i, entry := range p.Chain {
			if _, err := stmt.ExecContext(ctx,
				eventID, i, entry.PID, entry.PPID, entry.UID, entry.EUID, entry.SID,
				entry.TTY, entry.Comm, entry.Exe, entry.Cmdline, entry.StartTimeNS,
			); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

// QueryEvents : 필터 기반 이벤트 조회
func (s *MySQLEventStore) QueryEvents(ctx context.Context, f internal.EventFilter) ([]internal.FileEvent, error) {
	query := `
		SELECT id, agent_id, event_type, file_path, file_name, file_permission, detected_by, pid,
		       target_dev, target_ino, blocked,
		       actor_pid, actor_ppid, actor_uid, actor_euid, actor_sid, actor_tty,
		       actor_comm, actor_exe, actor_cmdline, actor_start_time_ns,
		       chain_depth, chain_truncated, occurred_at, received_at
		FROM file_events WHERE 1=1`
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
		var actorCmdline sql.NullString
		err := rows.Scan(
			&e.ID, &e.AgentID, &e.EventType, &e.FilePath, &e.FileName, &e.FilePermission, &e.DetectedBy, &e.Pid,
			&e.TargetDev, &e.TargetIno, &e.Blocked,
			&e.ActorPID, &e.ActorPPID, &e.ActorUID, &e.ActorEUID, &e.ActorSID, &e.ActorTTY,
			&e.ActorComm, &e.ActorExe, &actorCmdline, &e.ActorStartTimeNS,
			&e.ChainDepth, &e.ChainTruncated, &e.OccurredAt, &e.ReceivedAt,
		)
		if err != nil {
			return nil, err
		}
		e.ActorCmdline = actorCmdline.String
		events = append(events, e)
	}
	return events, nil
}
