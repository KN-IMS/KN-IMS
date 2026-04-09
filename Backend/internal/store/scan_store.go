package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// MySQLScanStore : ScanStore 인터페이스의 MySQL 구현체
type MySQLScanStore struct {
	db *sql.DB
}

// NewMySQLScanStore : MySQLScanStore 생성
func NewMySQLScanStore(db *sql.DB) internal.ScanStore {
	return &MySQLScanStore{db: db}
}

// SaveScanResult : 스캔 결과 요약 + 개별 파일 항목 저장
func (s *MySQLScanStore) SaveScanResult(ctx context.Context, p internal.ScanResultPayload, scanType string) error {
	// 1. scan_results에 요약 저장
	query := `
		INSERT INTO scan_results (agent_id, scan_type, scan_path, total, changed, scanned_at)
		VALUES (?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, query,
		p.AgentID, scanType, p.ScanPath, p.Total, p.Changed,
		time.Unix(p.Timestamp, 0),
	)
	if err != nil {
		return err
	}

	// 2. 방금 INSERT한 scan_results의 id 가져오기
	scanID, err := result.LastInsertId()
	if err != nil {
		return err
	}

	// 3. scan_entries에 개별 파일 항목 저장
	entryQuery := `
		INSERT INTO scan_entries (scan_id, file_path, file_name, file_hash, file_permission, size, mod_time, changed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	for _, f := range p.Files {
		_, err := s.db.ExecContext(ctx, entryQuery,
			scanID, f.FilePath, f.FileName, f.FileHash,
			f.FilePermission, f.Size, time.Unix(f.ModTime, 0), f.Changed,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetLatestScan : 에이전트의 가장 최근 스캔 결과 조회
func (s *MySQLScanStore) GetLatestScan(ctx context.Context, agentID string) (internal.ScanResult, error) {
	query := `SELECT id, agent_id, scan_type, scan_path, total, changed, scanned_at FROM scan_results WHERE agent_id = ? ORDER BY scanned_at DESC LIMIT 1`

	var sr internal.ScanResult
	err := s.db.QueryRowContext(ctx, query, agentID).Scan(
		&sr.ID, &sr.AgentID, &sr.ScanType, &sr.ScanPath,
		&sr.Total, &sr.Changed, &sr.ScannedAt,
	)
	if err == sql.ErrNoRows {
		return internal.ScanResult{}, nil
	}
	return sr, err
}

// GetScanEntries : 특정 스캔의 개별 파일 목록 조회
func (s *MySQLScanStore) GetScanEntries(ctx context.Context, scanID int64) ([]internal.ScanFileEntry, error) {
	query := `SELECT file_path, file_name, file_hash, file_permission, size, COALESCE(UNIX_TIMESTAMP(mod_time), 0), changed FROM scan_entries WHERE scan_id = ?`

	rows, err := s.db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []internal.ScanFileEntry
	for rows.Next() {
		var e internal.ScanFileEntry
		err := rows.Scan(&e.FilePath, &e.FileName, &e.FileHash, &e.FilePermission, &e.Size, &e.ModTime, &e.Changed)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}
