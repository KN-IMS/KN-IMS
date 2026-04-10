package store

import (
	"context"
	"database/sql"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// MySQLFileStore : FileStore 인터페이스의 MySQL 구현체
// file 테이블(베이스라인)의 CRUD 작업을 담당
type MySQLFileStore struct {
	db *sql.DB
}

// NewMySQLFileStore : MySQLFileStore 생성자
func NewMySQLFileStore(db *sql.DB) internal.FileStore {
	return &MySQLFileStore{db: db}
}

// SaveBaseline : 파일 베이스라인 저장 (UPSERT)
func (s *MySQLFileStore) SaveBaseline(ctx context.Context, f internal.File) error {
	query := `
		INSERT INTO file (agent_id, file_path_hash, file_path, file_hash, file_permission, mod_time)
		VALUES (?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE file_hash = ?, file_permission = ?, mod_time = ?`
	_, err := s.db.ExecContext(ctx, query,
		f.AgentID, f.FilePathHash, f.FilePath, f.FileHash, f.FilePermission, f.ModTime,
		f.FileHash, f.FilePermission, f.ModTime,
	)
	return err
}

// GetBaseline : 단일 파일의 베이스라인 조회
func (s *MySQLFileStore) GetBaseline(ctx context.Context, agentID string, filePathHash string) (internal.File, error) {
	query := `SELECT agent_id, file_path_hash, file_path, file_hash, file_permission, mod_time, updated_at FROM file WHERE agent_id = ? AND file_path_hash = ?`
	var f internal.File
	err := s.db.QueryRowContext(ctx, query, agentID, filePathHash).Scan(
		&f.AgentID, &f.FilePathHash, &f.FilePath, &f.FileHash, &f.FilePermission, &f.ModTime, &f.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return internal.File{}, internal.ErrFileNotFound
	}
	return f, err
}

// ListBaselines : 특정 에이전트의 전체 베이스라인 목록 조회
// GET /api/agents/:id/baselines 등에서 사용
// 해당 에이전트가 모니터링 중인 모든 파일의 기준 상태를 반환
func (s *MySQLFileStore) ListBaselines(ctx context.Context, agentID string) ([]internal.File, error) {
	query := `SELECT agent_id, file_path_hash, file_path, file_hash, file_permission, mod_time, updated_at FROM file WHERE agent_id = ?`
	rows, err := s.db.QueryContext(ctx, query, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []internal.File
	for rows.Next() {
		var f internal.File
		err := rows.Scan(&f.AgentID, &f.FilePathHash, &f.FilePath, &f.FileHash, &f.FilePermission, &f.ModTime, &f.UpdatedAt)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

// DeleteBaseline : 단일 파일의 베이스라인 삭제
// 모니터링 대상에서 특정 파일을 제외할 때 사용
func (s *MySQLFileStore) DeleteBaseline(ctx context.Context, agentID string, filePathHash string) error {
	query := `DELETE FROM file WHERE agent_id = ? AND file_path_hash = ?`
	_, err := s.db.ExecContext(ctx, query, agentID, filePathHash)
	return err
}

// DeleteAllBaselines : 특정 에이전트의 전체 베이스라인 삭제
// 에이전트 초기화 또는 베이스라인 재생성 시 사용
func (s *MySQLFileStore) DeleteAllBaselines(ctx context.Context, agentID string) error {
	query := `DELETE FROM file WHERE agent_id = ?`
	_, err := s.db.ExecContext(ctx, query, agentID)
	return err
}