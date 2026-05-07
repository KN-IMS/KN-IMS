package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// MySQLAuthStore : AuthStore의 MySQL 구현체.
// auth_state 테이블의 단일 행(id=1)을 사용한다.
type MySQLAuthStore struct {
	db *sql.DB
}

// NewMySQLAuthStore : MySQLAuthStore 생성
func NewMySQLAuthStore(db *sql.DB) internal.AuthStore {
	return &MySQLAuthStore{db: db}
}

// GetPINHash : 미설정 시 ""(nil err)
func (s *MySQLAuthStore) GetPINHash(ctx context.Context) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT pin_hash FROM auth_state WHERE id = 1`).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return hash, err
}

// SetPINHash : id=1 행 upsert
func (s *MySQLAuthStore) SetPINHash(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_state (id, pin_hash) VALUES (1, ?)
		ON DUPLICATE KEY UPDATE pin_hash = VALUES(pin_hash)`, hash)
	return err
}
