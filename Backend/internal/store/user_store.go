package store

import (
	"context"
	"database/sql"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// MySQLUserStore : UserStore 인터페이스의 MySQL 구현체
// user 테이블의 생성/조회 작업을 담당 (대시보드 인증용)
type MySQLUserStore struct {
	db *sql.DB
}

// NewMySQLUserStore : MySQLUserStore 생성자
func NewMySQLUserStore(db *sql.DB) internal.UserStore {
	return &MySQLUserStore{db: db}
}

// CreateUser : 신규 사용자 등록
func (s *MySQLUserStore) CreateUser(ctx context.Context, username string, password string) error {
	query := `INSERT INTO user (username, password) VALUES (?, ?)`
	_, err := s.db.ExecContext(ctx, query, username, password)
	return err
}

// GetUserByUsername : 사용자 이름으로 조회
func (s *MySQLUserStore) GetUserByUsername(ctx context.Context, username string) (internal.User, error) {
	query := `SELECT user_id, username, password, created_at FROM user WHERE username = ?`
	var u internal.User
	err := s.db.QueryRowContext(ctx, query, username).Scan(&u.UserID, &u.Username, &u.Password, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return internal.User{}, internal.ErrUserNotFound
	}
	return u, err
}