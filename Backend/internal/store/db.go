package store

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/go-sql-driver/mysql"
)

// DB : MySQL 커넥션 풀 래퍼
type DB struct {
	Conn *sql.DB
}

// NewDB : .env 파일에서 DATABASE_URL 읽어 MySQL 연결
func NewDB() (*DB, error) {
	// .env 파일 로드
	godotenv.Load()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL 환경변수가 설정되지 않았습니다")
	}

	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("DB 연결 실패: %w", err)
	}

	// 연결 확인
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("DB 핑 실패: %w", err)
	}

	// 연결 풀 설정
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)

	return &DB{Conn: conn}, nil
}

// Close : DB 연결 종료
func (db *DB) Close() error {
	return db.Conn.Close()
}