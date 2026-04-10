package store

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	_ "github.com/go-sql-driver/mysql" // MySQL 드라이버 등록 (직접 호출하지 않지만 드라이버로 등록 필요)
)

// DB : MySQL 커넥션 풀 래퍼 구조체
// database/sql의 *sql.DB를 감싸서 커넥션 관리
type DB struct {
	Conn *sql.DB
}

// NewDB : .env 파일에서 DATABASE_URL을 읽어 MySQL에 연결
// 이미 DB가 존재하는 상태에서 사용 (마이그레이션 없음)
// 반환: DB 구조체 포인터, 에러
func NewDB() (*DB, error) {
	// .env 파일에서 환경변수 로드
	godotenv.Load()

	// DATABASE_URL 형식: username:password@tcp(host:port)/dbname?parseTime=true
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL 환경변수가 설정되지 않았습니다")
	}

	// MySQL 연결 생성
	// multiStatements=true: 여러 SQL문을 한번에 실행 가능하게 설정
	conn, err := sql.Open("mysql", dsn+"&multiStatements=true")
	if err != nil {
		return nil, fmt.Errorf("DB 연결 실패: %w", err)
	}

	// 실제 연결 확인 (sql.Open은 연결을 지연 생성하므로 Ping으로 확인)
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("DB 핑 실패: %w", err)
	}

	// 커넥션 풀 설정
	conn.SetMaxOpenConns(25) // 동시에 열 수 있는 최대 연결 수
	conn.SetMaxIdleConns(5)  // 사용하지 않을 때 유지하는 유휴 연결 수

	return &DB{Conn: conn}, nil
}

// NewDBWithMigration : DB가 없으면 자동 생성하고 schema.sql로 테이블까지 생성
// 서버 최초 실행 시 사용 — DB, 테이블이 없어도 자동으로 세팅
// schemaPath: schema.sql 파일 경로 (예: "internal/store/schema.sql")
func NewDBWithMigration(schemaPath string) (*DB, error) {
	godotenv.Load()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL 환경변수가 설정되지 않았습니다")
	}

	// ── 1단계: DB 이름 없이 MySQL에 연결해서 CREATE DATABASE 실행 ──
	// DSN에서 DB 이름을 제거하여 MySQL 서버 자체에 먼저 연결
	// 예: user:pass@tcp(localhost:3306)/fims → user:pass@tcp(localhost:3306)/
	baseDSN := removeDBName(dsn)
	tmpConn, err := sql.Open("mysql", baseDSN+"&multiStatements=true")
	if err != nil {
		return nil, fmt.Errorf("초기 연결 실패: %w", err)
	}

	// schema.sql 파일 읽기
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		tmpConn.Close()
		return nil, fmt.Errorf("schema.sql 읽기 실패: %w", err)
	}

	// schema.sql을 세미콜론으로 분리하여 한 문장씩 처리
	// CREATE DATABASE와 USE만 먼저 실행 (DB가 없는 상태에서 테이블 생성 불가)
	statements := strings.Split(string(schema), ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		lower := strings.ToLower(stmt)
		if strings.HasPrefix(lower, "create database") || strings.HasPrefix(lower, "use ") {
			_, err := tmpConn.Exec(stmt)
			if err != nil {
				tmpConn.Close()
				return nil, fmt.Errorf("DB 생성 실패: %w", err)
			}
		}
	}
	tmpConn.Close() // 임시 연결 종료

	// ── 2단계: 생성된 fims DB에 정식 연결 ──
	conn, err := sql.Open("mysql", dsn+"&multiStatements=true")
	if err != nil {
		return nil, fmt.Errorf("DB 연결 실패: %w", err)
	}

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("DB 핑 실패: %w", err)
	}

	// ── 3단계: CREATE TABLE 문 실행 (CREATE DATABASE, USE는 건너뜀) ──
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		lower := strings.ToLower(stmt)
		// 이미 1단계에서 실행한 CREATE DATABASE, USE는 스킵
		if strings.HasPrefix(lower, "create database") || strings.HasPrefix(lower, "use ") {
			continue
		}
		_, err := conn.Exec(stmt)
		if err != nil {
			return nil, fmt.Errorf("마이그레이션 실패: %w", err)
		}
	}

	// 커넥션 풀 설정
	conn.SetMaxOpenConns(25) // 동시에 열 수 있는 최대 연결 수
	conn.SetMaxIdleConns(5)  // 사용하지 않을 때 유지하는 유휴 연결 수

	return &DB{Conn: conn}, nil
}

// removeDBName : DSN 문자열에서 데이터베이스 이름을 제거

// DB가 아직 없는 상태에서 MySQL 서버에 연결하기 위해 사용
func removeDBName(dsn string) string {
	// ")/" 위치를 찾아서 DB 이름 부분을 제거
	slashIdx := strings.Index(dsn, ")/")
	if slashIdx == -1 {
		return dsn
	}
	// "?" 위치를 찾아서 쿼리 파라미터는 유지
	questionIdx := strings.Index(dsn[slashIdx:], "?")
	if questionIdx == -1 {
		return dsn[:slashIdx+2]
	}
	return dsn[:slashIdx+2] + dsn[slashIdx+questionIdx:]
}

// Close : MySQL 연결 종료
// defer db.Close()로 사용하여 프로그램 종료 시 연결 정리
func (db *DB) Close() error {
	return db.Conn.Close()
}