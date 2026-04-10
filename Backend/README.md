# KGU-FIMS Backend

파일 무결성 모니터링 시스템(File Integrity Monitoring System)의 REST API 서버입니다.

## 기술 스택

- **Go** 1.25.5
- **MySQL** 8.0+
- **Gin** — HTTP 라우터
- **golang-jwt** — JWT 인증
- **bcrypt** — 비밀번호 해싱

## 프로젝트 구조

```
Backend/
├── cmd/server/
│   └── main.go                 # 서버 진입점
├── internal/
│   ├── interfaces.go           # 도메인 구조체 및 Store 인터페이스 정의
│   ├── api/
│   │   ├── server.go           # 라우터 설정 및 의존성 주입
│   │   ├── auth_handler.go     # 회원가입 / 로그인 (JWT 발급)
│   │   ├── middleware.go       # JWT 인증 미들웨어
│   │   ├── agent_handler.go    # 에이전트 CRUD API
│   │   ├── alert_handler.go    # 알림 조회 API (필터링 지원)
│   │   ├── command_handler.go  # 에이전트 명령 전송 API
│   │   └── sse.go              # 실시간 이벤트 스트리밍 (SSE)
│   └── store/
│       ├── schema.sql          # DB 스키마 (자동 마이그레이션)
│       ├── db.go               # MySQL 연결 및 마이그레이션
│       ├── agent_store.go      # 에이전트 Store 구현
│       ├── alert_store.go      # 알림 Store 구현
│       ├── file_store.go       # 파일 베이스라인 Store 구현
│       └── user_store.go       # 사용자 Store 구현
├── .env.example                # 환경변수 템플릿
├── go.mod
└── go.sum
```

## 실행 방법

### 1. MySQL 설정

MySQL이 실행 중이어야 합니다. 사용자 계정이 DB 생성 권한을 가지고 있어야 합니다.

```bash
# MySQL 상태 확인
sudo systemctl status mysql
```

### 2. 환경변수 설정

```bash
cd Backend
cp .env.example .env
```

`.env` 파일을 열어 MySQL 접속 정보를 수정합니다:

```dotenv
DATABASE_URL=<username>:<password>@tcp(localhost:3306)/fims?parseTime=true
```

예시:

```dotenv
DATABASE_URL=root:mypassword@tcp(localhost:3306)/fims?parseTime=true
```

### 3. 서버 실행

```bash
cd Backend
go mod tidy
go run cmd/server/main.go
```

서버가 정상 실행되면 아래 로그가 출력됩니다:

```
MySQL 연결 및 마이그레이션 성공!
HTTP 서버 시작: :8080
```

> DB와 테이블이 없어도 `schema.sql`을 읽어 자동으로 생성합니다.

## API 테스트

### 접속 주소

서버가 VM에서 실행되고 있으므로, 외부에서 접속할 때는 VM의 IP 주소를 사용해야 합니다.

```bash
# VM 서버에서 IP 확인
hostname -I
```

- **VM 내부에서 테스트**: `http://localhost:8080`
- **외부(WSL/로컬 PC)에서 테스트**: `http://<SERVER_IP>:8080`

> 아래 예시의 `<SERVER_IP>`를 자신의 VM IP 주소로 바꿔주세요. VM 내부에서 테스트한다면 `localhost`를 사용하면 됩니다.

### 1. 회원가입

```bash
curl -X POST http://<SERVER_IP>:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### 2. 로그인 (JWT 토큰 발급)

```bash
curl -X POST http://<SERVER_IP>:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

응답에서 `token` 값을 복사합니다:

```json
{"token":"eyJhbGciOiJIUzI1NiIs..."}
```

### 3. 에이전트 목록 조회

```bash
curl http://<SERVER_IP>:8080/api/agents \
  -H "Authorization: Bearer <복사한_토큰>"
```

### 4. 알림 목록 조회

```bash
# 전체 조회
curl http://<SERVER_IP>:8080/api/alerts \
  -H "Authorization: Bearer <토큰>"

# 필터링 조회
curl 'http://<SERVER_IP>:8080/api/alerts?event_type=MODIFY&limit=20' \
  -H "Authorization: Bearer <토큰>"
```

### 5. SSE 실시간 스트리밍

```bash
curl -N http://<SERVER_IP>:8080/api/events/stream \
  -H "Authorization: Bearer <토큰>"
```

## API 엔드포인트 요약

| 메서드 | 경로 | 설명 | 인증 |
|--------|------|------|------|
| POST | `/api/auth/register` | 회원가입 | X |
| POST | `/api/auth/login` | 로그인 (토큰 발급) | X |
| GET | `/api/agents` | 에이전트 목록 | O |
| GET | `/api/agents/:id` | 에이전트 상세 | O |
| DELETE | `/api/agents/:id` | 에이전트 삭제 | O |
| PUT | `/api/agents/:id/status` | 에이전트 상태 변경 | O |
| POST | `/api/agents/:id/baseline` | 베이스라인 생성 명령 | O |
| POST | `/api/agents/:id/scan` | 무결성 스캔 명령 | O |
| GET | `/api/alerts` | 알림 목록 (필터 지원) | O |
| GET | `/api/events/stream` | 실시간 이벤트 (SSE) | O |

> 자세한 API 명세는 `API_DOCUMENTATION.md`를 참고하세요.

## 참고사항

- **CommandSender**는 현재 `nil`로 설정되어 있어, 베이스라인 생성/스캔 명령 API는 `503` 응답을 반환합니다. Collector 연동 후 정상 동작합니다.
- JWT 토큰 만료 시간은 **24시간**입니다.
- 서버 기본 포트는 **8080**입니다.