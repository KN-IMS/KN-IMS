# FileGuard Backend REST API Documentation

## Base URL

```
http://<server-ip>:8080/api
```

## Authentication

JWT(JSON Web Token) 기반 인증을 사용합니다.
로그인 후 발급받은 토큰을 모든 API 요청의 헤더에 포함해야 합니다.

```
Authorization: Bearer <JWT_TOKEN>
```

토큰 만료 시간: 24시간

---

## Auth API (인증 불필요)

### POST /api/auth/register

사용자 계정 생성

**Request Body:**

```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response (201):**

```json
{
  "message": "user created"
}
```

**Error (409):**

```json
{
  "error": "username already exists"
}
```

---

### POST /api/auth/login

로그인 및 JWT 토큰 발급

**Request Body:**

```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response (200):**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error (401):**

```json
{
  "error": "invalid credentials"
}
```

---

## Agent API (인증 필요)

### GET /api/agents

전체 에이전트 목록 조회

**Response (200):**

```json
[
  {
    "AgentID": "abc-123-def",
    "Hostname": "server-01",
    "IP": "192.168.1.10",
    "OS": "Ubuntu 24.04",
    "Version": "1.0.0",
    "Status": 1,
    "RegisteredAt": "2026-04-09T12:00:00Z",
    "LastSeenAt": "2026-04-09T12:30:00Z"
  }
]
```

> Status: 1 = online, 0 = offline

---

### GET /api/agents/:id

단일 에이전트 상세 조회

**Path Parameter:**

- `id` — 에이전트 UUID

**Response (200):**

```json
{
  "AgentID": "abc-123-def",
  "Hostname": "server-01",
  "IP": "192.168.1.10",
  "OS": "Ubuntu 24.04",
  "Version": "1.0.0",
  "Status": 1,
  "RegisteredAt": "2026-04-09T12:00:00Z",
  "LastSeenAt": "2026-04-09T12:30:00Z"
}
```

**Error (404):**

```json
{
  "error": "agent not found"
}
```

---

### DELETE /api/agents/:id

에이전트 삭제 (관련 file, alert 데이터도 CASCADE 삭제)

**Path Parameter:**

- `id` — 에이전트 UUID

**Response (200):**

```json
{
  "message": "agent deleted"
}
```

---

### PUT /api/agents/:id/status

에이전트 상태 수동 변경

**Path Parameter:**

- `id` — 에이전트 UUID

**Request Body:**

```json
{
  "status": 0
}
```

> status: 1 = online, 0 = offline

**Response (200):**

```json
{
  "message": "status updated"
}
```

---

## Command API (인증 필요)

### POST /api/agents/:id/baseline

에이전트에 베이스라인 생성 명령 전송

**Path Parameter:**

- `id` — 에이전트 UUID

**Request Body:**

```json
{
  "path": "/etc"
}
```

**Response (200):**

```json
{
  "message": "baseline command sent",
  "agent_id": "abc-123-def",
  "path": "/etc"
}
```

**Error (503):**

```json
{
  "error": "command sender not available"
}
```

---

### POST /api/agents/:id/scan

에이전트에 무결성 스캔 명령 전송

**Path Parameter:**

- `id` — 에이전트 UUID

**Request Body:**

```json
{
  "path": "/etc"
}
```

**Response (200):**

```json
{
  "message": "scan command sent",
  "agent_id": "abc-123-def",
  "path": "/etc"
}
```

**Error (503):**

```json
{
  "error": "command sender not available"
}
```

---

## Alert API (인증 필요)

### GET /api/alerts

알림 목록 조회 (필터 지원)

**Query Parameters:**
| 파라미터 | 타입 | 설명 | 예시 |
|---------|------|------|------|
| agent_id | string | 에이전트 필터 | agent_id=abc-123 |
| event_type | string | 이벤트 타입 필터 | event_type=MODIFY |
| from | string | 시작 시각 (RFC3339) | from=2026-04-01T00:00:00Z |
| to | string | 종료 시각 (RFC3339) | to=2026-04-09T23:59:59Z |
| limit | int | 최대 조회 수 | limit=20 |
| offset | int | 건너뛸 수 | offset=0 |

**Response (200):**

```json
[
  {
    "AlertID": 1,
    "AgentID": "abc-123-def",
    "FilePath": "/etc/passwd",
    "EventType": "MODIFY",
    "DetectedAt": "2026-04-09T14:23:10Z"
  }
]
```

**Example:**

```bash
curl 'http://<ip>:8080/api/alerts?agent_id=abc-123&event_type=MODIFY&limit=20' \
  -H "Authorization: Bearer <TOKEN>"
```

---

## SSE API (인증 필요)

### GET /api/events/stream

실시간 파일 변경 이벤트 스트리밍 (Server-Sent Events)

**Response:** `text/event-stream`

```
data:{"AlertID":0,"AgentID":"abc-123","FilePath":"/etc/test.txt","EventType":"CREATE","DetectedAt":"2026-04-09T14:43:50Z"}

data:{"AlertID":0,"AgentID":"abc-123","FilePath":"/etc/test.txt","EventType":"MODIFY","DetectedAt":"2026-04-09T14:43:50Z"}
```

**Example:**

```bash
curl -N 'http://<ip>:8080/api/events/stream' \
  -H "Authorization: Bearer <TOKEN>"
```

---

## Error Responses

모든 에러는 아래 형식으로 반환됩니다.

```json
{
  "error": "에러 메시지"
}
```

| HTTP Status | 설명                             |
| ----------- | -------------------------------- |
| 200         | 성공                             |
| 201         | 생성 성공                        |
| 400         | 잘못된 요청 (파라미터 오류)      |
| 401         | 인증 실패 (토큰 없음/만료)       |
| 404         | 리소스 없음                      |
| 409         | 충돌 (중복 username)             |
| 500         | 서버 내부 오류                   |
| 503         | 서비스 불가 (CommandSender 없음) |

---

## DB Schema

4개 테이블: user, agent, file, alert

- **user** — 웹 대시보드 로그인 계정
- **agent** — 모니터링 대상 호스트 정보
- **file** — 파일 베이스라인 (정상 상태 기준선)
- **alert** — 무결성 이벤트 로그

---

## Quick Start(로컬)

```bash
# 1. .env 설정
cp .env.example .env
# .env에서 MySQL 접속 정보 수정

# 2. 서버 실행 (DB 자동 생성 + 마이그레이션)
go mod tidy
go run cmd/server/main.go

# 3. 회원가입
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# 4. 로그인 (토큰 발급)
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# 5. 토큰으로 API 호출
curl http://localhost:8080/api/agents \
  -H "Authorization: Bearer <발급받은_토큰>"
```
