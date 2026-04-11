# Backend

KN-IMS Backend는 agent가 전송한 이벤트를 수집하고 저장하며,
frontend에 실시간으로 전달하는 collector backend입니다.

## 역할

- mTLS 기반 TCP collector로 agent 연결 수락
- agent REGISTER, HEARTBEAT, FILE_EVENT 처리
- MySQL에 agent 상태와 file event 저장
- SSE로 frontend에 실시간 event 전달
- anomaly engine으로 burst 기반 alert 생성

## 현재 통신 흐름

1. agent가 collector에 mTLS로 연결
2. REGISTER로 `agent_id`, `hostname`, `ip`, `monitor_type`, `os` 등록
3. HEARTBEAT로 `last_seen` 갱신
4. FILE_EVENT를 collector로 전송
5. backend가 event를 DB에 저장
6. 저장된 event를 SSE로 publish
7. 짧은 시간에 event가 몰리면 burst alert 생성

현재 transport에서 사용하는 메시지는 아래 3개입니다.

- `REGISTER`
- `HEARTBEAT`
- `FILE_EVENT`

`COMMAND`, `SCAN_RESULT`는 현재 backend runtime 경로에서 사용하지 않습니다.

## 디렉토리 구조

- `cmd/server`
  backend 진입점
- `internal/api`
  frontend가 호출하는 HTTP API와 SSE
- `internal/collector`
  TCP collector, TLS 설정, message decode
- `internal/engine`
  anomaly rule 처리
- `internal/store`
  MySQL 저장 계층

## API

주요 API는 아래와 같습니다.

- `GET /api/agents`
- `GET /api/agents/:id`
- `DELETE /api/agents/:id`
- `PUT /api/agents/:id/status`
- `GET /api/events`
- `GET /api/events/stream`
- `GET /api/alerts`
- `PATCH /api/alerts/:id/resolve`

## TLS / 인증

collector는 mTLS를 사용합니다.

- server는 `TLS_CERT`, `TLS_KEY`로 서버 인증서를 제시
- client agent는 `IM_AGENT_CRT`, `IM_AGENT_KEY`로 클라이언트 인증서를 제시
- backend는 `TLS_CA` 기준으로 agent 인증서를 검증

현재 backend 최소 TLS 버전은 `TLS 1.2`입니다.
구형 OpenSSL agent도 붙을 수 있게 낮췄고, 최신 agent는 TLS 1.3으로 협상할 수 있습니다.

구형 호환이 필요한 환경에서는 인증서를 `RSA 2048 + SHA256`로 생성하는 것을 권장합니다.

## 실행

`.env` 예시:

```env
DATABASE_URL=root@tcp(127.0.0.1:3306)/fileguard?parseTime=true
HTTP_ADDR=:18080
TCP_ADDR=:9000
TLS_CA=/abs/path/ca.crt
TLS_CERT=/abs/path/server.crt
TLS_KEY=/abs/path/server.key
```

실행:

```bash
cd Backend
go run ./cmd/server
```

## 검증 포인트

backend가 정상 동작하면 아래를 확인할 수 있습니다.

- `/api/agents` 에서 `Status=online`, `MonitorType=ebpf|lkm`
- `/api/events` 에서 최신 event의 `DetectedBy=ebpf|lkm`
- `/api/events/stream` 에서 SSE 수신
- `/api/alerts` 에서 burst alert 확인

## 참고

backend는 현재 `file_hash`를 transport나 API 모델에 포함하지 않습니다.
FILE_EVENT는 경로, 타입, permission, detected_by, pid, timestamp 중심으로 처리합니다.
