# KN-IMS backend-agent setup guide

## 1. 목적

- docker backend 기동 절차
- VM agent 설정 절차
- agent registration 확인 절차
- cleanup 절차

## 2. 기본 변수

```text
BACKEND_HOST=192.168.64.1
VM_TARGET=user@192.168.64.11
VM_PASSWORD=<VM sudo/ssh password>
PROJECT_ROOT=KN-IMS
```

## 3. Host flow

### 3-1. backend docker setup

```bash
cd KN-IMS

sudo ./setup_backend_agent_runtime.sh \
  -m backend \
  --backend-runtime docker \
  -c 192.168.64.1 \
  -v user@192.168.64.11 \
  -p <VM_PASSWORD>
```

### 3-2. backend 상태 확인

```bash
curl -fsS http://127.0.0.1:8080/api/agents
curl -fsS 'http://127.0.0.1:8080/api/events?limit=20'
curl -fsS 'http://127.0.0.1:8080/api/alerts?limit=20'
```

### 3-3. backend 로그 확인

```bash
docker logs -f knims-backend-runtime-test
docker exec -it -u knims knims-backend-runtime-test bash
```

## 4. VM flow

### 4-1. VM 접속

```bash
ssh user@192.168.64.11
```

### 4-2. agent cert/env setup

```bash
cd /home/user/KN-IMS
sudo ./setup_backend_agent_runtime.sh -m agent -c 192.168.64.1 --tcp-addr :9000
```

### 4-3. agent build 및 service install

```bash
cd /home/user/KN-IMS/Agent

sudo ./scripts/setup_ebpf_deps.sh
cmake -S . -B build
cmake --build build
sudo ./scripts/install_agent_service.sh
```

### 4-4. apt recovery 절차

```bash
sudo apt --fix-broken install -y
```

## 5. registration verification flow

### 5-1. VM 측 상태 확인

```bash
sudo systemctl status fileguard.service --no-pager
sudo ss -tnp | grep :9000
sudo journalctl -u fileguard.service -n 100 --no-pager
```

### 5-2. Host 측 agent 조회

```bash
curl -fsS http://127.0.0.1:8080/api/agents
```

### 5-3. 성공 기준

- `fileguard.service` active 상태
- `ESTAB <vm-ip> -> <backend-host>:9000` 상태
- `/api/agents` 기준 `Status":"online"` 응답

## 6. 빠른 실행 순서

### 6-1. Host

```bash
cd KN-IMS

sudo ./setup_backend_agent_runtime.sh \
  -m backend \
  --backend-runtime docker \
  -c 192.168.64.1 \
  -v user@192.168.64.11 \
  -p <VM_PASSWORD>

curl -fsS http://127.0.0.1:8080/api/agents
```

### 6-2. VM

```bash
ssh user@192.168.64.11

cd /home/user/KN-IMS
sudo ./setup_backend_agent_runtime.sh -m agent -c 192.168.64.1 --tcp-addr :9000

cd /home/user/KN-IMS/Agent
sudo ./scripts/setup_ebpf_deps.sh
cmake -S . -B build
cmake --build build
sudo ./scripts/install_agent_service.sh

sudo systemctl status fileguard.service --no-pager
sudo ss -tnp | grep :9000
```

### 6-3. Host 재확인

```bash
curl -fsS http://127.0.0.1:8080/api/agents
```

## 7. duplicate cleanup flow

### 7-1. agent 정리

```bash
sudo systemctl stop fileguard.service 2>/dev/null || true
sudo pkill -TERM -f '/usr/local/bin/agent|/build/agent' 2>/dev/null || true
sleep 1
sudo pkill -KILL -f '/usr/local/bin/agent|/build/agent' 2>/dev/null || true
sudo systemctl start fileguard.service
```

### 7-2. backend 정리

```bash
docker rm -f knims-backend-runtime-test
docker image rm -f knims-backend-runtime-test:22.04
```

### 7-3. service 비활성화

```bash
sudo systemctl stop fileguard.service
sudo systemctl disable fileguard.service
```

## 8. script flow summary

### `setup_backend_agent_runtime.sh`

- backend mode orchestration
- agent cert/env 설치
- docker backend flow 연결
- VM sync flow 연결

### `scripts/setup_backend_agent_runtime/certs.sh`

- cert source 탐색
- cert consistency 확인
- legacy cert generation

### `scripts/setup_backend_agent_runtime/modules.sh`

- backend dependency 설치
- Go toolchain 준비
- MySQL setup 지원

### `scripts/setup_backend_agent_runtime/vm_sync.sh`

- VM directory 준비
- Agent code 및 cert 전송
- remote follow-up command 안내

### `Agent/scripts/install_agent_service.sh`

- fileguard service 정리
- stale process cleanup
- binary/config/systemd unit 설치
- enable/start 처리

### `docker/backend-runtime-test/Dockerfile`

- backend runtime test image 정의
- systemd 기반 runtime 환경 준비

### `docker/backend-runtime-test/start.sh`

- test image build
- test container run
- container shell 안내

## 9. 검증 범위

- docker backend startup 검증
- VM agent service startup 검증
- collector TCP connection 검증
- `/api/agents` 기준 agent registration 검증
