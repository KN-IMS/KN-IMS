# KN-IG Setup

IG-Server / IG-Agent 두 VM 구성을 가정한다.

---

## 0. 테스트 환경

| 역할     | 호스트                        | 비고                              |
|----------|-------------------------------|-----------------------------------|
| Server   | `server@192.168.64.10`   | Backend (Go) + MySQL              |
| Agent    | `agent@192.168.64.11`     | Agent (LKM / eBPF)    |

- 두 VM은 서로 통신 가능해야 한다.
  - Agent → Server: TCP `9000` (mTLS)
  - HOST → 양 VM: SSH `22`

### SSH Alias Setting

이후 모든 단계는 HOST의 `~/.ssh/config`에 두 별칭이 등록되어 있다고 가정한다.

```sshconfig
Host IG-Server
    HostName 192.168.64.10
    User     server
    IdentityFile ~/.ssh/ig_server
    IdentitiesOnly yes

Host IG-Agent
    HostName 192.168.64.11
    User     agent
    IdentityFile ~/.ssh/ig_agent
    IdentitiesOnly yes
```

키 생성·배포:

```bash
# HOST

ssh-keygen -t ed25519 -N '' -f ~/.ssh/ig_server
ssh-keygen -t ed25519 -N '' -f ~/.ssh/ig_agent
ssh-copy-id -i ~/.ssh/ig_server.pub server@192.168.64.10
ssh-copy-id -i ~/.ssh/ig_agent.pub  agent@192.168.64.11
ssh IG-Server true && ssh IG-Agent true && echo OK
```

터미널에 `OK`가 출력되면 검증된 것.

---

## 1. IG-Server Setup

Ubuntu 24.04.4 LTS (x86_64) 환경을 가정.
스크립트 실행 전 `setup/setup_backend.sh` 상단의 `BACKEND_HOST`를 실제 환경에 맞게 수정.

```bash
# IG-Server

cd ~/KN-IG
./setup/setup_backend.sh
```

`setup_backend.sh`가 일괄 처리하는 것:

| 단계         | 처리 내용                                                                  |
|--------------|----------------------------------------------------------------------------|
| Runtime 설치 | Go 1.25.5 (tarball → `/usr/local/go`) + MySQL 8.0 (`apt`) — 이미 있으면 스킵 |
| DB 초기화    | DB/계정/스키마 (`Backend/internal/store/schema.sql`)                       |
| mTLS 인증서  | CA + server(SAN: `BACKEND_HOST`) + agent(`clientAuth`) → `Backend/certs/`   |
| `.env`       | `DATABASE_URL`, `HTTP_ADDR`, `TCP_ADDR`, `TLS_*` → `Backend/.env`            |
| 빌드 사전검증 | `go build -o /dev/null ./cmd/server`               |

서버 실행:

```bash
# IG-Server

cd ~/KN-IG/Backend
go run ./cmd/server
```

검증 (별도 터미널):

```bash
# IG-Server

curl -sS http://127.0.0.1:8080/api/agents
curl -sS "http://127.0.0.1:8080/api/events?limit=5"
curl -sS "http://127.0.0.1:8080/api/alerts?limit=5"
```

세 응답 모두 `null`이면 OK (DB 비어있는 정상 상태).

---

## 2. 인증서 전달 (Server → Agent)

`setup_backend.sh`가 만든 ca/agent 인증서 3종을 Agent VM에 스테이징한다.

```bash
# HOST

mkdir -p /tmp/ig_certs
scp -q IG-Server:KN-IG/Backend/certs/ca.crt    /tmp/ig_certs/
scp -q IG-Server:KN-IG/Backend/certs/agent.crt /tmp/ig_certs/
scp -q IG-Server:KN-IG/Backend/certs/agent.key /tmp/ig_certs/

ssh IG-Agent 'mkdir -p ~/KN-IG/Agent/certs'
scp -q /tmp/ig_certs/* IG-Agent:KN-IG/Agent/certs/
ssh IG-Agent 'cd ~/KN-IG/Agent/certs && chmod 644 ca.crt agent.crt && chmod 600 agent.key'

rm -rf /tmp/ig_certs
```

검증:

```bash
# IG-Agent

cd ~/KN-IG/Agent/certs
openssl verify -CAfile ca.crt agent.crt
```

`agent.crt: OK`이면 OK.

---

## 3. IG-Agent Setup

Ubuntu 24.04.4 LTS (x86_64) 환경을 가정.
스크립트 실행 전 `setup/setup_agent.sh` 상단의 `BACKEND_HOST`를 Server IP로 맞춘다.

```bash
# IG-Agent

cd ~/KN-IG
./setup/setup_agent.sh
```

`setup_agent.sh`가 일괄 처리하는 것:

| 단계         | 처리 내용                                                                                                       |
|--------------|----------------------------------------------------------------------------------------------------------------|
| Runtime 설치 | eBPF deps (clang/llvm/libbpf/headers) + libssl-dev + libsystemd-dev + pkg-config + LSM `bpf` GRUB 자동 활성화   |
| LSM 검사     | `/sys/kernel/security/lsm`에 `bpf` 미포함이면 재부팅 안내 후 종료 (재실행 시 이어서 진행)                       |
| 빌드         | cmake configure + build → `Agent/build/agent`                                                                  |
| init         | `/etc/ig_monitor/{certs/, ig.env, ig.conf}` + `/usr/local/bin/agent` + systemd unit + enable·start |

LSM에 `bpf`가 없다면 GRUB만 갱신하고 종료한다.
재부팅 후 같은 스크립트를 한 번 더 실행하면 빌드·init 단계로 이어진다.

```bash
# IG-Agent

sudo reboot
# 재기동 후
cd ~/KN-IG && ./setup/setup_agent.sh
```

검증:

```bash
# IG-Agent

sudo systemctl is-active integrityguard.service
sudo journalctl -u integrityguard.service --no-pager -n 5
```

검증:

```bash
# IG-Server

curl -sS http://127.0.0.1:8080/api/agents
```

`AgentID`, `Hostname`, `IP:"<agent-ip>"`, `MonitorType:"ebpf"`, `Status:"online"`이 보이면 end-to-end 성공.

---

## 4. 동작 검증

Agent VM에서 보호 대상 파일에 쓰기 시도 (`/etc/skel/.bashrc`는 `[watch] /etc = recursive` 정책에 포함되는 무해한 템플릿 파일):

```bash
# IG-Agent

sudo bash -c 'echo "# test event" >> /etc/skel/.bashrc'
```

기대: `bash: /etc/skel/.bashrc: Operation not permitted` (LSM이 차단).
파일 내용은 변하지 않는다.

Agent 로그:

```bash
# IG-Agent

sudo journalctl -u integrityguard.service --no-pager --since "30 sec ago" | grep ebpf
```

`[ALERT] [ebpf] DENY WRITE hook=file_open path=/etc/skel/.bashrc ...`이 보이면 OK.

Backend에서 이벤트 조회:

```bash
# IG-Server

curl -sS "http://127.0.0.1:8080/api/events?limit=5"
```

`AgentID`, `EventType:"MODIFY"`, `FilePath:"/etc/skel/.bashrc"`, `DetectedBy:"ebpf"`가 포함된 JSON이 반환되면 end-to-end 동작 확인.

---
