#!/usr/bin/env bash
# setup_backend.sh — Backend 통합 셋업 (Ubuntu 24.04.4 LTS / x86_64).
#   Go + MySQL 설치 → DB/계정/스키마 → mTLS 인증서 → .env 까지.

set -euo pipefail

# ── 환경별로 직접 수정 ────────────────────────────
BACKEND_HOST="192.168.64.10"
DB_NAME="integrityguard"
DB_USER="integrityguard_app"
DB_PASS="integrityguard"
HTTP_ADDR=":8080"
TCP_ADDR=":9000"
GO_VERSION="1.25.5"
CA_CN="KN-IG Legacy Root CA"
SERVER_CN="KN-IG Backend"
AGENT_CN="KN-IG Agent"
# ──────────────────────────────────────────────────

log() { printf '[*] %s\n' "$*"; }
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_DIR="${ROOT_DIR}/Backend"
SCHEMA_FILE="${BACKEND_DIR}/internal/store/schema.sql"
CERT_DIR="${BACKEND_DIR}/certs"
ENV_FILE="${BACKEND_DIR}/.env"

export PATH="$PATH:/usr/local/go/bin"

# ── 사전 검증 ─────────────────────────────────────
[[ "$(uname -s)" == "Linux" ]]   || die "Linux 전용 — 현재: $(uname -s)"
[[ "$(uname -m)" == "x86_64" ]]  || die "x86_64 전용 — 현재: $(uname -m)"
command -v apt-get >/dev/null    || die "apt-get 필요"
command -v sudo    >/dev/null    || die "sudo 필요"
command -v openssl >/dev/null    || die "openssl 필요"
command -v curl    >/dev/null    || die "curl 필요"
[[ -f "$SCHEMA_FILE" ]]          || die "schema.sql 없음: $SCHEMA_FILE"

# Ubuntu 24.04 확인
if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
        log "경고: Ubuntu 24.04를 가정하지만 현재 ${PRETTY_NAME:-unknown}"
    fi
fi

# ── Go ────────────────────────────────────────────
install_go() {
    if command -v go >/dev/null 2>&1 && go version | grep -q "go${GO_VERSION} "; then
        log "Go ${GO_VERSION} 이미 설치됨, 스킵"
        return
    fi
    log "Go ${GO_VERSION} 설치 (linux-amd64 tarball)"
    local tmp; tmp="$(mktemp)"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "$tmp"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$tmp"
    rm -f "$tmp"
    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh >/dev/null
    sudo chmod 644 /etc/profile.d/go.sh
}

# ── MySQL ─────────────────────────────────────────
install_mysql() {
    if command -v mysql >/dev/null 2>&1 && systemctl is-active --quiet mysql; then
        log "MySQL 이미 설치/구동 중, 스킵"
        return
    fi
    log "MySQL 8.0 설치 (apt)"
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server
    sudo systemctl enable --now mysql
}

# ── DB / 계정 / 스키마 ────────────────────────────
setup_db() {
    log "DB '${DB_NAME}', 계정 '${DB_USER}@localhost' 준비"
    sudo mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER  '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
    sudo mysql "$DB_NAME" < "$SCHEMA_FILE"
}

# ── mTLS 인증서 ───────────────────────────────────
sign_cert() {
    local name="$1" subj="$2" cnf="$3"
    openssl genrsa -out "${name}.key" 2048 2>/dev/null
    openssl req -new -sha256 -key "${name}.key" -out "${name}.csr" \
        -subj "$subj" 2>/dev/null
    openssl x509 -req -sha256 -days 3650 \
        -in "${name}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${name}.crt" -extfile "$cnf" -extensions v3 2>/dev/null
}

gen_certs() {
    log "mTLS 인증서 생성: ${CERT_DIR}"
    mkdir -p "$CERT_DIR"
    (
        cd "$CERT_DIR"
        openssl genrsa -out ca.key 2048 2>/dev/null
        openssl req -x509 -new -sha256 -days 3650 \
            -key ca.key -out ca.crt -subj "/CN=${CA_CN}" 2>/dev/null

        {
            cat <<EOF
[v3]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt
[alt]
DNS.1=localhost
IP.1=127.0.0.1
EOF
            if [[ "$BACKEND_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "IP.2=${BACKEND_HOST}"
            else
                echo "DNS.2=${BACKEND_HOST}"
            fi
        } > server.cnf

        cat > agent.cnf <<EOF
[v3]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

        sign_cert server "/CN=${SERVER_CN}" server.cnf
        sign_cert agent  "/CN=${AGENT_CN}"  agent.cnf

        rm -f ./*.csr ./*.cnf ca.srl
        chmod 600 ./*.key
        chmod 644 ./*.crt

        openssl verify -CAfile ca.crt server.crt
        openssl verify -CAfile ca.crt agent.crt
    )
}

# ── Backend/.env ──────────────────────────────────
write_env() {
    log "Backend/.env 작성"
    cat > "$ENV_FILE" <<EOF
DATABASE_URL=${DB_USER}:${DB_PASS}@tcp(localhost:3306)/${DB_NAME}?parseTime=true
HTTP_ADDR=${HTTP_ADDR}
TCP_ADDR=${TCP_ADDR}
TLS_CA=./certs/ca.crt
TLS_CERT=./certs/server.crt
TLS_KEY=./certs/server.key
EOF
    chmod 600 "$ENV_FILE"
}

# ── 빌드 사전 검증 (캐시 워밍 + 컴파일 오류 조기 발견) ──
build_check() {
    command -v go >/dev/null || die "go 명령 못 찾음 — PATH 확인"
    log "빌드 사전 검증 (go build → /dev/null)"
    (cd "$BACKEND_DIR" && go build -o /dev/null ./cmd/server)
}

# ── 실행 순서 ─────────────────────────────────────
install_go
install_mysql
setup_db
gen_certs
write_env
build_check

log "Backend setup 완료"
log "  cert dir : ${CERT_DIR}"
log "  env file : ${ENV_FILE}"
log ""
log "백엔드 실행 (새 터미널):"
log "  cd ${BACKEND_DIR} && go run ./cmd/server"
