#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_CERT_DIR="${ROOT_DIR}/certs"

# Defaults
OUT_DIR=""
BACKEND_HOST=""
CA_CN="KN-IMS Legacy Root CA"
SERVER_CN="KN-IMS Backend"
AGENT_CN="KN-IMS Agent"

usage() {
    cat <<'EOF'
Usage:
  ./gen_certs.sh [options]

Options:
  -o, --out-dir PATH       Output directory for generated certs
                           (default: <repo>/certs/generated-legacy)
  --backend-host VALUE     Backend IP or hostname to include in server cert SAN
                           (e.g. 192.168.27.133)
  --ca-cn VALUE            CA certificate CN       (default: KN-IMS Legacy Root CA)
  --server-cn VALUE        Server certificate CN   (default: KN-IMS Backend)
  --agent-cn VALUE         Agent certificate CN    (default: KN-IMS Agent)
  -h, --help               Show this help

Description:
  Generates a self-signed RSA-2048 / SHA-256 mTLS certificate bundle:
    ca.key / ca.crt        — Root CA
    server.key / server.crt — Backend server cert  (serverAuth, SAN: localhost + backend IP)
    agent.key  / agent.crt  — Agent client cert    (clientAuth)

  Re-running the script overwrites existing files in the output directory.
EOF
}

log() { printf '[*] %s\n' "$*"; }
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "필수 명령이 없습니다: $1"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--out-dir)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        --backend-host)
            BACKEND_HOST="${2:-}"
            shift 2
            ;;
        --ca-cn)
            CA_CN="${2:-}"
            shift 2
            ;;
        --server-cn)
            SERVER_CN="${2:-}"
            shift 2
            ;;
        --agent-cn)
            AGENT_CN="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "알 수 없는 옵션: $1  (--help 로 사용법 확인)"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
require_command openssl

[[ -n "$OUT_DIR" ]] || OUT_DIR="${BACKEND_CERT_DIR}/generated-legacy"
mkdir -p "$OUT_DIR"

ca_key="${OUT_DIR}/ca.key"
ca_crt="${OUT_DIR}/ca.crt"
server_key="${OUT_DIR}/server.key"
server_csr="${OUT_DIR}/server.csr"
server_crt="${OUT_DIR}/server.crt"
agent_key="${OUT_DIR}/agent.key"
agent_csr="${OUT_DIR}/agent.csr"
agent_crt="${OUT_DIR}/agent.crt"
server_ext="${OUT_DIR}/server_ext.cnf"
agent_ext="${OUT_DIR}/agent_ext.cnf"

log "구형 호환 인증서 생성 (RSA 2048 + SHA256)"
log "출력 디렉토리: ${OUT_DIR}"

# --- CA ---
log "CA 생성 중..."
openssl genrsa -out "$ca_key" 2048
openssl req -x509 -new -sha256 -days 3650 \
    -key "$ca_key" \
    -out "$ca_crt" \
    -subj "/CN=${CA_CN}"

# --- Server cert (serverAuth + SAN) ---
cat > "$server_ext" <<EOF
[v3_server]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF

if [[ -n "$BACKEND_HOST" ]]; then
    if [[ "$BACKEND_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf 'IP.2=%s\n' "$BACKEND_HOST" >> "$server_ext"
        log "Server SAN에 IP 추가: ${BACKEND_HOST}"
    else
        printf 'DNS.2=%s\n' "$BACKEND_HOST" >> "$server_ext"
        log "Server SAN에 DNS 추가: ${BACKEND_HOST}"
    fi
fi

log "Server 인증서 생성 중..."
openssl genrsa -out "$server_key" 2048
openssl req -new -sha256 \
    -key "$server_key" \
    -out "$server_csr" \
    -subj "/CN=${SERVER_CN}"
openssl x509 -req -sha256 -days 3650 \
    -in "$server_csr" \
    -CA "$ca_crt" \
    -CAkey "$ca_key" \
    -CAcreateserial \
    -out "$server_crt" \
    -extfile "$server_ext" \
    -extensions v3_server

# --- Agent cert (clientAuth) ---
cat > "$agent_ext" <<'EOF'
[v3_agent]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

log "Agent 인증서 생성 중..."
openssl genrsa -out "$agent_key" 2048
openssl req -new -sha256 \
    -key "$agent_key" \
    -out "$agent_csr" \
    -subj "/CN=${AGENT_CN}"
openssl x509 -req -sha256 -days 3650 \
    -in "$agent_csr" \
    -CA "$ca_crt" \
    -CAkey "$ca_key" \
    -CAcreateserial \
    -out "$agent_crt" \
    -extfile "$agent_ext" \
    -extensions v3_agent

# --- Cleanup temp files ---
rm -f "$server_csr" "$agent_csr" "$server_ext" "$agent_ext"

cat <<EOF

legacy mTLS 인증서 생성 완료
  dir        : ${OUT_DIR}
  ca.crt     : ${ca_crt}
  server.crt : ${server_crt}
  server.key : ${server_key}
  agent.crt  : ${agent_crt}
  agent.key  : ${agent_key}

다음 단계:
  Backend  : setup_backend_agent_runtime.sh -m backend \\
               --ca-src ${ca_crt} \\
               --server-cert-src ${server_crt} \\
               --server-key-src  ${server_key}
  Agent VM : setup_backend_agent_runtime.sh -m agent \\
               --ca-src ${ca_crt} \\
               --agent-cert-src ${agent_crt} \\
               --agent-key-src  ${agent_key}
EOF
