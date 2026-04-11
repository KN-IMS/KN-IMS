#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="${ROOT_DIR}/Backend"
AGENT_DIR="${ROOT_DIR}/Agent"
BACKEND_CERT_DIR="${ROOT_DIR}/certs"
BACKEND_ENV_FILE="${BACKEND_DIR}/.env"
BACKEND_SCHEMA_FILE="${BACKEND_DIR}/internal/store/schema.sql"
AGENT_ENV_TEMPLATE="${AGENT_DIR}/configs/im.env"

MODE="all"
DATABASE_URL=""
BACKEND_HOST=""
HTTP_ADDR=":8080"
TCP_ADDR=":9000"
VM_SYNC_ENABLED=0
VM_TARGET=""
VM_HOST=""
VM_USER=""
VM_PORT="22"
VM_REMOTE_DIR=""
CA_SRC=""
SERVER_CERT_SRC=""
SERVER_KEY_SRC=""
AGENT_CERT_SRC=""
AGENT_KEY_SRC=""
SKIP_BACKEND_DEPS=0
GENERATE_LEGACY_CERTS=0
SETUP_DATABASE=1
CERT_OUTPUT_DIR=""
CA_CN="KN-IMS Legacy Root CA"
SERVER_CN="KN-IMS Backend"
AGENT_CN="KN-IMS Agent"
DB_HOST="127.0.0.1"
DB_PORT="3306"
DB_NAME="fileguard"
DB_ADMIN_USER="root"
DB_ADMIN_PASSWORD=""
DB_APP_USER="fileguard_app"
DB_APP_PASSWORD=""

usage() {
    cat <<'EOF'
Usage:
  ./setup_backend_agent_runtime.sh [options]

Modes:
  backend   Install backend dependencies, copy backend certs, write Backend/.env
  agent     Install agent certs/env under /etc/im_monitor with proper permissions
  all       Run backend + agent setup together

Optional:
  -m, --mode VALUE        Run mode: backend, agent, all
  -c, --backend-host VAL  Backend host used by agent transport
  -v, --vm-target VALUE   Sync Agent runtime to VM target (format: user@host)
  --database-url VALUE     Override backend DATABASE_URL directly
  --http-addr VALUE        Backend HTTP listen address (default: :8080)
  --tcp-addr VALUE         Backend collector address (default: :9000)
  --vm-host VALUE          VM host for automatic Agent sync
  --vm-user VALUE          VM SSH user for automatic Agent sync
  --vm-port VALUE          VM SSH port for automatic Agent sync (default: 22)
  --vm-dir VALUE           VM target directory (default: /home/<user>/KN-IMS)
  --generate-legacy-certs  Generate RSA 2048 + SHA256 CA/server/agent certs
  --cert-output-dir PATH   Output directory for generated certs
  --ca-cn VALUE            CA certificate CN (default: KN-IMS Legacy Root CA)
  --server-cn VALUE        Server certificate CN (default: KN-IMS Backend)
  --agent-cn VALUE         Agent certificate CN (default: KN-IMS Agent)
  --skip-db-setup          Do not create DB or apply Backend schema.sql
  --db-host VALUE          MySQL host for backend app and DB setup (default: 127.0.0.1)
  --db-port VALUE          MySQL port for backend app and DB setup (default: 3306)
  --db-name VALUE          MySQL database name (default: fileguard)
  --db-admin-user VALUE    MySQL admin user for CREATE DATABASE/USER (default: root)
  --db-admin-password VAL  MySQL admin password
  --db-app-user VALUE      Backend app DB user (default: fileguard_app)
  --db-app-password VAL    Backend app DB password
  --skip-backend-deps      Do not install backend system packages or run go mod download
  -h, --help               Show help

Examples:
  ./setup_backend_agent_runtime.sh
  ./setup_backend_agent_runtime.sh -m backend
  ./setup_backend_agent_runtime.sh -m backend -v user@192.168.64.11
  sudo ./setup_backend_agent_runtime.sh -m agent -c 192.168.64.1
EOF
}

log() {
    printf '[*] %s\n' "$*"
}

warn() {
    printf '[!] %s\n' "$*" >&2
}

die() {
    printf '[x] %s\n' "$*" >&2
    exit 1
}

is_abs_path() {
    [[ "$1" == /* ]]
}

assert_abs_path() {
    local path="$1"
    local label="$2"
    [[ -n "$path" ]] || die "${label} 값이 비어 있습니다."
    is_abs_path "$path" || die "${label} 는 절대 경로여야 합니다: ${path}"
}

assert_file() {
    local path="$1"
    [[ -f "$path" ]] || die "파일이 없습니다: ${path}"
}

backup_if_exists() {
    local path="$1"
    if [[ -f "$path" ]]; then
        local backup="${path}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$path" "$backup"
        log "백업 생성 -> ${backup}"
    fi
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "agent 모드는 /etc/im_monitor 에 설치하므로 sudo 권한이 필요합니다."
    fi
}

require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "필수 명령이 없습니다: ${cmd}"
}

brew_safe() {
    HOMEBREW_NO_AUTO_UPDATE=1 \
    HOMEBREW_NO_INSTALL_CLEANUP=1 \
    HOMEBREW_NO_ENV_HINTS=1 \
    brew "$@"
}

is_interactive() {
    [[ -t 0 ]]
}

prompt_value() {
    local var_name="$1"
    local prompt="$2"
    local default_value="${3:-}"
    local input=""

    if [[ -n "$default_value" ]]; then
        read -r -p "${prompt} [${default_value}]: " input || true
        if [[ -z "$input" ]]; then
            printf -v "$var_name" '%s' "$default_value"
        else
            printf -v "$var_name" '%s' "$input"
        fi
    else
        while :; do
            read -r -p "${prompt}: " input || true
            if [[ -n "$input" ]]; then
                printf -v "$var_name" '%s' "$input"
                break
            fi
            warn "값을 입력해야 합니다."
        done
    fi
}

prompt_yes_no() {
    local var_name="$1"
    local prompt="$2"
    local default_value="${3:-y}"
    local input=""

    while :; do
        read -r -p "${prompt} [y/n, default=${default_value}]: " input || true
        input="${input:-$default_value}"
        case "$input" in
            y|Y|yes|YES)
                printf -v "$var_name" '%s' "1"
                return 0
                ;;
            n|N|no|NO)
                printf -v "$var_name" '%s' "0"
                return 0
                ;;
        esac
        warn "y 또는 n 으로 입력하세요."
    done
}

generate_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 16
    else
        LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32
    fi
}

prompt_secret() {
    local var_name="$1"
    local prompt="$2"
    local default_value="${3:-}"
    local input=""

    while :; do
        if [[ -n "$default_value" ]]; then
            read -r -s -p "${prompt} [기본값 사용 시 Enter]: " input || true
            printf '\n'
            if [[ -z "$input" ]]; then
                printf -v "$var_name" '%s' "$default_value"
            else
                printf -v "$var_name" '%s' "$input"
            fi
            return 0
        fi

        read -r -s -p "${prompt}: " input || true
        printf '\n'
        printf -v "$var_name" '%s' "$input"
        return 0
    done
}

prompt_abs_path() {
    local var_name="$1"
    local prompt="$2"
    local default_value="${3:-}"
    local value=""

    while :; do
        prompt_value value "$prompt" "$default_value"
        if [[ "$value" == /* ]]; then
            printf -v "$var_name" '%s' "$value"
            return 0
        fi
        warn "절대 경로를 입력해야 합니다: ${value}"
    done
}

parse_vm_target() {
    local target="$1"

    [[ -n "$target" ]] || die "VM SSH 대상이 비어 있습니다."
    [[ "$target" == *@* ]] || die "VM SSH 대상 형식이 올바르지 않습니다. user@host 형태로 입력하세요: ${target}"

    VM_USER="${target%@*}"
    VM_HOST="${target#*@}"

    [[ -n "$VM_USER" ]] || die "VM SSH user를 해석하지 못했습니다: ${target}"
    [[ -n "$VM_HOST" ]] || die "VM host를 해석하지 못했습니다: ${target}"
}

finalize_vm_sync_config() {
    if [[ -n "$VM_TARGET" ]]; then
        parse_vm_target "$VM_TARGET"
    fi

    if [[ -n "$VM_HOST" || -n "$VM_USER" || -n "$VM_TARGET" ]]; then
        VM_SYNC_ENABLED=1
    fi

    if [[ "$VM_SYNC_ENABLED" -ne 1 ]]; then
        return 0
    fi

    [[ -n "$VM_HOST" ]] || die "VM 자동 전송을 사용하려면 VM host가 필요합니다."
    [[ -n "$VM_USER" ]] || die "VM 자동 전송을 사용하려면 VM SSH user가 필요합니다."

    if [[ -z "$VM_REMOTE_DIR" ]]; then
        VM_REMOTE_DIR="/home/${VM_USER}/KN-IMS"
    fi

    [[ "$VM_REMOTE_DIR" == /* ]] || die "VM 대상 디렉토리는 절대 경로여야 합니다: ${VM_REMOTE_DIR}"
    [[ "$VM_REMOTE_DIR" != *[[:space:]]* ]] || die "VM 대상 디렉토리는 공백을 포함할 수 없습니다: ${VM_REMOTE_DIR}"
    [[ "$VM_REMOTE_DIR" != *:* ]] || die "VM 대상 디렉토리는 ':' 문자를 포함할 수 없습니다: ${VM_REMOTE_DIR}"
    [[ "$VM_PORT" =~ ^[0-9]+$ ]] || die "VM SSH port가 올바르지 않습니다: ${VM_PORT}"
}

infer_backend_host() {
    local route_out=""
    local iface=""
    local src_ip=""

    [[ -n "$BACKEND_HOST" ]] && return 0
    [[ "$VM_SYNC_ENABLED" -eq 1 ]] || return 1
    [[ -n "$VM_HOST" ]] || return 1

    if command -v ip >/dev/null 2>&1; then
        route_out="$(ip route get "$VM_HOST" 2>/dev/null | head -n 1 || true)"
        src_ip="$(printf '%s\n' "$route_out" | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n 1)"
        if [[ -n "$src_ip" ]]; then
            BACKEND_HOST="$src_ip"
            return 0
        fi
    fi

    if command -v route >/dev/null 2>&1 && command -v ifconfig >/dev/null 2>&1; then
        route_out="$(route -n get "$VM_HOST" 2>/dev/null || true)"
        iface="$(printf '%s\n' "$route_out" | awk '/interface:/{print $2; exit}')"
        if [[ -n "$iface" ]]; then
            src_ip="$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2; exit}')"
            if [[ -n "$src_ip" ]]; then
                BACKEND_HOST="$src_ip"
                return 0
            fi
        fi
    fi

    return 1
}

infer_mode() {
    if [[ -d "$BACKEND_DIR" && -d "$AGENT_DIR" ]]; then
        if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
            MODE="all"
        else
            MODE="backend"
        fi
        return 0
    fi

    if [[ -d "$BACKEND_DIR" ]]; then
        MODE="backend"
        return 0
    fi

    if [[ -d "$AGENT_DIR" ]]; then
        MODE="agent"
        return 0
    fi

    die "Backend 또는 Agent 디렉토리를 찾지 못해 mode를 자동 판단할 수 없습니다."
}

first_existing_file() {
    local candidate=""
    for candidate in "$@"; do
        if [[ -n "$candidate" && -f "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

port_from_addr() {
    local addr="$1"
    printf '%s\n' "${addr##*:}"
}

find_listen_pids() {
    local port="$1"

    if command -v lsof >/dev/null 2>&1; then
        lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | sort -u
        return 0
    fi

    if command -v ss >/dev/null 2>&1; then
        ss -ltnp "( sport = :$port )" 2>/dev/null | awk -F'pid=' 'NR>1 && NF>1 {split($2,a,","); print a[1]}' | sort -u
        return 0
    fi

    return 1
}

show_port_usage() {
    local port="$1"

    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
        return 0
    fi

    if command -v ss >/dev/null 2>&1; then
        ss -ltnp "( sport = :$port )" 2>/dev/null || true
    fi
}

ensure_port_available() {
    local addr="$1"
    local label="$2"
    local port
    local pids=""
    local kill_conflict="0"

    port="$(port_from_addr "$addr")"
    [[ "$port" =~ ^[0-9]+$ ]] || return 0

    pids="$(find_listen_pids "$port" || true)"
    [[ -n "$pids" ]] || return 0

    warn "${label} 포트 ${port}가 이미 사용 중입니다."
    show_port_usage "$port"

    if ! is_interactive; then
        die "포트 ${port} 충돌을 자동으로 해결할 수 없습니다."
    fi

    prompt_yes_no kill_conflict "포트 ${port}를 사용 중인 프로세스를 종료할까요?" "n"
    if [[ "$kill_conflict" != "1" ]]; then
        die "포트 ${port} 충돌이 해결되지 않았습니다."
    fi

    while read -r pid; do
        [[ -n "$pid" ]] || continue
        kill "$pid" 2>/dev/null || sudo kill "$pid" 2>/dev/null || die "PID ${pid} 종료 실패"
    done <<< "$pids"

    sleep 1

    if [[ -n "$(find_listen_pids "$port" || true)" ]]; then
        die "포트 ${port}가 여전히 사용 중입니다."
    fi

    log "${label} 포트 ${port} 충돌 해결 완료"
}

load_existing_backend_url() {
    if [[ -n "$DATABASE_URL" || ! -f "$BACKEND_ENV_FILE" ]]; then
        return 0
    fi

    local existing_url=""
    existing_url="$(sed -n 's/^DATABASE_URL=//p' "$BACKEND_ENV_FILE" | head -n 1)"
    if [[ -n "$existing_url" ]]; then
        DATABASE_URL="$existing_url"
        parse_database_url_defaults
    fi
}

parse_database_url_defaults() {
    if [[ -z "$DATABASE_URL" ]]; then
        return 0
    fi

    local dsn_re='^([^:@/?]+)(:([^@/?]*))?@tcp\(([^:)]+)(:([0-9]+))?\)/([^?]+)'
    if [[ "$DATABASE_URL" =~ $dsn_re ]]; then
        DB_APP_USER="${BASH_REMATCH[1]}"
        DB_APP_PASSWORD="${BASH_REMATCH[3]}"
        DB_HOST="${BASH_REMATCH[4]}"
        DB_PORT="${BASH_REMATCH[6]:-3306}"
        DB_NAME="${BASH_REMATCH[7]}"
    fi
}

build_database_url() {
    if [[ -n "$DATABASE_URL" ]]; then
        return 0
    fi

    if [[ -n "$DB_APP_PASSWORD" ]]; then
        DATABASE_URL="${DB_APP_USER}:${DB_APP_PASSWORD}@tcp(${DB_HOST}:${DB_PORT})/${DB_NAME}?parseTime=true"
    else
        DATABASE_URL="${DB_APP_USER}@tcp(${DB_HOST}:${DB_PORT})/${DB_NAME}?parseTime=true"
    fi
}

cert_pubkey_matches() {
    local cert_path="$1"
    local key_path="$2"

    diff -q \
        <(openssl x509 -in "$cert_path" -pubkey -noout 2>/dev/null | openssl pkey -pubin -pubout 2>/dev/null) \
        <(openssl pkey -in "$key_path" -pubout 2>/dev/null) \
        >/dev/null 2>&1
}

full_cert_bundle_consistent() {
    [[ -n "$CA_SRC" ]] || return 1
    [[ -n "$SERVER_CERT_SRC" ]] || return 1
    [[ -n "$SERVER_KEY_SRC" ]] || return 1
    [[ -n "$AGENT_CERT_SRC" ]] || return 1
    [[ -n "$AGENT_KEY_SRC" ]] || return 1

    [[ -f "$CA_SRC" ]] || return 1
    [[ -f "$SERVER_CERT_SRC" ]] || return 1
    [[ -f "$SERVER_KEY_SRC" ]] || return 1
    [[ -f "$AGENT_CERT_SRC" ]] || return 1
    [[ -f "$AGENT_KEY_SRC" ]] || return 1

    command -v openssl >/dev/null 2>&1 || return 1

    openssl verify -CAfile "$CA_SRC" "$SERVER_CERT_SRC" >/dev/null 2>&1 || return 1
    openssl verify -CAfile "$CA_SRC" "$AGENT_CERT_SRC" >/dev/null 2>&1 || return 1
    cert_pubkey_matches "$SERVER_CERT_SRC" "$SERVER_KEY_SRC" || return 1
    cert_pubkey_matches "$AGENT_CERT_SRC" "$AGENT_KEY_SRC" || return 1

    return 0
}

resolve_cert_sources() {
    local generated_dir="${CERT_OUTPUT_DIR:-${BACKEND_CERT_DIR}/generated-legacy}"

    if [[ "$MODE" == "backend" || "$MODE" == "all" ]]; then
        if [[ -z "$CA_SRC" ]]; then
            CA_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/ca.crt" \
                "${generated_dir}/ca.crt" \
                "${ROOT_DIR}/ca.crt" || true)"
        fi
        if [[ -z "$SERVER_CERT_SRC" ]]; then
            SERVER_CERT_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/server.crt" \
                "${generated_dir}/server.crt" \
                "${ROOT_DIR}/server.crt" || true)"
        fi
        if [[ -z "$SERVER_KEY_SRC" ]]; then
            SERVER_KEY_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/server.key" \
                "${generated_dir}/server.key" \
                "${ROOT_DIR}/server.key" || true)"
        fi
    fi

    if [[ "$MODE" == "backend" || "$MODE" == "all" || "$VM_SYNC_ENABLED" -eq 1 ]]; then
        if [[ -z "$CA_SRC" ]]; then
            CA_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/ca.crt" \
                "${generated_dir}/ca.crt" \
                "${ROOT_DIR}/ca.crt" || true)"
        fi
        if [[ -z "$AGENT_CERT_SRC" ]]; then
            AGENT_CERT_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/agent.crt" \
                "${generated_dir}/agent.crt" \
                "${ROOT_DIR}/agent.crt" || true)"
        fi
        if [[ -z "$AGENT_KEY_SRC" ]]; then
            AGENT_KEY_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/agent.key" \
                "${generated_dir}/agent.key" \
                "${ROOT_DIR}/agent.key" || true)"
        fi
    fi

    if [[ "$MODE" == "agent" ]]; then
        if [[ -z "$CA_SRC" ]]; then
            CA_SRC="$(first_existing_file \
                "${ROOT_DIR}/ca.crt" \
                "${BACKEND_CERT_DIR}/ca.crt" \
                "${generated_dir}/ca.crt" || true)"
        fi
        if [[ -z "$AGENT_CERT_SRC" ]]; then
            AGENT_CERT_SRC="$(first_existing_file \
                "${ROOT_DIR}/agent.crt" \
                "${BACKEND_CERT_DIR}/agent.crt" \
                "${generated_dir}/agent.crt" || true)"
        fi
        if [[ -z "$AGENT_KEY_SRC" ]]; then
            AGENT_KEY_SRC="$(first_existing_file \
                "${ROOT_DIR}/agent.key" \
                "${BACKEND_CERT_DIR}/agent.key" \
                "${generated_dir}/agent.key" || true)"
        fi
    fi

    if [[ "$MODE" == "backend" || "$MODE" == "all" ]]; then
        if ! full_cert_bundle_consistent; then
            GENERATE_LEGACY_CERTS=1
            [[ -n "$CERT_OUTPUT_DIR" ]] || CERT_OUTPUT_DIR="${generated_dir}"
            log "backend/server/agent 인증서 묶음이 없거나 서로 맞지 않아 legacy mTLS 인증서를 자동 생성합니다."
        fi
    fi
}

interactive_collect_inputs() {
    local enable_vm_sync="0"
    local vm_target_default=""
    local needs_backend_host="0"

    if [[ -n "$VM_TARGET" || -n "$VM_HOST" || -n "$VM_USER" ]]; then
        VM_SYNC_ENABLED=1
    fi

    if ! is_interactive; then
        return 0
    fi

    if [[ "$MODE" == "backend" || "$MODE" == "all" ]]; then
        load_existing_backend_url
        parse_database_url_defaults
        if [[ "$SETUP_DATABASE" -eq 1 ]]; then
            if [[ "$(uname -s)" != "Linux" || "${EUID:-$(id -u)}" -ne 0 || "$DB_ADMIN_USER" != "root" ]]; then
                prompt_secret DB_ADMIN_PASSWORD "MySQL admin password" "${DB_ADMIN_PASSWORD:-}"
            fi
        fi
    fi

    if [[ "$MODE" == "backend" || "$MODE" == "all" ]]; then
        if [[ "$VM_SYNC_ENABLED" -eq 1 ]]; then
            enable_vm_sync="1"
        else
            prompt_yes_no enable_vm_sync "VM으로 Agent 디렉토리와 인증서를 자동 전송할까요?" "n"
        fi

        if [[ "$enable_vm_sync" == "1" ]]; then
            VM_SYNC_ENABLED=1
            if [[ -n "$VM_USER" && -n "$VM_HOST" ]]; then
                vm_target_default="${VM_USER}@${VM_HOST}"
            elif [[ -n "$VM_TARGET" ]]; then
                vm_target_default="$VM_TARGET"
            fi

            prompt_value VM_TARGET "VM SSH 대상 (user@host)" "$vm_target_default"
            parse_vm_target "$VM_TARGET"
        fi
    fi

    if [[ "$MODE" == "agent" || "$MODE" == "all" || "$VM_SYNC_ENABLED" -eq 1 ]]; then
        needs_backend_host="1"
    fi

    if [[ "$needs_backend_host" == "1" ]]; then
        if [[ -z "$BACKEND_HOST" && "$MODE" == "backend" && "$VM_SYNC_ENABLED" -eq 1 ]]; then
            infer_backend_host || true
        fi

        if [[ "$MODE" == "backend" && "$VM_SYNC_ENABLED" -eq 1 && -n "$BACKEND_HOST" ]]; then
            log "backend host 자동 추론: ${BACKEND_HOST}"
        else
            prompt_value BACKEND_HOST "Agent가 붙을 backend host" "${BACKEND_HOST:-192.168.64.1}"
        fi
    fi
}

generate_legacy_certs() {
    require_command openssl

    local out_dir="$CERT_OUTPUT_DIR"
    if [[ -z "$out_dir" ]]; then
        out_dir="${BACKEND_CERT_DIR}/generated-legacy"
    fi

    mkdir -p "$out_dir"

    local ca_key="${out_dir}/ca.key"
    local ca_crt="${out_dir}/ca.crt"
    local server_key="${out_dir}/server.key"
    local server_csr="${out_dir}/server.csr"
    local server_crt="${out_dir}/server.crt"
    local agent_key="${out_dir}/agent.key"
    local agent_csr="${out_dir}/agent.csr"
    local agent_crt="${out_dir}/agent.crt"
    local server_ext="${out_dir}/server_ext.cnf"
    local agent_ext="${out_dir}/agent_ext.cnf"

    log "구형 호환 인증서 생성 (RSA 2048 + SHA256)"

    openssl genrsa -out "$ca_key" 2048
    openssl req -x509 -new -sha256 -days 3650 \
        -key "$ca_key" \
        -out "$ca_crt" \
        -subj "/CN=${CA_CN}"

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
        else
            printf 'DNS.2=%s\n' "$BACKEND_HOST" >> "$server_ext"
        fi
    fi

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

    cat > "$agent_ext" <<'EOF'
[v3_agent]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

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

    CA_SRC="$ca_crt"
    SERVER_CERT_SRC="$server_crt"
    SERVER_KEY_SRC="$server_key"
    AGENT_CERT_SRC="$agent_crt"
    AGENT_KEY_SRC="$agent_key"

    cat <<EOF

legacy mTLS 인증서 생성 완료
  dir        : ${out_dir}
  ca.crt     : ${ca_crt}
  server.crt : ${server_crt}
  server.key : ${server_key}
  agent.crt  : ${agent_crt}
  agent.key  : ${agent_key}

EOF
}

install_backend_deps() {
    if [[ "$SKIP_BACKEND_DEPS" -eq 1 ]]; then
        log "backend 모듈 설치 생략"
        return 0
    fi

    if [[ ! -d "$BACKEND_DIR" ]]; then
        die "Backend 디렉토리가 없습니다: ${BACKEND_DIR}"
    fi

    case "$(uname -s)" in
        Darwin)
            command -v brew >/dev/null 2>&1 \
                || die "macOS에서는 Homebrew가 필요합니다."

            log "backend 모듈 설치 (brew)"
            brew list go >/dev/null 2>&1 || brew_safe install go
            brew list mysql >/dev/null 2>&1 || brew_safe install mysql
            ;;
        Linux)
            if command -v apt-get >/dev/null 2>&1; then
                log "backend 모듈 설치 (apt)"
                sudo apt-get update
                sudo apt-get install -y golang mysql-server
            else
                warn "자동 설치를 지원하지 않는 Linux 배포판입니다. go와 mysql-server를 수동 설치하세요."
            fi
            ;;
        *)
            warn "지원하지 않는 OS입니다. backend 의존성은 수동 설치가 필요할 수 있습니다."
            ;;
    esac

    if command -v go >/dev/null 2>&1; then
        log "Backend Go 모듈 다운로드"
        (cd "$BACKEND_DIR" && go mod download)
    else
        warn "go 명령을 찾지 못해 go mod download를 건너뜁니다."
    fi
}

ensure_mysql_service() {
    require_command mysql

    case "$(uname -s)" in
        Darwin)
            if command -v brew >/dev/null 2>&1; then
                log "MySQL 서비스 시작 확인 (brew services)"
                HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1 \
                    brew services start mysql >/dev/null 2>&1 || true
            fi
            ;;
        Linux)
            if command -v systemctl >/dev/null 2>&1; then
                if systemctl list-unit-files | grep -q '^mysql\.service'; then
                    log "MySQL 서비스 시작 (mysql.service)"
                    sudo systemctl enable --now mysql >/dev/null 2>&1 || true
                elif systemctl list-unit-files | grep -q '^mysqld\.service'; then
                    log "MySQL 서비스 시작 (mysqld.service)"
                    sudo systemctl enable --now mysqld >/dev/null 2>&1 || true
                fi
            fi
            ;;
    esac

    if ! mysqladmin ping >/dev/null 2>&1; then
        warn "기본 mysqladmin ping 확인 실패 — DB 접속 정보 기준으로 계속 진행합니다."
    fi
}

mysql_admin_exec() {
    local sql="$1"
    local mysql_args=()

    if [[ -n "$DB_ADMIN_PASSWORD" ]]; then
        mysql_args+=(-u "$DB_ADMIN_USER" -h "$DB_HOST" -P "$DB_PORT")
        MYSQL_PWD="$DB_ADMIN_PASSWORD" mysql "${mysql_args[@]}" -e "$sql"
        return $?
    fi

    if [[ "$(uname -s)" == "Linux" && "${EUID:-$(id -u)}" -eq 0 && "$DB_ADMIN_USER" == "root" ]]; then
        mysql -e "$sql"
    else
        mysql -u "$DB_ADMIN_USER" -h "$DB_HOST" -P "$DB_PORT" -e "$sql"
    fi
}

mysql_admin_query() {
    local sql="$1"
    local mysql_args=(-N -s)

    if [[ -n "$DB_ADMIN_PASSWORD" ]]; then
        mysql_args+=(-u "$DB_ADMIN_USER" -h "$DB_HOST" -P "$DB_PORT")
        MYSQL_PWD="$DB_ADMIN_PASSWORD" mysql "${mysql_args[@]}" -e "$sql"
        return $?
    fi

    if [[ "$(uname -s)" == "Linux" && "${EUID:-$(id -u)}" -eq 0 && "$DB_ADMIN_USER" == "root" ]]; then
        mysql "${mysql_args[@]}" -e "$sql"
    else
        mysql "${mysql_args[@]}" -u "$DB_ADMIN_USER" -h "$DB_HOST" -P "$DB_PORT" -e "$sql"
    fi
}

mysql_admin_import() {
    local db_name="$1"
    local sql_file="$2"
    local mysql_args=()

    if [[ -n "$DB_ADMIN_PASSWORD" ]]; then
        mysql_args+=(-u "$DB_ADMIN_USER" -h "$DB_HOST" -P "$DB_PORT")
        MYSQL_PWD="$DB_ADMIN_PASSWORD" mysql "${mysql_args[@]}" "$db_name" < "$sql_file"
        return $?
    fi

    if [[ "$(uname -s)" == "Linux" && "${EUID:-$(id -u)}" -eq 0 && "$DB_ADMIN_USER" == "root" ]]; then
        mysql "$db_name" < "$sql_file"
    else
        mysql -u "$DB_ADMIN_USER" -h "$DB_HOST" -P "$DB_PORT" "$db_name" < "$sql_file"
    fi
}

sql_escape() {
    local raw="$1"
    printf "%s" "$raw" | sed "s/'/''/g"
}

setup_database() {
    if [[ "$SETUP_DATABASE" -ne 1 ]]; then
        log "DB 생성 및 schema 적용 생략"
        return 0
    fi

    ensure_mysql_service
    require_command mysql
    [[ -f "$BACKEND_SCHEMA_FILE" ]] || die "schema.sql 파일이 없습니다: ${BACKEND_SCHEMA_FILE}"

    [[ -n "$DB_HOST" ]] || die "DB host 값이 없습니다."
    [[ -n "$DB_PORT" ]] || die "DB port 값이 없습니다."
    [[ -n "$DB_NAME" ]] || die "DB name 값이 없습니다."
    [[ -n "$DB_ADMIN_USER" ]] || die "DB admin user 값이 없습니다."
    [[ -n "$DB_APP_USER" ]] || die "DB app user 값이 없습니다."

    local esc_db_name
    local esc_app_user
    local esc_app_host
    local esc_app_pass
    local db_exists="0"
    local user_exists="0"
    local schema_ready="0"
    esc_db_name="$(sql_escape "$DB_NAME")"
    esc_app_user="$(sql_escape "$DB_APP_USER")"
    esc_app_host="$(sql_escape "$DB_HOST")"

    db_exists="$(mysql_admin_query "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='${esc_db_name}';" | tr -d '[:space:]')" \
        || die "DB 존재 여부 확인 실패"
    if [[ "$db_exists" == "0" ]]; then
        log "DB 생성: ${DB_NAME}"
        mysql_admin_exec "CREATE DATABASE \`${esc_db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" \
            || die "DB 생성 실패: ${DB_NAME}"
    else
        log "기존 DB 감지 — 생성 생략: ${DB_NAME}"
    fi

    user_exists="$(mysql_admin_query "SELECT COUNT(*) FROM mysql.user WHERE user='${esc_app_user}' AND host='${esc_app_host}';" | tr -d '[:space:]')" \
        || die "Backend app 계정 존재 여부 확인 실패"

    if [[ "$user_exists" == "0" ]]; then
        if [[ -z "$DB_APP_PASSWORD" ]]; then
            DB_APP_PASSWORD="$(generate_password)"
            log "Backend app DB password 자동 생성 완료"
        fi
        esc_app_pass="$(sql_escape "$DB_APP_PASSWORD")"

        log "Backend app 계정 생성: ${DB_APP_USER}@${DB_HOST}"
        mysql_admin_exec "CREATE USER '${esc_app_user}'@'${esc_app_host}' IDENTIFIED BY '${esc_app_pass}';" \
            || die "DB app 계정 생성 실패"

        log "Backend app 계정 권한 부여"
        mysql_admin_exec "GRANT ALL PRIVILEGES ON \`${esc_db_name}\`.* TO '${esc_app_user}'@'${esc_app_host}'; FLUSH PRIVILEGES;" \
            || die "DB 권한 부여 실패"
    else
        [[ -n "$DB_APP_PASSWORD" ]] || die "기존 Backend app 계정(${DB_APP_USER}@${DB_HOST})이 있어 비밀번호를 자동 결정할 수 없습니다. 기존 Backend/.env를 유지하거나 --database-url/--db-app-password를 지정하세요."
        log "기존 Backend app 계정 감지 — 생성/권한 부여 생략: ${DB_APP_USER}@${DB_HOST}"
    fi

    schema_ready="$(mysql_admin_query "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${esc_db_name}' AND TABLE_NAME IN ('agents','file_events','alerts');" | tr -d '[:space:]')" \
        || die "기존 schema 존재 여부 확인 실패"
    if [[ "$schema_ready" == "3" ]]; then
        log "기존 schema 감지 — schema.sql 적용 생략"
    else
        log "schema.sql 적용: ${BACKEND_SCHEMA_FILE}"
        mysql_admin_import "$DB_NAME" "$BACKEND_SCHEMA_FILE" || die "schema.sql 적용 실패"
    fi

    log "DB 세팅 완료 (${DB_HOST}:${DB_PORT}/${DB_NAME})"
}

setup_backend() {
    [[ -d "$BACKEND_DIR" ]] || die "Backend 디렉토리가 없습니다: ${BACKEND_DIR}"

    assert_abs_path "$CA_SRC" "ca-src"
    assert_abs_path "$SERVER_CERT_SRC" "server-cert-src"
    assert_abs_path "$SERVER_KEY_SRC" "server-key-src"
    assert_file "$CA_SRC"
    assert_file "$SERVER_CERT_SRC"
    assert_file "$SERVER_KEY_SRC"

    install_backend_deps
    load_existing_backend_url
    parse_database_url_defaults
    ensure_port_available "$HTTP_ADDR" "Backend HTTP"
    ensure_port_available "$TCP_ADDR" "Backend collector"

    log "backend 인증서 동기화"
    mkdir -p "$BACKEND_CERT_DIR"
    install -m 0644 "$CA_SRC" "${BACKEND_CERT_DIR}/ca.crt"
    install -m 0644 "$SERVER_CERT_SRC" "${BACKEND_CERT_DIR}/server.crt"
    install -m 0600 "$SERVER_KEY_SRC" "${BACKEND_CERT_DIR}/server.key"

    setup_database
    build_database_url

    log "Backend/.env 생성"
    backup_if_exists "$BACKEND_ENV_FILE"
    cat > "$BACKEND_ENV_FILE" <<EOF
DATABASE_URL=${DATABASE_URL}
HTTP_ADDR=${HTTP_ADDR}
TCP_ADDR=${TCP_ADDR}
TLS_CA=${BACKEND_CERT_DIR}/ca.crt
TLS_CERT=${BACKEND_CERT_DIR}/server.crt
TLS_KEY=${BACKEND_CERT_DIR}/server.key
EOF

    cat <<EOF

backend 설정 완료
  env  : ${BACKEND_ENV_FILE}
  cert : ${BACKEND_CERT_DIR}/ca.crt
  cert : ${BACKEND_CERT_DIR}/server.crt
  key  : ${BACKEND_CERT_DIR}/server.key
  db   : ${DB_HOST:-미설정}:${DB_PORT:-미설정}/${DB_NAME:-미설정}

backend 실행:
  cd ${BACKEND_DIR}
  go run ./cmd/server

EOF
}

setup_agent() {
    [[ -d "$AGENT_DIR" ]] || die "Agent 디렉토리가 없습니다: ${AGENT_DIR}"
    [[ -n "$BACKEND_HOST" ]] || die "-c/--backend-host 값이 필요합니다."

    [[ -n "$CA_SRC" ]] || die "자동으로 사용할 CA 인증서를 찾지 못했습니다. ${ROOT_DIR}/ca.crt 또는 ${BACKEND_CERT_DIR}/ca.crt 에 인증서를 두고 다시 실행하세요."
    [[ -n "$AGENT_CERT_SRC" ]] || die "자동으로 사용할 Agent 인증서를 찾지 못했습니다. ${ROOT_DIR}/agent.crt 또는 ${BACKEND_CERT_DIR}/generated-legacy/agent.crt 를 준비하세요."
    [[ -n "$AGENT_KEY_SRC" ]] || die "자동으로 사용할 Agent 개인키를 찾지 못했습니다. ${ROOT_DIR}/agent.key 또는 ${BACKEND_CERT_DIR}/generated-legacy/agent.key 를 준비하세요."

    assert_abs_path "$CA_SRC" "ca-src"
    assert_abs_path "$AGENT_CERT_SRC" "agent-cert-src"
    assert_abs_path "$AGENT_KEY_SRC" "agent-key-src"
    assert_file "$CA_SRC"
    assert_file "$AGENT_CERT_SRC"
    assert_file "$AGENT_KEY_SRC"

    require_root

    mkdir -p /etc/im_monitor/certs

    log "Agent env 템플릿 갱신"
    backup_if_exists "$AGENT_ENV_TEMPLATE"
    cat > "$AGENT_ENV_TEMPLATE" <<EOF
# IM Agent transport 설정
# 위치: /etc/im_monitor/im.env
# 권한: sudo chown root:root im.env && sudo chmod 640 im.env

IM_SERVER_HOST=${BACKEND_HOST}
IM_SERVER_PORT=${TCP_ADDR#:}
IM_CA_CRT=/etc/im_monitor/certs/ca.crt
IM_AGENT_CRT=/etc/im_monitor/certs/agent.crt
IM_AGENT_KEY=/etc/im_monitor/certs/agent.key
EOF

    log "agent 인증서 설치"
    install -o root -g root -m 0644 "$CA_SRC" /etc/im_monitor/certs/ca.crt
    install -o root -g root -m 0644 "$AGENT_CERT_SRC" /etc/im_monitor/certs/agent.crt
    install -o root -g root -m 0600 "$AGENT_KEY_SRC" /etc/im_monitor/certs/agent.key

    log "agent env 설치"
    install -o root -g root -m 0640 "$AGENT_ENV_TEMPLATE" /etc/im_monitor/im.env

    cat <<EOF

agent 인증키 및 권한 설정 완료
  env  : /etc/im_monitor/im.env
  cert : /etc/im_monitor/certs/ca.crt
  cert : /etc/im_monitor/certs/agent.crt
  key  : /etc/im_monitor/certs/agent.key

다음 단계:
  기존 agent 설치 스크립트 또는 systemd/service 절차를 그대로 사용

EOF
}

sync_vm_runtime() {
    local ssh_target=""
    local remote_root_q=""
    local remote_agent_q=""
    local ssh_cmd=()
    local scp_cmd=()
    local rsync_ssh=""

    [[ "$VM_SYNC_ENABLED" -eq 1 ]] || return 0
    [[ -d "$AGENT_DIR" ]] || die "VM으로 전송할 Agent 디렉토리가 없습니다: ${AGENT_DIR}"
    [[ -n "$BACKEND_HOST" ]] || die "VM 자동 전송에는 -c/--backend-host 값이 필요합니다."
    [[ -n "$CA_SRC" ]] || die "VM으로 전송할 CA 인증서를 찾지 못했습니다."
    [[ -n "$AGENT_CERT_SRC" ]] || die "VM으로 전송할 Agent 인증서를 찾지 못했습니다."
    [[ -n "$AGENT_KEY_SRC" ]] || die "VM으로 전송할 Agent 개인키를 찾지 못했습니다."

    assert_file "$CA_SRC"
    assert_file "$AGENT_CERT_SRC"
    assert_file "$AGENT_KEY_SRC"

    require_command ssh
    require_command scp

    ssh_target="${VM_USER}@${VM_HOST}"
    printf -v remote_root_q '%q' "$VM_REMOTE_DIR"
    printf -v remote_agent_q '%q' "${VM_REMOTE_DIR}/Agent"

    ssh_cmd=(ssh -p "$VM_PORT" "$ssh_target")
    scp_cmd=(scp -P "$VM_PORT")

    log "VM 디렉토리 준비: ${ssh_target}:${VM_REMOTE_DIR}"
    "${ssh_cmd[@]}" "mkdir -p ${remote_root_q}" \
        || die "VM 대상 디렉토리 생성 실패: ${ssh_target}:${VM_REMOTE_DIR}"

    log "VM Agent 코드 전송"
    if command -v rsync >/dev/null 2>&1; then
        rsync_ssh="ssh -p ${VM_PORT}"
        rsync -az --delete -e "$rsync_ssh" \
            "${AGENT_DIR}/" \
            "${ssh_target}:${VM_REMOTE_DIR}/Agent/" \
            || die "Agent 디렉토리 rsync 실패"
    else
        warn "rsync가 없어 scp -r 로 전체 복사합니다."
        "${ssh_cmd[@]}" "rm -rf ${remote_agent_q}" \
            || die "기존 VM Agent 디렉토리 정리 실패"
        "${scp_cmd[@]}" -r "$AGENT_DIR" "${ssh_target}:${VM_REMOTE_DIR}/" \
            || die "Agent 디렉토리 scp 실패"
    fi

    log "VM setup 스크립트와 인증서 전송"
    "${scp_cmd[@]}" "$ROOT_DIR/setup_backend_agent_runtime.sh" "${ssh_target}:${VM_REMOTE_DIR}/setup_backend_agent_runtime.sh" \
        || die "setup_backend_agent_runtime.sh 전송 실패"
    "${scp_cmd[@]}" "$CA_SRC" "${ssh_target}:${VM_REMOTE_DIR}/ca.crt" \
        || die "CA 인증서 전송 실패"
    "${scp_cmd[@]}" "$AGENT_CERT_SRC" "${ssh_target}:${VM_REMOTE_DIR}/agent.crt" \
        || die "Agent 인증서 전송 실패"
    "${scp_cmd[@]}" "$AGENT_KEY_SRC" "${ssh_target}:${VM_REMOTE_DIR}/agent.key" \
        || die "Agent 개인키 전송 실패"

    "${ssh_cmd[@]}" "chmod +x ${remote_root_q}/setup_backend_agent_runtime.sh" \
        || die "원격 setup_backend_agent_runtime.sh 실행 권한 설정 실패"

    cat <<EOF

VM 전송 완료
  host : ${ssh_target}
  dir  : ${VM_REMOTE_DIR}

다음 단계:
  ssh -p ${VM_PORT} ${ssh_target}
  cd ${VM_REMOTE_DIR}
  sudo ./setup_backend_agent_runtime.sh -m agent -c ${BACKEND_HOST}
  cd ${VM_REMOTE_DIR}/Agent
  sudo ./scripts/setup_ebpf_deps.sh
  cmake -S . -B build
  cmake --build build

EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--mode)
            MODE="${2:-}"
            shift 2
            ;;
        --database-url)
            DATABASE_URL="${2:-}"
            shift 2
            ;;
        -c|--backend-host)
            BACKEND_HOST="${2:-}"
            shift 2
            ;;
        --http-addr)
            HTTP_ADDR="${2:-}"
            shift 2
            ;;
        --tcp-addr)
            TCP_ADDR="${2:-}"
            shift 2
            ;;
        -v|--vm-target)
            VM_TARGET="${2:-}"
            shift 2
            ;;
        --vm-host)
            VM_HOST="${2:-}"
            shift 2
            ;;
        --vm-user)
            VM_USER="${2:-}"
            shift 2
            ;;
        --vm-port)
            VM_PORT="${2:-}"
            shift 2
            ;;
        --vm-dir)
            VM_REMOTE_DIR="${2:-}"
            shift 2
            ;;
        --ca-src)
            CA_SRC="${2:-}"
            shift 2
            ;;
        --server-cert-src)
            SERVER_CERT_SRC="${2:-}"
            shift 2
            ;;
        --server-key-src)
            SERVER_KEY_SRC="${2:-}"
            shift 2
            ;;
        --agent-cert-src)
            AGENT_CERT_SRC="${2:-}"
            shift 2
            ;;
        --agent-key-src)
            AGENT_KEY_SRC="${2:-}"
            shift 2
            ;;
        --skip-backend-deps)
            SKIP_BACKEND_DEPS=1
            shift
            ;;
        --skip-db-setup)
            SETUP_DATABASE=0
            shift
            ;;
        --db-host)
            DB_HOST="${2:-}"
            shift 2
            ;;
        --db-port)
            DB_PORT="${2:-}"
            shift 2
            ;;
        --db-name)
            DB_NAME="${2:-}"
            shift 2
            ;;
        --db-admin-user)
            DB_ADMIN_USER="${2:-}"
            shift 2
            ;;
        --db-admin-password)
            DB_ADMIN_PASSWORD="${2:-}"
            shift 2
            ;;
        --db-app-user)
            DB_APP_USER="${2:-}"
            shift 2
            ;;
        --db-app-password)
            DB_APP_PASSWORD="${2:-}"
            shift 2
            ;;
        --db-user)
            DB_APP_USER="${2:-}"
            shift 2
            ;;
        --db-password)
            DB_APP_PASSWORD="${2:-}"
            shift 2
            ;;
        --generate-legacy-certs)
            GENERATE_LEGACY_CERTS=1
            shift
            ;;
        --cert-output-dir)
            CERT_OUTPUT_DIR="${2:-}"
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
            die "알 수 없는 옵션입니다: $1"
            ;;
    esac
done

if [[ -z "$MODE" || "$MODE" == "all" ]]; then
    infer_mode
fi

if [[ "$MODE" != "backend" && "$MODE" != "agent" && "$MODE" != "all" ]]; then
    die "지원하지 않는 mode 입니다: ${MODE}"
fi

interactive_collect_inputs
finalize_vm_sync_config

if [[ -z "$BACKEND_HOST" && "$MODE" == "backend" && "$VM_SYNC_ENABLED" -eq 1 ]]; then
    if infer_backend_host; then
        log "backend host 자동 추론: ${BACKEND_HOST}"
    else
        die "backend host를 자동 추론하지 못했습니다. -c/--backend-host 값을 지정하세요."
    fi
fi

resolve_cert_sources

if [[ "$GENERATE_LEGACY_CERTS" -eq 1 ]]; then
    [[ -n "$CERT_OUTPUT_DIR" ]] || CERT_OUTPUT_DIR="${BACKEND_CERT_DIR}/generated-legacy"
    generate_legacy_certs
    resolve_cert_sources
fi

case "$MODE" in
    backend)
        setup_backend
        sync_vm_runtime
        ;;
    agent)
        setup_agent
        ;;
    all)
        setup_backend
        setup_agent
        sync_vm_runtime
        ;;
    *)
        die "지원하지 않는 mode 입니다: ${MODE}"
        ;;
esac
