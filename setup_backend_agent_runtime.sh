#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="${ROOT_DIR}/Backend"
AGENT_DIR="${ROOT_DIR}/Agent"
BACKEND_CERT_DIR="${ROOT_DIR}/certs"
RUNTIME_HELPER_DIR="${ROOT_DIR}/scripts/setup_backend_agent_runtime"
BACKEND_ENV_FILE="${BACKEND_DIR}/.env"
BACKEND_SCHEMA_FILE="${BACKEND_DIR}/internal/store/schema.sql"
AGENT_ENV_TEMPLATE="${AGENT_DIR}/configs/im.env"

MODE="all"
MODE_EXPLICIT=0
DATABASE_URL=""
BACKEND_HOST=""
HTTP_ADDR=":8080"
TCP_ADDR=":9000"
BACKEND_RUNTIME="auto"
BACKEND_RUNTIME_RESOLVED=""
VM_SYNC_ENABLED=0
VM_TARGET=""
VM_HOST=""
VM_USER=""
VM_PORT="22"
VM_REMOTE_DIR=""
VM_PASSWORD=""
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
DB_APP_HOST=""
DATABASE_URL_EXPLICIT=0
DB_HOST_EXPLICIT=0
DB_PORT_EXPLICIT=0
DB_NAME_EXPLICIT=0
DB_APP_USER_EXPLICIT=0
DB_APP_PASSWORD_EXPLICIT=0
DB_APP_HOST_EXPLICIT=0
BACKEND_ENV_LOADED=0
EXISTING_DATABASE_URL=""
DB_APP_HOST_RESOLVED=0
MYSQL_CONN_ARGS=()
MYSQL_USE_PASSWORD=0
GO_REQUIRED_VERSION=""
GO_BIN=""
GO_TOOLCHAIN_ROOT=""
GO_TOOLCHAIN_URL_BASE="https://go.dev/dl"
GO_BIN_LINK=""
REPO_RUNTIME_OWNER=""
REPO_RUNTIME_GROUP=""
AUTO_START_BACKEND=1
VM_BOOTSTRAP_ENABLED=0
DOCKER_IMAGE_NAME="knims-backend-runtime-test:22.04"
DOCKER_CONTAINER_NAME="knims-backend-runtime-test"
DOCKER_PLATFORM=""
DOCKER_WORKDIR="/home/knims/KN-IMS"
VM_BOOTSTRAP_SSH_CMD=()
DOCKER_CMD=()
SUPPRESS_FOLLOWUP_SUMMARY=0
VM_ASKPASS_SCRIPT=""
VM_REMOTE_AUTH_PREFIX=()

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
  --backend-runtime VAL   Backend runtime: auto, local, docker (default: auto)
  -v, --vm-target VALUE   Sync Agent runtime to VM target (format: user@host)
  --database-url VALUE     Override backend DATABASE_URL directly
  --http-addr VALUE        Backend HTTP listen address (default: :8080)
  --tcp-addr VALUE         Backend collector address (default: :9000)
  --vm-host VALUE          VM host for automatic Agent sync
  --vm-user VALUE          VM SSH user for automatic Agent sync
  --vm-port VALUE          VM SSH port for automatic Agent sync (default: 22)
  --vm-dir VALUE           VM target directory (default: /home/<user>/KN-IMS)
  -p, --vm-password VALUE  VM SSH password for non-interactive sync
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
  --db-app-host VALUE      MySQL host restriction for backend app user
  --skip-backend-deps      Do not install backend system packages or run go mod download
  --no-start-backend       Finish setup only; do not auto-start backend
  --skip-vm-bootstrap      Sync files to VM only; skip remote agent build/service bootstrap (default)
  --docker-platform VALUE  Docker platform override (e.g. linux/arm64)
  --docker-image VALUE     Docker test image name (default: knims-backend-runtime-test:22.04)
  --docker-container VALUE Docker test container name (default: knims-backend-runtime-test)
  -h, --help               Show help

Examples:
  ./setup_backend_agent_runtime.sh
  ./setup_backend_agent_runtime.sh -m backend
  ./setup_backend_agent_runtime.sh -m backend -v user@192.168.64.11 -p qwer123
  ./setup_backend_agent_runtime.sh -m backend --backend-runtime docker -v user@192.168.64.11
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

file_owner_group() {
    local path="$1"

    case "$(uname -s)" in
        Darwin)
            stat -f '%Su:%Sg' "$path"
            ;;
        *)
            stat -c '%U:%G' "$path"
            ;;
    esac
}

file_mode() {
    local path="$1"

    case "$(uname -s)" in
        Darwin)
            stat -f '%Lp' "$path"
            ;;
        *)
            stat -c '%a' "$path"
            ;;
    esac
}

resolve_repo_runtime_owner() {
    local owner_probe=""
    local owner_group=""

    if [[ -n "$REPO_RUNTIME_OWNER" && -n "$REPO_RUNTIME_GROUP" ]]; then
        return 0
    fi

    for owner_probe in "$BACKEND_DIR" "$BACKEND_CERT_DIR" "$ROOT_DIR"; do
        [[ -e "$owner_probe" ]] || continue
        owner_group="$(file_owner_group "$owner_probe" 2>/dev/null || true)"
        [[ -n "$owner_group" && "$owner_group" == *:* ]] && break
    done

    if [[ -n "$owner_group" && "$owner_group" == *:* ]]; then
        REPO_RUNTIME_OWNER="${owner_group%%:*}"
        REPO_RUNTIME_GROUP="${owner_group#*:}"
    elif [[ -n "${SUDO_USER:-}" ]]; then
        REPO_RUNTIME_OWNER="${SUDO_USER}"
        REPO_RUNTIME_GROUP="$(id -gn "${SUDO_USER}" 2>/dev/null || id -gn)"
    else
        REPO_RUNTIME_OWNER="$(id -un)"
        REPO_RUNTIME_GROUP="$(id -gn)"
    fi
}

apply_file_metadata_if_needed() {
    local path="$1"
    local owner="$2"
    local group="$3"
    local mode="$4"
    local owner_spec=""
    local desired_owner_group=""
    local current_owner_group=""
    local current_mode=""

    if [[ -n "$owner" || -n "$group" ]]; then
        if [[ -n "$owner" ]]; then
            owner_spec="${owner}"
        else
            owner_spec="$(id -un)"
        fi
        if [[ -n "$group" ]]; then
            owner_spec="${owner_spec}:${group}"
        fi

        if [[ -n "$owner" && -n "$group" ]]; then
            desired_owner_group="${owner}:${group}"
            current_owner_group="$(file_owner_group "$path" 2>/dev/null || true)"
            if [[ "$current_owner_group" != "$desired_owner_group" ]]; then
                chown "$owner_spec" "$path"
            fi
        else
            chown "$owner_spec" "$path"
        fi
    fi

    if [[ -n "$mode" ]]; then
        current_mode="$(file_mode "$path" 2>/dev/null || true)"
        if [[ "$current_mode" != "$mode" ]]; then
            chmod "$mode" "$path"
        fi
    fi
}

install_file_if_different() {
    local src="$1"
    local dest="$2"
    shift 2
    local install_args=("$@")
    local owner=""
    local group=""
    local mode=""
    local arg=""
    local dest_dir=""
    local tmp_file=""

    if [[ -e "$dest" && "$src" -ef "$dest" ]]; then
        log "파일 복사 생략 (이미 대상과 동일): ${dest}"
        return 0
    fi

    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            -o)
                owner="${2:-}"
                shift 2
                ;;
            -g)
                group="${2:-}"
                shift 2
                ;;
            -m)
                mode="${2:-}"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
        apply_file_metadata_if_needed "$dest" "$owner" "$group" "$mode"
        log "파일 복사 생략 (내용 동일): ${dest}"
        return 0
    fi

    dest_dir="$(dirname "$dest")"
    mkdir -p "$dest_dir"
    tmp_file="$(mktemp "${dest_dir}/.knims-install.XXXXXX")"

    if ! install "${install_args[@]}" "$src" "$tmp_file"; then
        rm -f "$tmp_file"
        return 1
    fi

    if [[ -e "$dest" ]]; then
        if command -v chattr >/dev/null 2>&1; then
            chattr -i "$dest" >/dev/null 2>&1 || true
        fi
        chmod u+w "$dest" >/dev/null 2>&1 || true

        if cat "$tmp_file" > "$dest" 2>/dev/null; then
            :
        elif cp -f "$tmp_file" "$dest" 2>/dev/null; then
            :
        else
            rm -f "$tmp_file"
            install "${install_args[@]}" "$src" "$dest"
            return $?
        fi

        apply_file_metadata_if_needed "$dest" "$owner" "$group" "$mode"
        rm -f "$tmp_file"
        return 0
    fi

    if mv -f "$tmp_file" "$dest" 2>/dev/null; then
        return 0
    fi

    rm -f "$tmp_file"
    install "${install_args[@]}" "$src" "$dest"
}

ensure_runtime_tmp_dir() {
    mkdir -p "${ROOT_DIR}/tmp/setup_backend_agent_runtime"
}

ensure_vm_askpass_script() {
    ensure_runtime_tmp_dir
    VM_ASKPASS_SCRIPT="${ROOT_DIR}/tmp/setup_backend_agent_runtime/ssh_askpass.sh"

    {
        printf '#!/usr/bin/env bash\n'
        printf "printf '%%s\\n' %q\n" "$VM_PASSWORD"
    } > "$VM_ASKPASS_SCRIPT"

    chmod 0700 "$VM_ASKPASS_SCRIPT"
}

prepare_vm_remote_auth_prefix() {
    VM_REMOTE_AUTH_PREFIX=()

    [[ -n "$VM_PASSWORD" ]] || return 0

    if command -v sshpass >/dev/null 2>&1; then
        VM_REMOTE_AUTH_PREFIX=(sshpass -p "$VM_PASSWORD")
        return 0
    fi

    ensure_vm_askpass_script
    VM_REMOTE_AUTH_PREFIX=(
        env
        DISPLAY=knims-ssh-askpass
        SSH_ASKPASS="$VM_ASKPASS_SCRIPT"
        SSH_ASKPASS_REQUIRE=force
    )
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

source_runtime_helpers() {
    local helper=""

    for helper in certs.sh modules.sh vm_sync.sh; do
        if [[ -f "${RUNTIME_HELPER_DIR}/${helper}" ]]; then
            # shellcheck disable=SC1090
            source "${RUNTIME_HELPER_DIR}/${helper}"
        else
            warn "runtime helper가 없어 내장 구현을 사용합니다: ${RUNTIME_HELPER_DIR}/${helper}"
        fi
    done
}

prepare_docker_command() {
    if [[ ${#DOCKER_CMD[@]} -gt 0 ]]; then
        return 0
    fi

    if [[ "$(uname -s)" == "Darwin" && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        DOCKER_CMD=(sudo -u "$SUDO_USER" -H docker)
    else
        DOCKER_CMD=(docker)
    fi
}

run_docker() {
    prepare_docker_command
    "${DOCKER_CMD[@]}" "$@"
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

is_local_db_host() {
    case "$1" in
        127.0.0.1|localhost|::1)
            return 0
            ;;
    esac
    return 1
}

resolve_db_app_host() {
    if [[ "$DB_APP_HOST_RESOLVED" -eq 1 ]]; then
        return 0
    fi

    if [[ -n "$DB_APP_HOST" ]]; then
        DB_APP_HOST_RESOLVED=1
        return 0
    fi

    if is_local_db_host "$DB_HOST"; then
        DB_APP_HOST="127.0.0.1"
    else
        DB_APP_HOST="%"
    fi

    DB_APP_HOST_RESOLVED=1
}

db_component_overrides_requested() {
    [[ "$DB_HOST_EXPLICIT" -eq 1 ]] \
        || [[ "$DB_PORT_EXPLICIT" -eq 1 ]] \
        || [[ "$DB_NAME_EXPLICIT" -eq 1 ]] \
        || [[ "$DB_APP_USER_EXPLICIT" -eq 1 ]] \
        || [[ "$DB_APP_PASSWORD_EXPLICIT" -eq 1 ]]
}

validate_database_option_combinations() {
    if [[ "$DATABASE_URL_EXPLICIT" -eq 1 ]] && db_component_overrides_requested; then
        die "--database-url 는 --db-host/--db-port/--db-name/--db-app-user/--db-app-password 와 함께 사용할 수 없습니다."
    fi
}

collect_db_admin_credentials_if_needed() {
    if [[ "$SETUP_DATABASE" -ne 1 ]]; then
        return 0
    fi

    if [[ "$(uname -s)" != "Linux" || "${EUID:-$(id -u)}" -ne 0 || "$DB_ADMIN_USER" != "root" ]]; then
        prompt_secret DB_ADMIN_PASSWORD "MySQL admin password" "${DB_ADMIN_PASSWORD:-}"
    fi
}

extract_go_version() {
    printf '%s\n' "$1" | sed -nE 's/^go version go([0-9]+(\.[0-9]+){1,2}).*/\1/p'
}

parse_go_required_version() {
    if [[ -n "$GO_REQUIRED_VERSION" ]]; then
        return 0
    fi

    [[ -f "${BACKEND_DIR}/go.mod" ]] || die "Backend go.mod 파일이 없습니다: ${BACKEND_DIR}/go.mod"
    GO_REQUIRED_VERSION="$(awk '$1=="go"{print $2; exit}' "${BACKEND_DIR}/go.mod")"

    [[ -n "$GO_REQUIRED_VERSION" ]] || die "Backend go.mod 에서 go 버전을 찾지 못했습니다."
    [[ "$GO_REQUIRED_VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "지원하지 않는 go 버전 형식입니다: ${GO_REQUIRED_VERSION}"
}

resolve_go_toolchain_root() {
    if [[ -n "$GO_TOOLCHAIN_ROOT" ]]; then
        return 0
    fi

    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        GO_TOOLCHAIN_ROOT="/usr/local/share/knims/go-toolchains"
    else
        GO_TOOLCHAIN_ROOT="${HOME}/.cache/knims/go-toolchains"
    fi
}

download_file() {
    local url="$1"
    local output="$2"

    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL -o "$output" "$url"; then
            return 0
        fi
        warn "curl 다운로드 실패, 다른 downloader를 시도합니다: ${url}"
    fi

    if command -v wget >/dev/null 2>&1; then
        if wget -qO "$output" "$url"; then
            return 0
        fi
        warn "wget 다운로드 실패, 다른 downloader를 시도합니다: ${url}"
    fi

    if command -v python3 >/dev/null 2>&1; then
        if python3 - "$url" "$output" <<'PY'
import sys
import urllib.request

url, output = sys.argv[1], sys.argv[2]
with urllib.request.urlopen(url) as response, open(output, "wb") as fp:
    fp.write(response.read())
PY
        then
            return 0
        fi
    fi

    die "Go toolchain 다운로드를 위해 curl, wget, 또는 python3 가 필요합니다."
}

install_required_go_toolchain() {
    parse_go_required_version
    resolve_go_toolchain_root
    require_command tar

    local go_os=""
    local go_arch=""
    local archive=""
    local url=""
    local tmp_dir=""
    local archive_path=""
    local extract_dir=""
    local target_dir="${GO_TOOLCHAIN_ROOT}/go${GO_REQUIRED_VERSION}"
    local cached_version=""

    case "$(uname -s)" in
        Darwin)
            go_os="darwin"
            ;;
        Linux)
            go_os="linux"
            ;;
        *)
            die "자동 Go 설치를 지원하지 않는 OS입니다: $(uname -s)"
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)
            go_arch="amd64"
            ;;
        arm64|aarch64)
            go_arch="arm64"
            ;;
        *)
            die "자동 Go 설치를 지원하지 않는 CPU 아키텍처입니다: $(uname -m)"
            ;;
    esac

    if [[ -x "${target_dir}/bin/go" ]]; then
        cached_version="$(extract_go_version "$("${target_dir}/bin/go" version 2>/dev/null || true)")"
        if [[ -n "$cached_version" && "$cached_version" == "$GO_REQUIRED_VERSION" ]]; then
            GO_BIN="${target_dir}/bin/go"
            log "캐시된 Go toolchain 재사용: $("$GO_BIN" version)"
            return 0
        fi
        rm -rf "$target_dir"
    fi

    mkdir -p "$GO_TOOLCHAIN_ROOT"

    archive="go${GO_REQUIRED_VERSION}.${go_os}-${go_arch}.tar.gz"
    url="${GO_TOOLCHAIN_URL_BASE}/${archive}"
    tmp_dir="$(mktemp -d)"
    archive_path="${tmp_dir}/${archive}"
    extract_dir="${tmp_dir}/extract"
    mkdir -p "$extract_dir"

    log "Backend 요구 Go 버전(${GO_REQUIRED_VERSION}) toolchain 설치"
    download_file "$url" "$archive_path" || die "Go toolchain 다운로드 실패: ${url}"
    tar -C "$extract_dir" -xzf "$archive_path" || die "Go toolchain 압축 해제 실패: ${archive_path}"
    [[ -x "${extract_dir}/go/bin/go" ]] || die "압축 해제된 Go toolchain 에 go 실행 파일이 없습니다."

    mv "${extract_dir}/go" "$target_dir" || die "Go toolchain 설치 경로 이동 실패: ${target_dir}"
    rm -rf "$tmp_dir"

    GO_BIN="${target_dir}/bin/go"
    log "Go toolchain 설치 완료: $("$GO_BIN" version)"
}

ensure_backend_go() {
    parse_go_required_version

    local current_go=""
    local current_version=""

    if command -v go >/dev/null 2>&1; then
        current_go="$(command -v go)"
        current_version="$(extract_go_version "$(go version 2>/dev/null || true)")"
        if [[ -n "$current_version" && "$current_version" == "$GO_REQUIRED_VERSION" ]]; then
            GO_BIN="$current_go"
            log "Backend Go 버전 확인 완료: $(go version)"
            return 0
        fi
    fi

    if [[ -n "$current_version" ]]; then
        warn "현재 go 버전(${current_version})이 backend 요구 버전(${GO_REQUIRED_VERSION})과 달라 전용 toolchain을 설치합니다."
    else
        log "Backend 요구 Go 버전(${GO_REQUIRED_VERSION})이 없어서 전용 toolchain을 설치합니다."
    fi

    install_required_go_toolchain
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

replace_addr_port() {
    local addr="$1"
    local new_port="$2"

    if [[ "$addr" == *:* ]]; then
        printf '%s:%s\n' "${addr%:*}" "$new_port"
    else
        printf ':%s\n' "$new_port"
    fi
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
    local port=""
    local pids=""
    local next_port=""

    port="$(port_from_addr "$addr")"
    [[ "$port" =~ ^[0-9]+$ ]] || {
        printf '%s\n' "$addr"
        return 0
    }

    pids="$(find_listen_pids "$port" || true)"
    [[ -n "$pids" ]] || {
        printf '%s\n' "$addr"
        return 0
    }

    warn "${label} 포트 ${port}가 이미 사용 중입니다."
    show_port_usage "$port" >&2

    next_port="$port"
    while :; do
        next_port=$((next_port + 1))
        if [[ -z "$(find_listen_pids "$next_port" || true)" ]]; then
            addr="$(replace_addr_port "$addr" "$next_port")"
            warn "${label} 포트를 ${addr} 로 자동 조정합니다."
            printf '%s\n' "$addr"
            return 0
        fi
        if (( next_port >= port + 1000 )); then
            die "${label} 포트 충돌을 피할 빈 포트를 찾지 못했습니다."
        fi
    done
}

load_existing_backend_url() {
    if [[ "$BACKEND_ENV_LOADED" -eq 1 || ! -f "$BACKEND_ENV_FILE" ]]; then
        return 0
    fi

    BACKEND_ENV_LOADED=1
    EXISTING_DATABASE_URL="$(sed -n 's/^DATABASE_URL=//p' "$BACKEND_ENV_FILE" | head -n 1)"
    if [[ -n "$EXISTING_DATABASE_URL" && "$DATABASE_URL_EXPLICIT" -ne 1 ]]; then
        parse_database_url_defaults "$EXISTING_DATABASE_URL"
    fi
}

parse_database_url_defaults() {
    local dsn="${1:-${DATABASE_URL:-}}"

    if [[ -z "$dsn" ]]; then
        return 0
    fi

    local dsn_re='^([^:@/?]+)(:([^@/?]*))?@tcp\(([^:)]+)(:([0-9]+))?\)/([^?]+)'
    if [[ "$dsn" =~ $dsn_re ]]; then
        if [[ "$DB_APP_USER_EXPLICIT" -ne 1 ]]; then
            DB_APP_USER="${BASH_REMATCH[1]}"
        fi
        if [[ "$DB_APP_PASSWORD_EXPLICIT" -ne 1 ]]; then
            DB_APP_PASSWORD="${BASH_REMATCH[3]-}"
        fi
        if [[ "$DB_HOST_EXPLICIT" -ne 1 ]]; then
            DB_HOST="${BASH_REMATCH[4]}"
        fi
        if [[ "$DB_PORT_EXPLICIT" -ne 1 ]]; then
            DB_PORT="${BASH_REMATCH[6]:-3306}"
        fi
        if [[ "$DB_NAME_EXPLICIT" -ne 1 ]]; then
            DB_NAME="${BASH_REMATCH[7]}"
        fi
        DB_APP_HOST_RESOLVED=0
    fi
}

build_database_url() {
    if [[ "$DATABASE_URL_EXPLICIT" -eq 1 ]]; then
        return 0
    fi

    if [[ -n "$EXISTING_DATABASE_URL" ]] && ! db_component_overrides_requested; then
        DATABASE_URL="$EXISTING_DATABASE_URL"
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

is_running_in_container() {
    [[ -f /.dockerenv || -f /run/.containerenv ]]
}

resolve_backend_runtime() {
    if [[ -n "$BACKEND_RUNTIME_RESOLVED" ]]; then
        return 0
    fi

    case "$BACKEND_RUNTIME" in
        local|docker)
            BACKEND_RUNTIME_RESOLVED="$BACKEND_RUNTIME"
            ;;
        auto)
            if is_running_in_container; then
                BACKEND_RUNTIME_RESOLVED="local"
            elif [[ "$(uname -s)" == "Darwin" ]] \
                && command -v docker >/dev/null 2>&1 \
                && [[ -f "${ROOT_DIR}/docker/backend-runtime-test/Dockerfile" ]]; then
                BACKEND_RUNTIME_RESOLVED="docker"
            else
                BACKEND_RUNTIME_RESOLVED="local"
            fi
            ;;
        *)
            die "지원하지 않는 backend runtime 입니다: ${BACKEND_RUNTIME}"
            ;;
    esac
}

detect_docker_platform() {
    case "$(uname -m)" in
        arm64|aarch64)
            printf 'linux/arm64\n'
            ;;
        x86_64|amd64)
            printf 'linux/amd64\n'
            ;;
        *)
            die "자동 Docker platform 선택을 지원하지 않는 CPU 아키텍처입니다: $(uname -m)"
            ;;
    esac
}

build_shell_command_from_args() {
    local rendered=""
    local quoted=""

    for quoted in "$@"; do
        printf -v quoted '%q' "$quoted"
        rendered+="${rendered:+ }${quoted}"
    done

    printf '%s\n' "$rendered"
}

wait_for_backend_http_local() {
    local http_port="$1"
    local attempt=""
    local log_path="${ROOT_DIR}/tmp/setup_backend_agent_runtime/backend.log"

    for attempt in $(seq 1 40); do
        if curl -fsS "http://127.0.0.1:${http_port}/api/agents" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done

    warn "backend HTTP readiness 확인 실패: 127.0.0.1:${http_port}"
    [[ -f "$log_path" ]] && tail -n 120 "$log_path" >&2 || true
    return 1
}

wait_for_backend_http_in_docker() {
    local http_port="$1"
    local attempt=""

    for attempt in $(seq 1 40); do
        if run_docker exec "$DOCKER_CONTAINER_NAME" curl -fsS "http://127.0.0.1:${http_port}/api/agents" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done

    warn "docker backend HTTP readiness 확인 실패: 127.0.0.1:${http_port}"
    run_docker exec "$DOCKER_CONTAINER_NAME" bash -lc 'tail -n 120 /home/knims/KN-IMS/tmp/setup_backend_agent_runtime/backend.log 2>/dev/null || true' >&2 || true
    return 1
}

start_backend_local() {
    local http_port=""
    local runtime_dir="${ROOT_DIR}/tmp/setup_backend_agent_runtime"
    local pid_file="${runtime_dir}/backend.pid"
    local log_file="${runtime_dir}/backend.log"
    local old_pid=""

    [[ "$AUTO_START_BACKEND" -eq 1 ]] || return 0

    http_port="$(port_from_addr "$HTTP_ADDR")"
    [[ "$http_port" =~ ^[0-9]+$ ]] || die "backend HTTP 포트 형식이 올바르지 않습니다: ${HTTP_ADDR}"

    mkdir -p "$runtime_dir"

    if [[ -f "$pid_file" ]]; then
        old_pid="$(cat "$pid_file" 2>/dev/null || true)"
        if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
            log "기존 backend 프로세스 종료: pid=${old_pid}"
            kill "$old_pid" 2>/dev/null || true
            sleep 1
            kill -9 "$old_pid" 2>/dev/null || true
        fi
    fi

    log "backend 자동 시작"
    (
        cd "$BACKEND_DIR"
        nohup "${GO_BIN:-go}" run ./cmd/server >"$log_file" 2>&1 < /dev/null &
        echo $! > "$pid_file"
    )

    wait_for_backend_http_local "$http_port" \
        || die "backend 자동 시작 후 readiness 확인에 실패했습니다. 로그를 확인하세요: ${log_file}"

    cat <<EOF

backend 자동 시작 완료
  pid  : $(cat "$pid_file" 2>/dev/null || printf 'unknown')
  log  : ${log_file}
  http : http://127.0.0.1:${http_port}

EOF
}

start_backend_in_docker() {
    local http_port="$1"
    local remote_runtime_dir_q=""
    local remote_cmd=""

    [[ "$AUTO_START_BACKEND" -eq 1 ]] || return 0

    printf -v remote_runtime_dir_q '%q' "${DOCKER_WORKDIR}/tmp/setup_backend_agent_runtime"
    remote_cmd=$(
        cat <<EOF
pkill -x -f 'go run ./cmd/server' >/dev/null 2>&1 || true
pkill -f '^/tmp/go-build.*/exe/server$' >/dev/null 2>&1 || true
mkdir -p ${remote_runtime_dir_q}
cd ${DOCKER_WORKDIR}/Backend
nohup go run ./cmd/server > ${remote_runtime_dir_q}/backend.log 2>&1 < /dev/null &
echo \$! > ${remote_runtime_dir_q}/backend.pid
EOF
    )

    log "docker backend 자동 시작"
    run_docker exec -u root "$DOCKER_CONTAINER_NAME" bash -lc "$remote_cmd" \
        || die "docker backend 시작 실패"

    wait_for_backend_http_in_docker "$http_port" \
        || die "docker backend 자동 시작 후 readiness 확인에 실패했습니다."

    cat <<EOF

docker backend 자동 시작 완료
  container : ${DOCKER_CONTAINER_NAME}
  http      : http://127.0.0.1:${http_port}
  log       : ${ROOT_DIR}/tmp/setup_backend_agent_runtime/backend.log

EOF
}

run_backend_setup_in_docker() {
    local http_port=""
    local tcp_port=""
    local inner_args=()
    local inner_cmd=""

    resolve_backend_runtime
    [[ "$BACKEND_RUNTIME_RESOLVED" == "docker" ]] || return 1
    is_running_in_container && die "컨테이너 내부에서는 docker runtime을 다시 사용할 수 없습니다."

    require_command docker
    prepare_docker_command
    [[ -f "${ROOT_DIR}/docker/backend-runtime-test/Dockerfile" ]] \
        || die "docker backend 테스트 Dockerfile이 없습니다: ${ROOT_DIR}/docker/backend-runtime-test/Dockerfile"

    if [[ -z "$DOCKER_PLATFORM" ]]; then
        DOCKER_PLATFORM="$(detect_docker_platform)"
    fi

    HTTP_ADDR="$(ensure_port_available "$HTTP_ADDR" "Backend HTTP")"
    TCP_ADDR="$(ensure_port_available "$TCP_ADDR" "Backend collector")"
    http_port="$(port_from_addr "$HTTP_ADDR")"
    tcp_port="$(port_from_addr "$TCP_ADDR")"

    inner_args=(
        ./setup_backend_agent_runtime.sh
        -m backend
        --backend-runtime local
        --no-start-backend
        --suppress-followup-summary
        --http-addr "$HTTP_ADDR"
        --tcp-addr "$TCP_ADDR"
        --db-host "$DB_HOST"
        --db-port "$DB_PORT"
        --db-name "$DB_NAME"
        --db-admin-user "$DB_ADMIN_USER"
        --db-app-user "$DB_APP_USER"
    )

    [[ -n "$BACKEND_HOST" ]] && inner_args+=(-c "$BACKEND_HOST")
    [[ "$SKIP_BACKEND_DEPS" -eq 1 ]] && inner_args+=(--skip-backend-deps)
    [[ "$SETUP_DATABASE" -ne 1 ]] && inner_args+=(--skip-db-setup)
    [[ "$DATABASE_URL_EXPLICIT" -eq 1 ]] && inner_args+=(--database-url "$DATABASE_URL")
    [[ -n "$DB_ADMIN_PASSWORD" ]] && inner_args+=(--db-admin-password "$DB_ADMIN_PASSWORD")
    [[ -n "$DB_APP_PASSWORD" ]] && inner_args+=(--db-app-password "$DB_APP_PASSWORD")
    [[ -n "$DB_APP_HOST" ]] && inner_args+=(--db-app-host "$DB_APP_HOST")
    [[ "$GENERATE_LEGACY_CERTS" -eq 1 ]] && inner_args+=(--generate-legacy-certs)
    [[ -n "$CERT_OUTPUT_DIR" ]] && inner_args+=(--cert-output-dir "$CERT_OUTPUT_DIR")
    [[ -n "$CA_CN" ]] && inner_args+=(--ca-cn "$CA_CN")
    [[ -n "$SERVER_CN" ]] && inner_args+=(--server-cn "$SERVER_CN")
    [[ -n "$AGENT_CN" ]] && inner_args+=(--agent-cn "$AGENT_CN")
    [[ -n "$CA_SRC" ]] && inner_args+=(--ca-src "$CA_SRC")
    [[ -n "$SERVER_CERT_SRC" ]] && inner_args+=(--server-cert-src "$SERVER_CERT_SRC")
    [[ -n "$SERVER_KEY_SRC" ]] && inner_args+=(--server-key-src "$SERVER_KEY_SRC")
    [[ -n "$AGENT_CERT_SRC" ]] && inner_args+=(--agent-cert-src "$AGENT_CERT_SRC")
    [[ -n "$AGENT_KEY_SRC" ]] && inner_args+=(--agent-key-src "$AGENT_KEY_SRC")

    inner_cmd="$(build_shell_command_from_args "${inner_args[@]}")"

    log "docker backend 테스트 이미지 빌드 (${DOCKER_PLATFORM})"
    run_docker build \
        --platform "$DOCKER_PLATFORM" \
        -f "${ROOT_DIR}/docker/backend-runtime-test/Dockerfile" \
        -t "$DOCKER_IMAGE_NAME" \
        "${ROOT_DIR}"

    run_docker rm -f "$DOCKER_CONTAINER_NAME" >/dev/null 2>&1 || true

    log "docker backend 테스트 컨테이너 기동"
    run_docker run -d \
        --platform "$DOCKER_PLATFORM" \
        --privileged \
        --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        -v "${ROOT_DIR}:${DOCKER_WORKDIR}" \
        -w "${DOCKER_WORKDIR}" \
        -p "${http_port}:${http_port}" \
        -p "${tcp_port}:${tcp_port}" \
        --name "$DOCKER_CONTAINER_NAME" \
        "$DOCKER_IMAGE_NAME" >/dev/null

    log "docker 컨테이너 내부에서 backend 설정"
    if ! run_docker exec -u root "$DOCKER_CONTAINER_NAME" bash -lc "$inner_cmd"; then
        run_docker logs "$DOCKER_CONTAINER_NAME" >&2 || true
        die "docker 컨테이너 내부 backend setup 실패"
    fi

    start_backend_in_docker "$http_port"
}

prepare_vm_bootstrap_ssh_command() {
    prepare_vm_remote_auth_prefix

    VM_BOOTSTRAP_SSH_CMD=(
        "${VM_REMOTE_AUTH_PREFIX[@]}"
        ssh
        -o StrictHostKeyChecking=accept-new
        -o PreferredAuthentications=publickey,password,keyboard-interactive
        -o ConnectTimeout=10
        -p "$VM_PORT"
        "${VM_USER}@${VM_HOST}"
    )
}

build_vm_remote_sudo_command() {
    local inner_cmd="$1"

    if [[ -n "$VM_PASSWORD" ]]; then
        printf "printf '%%s\\n' %q | sudo -S -p '' bash -lc %q" "$VM_PASSWORD" "$inner_cmd"
        return 0
    fi

    printf "sudo bash -lc %q" "$inner_cmd"
}

bootstrap_vm_agent_runtime() {
    local remote_root_q=""
    local remote_agent_q=""
    local backend_host_q=""
    local tcp_addr_q=""
    local setup_cmd=""
    local deps_cmd=""
    local build_cmd=""
    local service_cmd=""
    local transport_check_port=""

    [[ "$VM_SYNC_ENABLED" -eq 1 ]] || return 0
    [[ "$VM_BOOTSTRAP_ENABLED" -eq 1 ]] || return 0

    prepare_vm_bootstrap_ssh_command

    printf -v remote_root_q '%q' "$VM_REMOTE_DIR"
    printf -v remote_agent_q '%q' "${VM_REMOTE_DIR}/Agent"
    printf -v backend_host_q '%q' "$BACKEND_HOST"
    printf -v tcp_addr_q '%q' "$TCP_ADDR"
    transport_check_port="${TCP_ADDR#:}"

    log "VM agent env/cert 자동 설치"
    setup_cmd="cd ${remote_root_q} && chmod +x ./setup_backend_agent_runtime.sh && ./setup_backend_agent_runtime.sh -m agent -c ${backend_host_q} --tcp-addr ${tcp_addr_q}"
    "${VM_BOOTSTRAP_SSH_CMD[@]}" "$(build_vm_remote_sudo_command "$setup_cmd")" \
        || die "VM agent env/cert 자동 설치 실패"

    log "VM agent 의존성 자동 준비"
    deps_cmd=$(
        cat <<EOF
cd ${remote_agent_q}
chmod +x ./scripts/setup_ebpf_deps.sh ./scripts/setup_lkm_env.sh ./scripts/install_agent_service.sh 2>/dev/null || true
if ./scripts/setup_ebpf_deps.sh --check >/dev/null 2>&1; then
    ./scripts/setup_ebpf_deps.sh
else
    ./scripts/setup_lkm_env.sh --deps-only
fi
EOF
    )
    "${VM_BOOTSTRAP_SSH_CMD[@]}" "$(build_vm_remote_sudo_command "$deps_cmd")" \
        || die "VM agent 의존성 자동 준비 실패"

    log "VM agent 빌드"
    build_cmd=$(
        cat <<EOF
cd ${remote_agent_q}
cmake -S . -B build
JOBS=\$(command -v nproc >/dev/null 2>&1 && nproc || getconf _NPROCESSORS_ONLN || echo 2)
cmake --build build -- -j"\${JOBS}"
EOF
    )
    "${VM_BOOTSTRAP_SSH_CMD[@]}" "$build_cmd" \
        || die "VM agent 빌드 실패"

    log "VM agent 서비스 설치/기동"
    service_cmd="cd ${remote_agent_q} && ./scripts/install_agent_service.sh"
    "${VM_BOOTSTRAP_SSH_CMD[@]}" "$(build_vm_remote_sudo_command "$service_cmd")" \
        || die "VM agent 서비스 설치/기동 실패"

    log "VM -> backend collector 포트 접근 확인"
    "${VM_BOOTSTRAP_SSH_CMD[@]}" "bash -lc $(printf '%q' "timeout 5 bash -lc '</dev/tcp/${BACKEND_HOST}/${transport_check_port}'")" \
        || warn "VM에서 backend collector(${BACKEND_HOST}:${transport_check_port}) TCP 접근 확인에 실패했습니다."
}

wait_for_agent_registration() {
    local http_port=""
    local attempt=""
    local agents_json=""

    [[ "$AUTO_START_BACKEND" -eq 1 ]] || return 0

    http_port="$(port_from_addr "$HTTP_ADDR")"
    [[ "$http_port" =~ ^[0-9]+$ ]] || return 0

    for attempt in $(seq 1 30); do
        agents_json="$(curl -fsS "http://127.0.0.1:${http_port}/api/agents" 2>/dev/null || true)"
        if [[ "$agents_json" == *"online"* || "$agents_json" == *"agent_id"* ]]; then
            cat <<EOF

agent 등록 확인
  http : http://127.0.0.1:${http_port}/api/agents

EOF
            return 0
        fi
        sleep 1
    done

    warn "agent 등록을 아직 확인하지 못했습니다. 직접 확인: curl -s http://127.0.0.1:${http_port}/api/agents"
    return 0
}

print_backend_api_snapshot() {
    local http_port=""
    local agents_json=""
    local events_json=""
    local alerts_json=""

    http_port="$(port_from_addr "$HTTP_ADDR")"
    [[ "$http_port" =~ ^[0-9]+$ ]] || return 0
    command -v curl >/dev/null 2>&1 || return 0

    agents_json="$(curl -fsS "http://127.0.0.1:${http_port}/api/agents" 2>/dev/null | head -c 4000 || true)"
    events_json="$(curl -fsS "http://127.0.0.1:${http_port}/api/events?limit=5" 2>/dev/null | head -c 4000 || true)"
    alerts_json="$(curl -fsS "http://127.0.0.1:${http_port}/api/alerts?limit=5" 2>/dev/null | head -c 4000 || true)"

    cat <<EOF

backend API 확인 명령:
  curl -s http://127.0.0.1:${http_port}/api/agents
  curl -s 'http://127.0.0.1:${http_port}/api/events?limit=5'
  curl -s 'http://127.0.0.1:${http_port}/api/alerts?limit=5'

EOF

    if [[ -n "$agents_json" ]]; then
        printf 'api/agents:\n%s\n\n' "$agents_json"
    fi
    if [[ -n "$events_json" ]]; then
        printf 'api/events?limit=5:\n%s\n\n' "$events_json"
    fi
    if [[ -n "$alerts_json" ]]; then
        printf 'api/alerts?limit=5:\n%s\n\n' "$alerts_json"
    fi
}

print_backend_followup_summary() {
    local http_port=""
    local tcp_port=""

    http_port="$(port_from_addr "$HTTP_ADDR")"
    tcp_port="$(port_from_addr "$TCP_ADDR")"

    cat <<EOF

backend 후속 명령:
EOF

    if [[ "$BACKEND_RUNTIME_RESOLVED" == "docker" ]]; then
        cat <<EOF
  로그 확인:
    docker logs -f ${DOCKER_CONTAINER_NAME}
  컨테이너 셸:
    docker exec -it -u knims ${DOCKER_CONTAINER_NAME} bash
  backend 정리:
    docker rm -f ${DOCKER_CONTAINER_NAME}
    docker image rm -f ${DOCKER_IMAGE_NAME}
EOF
    else
        cat <<EOF
  로그 확인:
    tail -f ${ROOT_DIR}/tmp/setup_backend_agent_runtime/backend.log
  backend 정리:
    kill \$(cat ${ROOT_DIR}/tmp/setup_backend_agent_runtime/backend.pid)
EOF
    fi

    cat <<EOF
  collector 주소:
    ${BACKEND_HOST:-127.0.0.1}:${tcp_port}
  HTTP 주소:
    http://127.0.0.1:${http_port}

EOF

    if [[ "$VM_SYNC_ENABLED" -eq 1 ]]; then
        cat <<EOF
VM 후속 명령:
  ssh -p ${VM_PORT} ${VM_USER}@${VM_HOST}
  cd ${VM_REMOTE_DIR}
  sudo ./setup_backend_agent_runtime.sh -m agent -c ${BACKEND_HOST} --tcp-addr ${TCP_ADDR}

EOF
    fi

    if [[ "$(uname -s)" == "Darwin" && -n "${SUDO_USER:-}" ]]; then
        cat <<EOF
참고:
  macOS에서 이 스크립트를 sudo로 실행했다면 이후 docker 명령은 일반 사용자 셸에서 실행하는 것을 권장합니다.

EOF
    fi

    print_backend_api_snapshot
}

list_running_agent_processes() {
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -af '(^|/)(agent)( |$)|/usr/local/bin/agent|/build/agent' 2>/dev/null || true
        return 0
    fi

    if command -v ps >/dev/null 2>&1; then
        ps -ef 2>/dev/null | grep -E '(/usr/local/bin/agent|/build/agent|[[:space:]]agent([[:space:]]|$))' | grep -v grep || true
    fi
}

print_agent_followup_summary() {
    local running_agents=""

    running_agents="$(list_running_agent_processes)"

    cat <<EOF

agent 후속 명령:
  cd ${AGENT_DIR}
  sudo ./scripts/setup_ebpf_deps.sh --check
  cmake -S . -B build
  cmake --build build
  sudo ./scripts/install_agent_service.sh

연결 확인 명령:
  sudo systemctl status fileguard.service --no-pager
  sudo journalctl -u fileguard.service -n 100 --no-pager
  sudo cat /etc/im_monitor/im.env
  sudo ss -tnp | grep :${TCP_ADDR#:}

agent 중복 실행 정리:
  sudo systemctl stop fileguard.service 2>/dev/null || true
  sudo pkill -TERM -f '/usr/local/bin/agent|/build/agent' 2>/dev/null || true
  sleep 1
  sudo pkill -KILL -f '/usr/local/bin/agent|/build/agent' 2>/dev/null || true
  sudo systemctl start fileguard.service

EOF

    if [[ -n "$running_agents" ]]; then
        printf '현재 감지된 agent 프로세스:\n%s\n\n' "$running_agents"
    fi
}

run_backend_flow() {
    resolve_backend_runtime

    case "$BACKEND_RUNTIME_RESOLVED" in
        docker)
            run_backend_setup_in_docker
            ;;
        local)
            setup_backend
            start_backend_local
            ;;
        *)
            die "지원하지 않는 backend runtime 입니다: ${BACKEND_RUNTIME_RESOLVED}"
            ;;
    esac
}

interactive_collect_inputs() {
    local enable_vm_sync="0"
    local vm_target_default=""
    local needs_backend_host="0"
    local backend_runtime_hint=""

    if [[ -n "$VM_TARGET" || -n "$VM_HOST" || -n "$VM_USER" ]]; then
        VM_SYNC_ENABLED=1
    fi

    if ! is_interactive; then
        return 0
    fi

    if [[ "$MODE" == "backend" || "$MODE" == "all" ]]; then
        resolve_backend_runtime
        backend_runtime_hint="$BACKEND_RUNTIME_RESOLVED"
    fi

    if [[ "$MODE" == "backend" || "$MODE" == "all" ]]; then
        load_existing_backend_url
        if [[ "$backend_runtime_hint" != "docker" ]] || is_running_in_container; then
            collect_db_admin_credentials_if_needed
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
            if [[ -z "$VM_PASSWORD" ]]; then
                prompt_secret VM_PASSWORD "VM SSH password (비어 있으면 기존 ssh 인증 사용)" ""
            fi
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

should_use_mysql_socket_auth() {
    [[ "$(uname -s)" == "Linux" ]] || return 1
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || return 1
    [[ "$DB_ADMIN_USER" == "root" ]] || return 1
    [[ -z "$DB_ADMIN_PASSWORD" ]] || return 1
    is_local_db_host "$DB_HOST" || return 1
    [[ "$DB_PORT" == "3306" ]] || return 1
}

prepare_mysql_admin_args() {
    MYSQL_CONN_ARGS=()
    MYSQL_USE_PASSWORD=0

    if should_use_mysql_socket_auth; then
        return 0
    fi

    MYSQL_CONN_ARGS=(-u "$DB_ADMIN_USER" -h "$DB_HOST" -P "$DB_PORT")
    if [[ -n "$DB_ADMIN_PASSWORD" ]]; then
        MYSQL_USE_PASSWORD=1
    fi
}

mysql_admin_ping() {
    prepare_mysql_admin_args

    if [[ "$MYSQL_USE_PASSWORD" -eq 1 ]]; then
        MYSQL_PWD="$DB_ADMIN_PASSWORD" mysqladmin "${MYSQL_CONN_ARGS[@]}" ping >/dev/null 2>&1
        return $?
    fi

    mysqladmin "${MYSQL_CONN_ARGS[@]}" ping >/dev/null 2>&1
}

generate_legacy_certs() {
    require_command openssl

    local out_dir="$CERT_OUTPUT_DIR"
    if [[ -z "$out_dir" ]]; then
        out_dir="${BACKEND_CERT_DIR}/generated-legacy"
    fi

    mkdir -p "$out_dir"

    local ca_key="${out_dir}/ca.key"
    local ca_csr="${out_dir}/ca.csr"
    local ca_crt="${out_dir}/ca.crt"
    local server_key="${out_dir}/server.key"
    local server_csr="${out_dir}/server.csr"
    local server_crt="${out_dir}/server.crt"
    local agent_key="${out_dir}/agent.key"
    local agent_csr="${out_dir}/agent.csr"
    local agent_crt="${out_dir}/agent.crt"
    local ca_ext="${out_dir}/ca_ext.cnf"
    local server_ext="${out_dir}/server_ext.cnf"
    local agent_ext="${out_dir}/agent_ext.cnf"

    log "구형 호환 인증서 생성 (RSA 2048 + SHA256)"

    cat > "$ca_ext" <<'EOF'
[v3_ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

    openssl genrsa -out "$ca_key" 2048
    openssl req -new -sha256 \
        -key "$ca_key" \
        -out "$ca_csr" \
        -subj "/CN=${CA_CN}"
    openssl x509 -req -sha256 -days 3650 \
        -in "$ca_csr" \
        -signkey "$ca_key" \
        -out "$ca_crt" \
        -extfile "$ca_ext" \
        -extensions v3_ca

    cat > "$server_ext" <<EOF
[v3_server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
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
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
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

    local need_downloader=0
    local need_mysql=0
    local packages=()

    if ! command -v curl >/dev/null 2>&1 \
        && ! command -v wget >/dev/null 2>&1 \
        && ! command -v python3 >/dev/null 2>&1; then
        need_downloader=1
    fi

    if [[ "$SETUP_DATABASE" -eq 1 ]]; then
        if ! command -v mysql >/dev/null 2>&1 || ! command -v mysqladmin >/dev/null 2>&1; then
            need_mysql=1
        fi
    fi

    case "$(uname -s)" in
        Darwin)
            if command -v brew >/dev/null 2>&1; then
                if [[ "$need_mysql" -eq 1 ]]; then
                    log "backend 모듈 설치 (brew)"
                    brew list mysql >/dev/null 2>&1 \
                        || brew_safe install mysql \
                        || warn "brew mysql 설치 실패 — 기존 mysql/mysqladmin 이 있으면 계속 진행합니다."
                else
                    log "backend 시스템 패키지 설치 생략"
                fi
            else
                warn "Homebrew가 없어 backend 시스템 패키지 자동 설치를 건너뜁니다."
            fi
            ;;
        Linux)
            if command -v apt-get >/dev/null 2>&1; then
                if [[ "$need_downloader" -eq 1 ]]; then
                    packages+=(curl)
                fi
                if [[ "$need_mysql" -eq 1 ]]; then
                    if is_local_db_host "$DB_HOST"; then
                        packages+=(mysql-server)
                    else
                        packages+=(default-mysql-client)
                    fi
                fi

                if (( ${#packages[@]} > 0 )); then
                    log "backend 모듈 설치 (apt): ${packages[*]}"
                    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
                        apt-get update || warn "apt-get update 실패"
                        apt-get install -y "${packages[@]}" || warn "apt 패키지 설치 실패: ${packages[*]}"
                    elif command -v sudo >/dev/null 2>&1; then
                        sudo apt-get update || warn "apt-get update 실패"
                        sudo apt-get install -y "${packages[@]}" || warn "apt 패키지 설치 실패: ${packages[*]}"
                    else
                        warn "apt 패키지 설치가 필요하지만 sudo가 없습니다. 수동 설치가 필요할 수 있습니다: ${packages[*]}"
                    fi
                else
                    log "backend 시스템 패키지 설치 생략"
                fi
            else
                warn "자동 설치를 지원하지 않는 Linux 배포판입니다. 필요한 경우 mysql/curl/wget/python3 를 수동 설치하세요."
            fi
            ;;
        *)
            warn "지원하지 않는 OS입니다. backend 의존성은 수동 설치가 필요할 수 있습니다."
            ;;
    esac

    ensure_backend_go
    log "Backend Go 모듈 다운로드"
    (cd "$BACKEND_DIR" && "$GO_BIN" mod download)
}

ensure_mysql_service() {
    require_command mysql
    require_command mysqladmin

    if ! is_local_db_host "$DB_HOST"; then
        log "원격 MySQL 대상 감지 (${DB_HOST}:${DB_PORT}) — 로컬 MySQL 서비스 기동은 건너뜁니다."
        if ! mysql_admin_ping; then
            warn "DB 접속 정보(${DB_HOST}:${DB_PORT}) 기준 mysqladmin ping 확인 실패 — 계속 진행합니다."
        fi
        return 0
    fi

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
                    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
                        systemctl enable --now mysql >/dev/null 2>&1 || true
                    elif command -v sudo >/dev/null 2>&1; then
                        sudo systemctl enable --now mysql >/dev/null 2>&1 || true
                    fi
                elif systemctl list-unit-files | grep -q '^mysqld\.service'; then
                    log "MySQL 서비스 시작 (mysqld.service)"
                    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
                        systemctl enable --now mysqld >/dev/null 2>&1 || true
                    elif command -v sudo >/dev/null 2>&1; then
                        sudo systemctl enable --now mysqld >/dev/null 2>&1 || true
                    fi
                fi
            fi
            ;;
    esac

    if ! mysql_admin_ping; then
        warn "DB 접속 정보(${DB_HOST}:${DB_PORT}) 기준 mysqladmin ping 확인 실패 — 계속 진행합니다."
    fi
}

mysql_admin_exec() {
    local sql="$1"
    prepare_mysql_admin_args

    if [[ "$MYSQL_USE_PASSWORD" -eq 1 ]]; then
        MYSQL_PWD="$DB_ADMIN_PASSWORD" mysql "${MYSQL_CONN_ARGS[@]}" -e "$sql"
        return $?
    fi

    mysql "${MYSQL_CONN_ARGS[@]}" -e "$sql"
}

mysql_admin_query() {
    local sql="$1"
    prepare_mysql_admin_args

    if [[ "$MYSQL_USE_PASSWORD" -eq 1 ]]; then
        MYSQL_PWD="$DB_ADMIN_PASSWORD" mysql "${MYSQL_CONN_ARGS[@]}" -N -s -e "$sql"
        return $?
    fi

    mysql "${MYSQL_CONN_ARGS[@]}" -N -s -e "$sql"
}

mysql_admin_import() {
    local db_name="$1"
    local sql_file="$2"
    prepare_mysql_admin_args

    if [[ "$MYSQL_USE_PASSWORD" -eq 1 ]]; then
        MYSQL_PWD="$DB_ADMIN_PASSWORD" mysql "${MYSQL_CONN_ARGS[@]}" "$db_name" < "$sql_file"
        return $?
    fi

    mysql "${MYSQL_CONN_ARGS[@]}" "$db_name" < "$sql_file"
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
    resolve_db_app_host
    [[ -n "$DB_APP_HOST" ]] || die "DB app host 값이 없습니다."

    local esc_db_name
    local esc_app_user
    local esc_app_host
    local esc_app_pass
    local db_exists="0"
    local user_exists="0"
    local schema_ready="0"
    esc_db_name="$(sql_escape "$DB_NAME")"
    esc_app_user="$(sql_escape "$DB_APP_USER")"
    esc_app_host="$(sql_escape "$DB_APP_HOST")"

    if [[ "$DB_APP_HOST_EXPLICIT" -ne 1 && "$DB_APP_HOST" == "%" ]]; then
        if ! is_local_db_host "$DB_HOST"; then
            log "원격 MySQL 대상 감지 — backend app 계정 host restriction을 '%' 로 사용합니다. 필요하면 --db-app-host로 조정하세요."
        fi
    fi

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

        log "Backend app 계정 생성: ${DB_APP_USER}@${DB_APP_HOST}"
        mysql_admin_exec "CREATE USER '${esc_app_user}'@'${esc_app_host}' IDENTIFIED BY '${esc_app_pass}';" \
            || die "DB app 계정 생성 실패"

        log "Backend app 계정 권한 부여"
        mysql_admin_exec "GRANT ALL PRIVILEGES ON \`${esc_db_name}\`.* TO '${esc_app_user}'@'${esc_app_host}'; FLUSH PRIVILEGES;" \
            || die "DB 권한 부여 실패"
    else
        [[ -n "$DB_APP_PASSWORD" ]] || die "기존 Backend app 계정(${DB_APP_USER}@${DB_APP_HOST})이 있어 비밀번호를 자동 결정할 수 없습니다. 기존 Backend/.env를 유지하거나 --database-url/--db-app-password를 지정하세요."
        log "기존 Backend app 계정 감지 — 생성/권한 부여 생략: ${DB_APP_USER}@${DB_APP_HOST}"
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
    resolve_repo_runtime_owner

    assert_abs_path "$CA_SRC" "ca-src"
    assert_abs_path "$SERVER_CERT_SRC" "server-cert-src"
    assert_abs_path "$SERVER_KEY_SRC" "server-key-src"
    assert_file "$CA_SRC"
    assert_file "$SERVER_CERT_SRC"
    assert_file "$SERVER_KEY_SRC"

    install_backend_deps
    load_existing_backend_url
    HTTP_ADDR="$(ensure_port_available "$HTTP_ADDR" "Backend HTTP")"
    TCP_ADDR="$(ensure_port_available "$TCP_ADDR" "Backend collector")"

    log "backend 인증서 동기화"
    mkdir -p "$BACKEND_CERT_DIR"
    install_file_if_different "$CA_SRC" "${BACKEND_CERT_DIR}/ca.crt" -o "$REPO_RUNTIME_OWNER" -g "$REPO_RUNTIME_GROUP" -m 0644
    install_file_if_different "$SERVER_CERT_SRC" "${BACKEND_CERT_DIR}/server.crt" -o "$REPO_RUNTIME_OWNER" -g "$REPO_RUNTIME_GROUP" -m 0644
    install_file_if_different "$SERVER_KEY_SRC" "${BACKEND_CERT_DIR}/server.key" -o "$REPO_RUNTIME_OWNER" -g "$REPO_RUNTIME_GROUP" -m 0600

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
    apply_file_metadata_if_needed "$BACKEND_ENV_FILE" "$REPO_RUNTIME_OWNER" "$REPO_RUNTIME_GROUP" "0644"

    cat <<EOF

backend 설정 완료
  env  : ${BACKEND_ENV_FILE}
  cert : ${BACKEND_CERT_DIR}/ca.crt
  cert : ${BACKEND_CERT_DIR}/server.crt
  key  : ${BACKEND_CERT_DIR}/server.key
  db   : ${DB_HOST:-미설정}:${DB_PORT:-미설정}/${DB_NAME:-미설정}

backend 실행:
  cd ${BACKEND_DIR}
  ${GO_BIN:-go} run ./cmd/server

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
    install_file_if_different "$CA_SRC" /etc/im_monitor/certs/ca.crt -o root -g root -m 0644
    install_file_if_different "$AGENT_CERT_SRC" /etc/im_monitor/certs/agent.crt -o root -g root -m 0644
    install_file_if_different "$AGENT_KEY_SRC" /etc/im_monitor/certs/agent.key -o root -g root -m 0600

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
  sudo ./setup_backend_agent_runtime.sh -m agent -c ${BACKEND_HOST} --tcp-addr ${TCP_ADDR}
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
            MODE_EXPLICIT=1
            shift 2
            ;;
        --database-url)
            DATABASE_URL="${2:-}"
            DATABASE_URL_EXPLICIT=1
            shift 2
            ;;
        -c|--backend-host)
            BACKEND_HOST="${2:-}"
            shift 2
            ;;
        --backend-runtime)
            BACKEND_RUNTIME="${2:-}"
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
        -p|--vm-password)
            VM_PASSWORD="${2:-}"
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
        --no-start-backend)
            AUTO_START_BACKEND=0
            shift
            ;;
        --suppress-followup-summary)
            SUPPRESS_FOLLOWUP_SUMMARY=1
            shift
            ;;
        --skip-vm-bootstrap)
            VM_BOOTSTRAP_ENABLED=0
            shift
            ;;
        --docker-platform)
            DOCKER_PLATFORM="${2:-}"
            shift 2
            ;;
        --docker-image)
            DOCKER_IMAGE_NAME="${2:-}"
            shift 2
            ;;
        --docker-container)
            DOCKER_CONTAINER_NAME="${2:-}"
            shift 2
            ;;
        --skip-db-setup)
            SETUP_DATABASE=0
            shift
            ;;
        --db-host)
            DB_HOST="${2:-}"
            DB_HOST_EXPLICIT=1
            DB_APP_HOST_RESOLVED=0
            shift 2
            ;;
        --db-port)
            DB_PORT="${2:-}"
            DB_PORT_EXPLICIT=1
            shift 2
            ;;
        --db-name)
            DB_NAME="${2:-}"
            DB_NAME_EXPLICIT=1
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
            DB_APP_USER_EXPLICIT=1
            shift 2
            ;;
        --db-app-password)
            DB_APP_PASSWORD="${2:-}"
            DB_APP_PASSWORD_EXPLICIT=1
            shift 2
            ;;
        --db-app-host)
            DB_APP_HOST="${2:-}"
            DB_APP_HOST_EXPLICIT=1
            DB_APP_HOST_RESOLVED=0
            shift 2
            ;;
        --db-user)
            DB_APP_USER="${2:-}"
            DB_APP_USER_EXPLICIT=1
            shift 2
            ;;
        --db-password)
            DB_APP_PASSWORD="${2:-}"
            DB_APP_PASSWORD_EXPLICIT=1
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

source_runtime_helpers

validate_database_option_combinations

if [[ "$DATABASE_URL_EXPLICIT" -eq 1 ]]; then
    parse_database_url_defaults "$DATABASE_URL"
fi

if [[ "$MODE_EXPLICIT" -ne 1 ]]; then
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
        run_backend_flow
        sync_vm_runtime
        bootstrap_vm_agent_runtime
        wait_for_agent_registration
        if [[ "$SUPPRESS_FOLLOWUP_SUMMARY" -ne 1 ]]; then
            print_backend_followup_summary
        fi
        ;;
    agent)
        setup_agent
        if [[ "$SUPPRESS_FOLLOWUP_SUMMARY" -ne 1 ]]; then
            print_agent_followup_summary
        fi
        ;;
    all)
        run_backend_flow
        setup_agent
        sync_vm_runtime
        bootstrap_vm_agent_runtime
        wait_for_agent_registration
        if [[ "$SUPPRESS_FOLLOWUP_SUMMARY" -ne 1 ]]; then
            print_backend_followup_summary
            print_agent_followup_summary
        fi
        ;;
    *)
        die "지원하지 않는 mode 입니다: ${MODE}"
        ;;
esac
