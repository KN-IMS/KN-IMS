local_mysql_client_available() {
    command -v mysql >/dev/null 2>&1 && command -v mysqladmin >/dev/null 2>&1
}

resolve_go_bin_link() {
    if [[ -n "$GO_BIN_LINK" ]]; then
        return 0
    fi

    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        GO_BIN_LINK="/usr/local/bin/go"
    else
        GO_BIN_LINK="${HOME}/.local/bin/go"
    fi
}

publish_go_bin() {
    local current_go=""
    local link_dir=""

    [[ -n "$GO_BIN" ]] || return 0

    current_go="$(command -v go 2>/dev/null || true)"
    if [[ -n "$current_go" && "$current_go" == "$GO_BIN" ]]; then
        return 0
    fi

    resolve_go_bin_link
    link_dir="$(dirname "$GO_BIN_LINK")"
    mkdir -p "$link_dir"

    if [[ -e "$GO_BIN_LINK" && ! -L "$GO_BIN_LINK" ]]; then
        warn "기존 go 실행 파일이 있어 링크 생성을 건너뜁니다: ${GO_BIN_LINK}"
        return 0
    fi

    ln -sfn "$GO_BIN" "$GO_BIN_LINK"
    log "Go 실행 링크 갱신: ${GO_BIN_LINK} -> ${GO_BIN}"
}

linux_mysql_server_package_present() {
    command -v dpkg-query >/dev/null 2>&1 || return 1

    dpkg-query -W -f='${Status}' mysql-server 2>/dev/null | grep -q 'install ok installed' && return 0
    dpkg-query -W -f='${Status}' mysql-community-server 2>/dev/null | grep -q 'install ok installed' && return 0
    dpkg-query -W -f='${Status}' mariadb-server 2>/dev/null | grep -q 'install ok installed' && return 0

    return 1
}

local_mysql_server_present() {
    if ! is_local_db_host "$DB_HOST"; then
        return 1
    fi

    case "$(uname -s)" in
        Darwin)
            if command -v brew >/dev/null 2>&1 && brew list mysql >/dev/null 2>&1; then
                return 0
            fi
            command -v mysqld >/dev/null 2>&1 && return 0
            ;;
        Linux)
            pgrep -x mysqld >/dev/null 2>&1 && return 0
            command -v mysqld >/dev/null 2>&1 && return 0
            linux_mysql_server_package_present && return 0
            ;;
    esac

    return 1
}

prompt_db_admin_credentials() {
    prompt_value DB_ADMIN_USER "MySQL admin user" "${DB_ADMIN_USER:-root}"
    prompt_secret DB_ADMIN_PASSWORD "MySQL admin password (비어 있으면 socket auth 또는 무비밀번호 시도)" "${DB_ADMIN_PASSWORD:-}"
}

collect_db_admin_credentials_if_needed() {
    if [[ "$SETUP_DATABASE" -ne 1 ]] || ! is_interactive; then
        return 0
    fi

    if is_local_db_host "$DB_HOST"; then
        if local_mysql_client_available && local_mysql_server_present; then
            log "기존 로컬 MySQL 감지 — admin 계정 정보를 확인합니다."
            prompt_db_admin_credentials
        fi
        return 0
    fi

    log "원격 MySQL 설정을 위해 admin 계정 정보를 확인합니다."
    prompt_db_admin_credentials
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
            publish_go_bin
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
    publish_go_bin
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
            publish_go_bin
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

start_linux_mysql_service() {
    local unit=""

    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true

        for unit in mysql mysqld mariadb; do
            if systemctl list-unit-files 2>/dev/null | grep -q "^${unit}\\.service"; then
                log "MySQL 서비스 시작 (${unit}.service)"
                if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
                    systemctl enable --now "$unit" >/dev/null 2>&1 || true
                elif command -v sudo >/dev/null 2>&1; then
                    sudo systemctl enable --now "$unit" >/dev/null 2>&1 || true
                fi

                if mysql_admin_ping; then
                    return 0
                fi
            fi
        done
    fi

    if command -v service >/dev/null 2>&1; then
        for unit in mysql mysqld mariadb; do
            if service "$unit" status >/dev/null 2>&1 || service "$unit" start >/dev/null 2>&1; then
                log "MySQL 서비스 시작 확인 (service ${unit})"
                if mysql_admin_ping; then
                    return 0
                fi
            fi
        done
    fi

    for unit in mysql mysqld mariadb; do
        if [[ -x "/etc/init.d/${unit}" ]]; then
            "/etc/init.d/${unit}" start >/dev/null 2>&1 || true
            log "MySQL 서비스 시작 확인 (/etc/init.d/${unit})"
            if mysql_admin_ping; then
                return 0
            fi
        fi
    done

    return 1
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

prompt_mysql_admin_recovery_if_needed() {
    if [[ "$SETUP_DATABASE" -ne 1 ]] || ! is_interactive; then
        return 1
    fi

    warn "현재 MySQL admin 계정 정보로 접속 확인에 실패했습니다."
    prompt_db_admin_credentials
    mysql_admin_ping
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
    local need_sshpass=0
    local packages=()

    if ! command -v curl >/dev/null 2>&1 \
        && ! command -v wget >/dev/null 2>&1 \
        && ! command -v python3 >/dev/null 2>&1; then
        need_downloader=1
    fi

    if [[ "$SETUP_DATABASE" -eq 1 ]]; then
        if is_local_db_host "$DB_HOST"; then
            if ! local_mysql_client_available || ! local_mysql_server_present; then
                need_mysql=1
            fi
        else
            if ! local_mysql_client_available; then
                need_mysql=1
            fi
        fi
    fi

    if [[ "$VM_SYNC_ENABLED" -eq 1 && -n "$VM_PASSWORD" ]] && ! command -v sshpass >/dev/null 2>&1; then
        need_sshpass=1
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

                if [[ "$need_sshpass" -eq 1 ]]; then
                    warn "macOS에서는 sshpass 자동 설치를 지원하지 않습니다. VM 비밀번호 자동 입력이 필요하면 sshpass를 수동 설치하거나 SSH 키 인증을 사용하세요."
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
                if [[ "$need_sshpass" -eq 1 ]]; then
                    packages+=(sshpass)
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
        if ! mysql_admin_ping && ! prompt_mysql_admin_recovery_if_needed; then
            warn "DB 접속 정보(${DB_HOST}:${DB_PORT}) 기준 mysqladmin ping 확인 실패 — 이후 DB 단계에서 재시도합니다."
        fi
        return 0
    fi

    case "$(uname -s)" in
        Darwin)
            if command -v brew >/dev/null 2>&1 && brew list mysql >/dev/null 2>&1; then
                log "MySQL 서비스 시작 확인 (brew services)"
                HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1 \
                    brew services start mysql >/dev/null 2>&1 || true
            fi
            ;;
        Linux)
            start_linux_mysql_service || true
            ;;
    esac

    if ! mysql_admin_ping && ! prompt_mysql_admin_recovery_if_needed; then
        warn "DB 접속 정보(${DB_HOST}:${DB_PORT}) 기준 mysqladmin ping 확인 실패 — 이후 DB 단계에서 재시도합니다."
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
