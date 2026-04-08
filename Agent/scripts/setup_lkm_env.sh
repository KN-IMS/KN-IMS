#!/usr/bin/env bash
# =============================================================================
# setup_lkm_env.sh — fim_lkm.ko (LKM) 빌드 환경 세팅
#
# LKM 전용 (sys_call_table 후킹, kernel 3.10+)
# eBPF 의존성은 scripts/setup_ebpf_deps.sh 참조
#
# 지원 OS:
#   Ubuntu 18.04 / 20.04 / 22.04
#   CentOS 7 (kernel 3.10)
#   CentOS Stream 8 / RHEL 8 (kernel 4.18)
#
# 사용법:
#   chmod +x setup_lkm_env.sh
#   ./setup_lkm_env.sh             # 의존성 설치 + 빌드
#   ./setup_lkm_env.sh --deps-only  # 의존성 설치만
#   ./setup_lkm_env.sh --build-only # 빌드만 (의존성 이미 설치된 경우)
# =============================================================================

set -euo pipefail

# ── 색상 출력 ──────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }

# ── 인자 파싱 ──────────────────────────────────────────────
DO_DEPS=1
DO_BUILD=1

for arg in "$@"; do
    case "$arg" in
        --deps-only)  DO_BUILD=0 ;;
        --build-only) DO_DEPS=0  ;;
        -h|--help)
            grep '^#' "$0" | head -20 | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

# ── 루트 확인 ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "루트 권한 필요: sudo $0 $*"
fi

# ── 스크립트 위치 기준으로 프로젝트 루트 결정 ──────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LKM_DIR="$PROJECT_DIR/src/lkm"
BUILD_DIR="$PROJECT_DIR/build"

info "프로젝트 루트: $PROJECT_DIR"

# ── OS 감지 ────────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VER="${VERSION_ID:-0}"
    else
        OS_ID="unknown"
        OS_VER="0"
    fi

    KVER=$(uname -r)
    KMAJ=$(uname -r | cut -d. -f1)
    KMIN=$(uname -r | cut -d. -f2)

    info "감지된 OS: ${PRETTY_NAME:-$OS_ID $OS_VER}"
    info "커널 버전: $KVER (${KMAJ}.${KMIN})"
}

# ── Ubuntu / Debian 의존성 설치 ────────────────────────────
install_debian() {
    info "패키지 목록 업데이트..."
    apt-get update -q

    info "기본 빌드 도구 설치..."
    apt-get install -y \
        build-essential \
        cmake \
        pkg-config \
        libssl-dev \
        git

    info "커널 헤더 설치 ($(uname -r))..."
    if apt-get install -y "linux-headers-$(uname -r)"; then
        ok "커널 헤더 설치 완료"
    else
        warn "정확한 버전 헤더 없음 — generic 시도..."
        apt-get install -y linux-headers-generic || \
            error "커널 헤더 설치 실패. 수동으로 설치하세요."
    fi

    # libbpf (선택적 — 5.8+에서만 실제 사용)
    if apt-get install -y libbpf-dev 2>/dev/null; then
        ok "libbpf 설치 완료"
    else
        warn "libbpf 없음 — eBPF 비활성으로 빌드됨 (LKM 모드는 정상 동작)"
    fi
}

# ── CentOS 7 EOL 미러 픽스 ────────────────────────────────
# CentOS 7은 2024년 6월 EOL. 공식 미러 내려감 → vault.centos.org 사용
fix_centos7_repos() {
    info "CentOS 7 저장소를 vault.centos.org로 교체..."

    # base / updates / extras: mirrorlist → vault baseurl
    for repo in CentOS-Base CentOS-Updates CentOS-Extras; do
        [[ -f "/etc/yum.repos.d/${repo}.repo" ]] && \
        sed -i \
            -e 's|^mirrorlist=|#mirrorlist=|g' \
            -e 's|^#baseurl=http://mirror.centos.org/centos|baseurl=http://vault.centos.org/centos|g' \
            "/etc/yum.repos.d/${repo}.repo"
    done

    # SCL 저장소 비활성화 — devtoolset 미사용, 미러 내려가서 makecache 실패 유발
    for repo in CentOS-SCLo-scl CentOS-SCLo-scl-rh; do
        if [[ -f "/etc/yum.repos.d/${repo}.repo" ]]; then
            sed -i 's/^enabled=1/enabled=0/' "/etc/yum.repos.d/${repo}.repo"
            info "SCL 저장소 비활성화: ${repo}"
        fi
    done

    yum clean all -q
    yum makecache fast -q 2>/dev/null || yum makecache -q
    ok "저장소 교체 완료 (vault.centos.org)"
}

# ── CentOS 7 (3.10) 의존성 설치 ───────────────────────────
install_centos7() {
    fix_centos7_repos

    info "EPEL 저장소 활성화..."
    # EPEL도 vault 경유로 설치
    yum install -y \
        "https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/Packages/e/epel-release-7-14.noarch.rpm" \
        2>/dev/null || warn "EPEL 설치 실패 (계속 진행)"

    info "기본 빌드 도구 설치..."
    yum install -y \
        gcc \
        gcc-c++ \
        make \
        cmake3 \
        openssl-devel \
        git

    info "커널 헤더 설치 ($(uname -r))..."
    if yum install -y "kernel-devel-$(uname -r)"; then
        ok "커널 헤더 설치 완료"
    else
        warn "정확한 버전 헤더 없음 — 최신 kernel-devel 시도..."
        yum install -y kernel-devel || error "커널 헤더 설치 실패."
        warn "헤더 버전과 실행 중인 커널 버전이 다를 수 있음."
        warn "재부팅 후 uname -r 과 rpm -qa kernel-devel 버전 일치 확인 필요."
    fi

    # cmake3 → cmake 심링크 (없으면 빌드 스크립트에서 cmake 못 찾음)
    if ! command -v cmake &>/dev/null; then
        ln -sf /usr/bin/cmake3 /usr/local/bin/cmake
        ok "cmake → cmake3 심링크 생성"
    fi

    # CentOS 7 기본 gcc(4.8)는 너무 오래됨 — devtoolset 권장
    GCC_VER=$(gcc -dumpversion | cut -d. -f1)
    if [[ "$GCC_VER" -lt 7 ]]; then
        warn "gcc $GCC_VER 감지 — 커널 모듈 빌드에 문제 없지만 최신 gcc 권장"
        info "devtoolset-8 설치 시도..."
        if yum install -y centos-release-scl && \
           yum install -y devtoolset-8; then
            ok "devtoolset-8 설치 완료"
            warn "새 gcc 사용하려면: scl enable devtoolset-8 bash"
        else
            warn "devtoolset-8 설치 실패 — 기본 gcc로 계속"
        fi
    fi
}

# ── CentOS 8 / RHEL 8 (4.18) 의존성 설치 ──────────────────
install_centos8() {
    info "PowerTools/CRB 저장소 활성화..."
    dnf install -y epel-release || warn "EPEL 설치 실패 (계속 진행)"
    dnf config-manager --set-enabled powertools 2>/dev/null || \
    dnf config-manager --set-enabled crb 2>/dev/null || \
        warn "PowerTools/CRB 활성화 실패 (계속 진행)"

    info "기본 빌드 도구 설치..."
    dnf install -y \
        gcc \
        gcc-c++ \
        make \
        cmake \
        openssl-devel \
        git

    info "커널 헤더 설치 ($(uname -r))..."
    if dnf install -y "kernel-devel-$(uname -r)"; then
        ok "커널 헤더 설치 완료"
    else
        warn "정확한 버전 헤더 없음 — 최신 kernel-devel 시도..."
        dnf install -y kernel-devel || error "커널 헤더 설치 실패."
    fi

    if dnf install -y libbpf-devel 2>/dev/null; then
        ok "libbpf 설치 완료"
    else
        warn "libbpf 없음 — eBPF 비활성으로 빌드됨"
    fi
}

# ── 빌드 디렉토리 / 심링크 확인 ───────────────────────────
verify_kernel_headers() {
    local build_link="/lib/modules/$(uname -r)/build"
    if [[ ! -d "$build_link" ]]; then
        error "커널 빌드 디렉토리 없음: $build_link\n커널 헤더가 올바르게 설치되지 않았습니다."
    fi
    ok "커널 빌드 디렉토리 확인: $build_link"
}

# ── LKM 빌드 ───────────────────────────────────────────────
build_lkm() {
    info "LKM 빌드 시작: $LKM_DIR"
    if [[ ! -d "$LKM_DIR" ]]; then
        error "LKM 소스 디렉토리 없음: $LKM_DIR"
    fi

    make -C "$LKM_DIR" clean 2>/dev/null || true
    make -C "$LKM_DIR" -j$(nproc)

    if [[ -f "$LKM_DIR/fim_lkm.ko" ]]; then
        ok "LKM 빌드 완료: $LKM_DIR/fim_lkm.ko"
        modinfo "$LKM_DIR/fim_lkm.ko" | grep -E "^(filename|version|license|description)"
    else
        error "fim_lkm.ko 생성 실패"
    fi
}

# ── fim_agent 빌드 ─────────────────────────────────────────
build_agent() {
    info "fim_agent 빌드 시작: $PROJECT_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)

    if [[ -f "$BUILD_DIR/fim_agent" ]]; then
        ok "fim_agent 빌드 완료: $BUILD_DIR/fim_agent"
    else
        error "fim_agent 빌드 실패"
    fi
}

# ── 설정 파일 초기화 ───────────────────────────────────────
setup_config() {
    local conf_dir="/etc/fim_monitor"
    local conf_file="$conf_dir/fim.conf"

    mkdir -p "$conf_dir"

    # 기존 설정이 있으면 덮어쓰지 않음
    if [[ -f "$conf_file" ]]; then
        info "설정 파일 이미 존재: $conf_file (덮어쓰지 않음)"
        return
    fi

    # 프로젝트 내 설정 파일 복사 시도
    local src_conf=""
    for candidate in \
        "$PROJECT_DIR/configs/test.conf" \
        "$PROJECT_DIR/configs/agent.yaml" \
        "$PROJECT_DIR/configs/fim.conf"
    do
        if [[ -f "$candidate" ]]; then
            src_conf="$candidate"
            break
        fi
    done

    if [[ -n "$src_conf" ]]; then
        cp "$src_conf" "$conf_file"
        ok "설정 파일 복사: $src_conf → $conf_file"
    else
        # 최소 기본 설정 생성
        warn "설정 파일 없음 — 기본 설정 생성"
        cat > "$conf_file" << 'EOF'
[general]
daemonize = false
log_file  = /var/log/fim_monitor.log
verbose   = true

[watch]
path      = /tmp/fim_test
recursive = true
EOF
        mkdir -p /tmp/fim_test
        echo "test" > /tmp/fim_test/sample.txt
        ok "기본 설정 생성: $conf_file (감시 경로: /tmp/fim_test)"
    fi
}

# ── 빠른 동작 확인 ─────────────────────────────────────────
smoke_test() {
    info "빠른 동작 확인..."

    # LKM 로드 테스트
    if [[ -f "$LKM_DIR/fim_lkm.ko" ]]; then
        if lsmod | grep -q fim_lkm; then
            warn "fim_lkm 이미 로드됨 — 언로드 후 재로드"
            rmmod fim_lkm 2>/dev/null || true
            sleep 1
        fi
        if insmod "$LKM_DIR/fim_lkm.ko"; then
            ok "fim_lkm.ko 로드 성공"
            sleep 1
            dmesg | tail -5
            rmmod fim_lkm
            ok "fim_lkm.ko 언로드 성공 (smoke test 완료)"
        else
            warn "fim_lkm.ko 로드 실패 — dmesg 확인 필요"
            dmesg | tail -10
        fi
    fi
}

# ── 사용법 안내 출력 ───────────────────────────────────────
print_next_steps() {
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  빌드 완료!  다음 단계:${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════${NC}"
    echo ""
    echo "  # 1. LKM 로드"
    echo "  sudo insmod $LKM_DIR/fim_lkm.ko"
    echo "  dmesg | tail -5"
    echo ""
    echo "  # 2. fim_agent 실행 (포그라운드 + 상세 로그)"
    echo "  sudo $BUILD_DIR/fim_agent -f -v -c /etc/fim_monitor/fim.conf -m lock"
    echo ""
    echo "  # 3. 차단 테스트 (별도 터미널)"
    echo "  echo 'hack' > /tmp/fim_test/sample.txt   # → Permission denied"
    echo "  rm /tmp/fim_test/sample.txt              # → Operation not permitted"
    echo ""
    echo "  # 4. 종료 후 LKM 언로드"
    echo "  sudo rmmod fim_lkm"
    echo ""
}

# ── 메인 ───────────────────────────────────────────────────
main() {
    echo ""
    info "fim_monitor VM 세팅 시작"
    echo ""

    detect_os

    if [[ "$DO_DEPS" -eq 1 ]]; then
        echo ""
        info "── 의존성 설치 ────────────────────────────────"
        case "$OS_ID" in
            ubuntu|debian)   install_debian  ;;
            centos)
                case "${OS_VER%%.*}" in
                    7) install_centos7 ;;
                    8) install_centos8 ;;
                    *) warn "CentOS $OS_VER — CentOS 8 방식 시도"; install_centos8 ;;
                esac
                ;;
            rhel|rocky|almalinux) install_centos8 ;;
            *)
                error "지원하지 않는 OS: $OS_ID $OS_VER\nUbuntu, Debian, CentOS 7/8, RHEL 8 지원"
                ;;
        esac

        verify_kernel_headers
        ok "의존성 설치 완료"
    fi

    if [[ "$DO_BUILD" -eq 1 ]]; then
        echo ""
        info "── 빌드 ───────────────────────────────────────"
        build_lkm
        build_agent
        setup_config

        echo ""
        info "── Smoke Test ─────────────────────────────────"
        smoke_test
    fi

    print_next_steps
}

main
