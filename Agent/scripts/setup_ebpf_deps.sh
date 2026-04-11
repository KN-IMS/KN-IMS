#!/usr/bin/env bash
# =============================================================================
# setup_ebpf_deps.sh — im_monitor eBPF 빌드 의존성 설치
#
# eBPF 전용 (LSM 훅, kernel 5.8+ 필수)
# LKM 의존성은 scripts/setup_lkm_env.sh 참조
#
# 필수 조건:
#   - kernel >= 5.8  (BPF LSM 지원)
#   - CONFIG_BPF_LSM=y
#   - CONFIG_DEBUG_INFO_BTF=y  (BTF 타입 정보)
#
# 지원 OS:
#   Ubuntu 20.04 / 22.04 / 24.04
#   CentOS Stream 9 / RHEL 9 (kernel 5.14+)
#   Debian 11 (bullseye) / 12 (bookworm)
#
# 사용법:
#   chmod +x setup_ebpf_deps.sh
#   ./setup_ebpf_deps.sh           # 의존성 설치
#   ./setup_ebpf_deps.sh --check   # 커널 요구사항만 확인 (설치 없음)
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
DO_INSTALL=1

for arg in "$@"; do
    case "$arg" in
        --check) DO_INSTALL=0 ;;
        -h|--help)
            grep '^#' "$0" | head -25 | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

# ── 루트 확인 ──────────────────────────────────────────────
if [[ "$DO_INSTALL" -eq 1 && $EUID -ne 0 ]]; then
    error "의존성 설치에는 루트 권한 필요: sudo $0 $*"
fi

# ── OS / 커널 감지 ─────────────────────────────────────────
detect_env() {
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

# ── 커널 요구사항 검사 ─────────────────────────────────────
check_kernel_requirements() {
    echo ""
    info "── 커널 요구사항 검사 ──────────────────────────"

    local fail=0

    # 커널 버전 5.8 이상
    if [[ "$KMAJ" -gt 5 ]] || [[ "$KMAJ" -eq 5 && "$KMIN" -ge 8 ]]; then
        ok "커널 버전: $KMAJ.$KMIN >= 5.8  ✓"
    else
        error "커널 버전 $KMAJ.$KMIN — eBPF LSM은 5.8 이상 필요. LKM 방식(setup_lkm_env.sh) 사용 권장"
    fi

    # CONFIG_BPF_LSM
    local kconfig=""
    if [[ -f "/boot/config-$(uname -r)" ]]; then
        kconfig="/boot/config-$(uname -r)"
    elif [[ -f /proc/config.gz ]]; then
        kconfig="proc_gz"
    fi

    check_kconfig() {
        local opt="$1"
        local val
        if [[ "$kconfig" == "proc_gz" ]]; then
            val=$(zcat /proc/config.gz 2>/dev/null | grep "^${opt}=" | cut -d= -f2)
        elif [[ -n "$kconfig" ]]; then
            val=$(grep "^${opt}=" "$kconfig" 2>/dev/null | cut -d= -f2)
        else
            warn "$opt — 커널 설정 파일 없음 (확인 불가)"
            return
        fi

        if [[ "$val" == "y" ]]; then
            ok "$opt=y  ✓"
        else
            warn "$opt=${val:-미설정}  — eBPF LSM 동작 안 할 수 있음"
            fail=1
        fi
    }

    check_kconfig CONFIG_BPF_LSM
    check_kconfig CONFIG_DEBUG_INFO_BTF
    check_kconfig CONFIG_BPF_SYSCALL
    check_kconfig CONFIG_BPF_JIT

    # BTF vmlinux 파일 (CO-RE 필수)
    if [[ -f /sys/kernel/btf/vmlinux ]]; then
        ok "/sys/kernel/btf/vmlinux 존재  ✓"
    else
        warn "/sys/kernel/btf/vmlinux 없음 — CONFIG_DEBUG_INFO_BTF=y 재빌드 또는 btf 패키지 필요"
        fail=1
    fi

    # lsm= 부트 파라미터 확인 (bpf 포함 여부)
    if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
        ok "LSM 스택에 bpf 포함  ✓ ($(cat /sys/kernel/security/lsm))"
    else
        warn "LSM 스택에 bpf 없음 — 부트 파라미터 lsm=...,bpf 추가 필요"
        warn "  예) GRUB_CMDLINE_LINUX=\"... lsm=lockdown,capability,yama,apparmor,bpf\""
        warn "  설정 후: sudo update-grub && sudo reboot"
        fail=1
    fi

    if [[ "$fail" -eq 0 ]]; then
        ok "모든 커널 요구사항 충족"
    else
        warn "일부 요구사항 미충족 — 위 경고 확인 후 진행"
    fi
    echo ""
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
        git

    info "eBPF 필수 도구 설치..."
    apt-get install -y \
        clang \
        llvm \
        libelf-dev \
        zlib1g-dev

    info "libbpf 개발 헤더 설치..."
    if apt-get install -y libbpf-dev; then
        ok "libbpf-dev 설치 완료"
    else
        warn "libbpf-dev 패키지 없음 — 소스 빌드 시도..."
        install_libbpf_from_source
    fi

    # bpftool — 소스 빌드
    install_bpftool_from_source

    info "커널 헤더 설치 ($(uname -r))..."
    if apt-get install -y "linux-headers-$(uname -r)"; then
        ok "커널 헤더 설치 완료"
    else
        warn "정확한 버전 헤더 없음 — generic 시도..."
        apt-get install -y linux-headers-generic || \
            warn "커널 헤더 설치 실패 — libbpf 헤더만으로 빌드 시도 가능"
    fi
}

# ── CentOS Stream 9 / RHEL 9 의존성 설치 ──────────────────
install_centos9() {
    info "EPEL 및 CRB 저장소 활성화..."
    dnf install -y epel-release || warn "EPEL 설치 실패 (계속 진행)"
    dnf config-manager --set-enabled crb 2>/dev/null || \
        warn "CRB 활성화 실패 (계속 진행)"

    info "기본 빌드 도구 설치..."
    dnf install -y \
        gcc \
        gcc-c++ \
        make \
        cmake \
        git \
        elfutils-libelf-devel \
        zlib-devel

    info "eBPF 필수 도구 설치..."
    dnf install -y \
        clang \
        llvm

    # bpftool — 소스 빌드
    install_bpftool_from_source

    info "libbpf 개발 헤더 설치..."
    if dnf install -y libbpf-devel; then
        ok "libbpf-devel 설치 완료"
    else
        warn "libbpf-devel 없음 — 소스 빌드 시도..."
        install_libbpf_from_source
    fi

    info "커널 헤더 설치 ($(uname -r))..."
    if dnf install -y "kernel-devel-$(uname -r)"; then
        ok "커널 헤더 설치 완료"
    else
        warn "정확한 버전 헤더 없음 — 최신 kernel-devel 시도..."
        dnf install -y kernel-devel || warn "커널 헤더 설치 실패"
    fi
}

# ── libbpf 소스 빌드 (패키지 없는 경우 폴백) ──────────────
install_libbpf_from_source() {
    info "libbpf 소스에서 빌드 중..."

    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    if ! command -v git &>/dev/null; then
        error "git 없음 — libbpf 소스 빌드 불가"
    fi

    git clone --depth=1 https://github.com/libbpf/libbpf.git "$TMP_DIR/libbpf"
    cd "$TMP_DIR/libbpf/src"
    make -j"$(nproc)"
    make install

    ok "libbpf 소스 빌드 및 설치 완료"
    cd - >/dev/null
}

# ── bpftool 소스 빌드 ─────────────────────────────────────
# standalone bpftool 저장소 (kernel tree 불필요)
# https://github.com/libbpf/bpftool
install_bpftool_from_source() {
    if command -v bpftool &>/dev/null; then
        ok "bpftool 이미 설치됨: $(bpftool version 2>/dev/null | head -1)"
        return
    fi

    info "bpftool 소스 빌드 중 (github.com/libbpf/bpftool)..."

    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    trap "rm -rf '$TMP_DIR'" RETURN

    if ! command -v git &>/dev/null; then
        error "git 없음 — bpftool 소스 빌드 불가"
    fi

    git clone --depth=1 --recurse-submodules \
        https://github.com/libbpf/bpftool.git "$TMP_DIR/bpftool"

    # bpftool은 내부적으로 libbpf 서브모듈을 포함하므로
    # 시스템 libbpf와 무관하게 독립 빌드 가능
    make -C "$TMP_DIR/bpftool/src" -j"$(nproc)"
    cp "$TMP_DIR/bpftool/src/bpftool" /usr/local/bin/bpftool
    chmod +x /usr/local/bin/bpftool

    ok "bpftool 설치 완료: $(bpftool version 2>/dev/null | head -1)"
}

# ── clang 버전 검증 ────────────────────────────────────────
verify_clang() {
    if ! command -v clang &>/dev/null; then
        error "clang 없음 — eBPF BPF 바이트코드 컴파일 불가"
    fi

    local CLANG_MAJ
    CLANG_MAJ=$(clang --version | grep -oP 'clang version \K[0-9]+' | head -1)
    if [[ -n "$CLANG_MAJ" && "$CLANG_MAJ" -ge 10 ]]; then
        ok "clang $CLANG_MAJ 감지 (>= 10 필요)  ✓"
    else
        warn "clang ${CLANG_MAJ:-?} — 10 이상 권장"
    fi
}

# ── GRUB / LSM 커널 파라미터 설정 (재부팅 필요) ───────────
#
# eBPF LSM은 부트 파라미터 lsm=...,bpf 없이는 동작하지 않는다.
# 이 함수는 /etc/default/grub을 수정하고 update-grub / grub2-mkconfig를 실행.
# 실제 적용은 재부팅 후.
configure_lsm_grub() {
    echo ""
    info "── 커널 LSM 파라미터 설정 ──────────────────────"

    # 이미 bpf가 lsm 목록에 있으면 스킵
    if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
        ok "LSM 스택에 이미 bpf 포함 — GRUB 수정 불필요"
        return
    fi

    local GRUB_FILE=""
    if [[ -f /etc/default/grub ]]; then
        GRUB_FILE="/etc/default/grub"
    else
        warn "/etc/default/grub 없음 — GRUB 설정을 수동으로 진행하세요"
        print_manual_grub_guide
        return
    fi

    info "GRUB 설정 파일: $GRUB_FILE"

    # 현재 GRUB_CMDLINE_LINUX 값 추출
    local current_cmdline
    current_cmdline=$(grep '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE" \
                      | sed 's/GRUB_CMDLINE_LINUX=//' | tr -d '"')

    # lsm= 파라미터가 이미 있으면 bpf 추가, 없으면 새로 추가
    local new_cmdline
    if echo "$current_cmdline" | grep -q "lsm="; then
        # 기존 lsm= 값에 ,bpf 추가 (중복 방지)
        if echo "$current_cmdline" | grep -q "lsm=.*bpf"; then
            ok "lsm 파라미터에 bpf 이미 포함됨"
            new_cmdline="$current_cmdline"
        else
            new_cmdline=$(echo "$current_cmdline" \
                          | sed 's/\(lsm=[^[:space:]]*\)/\1,bpf/')
            info "기존 lsm= 파라미터에 bpf 추가"
        fi
    else
        # lsm= 파라미터 없음 → 기본 LSM 스택 + bpf 추가
        local default_lsm="lockdown,capability,yama,apparmor,bpf"
        new_cmdline="${current_cmdline} lsm=${default_lsm}"
        info "lsm 파라미터 신규 추가: lsm=${default_lsm}"
    fi

    # GRUB 파일 백업
    cp "$GRUB_FILE" "${GRUB_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    ok "GRUB 설정 백업 완료: ${GRUB_FILE}.bak.*"

    # GRUB_CMDLINE_LINUX 교체
    sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${new_cmdline}\"|" "$GRUB_FILE"
    info "적용된 GRUB_CMDLINE_LINUX: \"${new_cmdline}\""

    # GRUB 업데이트
    if command -v update-grub &>/dev/null; then
        update-grub
        ok "update-grub 완료"
    elif command -v grub2-mkconfig &>/dev/null; then
        # RHEL / CentOS 계열
        local grub_cfg=""
        if [[ -f /boot/grub2/grub.cfg ]]; then
            grub_cfg="/boot/grub2/grub.cfg"
        elif [[ -f /boot/efi/EFI/redhat/grub.cfg ]]; then
            grub_cfg="/boot/efi/EFI/redhat/grub.cfg"
        elif [[ -f /boot/efi/EFI/centos/grub.cfg ]]; then
            grub_cfg="/boot/efi/EFI/centos/grub.cfg"
        fi
        if [[ -n "$grub_cfg" ]]; then
            grub2-mkconfig -o "$grub_cfg"
            ok "grub2-mkconfig 완료: $grub_cfg"
        else
            warn "grub.cfg 경로를 찾지 못했습니다. 수동으로 실행하세요:"
            warn "  grub2-mkconfig -o /boot/grub2/grub.cfg"
        fi
    else
        warn "GRUB 업데이트 명령어(update-grub / grub2-mkconfig) 없음"
        warn "수동으로 GRUB를 업데이트하세요"
    fi

    echo ""
    echo -e "${YELLOW}  ┌─────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}  │  재부팅 후 LSM 설정이 적용됩니다.       │${NC}"
    echo -e "${YELLOW}  │  sudo reboot                            │${NC}"
    echo -e "${YELLOW}  │                                         │${NC}"
    echo -e "${YELLOW}  │  재부팅 후 확인:                        │${NC}"
    echo -e "${YELLOW}  │  cat /sys/kernel/security/lsm           │${NC}"
    echo -e "${YELLOW}  └─────────────────────────────────────────┘${NC}"
}

print_manual_grub_guide() {
    echo ""
    warn "수동 GRUB 설정 방법:"
    echo "  1. /etc/default/grub 편집"
    echo "     GRUB_CMDLINE_LINUX=\"... lsm=lockdown,capability,yama,apparmor,bpf\""
    echo "  2. GRUB 업데이트"
    echo "     Ubuntu/Debian:  sudo update-grub"
    echo "     RHEL/CentOS:    sudo grub2-mkconfig -o /boot/grub2/grub.cfg"
    echo "  3. 재부팅: sudo reboot"
    echo "  4. 확인:   cat /sys/kernel/security/lsm"
}

# ── 설치 요약 출력 ─────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  eBPF 의존성 설치 완료!  확인 사항:${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════${NC}"
    echo ""
    echo "  # 설치된 버전 확인"
    echo "  clang --version"
    echo "  llvm-config --version"
    echo "  pkg-config --modversion libbpf"
    echo ""
    echo "  # BTF 지원 확인"
    echo "  ls /sys/kernel/btf/vmlinux"
    echo ""
    echo "  # LSM 스택 확인 (bpf 포함 여부)"
    echo "  cat /sys/kernel/security/lsm"
    echo ""
    echo "  # lsm=...bpf 부트 파라미터 미설정 시 추가 필요:"
    echo "  # /etc/default/grub 편집 후 update-grub && reboot"
    echo ""
    echo "  # 빌드 (eBPF 활성으로 자동 감지됨)"
    echo "  mkdir -p build && cd build && cmake .. && make -j\$(nproc)"
    echo ""
}

# ── 메인 ───────────────────────────────────────────────────
main() {
    echo ""
    info "im_monitor eBPF 의존성 설치 시작"
    echo ""

    detect_env
    check_kernel_requirements

    if [[ "$DO_INSTALL" -eq 0 ]]; then
        info "--check 모드: 설치 없이 종료"
        exit 0
    fi

    info "── 의존성 설치 ────────────────────────────────"
    case "$OS_ID" in
        ubuntu|debian)
            install_debian
            ;;
        centos|rhel|rocky|almalinux)
            case "${OS_VER%%.*}" in
                7|8) error "CentOS/RHEL $OS_VER (kernel ${KMAJ}.${KMIN}) — eBPF LSM 미지원. setup_lkm_env.sh 사용 권장" ;;
                *)   install_centos9 ;;
            esac
            ;;
        *)
            error "지원하지 않는 OS: $OS_ID $OS_VER\nUbuntu 20.04+, Debian 11+, CentOS Stream 9+, RHEL 9+ 지원"
            ;;
    esac

    verify_clang
    ok "의존성 설치 완료"

    configure_lsm_grub

    print_summary
}

main
