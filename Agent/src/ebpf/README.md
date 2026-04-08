# fim_trace — eBPF LSM 파일 감시 모듈

kernel 5.8+ 에서 동작하는 CO-RE(Compile Once – Run Everywhere) eBPF 프로그램.  
LSM(Linux Security Module) 훅으로 파일 접근을 탐지·차단하고 PID/UID/프로세스명을 유저스페이스로 전달합니다.

---

## 아키텍처

```
유저스페이스                    커널 공간
──────────────                  ──────────────────────────────────
fim_agent
  │
  ├─ ebpf_policy_init()  ──→   BPF 맵 로드 (skeleton)
  │
  ├─ ebpf_policy_add_path_recursive()
  │   베이스라인 경로 주입   ──→  policy_map (inode → mask/block)
  │
  └─ ebpf_poll_thread()        Ring Buffer 폴링
       이벤트 수신 루프    ←──   fim_lkm_events (ring_buf)
                                      ▲
                               fim_trace.bpf.c
                               LSM 훅 (BPF_PROG_TYPE_LSM)
                               ┌──────────────────────────┐
                               │ lsm/inode_permission      │ VFS 권한 검사
                               │ lsm/file_open             │ 파일 열기
                               └──────────────────────────┘
                                  policy_map 조회 →
                                    DENY:  return -EPERM
                                    AUDIT: return 0 + Ring Buffer 기록
```

---

## 파일 구성

| 파일 | 역할 |
|---|---|
| `fim_trace.bpf.c` | eBPF 커널 프로그램 (LSM 훅 구현) |
| `fim_trace.c` | 유저스페이스 로더 · Ring Buffer 폴링 |
| `fim_trace_api.h` | fim_agent ↔ eBPF 로더 인터페이스 |
| `fim_trace.skel.h` | bpftool이 생성하는 C 스켈레톤 헤더 (빌드 산출물) |
| `vmlinux.h` | CO-RE용 커널 타입 정의 (bpftool btf dump으로 생성) |

---

## 커널 요구사항

### 필수 커널 설정

| 옵션 | 역할 |
|---|---|
| `CONFIG_BPF_LSM=y` | BPF 타입 LSM 프로그램 허용 |
| `CONFIG_DEBUG_INFO_BTF=y` | BTF 타입 정보 생성 (CO-RE 필수) |
| `CONFIG_BPF_SYSCALL=y` | BPF 시스템 콜 활성화 |
| `CONFIG_BPF_JIT=y` | BPF JIT 컴파일러 (성능) |

```bash
# 현재 커널 설정 확인
grep -E "CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF" /boot/config-$(uname -r)
```

### 필수 부트 파라미터

eBPF LSM은 `lsm=` 부트 파라미터에 `bpf`가 포함되어야 활성화됩니다.

```bash
# 현재 LSM 스택 확인
cat /sys/kernel/security/lsm
# 출력 예: lockdown,capability,yama,apparmor,bpf
```

`bpf`가 없으면 `scripts/setup_ebpf_deps.sh`가 자동으로 GRUB 설정을 수정합니다.  
수동 설정 방법:

```bash
# /etc/default/grub 편집
GRUB_CMDLINE_LINUX="... lsm=lockdown,capability,yama,apparmor,bpf"

# GRUB 업데이트
sudo update-grub          # Ubuntu / Debian
sudo grub2-mkconfig -o /boot/grub2/grub.cfg  # RHEL / CentOS Stream

# 재부팅
sudo reboot
```

---

## 의존성 설치

`scripts/setup_ebpf_deps.sh`로 한 번에 설치 가능합니다.

```bash
sudo ./scripts/setup_ebpf_deps.sh
```

### 수동 설치 (Ubuntu / Debian)

```bash
sudo apt install -y \
    clang llvm \
    libelf-dev zlib1g-dev \
    libbpf-dev \
    linux-headers-$(uname -r)

# bpftool (소스 빌드 권장)
git clone --depth=1 --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src && make -j$(nproc) && sudo cp bpftool /usr/local/bin/
```

### 수동 설치 (RHEL 9 / CentOS Stream 9)

```bash
sudo dnf install -y \
    clang llvm \
    elfutils-libelf-devel zlib-devel \
    libbpf-devel \
    kernel-devel-$(uname -r)

# bpftool (소스 빌드)
git clone --depth=1 --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src && make -j$(nproc) && sudo cp bpftool /usr/local/bin/
```

### 설치 확인

```bash
clang --version               # 10 이상
bpftool version
pkg-config --modversion libbpf
ls /sys/kernel/btf/vmlinux    # CO-RE 필수
```

---

## 빌드

```bash
cd src/ebpf
make
```

### 빌드 단계

```
fim_trace.bpf.c
    │
    │  clang -g -O2 -target bpf -D__TARGET_ARCH_x86
    ▼
.output/fim_trace.tmp.bpf.o     ← 원시 BPF ELF
    │
    │  bpftool gen object        (BTF 재배치 / CO-RE 처리)
    ▼
.output/fim_trace.bpf.o         ← 로드 가능한 최종 BPF 오브젝트
    │
    │  bpftool gen skeleton
    ▼
fim_trace.skel.h                ← 유저스페이스 로더용 C 헤더 (자동 생성)
```

---

## 자주 발생하는 오류

### `fatal error: 'bpf/bpf_helpers.h' file not found`

```bash
sudo apt install libbpf-dev     # Ubuntu
sudo dnf install libbpf-devel   # RHEL/CentOS Stream
```

### `libbpf: failed to find valid kernel BTF`

`/sys/kernel/btf/vmlinux` 없음 → `CONFIG_DEBUG_INFO_BTF=y` 필요

```bash
ls /sys/kernel/btf/vmlinux
```

### `bpftool: command not found`

소스 빌드:
```bash
git clone --depth=1 --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src && make -j$(nproc) && sudo cp bpftool /usr/local/bin/
```

### `clang: error: unknown target triple 'bpf'`

clang 버전 10 미만:
```bash
sudo apt install clang-14
export CLANG=clang-14
make CLANG=clang-14
```

### eBPF LSM 훅이 호출되지 않음

LSM 스택에 bpf 미포함:
```bash
cat /sys/kernel/security/lsm   # bpf 없으면 GRUB 설정 필요
# scripts/setup_ebpf_deps.sh 재실행 또는 수동 GRUB 설정 후 reboot
```
