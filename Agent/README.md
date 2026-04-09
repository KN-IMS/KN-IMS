# KGU-FIMS — File Integrity Monitor Agent

파일 무결성 모니터링 에이전트. 커널 버전에 따라 두 가지 백엔드를 지원합니다.

| 커널 | 백엔드 | 차단 방식 |
|---|---|---|
| 3.10 (CentOS 7) | **LKM** (sys_call_table 후킹) | DENY / AUDIT |
| < 5.8 | **inotify** (Kernel API) AUDIT ONLY |
| ≥ 5.8 | **eBPF LSM** | DENY / AUDIT |

---

## 디렉토리 구조

```
agent/
├── src/
│   ├── main.c                  # 데몬 진입점 · 이벤트 루프
│   ├── lkm/                    # LKM 커널 모듈 + 유저스페이스 클라이언트
│   │   └── README.md
│   ├── ebpf/                   # eBPF LSM 프로그램 + 유저스페이스 로더
│   │   └── README.md
│   ├── realtime/               # inotify 백엔드 (레거시, LKM/eBPF 비활성 시 폴백)
│   ├── scanner/                # 파일 베이스라인 스캔 · SHA-256 무결성 검사
│   └── transport/              # TLS TCP 클라이언트 · Go 서버 통신
├── scripts/
│   ├── setup_lkm_env.sh        # LKM 의존성 설치 (kernel 3.10+, CentOS 7 포함)
│   └── setup_ebpf_deps.sh      # eBPF 의존성 설치 + LSM GRUB 설정 (kernel 5.8+)
└── configs/
    └── test.conf               # 샘플 설정 파일
```

---

## 빠른 시작

### LKM 모드 (CentOS 7, kernel 3.10)

```bash
# 1. 의존성 설치
sudo ./scripts/setup_lkm_env.sh --deps-only

# 2. LKM 빌드
cd src/lkm && make

# 3. 에이전트 빌드
mkdir build && cd build && cmake .. && make -j$(nproc)

# 4. LKM 로드
sudo insmod src/lkm/fim_lkm.ko

# 5. 에이전트 실행
sudo ./build/fim_agent -f -v -c configs/test.conf -m lock
```

### eBPF 모드 (kernel 5.8+)

```bash
# 1. 의존성 설치 + LSM GRUB 설정 (재부팅 필요)
sudo ./scripts/setup_ebpf_deps.sh
sudo reboot

# 2. 재부팅 후 LSM 스택 확인
cat /sys/kernel/security/lsm   # bpf 포함 여부 확인

# 3. 빌드
mkdir build && cd build && cmake .. && make -j$(nproc)

## cmake 수동 설치
curl -L https://github.com/Kitware/CMake/releases/download/v3.28.3/cmake-3.28.3-linux-x86_64.sh -o cmake.sh   

chmod +x cmake.sh 
sudo sh cmake.sh --prefix=/usr/local --skip-license 

# 4. 에이전트 실행
sudo ./build/fim_agent -f -v -c configs/test.conf -m lock
```

---

## 동작 모드

| 플래그 | 모드 | 동작 |
|---|---|---|
| `-m lock` | DENY | 감시 파일 접근 시 `-EPERM` 반환 (기본값) |
| `-m maintenance` | AUDIT | 차단 없이 탐지·로그만 |

---

## 이벤트 흐름

```
[파일 접근 시도]
      │
      ├─ LKM:  sys_call_table 후킹 → inode 정책 조회 → DENY/AUDIT
      │        → /dev/fim_lkm (chardev) → lkm_event_thread
      │
      └─ eBPF: LSM 훅 → BPF 맵 정책 조회 → DENY/AUDIT
               → Ring Buffer → ebpf_poll_thread
                     │
                     ▼
              [공유 이벤트 큐]
                     │
                     ▼
          [메인 스레드 — process_event()]
           ├─ SHA-256 무결성 검사
           ├─ 로그 출력 (LOG_ALERT)
           └─ TCP 전송 → Go 서버
```

---

## 설정 파일

`/etc/fim_monitor/fim.conf` (또는 `-c` 플래그로 지정 단, 소유자 root 필수)

```ini
[general]
daemonize = false
log_file  = /var/log/fim_monitor.log
verbose   = true

[ebpf]
enabled = true

[watch]
path      = /etc/important
recursive = true

[watch]
path      = /opt/app/config
recursive = false
```

---

## 의존성 요약

| 항목 | LKM | eBPF |
|---|---|---|
| gcc / make | 필수 | 필수 |
| cmake | 필수 | 필수 |
| kernel-devel (현재 실행 커널) | 필수 | 필수 |
| openssl-devel / libssl-dev | 필수 | 필수 |
| clang ≥ 10 | 불필요 | 필수 |
| libbpf-dev | 불필요 | 필수 |
| bpftool | 불필요 | 빌드 시 필수 |
| CONFIG_BPF_LSM=y | 불필요 | 필수 |
| lsm=...,bpf (부트 파라미터) | 불필요 | 필수 |
