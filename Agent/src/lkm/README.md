# fim_lkm — LKM 파일 차단 커널 모듈

kernel 3.10+ (CentOS 7)에서 동작하는 sys_call_table 후킹 기반 파일 무결성 모듈.  
eBPF LSM이 불가능한 환경(kernel < 5.8)에서 파일 변경을 차단·탐지합니다.

---

## 아키텍처

```
유저스페이스                    커널 공간
──────────────                  ──────────────────────────────────
fim_agent
  │
  ├─ lkm_client_init()   ──→   /dev/fim_lkm  (chardev)
  │
  ├─ lkm_add_from_baseline()   ioctl(FIM_IOC_ADD_INODE)
  │   베이스라인 inode 주입  ──→   fim_lkm_policy.c
  │                              (해시테이블: dev+ino → mask/block/path)
  │
  └─ lkm_event_thread()        read(/dev/fim_lkm)  ←── kfifo
       이벤트 수신 루프              fim_lkm_events.c
                                      ▲
                               fim_lkm_hooks.c
                               sys_call_table 후킹
                               ┌──────────────────┐
                               │ sys_write         │ → FIM_OP_WRITE
                               │ sys_truncate      │
                               │ sys_ftruncate     │
                               │ sys_open (O_TRUNC)│
                               │ sys_openat        │
                               │ sys_creat         │
                               │ sys_unlink        │ → FIM_OP_DELETE
                               │ sys_unlinkat      │
                               │ sys_rename        │ → FIM_OP_RENAME
                               │ sys_renameat      │
                               │ sys_renameat2 *   │
                               │ sys_chmod         │ → FIM_OP_WRITE
                               │ sys_fchmodat      │
                               │ sys_chown         │
                               │ sys_fchownat      │
                               │ sys_link          │
                               │ sys_linkat        │
                               │ sys_setxattr      │
                               │ sys_lsetxattr     │
                               │ sys_fsetxattr     │
                               └──────────────────┘
                               * __NR_renameat2 정의 시 조건부 컴파일
```

---

## 파일 구성

| 파일 | 역할 |
|---|---|
| `fim_lkm_main.c` | 모듈 진입점 (`module_init` / `module_exit`) |
| `fim_lkm_hooks.c` | sys_call_table 후킹 · 정책 체크 · 이벤트 발행 |
| `fim_lkm_policy.c` | inode 기반 정책 해시테이블 (rwlock 보호) |
| `fim_lkm_events.c` | kfifo 이벤트 큐 + workqueue deferred wake_up |
| `fim_lkm_chardev.c` | `/dev/fim_lkm` char device (ioctl / blocking read / poll) |
| `fim_lkm_common.h` | 유저·커널 공유 구조체 및 상수 (`FIM_OP_*`, `FIM_BLOCK_*`) |
| `fim_lkm_policy.h` | 정책 API 선언 |
| `fim_lkm_events.h` | 이벤트 큐 API 선언 |
| `lkm_client.c/h` | 유저스페이스 클라이언트 (ioctl 래퍼 · 이벤트 수신) |

---

## 정책 모델

```
inode_policy_add(dev, ino, mask, block, path)
                               │       │
                        FIM_OP_WRITE   FIM_BLOCK_DENY   → -EPERM 반환
                        FIM_OP_DELETE  FIM_BLOCK_AUDIT  → 탐지만, 허용
                        FIM_OP_RENAME
```

- **키**: `(dev, ino)` — inode 번호 기반이므로 경로 이름 변경에 강건
- **삭제 감지 시**: `inode_policy_remove()` 로 inode 재사용 방지
- **정책 갱신**: SIGHUP 수신 시 `lkm_clear_all()` + `lkm_add_from_baseline()` 재주입

---

## 빌드

### 요구사항

- gcc (4.8 이상, CentOS 7 기본 gcc 가능)
- make
- 현재 실행 중인 커널과 동일 버전의 kernel-devel

```bash
# CentOS 7
sudo yum install kernel-devel-$(uname -r) gcc make

# Ubuntu
sudo apt install linux-headers-$(uname -r) gcc make
```

### 빌드 및 로드

```bash
cd src/lkm
make

# 로드
sudo insmod fim_lkm.ko
dmesg | tail -5       # "hooks installed" 확인

# 상태 확인
lsmod | grep fim_lkm

# 언로드
sudo rmmod fim_lkm
```

---

## 차단 테스트

```bash
# fim_agent 실행 중 상태에서 (lock 모드)
echo "tamper" >> /etc/important/file   # → Permission denied (EPERM)
rm /etc/important/file                 # → Operation not permitted
mv /etc/important/file /tmp/           # → Operation not permitted

# dmesg로 커널 로그 확인
dmesg | grep fim_lkm
# fim_lkm: DENY write: comm=bash dev=... ino=...
```

---

## 설계 결정 및 제약

### sys_call_table 방식을 선택한 이유

| 방식 | 문제 |
|---|---|
| kprobe `return 1` | kernel 3.10 CONFIG_OPTPROBES: JMP 트램폴린 최적화로 `regs->ip` 조작 무효 → VM 크래시 |
| vfs_write kprobe | atomic context에서 wake_up 직접 호출 불가 → 스케줄러 데드락 |
| **sys_call_table 교체** | process context에서 실행 → 안전하게 정책 조회·차단 가능 |

