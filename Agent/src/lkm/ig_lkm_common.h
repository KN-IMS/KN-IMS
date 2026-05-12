#ifndef IG_LKM_COMMON_H
#define IG_LKM_COMMON_H

/*
 * ig_lkm_common.h — 커널 모듈 ↔ 유저스페이스 공유 헤더
 *
 * 이 헤더는 커널 모듈(ig_lkm.ko)과 유저스페이스(lkm_client.c) 양쪽에서
 * include된다. ifdef로 커널/유저 타입을 분기한다.
 */

#ifdef __KERNEL__
#  include <linux/types.h>
#  include <linux/ioctl.h>
#else
#  include <stdint.h>
#  include <sys/ioctl.h>
#endif

/* ── 디바이스 ─────────────────────────────── */
#define IG_LKM_DEV_NAME  "ig_lkm"
#define IG_LKM_DEV_PATH  "/dev/ig_lkm"
#define IG_LKM_MAGIC     'F'

/* ── 동작 마스크 (mask 필드 비트) ────────── */
#define IG_OP_WRITE   (1U << 0)
#define IG_OP_DELETE  (1U << 1)
#define IG_OP_RENAME  (1U << 2)

/* ── 차단 모드 ───────────────────────────── */
#define IG_BLOCK_AUDIT  0U   /* 탐지 + 로그만, 허용 */
#define IG_BLOCK_DENY   1U   /* 탐지 + 차단 (-EPERM) */

/* ── ioctl 정책 요청 구조체 ──────────────── */
struct ig_lkm_policy_req {
    uint64_t dev;          /* stat_dev_to_kernel(st_dev) 변환 후 전달 */
    uint64_t ino;          /* st_ino 그대로 */
    uint32_t mask;         /* IG_OP_* 조합 */
    uint32_t block;        /* IG_BLOCK_AUDIT or IG_BLOCK_DENY */
    char     path[256];    /* 이벤트 로깅용 경로 (선택) */
};

/* ── 프로세스 계보 (chain) ─────────────────
 * hook 발동시 current → real_parent 따라가며 캡처 (race-free).
 * kernel context에서 mm 접근(exe/cmdline)은 비용/안전성 문제로 생략.
 * 유저 측에서 /proc 으로 best-effort 채워넣음.
 */
#define IG_LKM_CHAIN_MAX 16

#define IG_LKM_EXE_LEN     128
#define IG_LKM_CMDLINE_LEN 256
#define IG_LKM_TTY_LEN     16

struct ig_lkm_chain_entry {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;            /* real */
    uint32_t euid;           /* effective */
    uint32_t sid;
    uint32_t _pad0;
    char     comm[16];
    char     tty[IG_LKM_TTY_LEN];   /* "pts/1" / "tty1" / "" */
    uint64_t start_time_ns;  /* task->start_boottime / real_start_time → ns */
    /* fork-time 캐시에서 채움. 캐시 miss 시 빈 문자열 */
    char     exe[IG_LKM_EXE_LEN];
    char     cmdline[IG_LKM_CMDLINE_LEN];
};

/* ── 이벤트 구조체 (커널 → 유저) ─────────── */
struct ig_lkm_event {
    uint64_t dev;
    uint64_t ino;
    uint32_t op;           /* 발생한 동작 (IG_OP_*) */
    uint32_t blocked;      /* 1=실제 차단됨, 0=감지만 */
    uint32_t pid;
    uint32_t uid;
    char     comm[16];     /* 프로세스 이름 */
    char     path[256];    /* 정책에 저장된 경로 */
    int64_t  timestamp_ns; /* ktime_get_real_ns() */
    uint8_t  chain_depth;
    uint8_t  chain_truncated;
    uint16_t _pad1;
    uint32_t _pad2;
    struct ig_lkm_chain_entry chain[IG_LKM_CHAIN_MAX];
};

/* ── ioctl 명령어 ────────────────────────── */
#define IG_IOC_ADD_INODE    _IOW(IG_LKM_MAGIC, 1, struct ig_lkm_policy_req)
#define IG_IOC_REMOVE_INODE _IOW(IG_LKM_MAGIC, 2, struct ig_lkm_policy_req)
#define IG_IOC_CLEAR_ALL    _IO (IG_LKM_MAGIC, 3)

#endif /* IG_LKM_COMMON_H */
