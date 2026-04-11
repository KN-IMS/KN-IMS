#ifndef IM_LKM_COMMON_H
#define IM_LKM_COMMON_H

/*
 * im_lkm_common.h — 커널 모듈 ↔ 유저스페이스 공유 헤더
 *
 * 이 헤더는 커널 모듈(im_lkm.ko)과 유저스페이스(lkm_client.c) 양쪽에서
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
#define IM_LKM_DEV_NAME  "im_lkm"
#define IM_LKM_DEV_PATH  "/dev/im_lkm"
#define IM_LKM_MAGIC     'F'

/* ── 동작 마스크 (mask 필드 비트) ────────── */
#define IM_OP_WRITE   (1U << 0)
#define IM_OP_DELETE  (1U << 1)
#define IM_OP_RENAME  (1U << 2)

/* ── 차단 모드 ───────────────────────────── */
#define IM_BLOCK_AUDIT  0U   /* 탐지 + 로그만, 허용 */
#define IM_BLOCK_DENY   1U   /* 탐지 + 차단 (-EPERM) */

/* ── ioctl 정책 요청 구조체 ──────────────── */
struct im_lkm_policy_req {
    uint64_t dev;          /* stat_dev_to_kernel(st_dev) 변환 후 전달 */
    uint64_t ino;          /* st_ino 그대로 */
    uint32_t mask;         /* IM_OP_* 조합 */
    uint32_t block;        /* IM_BLOCK_AUDIT or IM_BLOCK_DENY */
    char     path[256];    /* 이벤트 로깅용 경로 (선택) */
};

/* ── 이벤트 구조체 (커널 → 유저) ─────────── */
struct im_lkm_event {
    uint64_t dev;
    uint64_t ino;
    uint32_t op;           /* 발생한 동작 (IM_OP_*) */
    uint32_t blocked;      /* 1=실제 차단됨, 0=감지만 */
    uint32_t pid;
    uint32_t uid;
    char     comm[16];     /* 프로세스 이름 */
    char     path[256];    /* 정책에 저장된 경로 */
    int64_t  timestamp_ns; /* ktime_get_real_ns() */
};

/* ── ioctl 명령어 ────────────────────────── */
#define IM_IOC_ADD_INODE    _IOW(IM_LKM_MAGIC, 1, struct im_lkm_policy_req)
#define IM_IOC_REMOVE_INODE _IOW(IM_LKM_MAGIC, 2, struct im_lkm_policy_req)
#define IM_IOC_CLEAR_ALL    _IO (IM_LKM_MAGIC, 3)

#endif /* IM_LKM_COMMON_H */
