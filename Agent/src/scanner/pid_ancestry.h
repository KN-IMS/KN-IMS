#ifndef IG_PID_ANCESTRY_H
#define IG_PID_ANCESTRY_H

/*
 * pid_ancestry — /proc 기반 프로세스 계보(부모 체인) 수집
 *
 * 이벤트 발생 시점 기준의 chain만 제공한다.
 * 이미 exit한 부모는 /proc 항목이 사라지므로 truncated로 표시된다.
 * fork-time 캐싱(LKM/eBPF)이 추가되면 이 모듈은 fallback으로 남는다.
 */

#include <sys/types.h>
#include <stdint.h>
#include <pthread.h>

#define IG_PA_COMM_LEN     16
#define IG_PA_EXE_LEN      256
#define IG_PA_CMDLINE_LEN  512
#define IG_PA_TTY_LEN      32
#define IG_PA_MAX_DEPTH    16

typedef struct {
    pid_t    pid;
    pid_t    ppid;
    uid_t    uid;                          /* real uid */
    uid_t    euid;                         /* effective uid (권한 상승 추적) */
    pid_t    sid;                          /* session id */
    char     tty[IG_PA_TTY_LEN];           /* "pts/1", "tty1", "" */
    char     comm[IG_PA_COMM_LEN];
    char     exe[IG_PA_EXE_LEN];           /* readlink /proc/<pid>/exe */
    char     cmdline[IG_PA_CMDLINE_LEN];   /* NUL → space 변환됨 */
    uint64_t start_ticks;                  /* /proc/<pid>/stat field 22 (ticks since boot) */
    uint64_t start_time_ns;                /* epoch ns (boot_epoch + ticks*ns_per_tick) */
} ig_proc_info_t;

typedef struct {
    int             depth;                 /* 채워진 entry 수 */
    int             truncated;             /* 깊이 한계 또는 /proc 사라짐 */
    ig_proc_info_t  chain[IG_PA_MAX_DEPTH];
} ig_pid_chain_t;

/*
 * /proc 직접 읽기. 캐시 우회.
 *   pid : 시작 PID (chain[0])
 *   out : 결과 저장. depth==0 이면 /proc/<pid> 자체가 없음.
 * 반환: depth (>=0)
 */
int  ig_pa_resolve(pid_t pid, ig_pid_chain_t *out);

/*
 * "comm(pid)<-comm(pid)<-..." 컴팩트 한 줄 포맷.
 * buf 길이 부족 시 잘림.
 */
int  ig_pa_format(const ig_pid_chain_t *c, char *buf, size_t buflen);

/*
 * 멀티라인 상세 포맷 — alert 분석용.
 *   [0] comm(pid) uid=R/E tty=... exe=...
 *       cmdline: ...
 *   [1] ...
 * buf 권장: 8KB 이상.
 */
int  ig_pa_format_full(const ig_pid_chain_t *c, char *buf, size_t buflen);

/*
 * /proc 기반 in-place enrichment.
 *   info->pid 가 채워져 있어야 한다.
 *   exe/cmdline 만 best-effort 로 채운다 (이미 채워진 다른 필드는 보존).
 *   /proc 항목이 사라졌으면 무시(필드는 빈 상태로).
 */
void ig_pa_enrich_entry(ig_proc_info_t *info);

/* 캐시 init/free (전역 1개). capacity<=0 이면 캐시 비활성. */
int  ig_pa_cache_init(int capacity);
void ig_pa_cache_free(void);

/*
 * 캐시 우선 lookup. miss 시 ig_pa_resolve 후 insert.
 * key는 (pid, start_ticks) 쌍 — start_ticks 변하면 PID reuse로 간주.
 * 캐시 비활성 상태면 그냥 ig_pa_resolve 위임.
 */
int  ig_pa_resolve_cached(pid_t pid, ig_pid_chain_t *out);

/* 디버그/모니터링 */
typedef struct {
    uint64_t lookups;
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
} ig_pa_cache_stats_t;
void ig_pa_cache_get_stats(ig_pa_cache_stats_t *s);

#endif
