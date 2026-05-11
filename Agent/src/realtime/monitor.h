#ifndef IG_MONITOR_H
#define IG_MONITOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <pthread.h>

/* ── 설정 상수 ─────────────────────────────────── */
#define IG_MAX_WATCHES      64
#define IG_MAX_PATH         PATH_MAX
#define IG_EVENT_BUF_SIZE   (1024 * (sizeof(struct inotify_event) + 256))
#define IG_CONFIG_PATH      "/etc/ig_monitor/ig.conf"
// #define IG_PID_FILE         "/var/run/ig_monitor.pid"
#define IG_PID_FILE         "/tmp/ig_monitor.pid"
#define IG_LOG_FILE         "/var/log/ig_monitor.log"
#define IG_EVENT_QUEUE_SIZE 512

/* ── 커널 버전 비교 매크로 ─────────────────────── */
#define KERNEL_VER(maj, min) ((maj) * 65536 + (min) * 256)

/* ── 이벤트 타입 ───────────────────────────────── */
typedef enum {
    IG_EVENT_CREATE   = 0x01,
    IG_EVENT_MODIFY   = 0x02,
    IG_EVENT_DELETE   = 0x04,
    IG_EVENT_ATTRIB   = 0x08,
    IG_EVENT_MOVE     = 0x10,
    IG_EVENT_ACCESS   = 0x20,
    IG_EVENT_UNKNOWN  = 0x00
} ig_event_type_t;

/* ── 이벤트 소스 ───────────────────────────────── */
typedef enum {
    IG_SOURCE_INOTIFY  = 0, /* inotify 상시 감시 */
    IG_SOURCE_EBPF     = 1, /* eBPF LSM 훅 (kernel 5.8+) */
    IG_SOURCE_LKM      = 2, /* 커널 모듈 kprobe (kernel < 5.8) */
    IG_SOURCE_FANOTIFY = 3, /* fanotify mount/filesystem 감시 */
} ig_event_source_t;

/* ── 이벤트 구조체 ─────────────────────────────── */
/*
 * chain은 별도 헤더에 정의된 ig_pid_chain_t 사용.
 * 큐 memcpy 비용 줄이려고 헤더 분리 + 임베드 by value.
 * sizeof(ig_event_t) ≈ 17KB — 큐 512슬롯 시 ~8.5MB.
 */
#include "../scanner/pid_ancestry.h"

typedef struct {
    ig_event_type_t   type;
    ig_event_source_t source;
    char               path[IG_MAX_PATH];
    char               filename[256];
    time_t             timestamp;
    /* target inode 식별 — LKM/eBPF에서 채움 */
    uint64_t           dev;        /* kernel-encoded dev_t (major<<20)|minor */
    uint64_t           ino;
    int                blocked;    /* 1 = 차단됨, 0 = audit only */
    /* actor 빠른 접근용 (chain.chain[0]과 동일). eBPF/LKM 미사용 시 0/"" */
    pid_t              pid;
    uid_t              uid;
    pid_t              sid;
    char               comm[16];
    /* 프로세스 계보 — depth==0 이면 chain 없음 */
    ig_pid_chain_t     chain;
} ig_event_t;

/* ── 스레드 안전 이벤트 큐 ─────────────────────── */
typedef struct {
    ig_event_t        events[IG_EVENT_QUEUE_SIZE];
    int                head;
    int                tail;
    int                count;
    uint64_t           dropped;   /* 오버플로우로 드롭된 이벤트 누적 수 */
    pthread_mutex_t    lock;
    pthread_cond_t     not_empty;
} ig_event_queue_t;

int      ig_queue_init(ig_event_queue_t *q);
void     ig_queue_destroy(ig_event_queue_t *q);
int      ig_queue_push(ig_event_queue_t *q, const ig_event_t *ev);
int      ig_queue_pop(ig_event_queue_t *q, ig_event_t *ev, int timeout_ms);
uint64_t ig_queue_dropped(ig_event_queue_t *q);

/* ── 감시 대상 항목 ────────────────────────────── */
typedef struct {
    char path[IG_MAX_PATH];
    int  recursive;
} ig_watch_entry_t;

/* ── 설정 구조체 ────────────────────────────────── */
typedef struct {
    int               daemonize;
    char              log_file[IG_MAX_PATH];
    int               log_to_syslog;
    int               verbose;

    /* eBPF who-data 추적 (kernel 5.8+에서만 실제 활성화됨) */
    int               ebpf_enabled;

    /* inotify 상시 감시 대상 */
    int               watch_count;
    ig_watch_entry_t watches[IG_MAX_WATCHES];

    /* 자체 보호 대상 — 변경 시 ALERT 로그 */
    int               protect_count;
    ig_watch_entry_t protect_paths[32];
} ig_config_t;

/* ── 백엔드 인터페이스 ─────────────────────────── */
typedef struct ig_backend {
    const char *name;
    int  (*init)(struct ig_backend *self, ig_config_t *cfg,
                 ig_event_queue_t *queue);
    int  (*add_watch)(struct ig_backend *self, const char *path, int recursive);
    int  (*remove_watch)(struct ig_backend *self, const char *path);
    int  (*poll_events)(struct ig_backend *self);
    void (*cleanup)(struct ig_backend *self);
    void *priv;
    ig_event_queue_t *queue;
} ig_backend_t;

/* ── 전역 변수 (로깅) ─────────────────────────── */
extern FILE *g_log_fp;
extern int   g_use_syslog;
extern int   g_verbose;
extern pthread_mutex_t g_log_lock;

static inline const char *ig_event_type_str(ig_event_type_t t) {
    switch (t) {
        case IG_EVENT_CREATE: return "CREATED";
        case IG_EVENT_MODIFY: return "MODIFIED";
        case IG_EVENT_DELETE: return "DELETED";
        case IG_EVENT_ATTRIB: return "ATTRIB_CHANGED";
        case IG_EVENT_MOVE:   return "MOVED";
        case IG_EVENT_ACCESS: return "ACCESSED";
        default:               return "UNKNOWN";
    }
}

static inline const char *ig_source_str(ig_event_source_t s) {
    switch (s) {
        case IG_SOURCE_INOTIFY:  return "inotify";
        case IG_SOURCE_EBPF:     return "ebpf";
        case IG_SOURCE_LKM:      return "lkm";
        case IG_SOURCE_FANOTIFY: return "fanotify";
        default:                 return "unknown";
    }
}

/* 스레드 안전 로깅 */
static inline void ig_log(const char *level, const char *fmt, ...) {
    va_list ap;
    char timebuf[64];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

    pthread_mutex_lock(&g_log_lock);

    va_start(ap, fmt);
    if (g_log_fp) {
        fprintf(g_log_fp, "[%s] [%s] ", timebuf, level);
        vfprintf(g_log_fp, fmt, ap);
        fprintf(g_log_fp, "\n");
        fflush(g_log_fp);
    }
    va_end(ap);

    if (g_use_syslog) {
        int prio = LOG_INFO;
        if (strcmp(level, "ERROR") == 0) prio = LOG_ERR;
        else if (strcmp(level, "WARN") == 0) prio = LOG_WARNING;
        else if (strcmp(level, "ALERT") == 0) prio = LOG_ALERT;
        va_start(ap, fmt);
        vsyslog(prio, fmt, ap);
        va_end(ap);
    }

    pthread_mutex_unlock(&g_log_lock);
}

#define LOG_INFO_IG(...)   ig_log("INFO",  __VA_ARGS__)
#define LOG_WARN_IG(...)   ig_log("WARN",  __VA_ARGS__)
#define LOG_ERROR_IG(...)  ig_log("ERROR", __VA_ARGS__)
#define LOG_ALERT_IG(...)  ig_log("ALERT", __VA_ARGS__)
#define LOG_DEBUG_IG(...)  do { } while(0)  /* 비활성화 */

#endif /* IG_MONITOR_H */
