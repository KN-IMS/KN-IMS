#ifndef IM_MONITOR_H
#define IM_MONITOR_H

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
#define IM_MAX_WATCHES      64
#define IM_MAX_PATH         PATH_MAX
#define IM_EVENT_BUF_SIZE   (1024 * (sizeof(struct inotify_event) + 256))
#define IM_CONFIG_PATH      "/etc/im_monitor/im.conf"
// #define IM_PID_FILE         "/var/run/im_monitor.pid"
#define IM_PID_FILE         "/tmp/im_monitor.pid"
#define IM_LOG_FILE         "/var/log/im_monitor.log"
#define IM_EVENT_QUEUE_SIZE 512

/* ── 커널 버전 비교 매크로 ─────────────────────── */
#define KERNEL_VER(maj, min) ((maj) * 65536 + (min) * 256)

/* ── 이벤트 타입 ───────────────────────────────── */
typedef enum {
    IM_EVENT_CREATE   = 0x01,
    IM_EVENT_MODIFY   = 0x02,
    IM_EVENT_DELETE   = 0x04,
    IM_EVENT_ATTRIB   = 0x08,
    IM_EVENT_MOVE     = 0x10,
    IM_EVENT_ACCESS   = 0x20,
    IM_EVENT_UNKNOWN  = 0x00
} im_event_type_t;

/* ── 이벤트 소스 ───────────────────────────────── */
typedef enum {
    IM_SOURCE_INOTIFY = 0,  /* inotify 상시 감시 */
    IM_SOURCE_EBPF    = 1,  /* eBPF LSM 훅 (kernel 5.8+) */
    IM_SOURCE_LKM     = 2,  /* 커널 모듈 kprobe (kernel < 5.8) */
} im_event_source_t;

/* ── 이벤트 구조체 ─────────────────────────────── */
typedef struct {
    im_event_type_t   type;
    im_event_source_t source;
    char               path[IM_MAX_PATH];
    char               filename[256];
    time_t             timestamp;
    /* who-data: eBPF 보강 시 채워짐. eBPF 미사용 시 0/"" */
    pid_t              pid;        /* 변경 유발 PID  (eBPF) */
    uid_t              uid;        /* 변경 유발 UID  (eBPF) */
    pid_t              sid;        /* 세션 ID        (eBPF) */
    char               comm[16];  /* 프로세스 이름  (eBPF) */
} im_event_t;

/* ── 스레드 안전 이벤트 큐 ─────────────────────── */
typedef struct {
    im_event_t        events[IM_EVENT_QUEUE_SIZE];
    int                head;
    int                tail;
    int                count;
    uint64_t           dropped;   /* 오버플로우로 드롭된 이벤트 누적 수 */
    pthread_mutex_t    lock;
    pthread_cond_t     not_empty;
} im_event_queue_t;

int      im_queue_init(im_event_queue_t *q);
void     im_queue_destroy(im_event_queue_t *q);
int      im_queue_push(im_event_queue_t *q, const im_event_t *ev);
int      im_queue_pop(im_event_queue_t *q, im_event_t *ev, int timeout_ms);
uint64_t im_queue_dropped(im_event_queue_t *q);

/* ── 감시 대상 항목 ────────────────────────────── */
typedef struct {
    char path[IM_MAX_PATH];
    int  recursive;
} im_watch_entry_t;

/* ── 설정 구조체 ────────────────────────────────── */
typedef struct {
    int               daemonize;
    char              log_file[IM_MAX_PATH];
    int               log_to_syslog;
    int               verbose;

    /* eBPF who-data 추적 (kernel 5.8+에서만 실제 활성화됨) */
    int               ebpf_enabled;

    /* inotify 상시 감시 대상 */
    int               watch_count;
    im_watch_entry_t watches[IM_MAX_WATCHES];

    /* 자체 보호 대상 — 변경 시 ALERT 로그 */
    int               protect_count;
    im_watch_entry_t protect_paths[32];
} im_config_t;

/* ── 백엔드 인터페이스 ─────────────────────────── */
typedef struct im_backend {
    const char *name;
    int  (*init)(struct im_backend *self, im_config_t *cfg,
                 im_event_queue_t *queue);
    int  (*add_watch)(struct im_backend *self, const char *path, int recursive);
    int  (*remove_watch)(struct im_backend *self, const char *path);
    int  (*poll_events)(struct im_backend *self);
    void (*cleanup)(struct im_backend *self);
    void *priv;
    im_event_queue_t *queue;
} im_backend_t;

/* ── 전역 변수 (로깅) ─────────────────────────── */
extern FILE *g_log_fp;
extern int   g_use_syslog;
extern int   g_verbose;
extern pthread_mutex_t g_log_lock;

static inline const char *im_event_type_str(im_event_type_t t) {
    switch (t) {
        case IM_EVENT_CREATE: return "CREATED";
        case IM_EVENT_MODIFY: return "MODIFIED";
        case IM_EVENT_DELETE: return "DELETED";
        case IM_EVENT_ATTRIB: return "ATTRIB_CHANGED";
        case IM_EVENT_MOVE:   return "MOVED";
        case IM_EVENT_ACCESS: return "ACCESSED";
        default:               return "UNKNOWN";
    }
}

static inline const char *im_source_str(im_event_source_t s) {
    switch (s) {
        case IM_SOURCE_INOTIFY: return "inotify";
        case IM_SOURCE_EBPF:    return "ebpf";
        case IM_SOURCE_LKM:     return "lkm";
        default:                 return "unknown";
    }
}

/* 스레드 안전 로깅 */
static inline void im_log(const char *level, const char *fmt, ...) {
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

#define LOG_INFO_FIM(...)   im_log("INFO",  __VA_ARGS__)
#define LOG_WARN_FIM(...)   im_log("WARN",  __VA_ARGS__)
#define LOG_ERROR_FIM(...)  im_log("ERROR", __VA_ARGS__)
#define LOG_ALERT_FIM(...)  im_log("ALERT", __VA_ARGS__)
#define LOG_DEBUG_FIM(...)  do { } while(0)  /* 비활성화 */

#endif /* IM_MONITOR_H */
