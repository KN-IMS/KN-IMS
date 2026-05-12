/*
 * pid_ancestry.c — /proc 기반 프로세스 계보 수집 + LRU 캐시
 *
 * 디스패치 흐름:
 *   ig_pa_resolve_cached(pid)
 *     → 캐시 hit (start_ticks 일치) ? 반환
 *     → miss → ig_pa_resolve(pid) → cache insert
 *
 * /proc 파싱 메모:
 *   /proc/<pid>/stat 필드 22(starttime, in clock ticks since boot)을
 *   PID 재사용 식별 키로 사용한다. 같은 PID여도 starttime이 다르면
 *   다른 프로세스다.
 *   stat 라인은 "pid (comm) state ppid pgrp sid ..." 포맷이며 comm은
 *   괄호로 둘러싸여 있고 그 안에 공백/괄호가 들어갈 수 있어 마지막
 *   ')'를 찾고 그 이후를 토크나이즈해야 한다.
 */

#include "pid_ancestry.h"
#include "../realtime/monitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

/* boot epoch (s) — start_ticks → start_time_ns 변환에 사용. 0이면 미초기화 */
static uint64_t g_boot_epoch_s = 0;
static long     g_clock_tck    = 100;     /* sysconf default */

static void load_boot_meta(void)
{
    if (g_boot_epoch_s) return;
    long tck = sysconf(_SC_CLK_TCK);
    if (tck > 0) g_clock_tck = tck;

    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long btime = 0;
        if (sscanf(line, "btime %llu", &btime) == 1) {
            g_boot_epoch_s = (uint64_t)btime;
            break;
        }
    }
    fclose(fp);
}

/* ── /proc 파서 ──────────────────────────────────── */

static int read_file_buf(const char *path, char *buf, size_t buflen, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, buflen - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    if (out_len) *out_len = (size_t)n;
    return 0;
}

/* tty_nr 인코딩 → "pts/N" or "ttyN" or "" */
static void format_tty(unsigned long tty_nr, char *out, size_t outlen)
{
    out[0] = '\0';
    if (tty_nr == 0) return;
    /* /proc/<pid>/stat 의 tty_nr 인코딩:
     *   bits 0..7    = minor low
     *   bits 8..15   = major
     *   bits 20..31  = minor high (linux 2.6+)
     */
    unsigned int major_n = (tty_nr >> 8) & 0xFF;
    unsigned int minor_n = (tty_nr & 0xFF) | ((tty_nr >> 12) & 0xFFF00);
    if (major_n == 136) {
        /* UNIX98 pty slave */
        snprintf(out, outlen, "pts/%u", minor_n);
    } else if (major_n == 4) {
        snprintf(out, outlen, "tty%u", minor_n);
    } else {
        snprintf(out, outlen, "tty:%u,%u", major_n, minor_n);
    }
}

/* /proc/<pid>/stat 파싱: ppid, sid, tty_nr, start_ticks, comm */
static int parse_stat(pid_t pid, ig_proc_info_t *info)
{
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    size_t n = 0;
    if (read_file_buf(path, buf, sizeof(buf), &n) < 0) return -1;

    /* 마지막 ')' 찾기 */
    char *rparen = NULL;
    for (size_t i = n; i > 0; i--) {
        if (buf[i - 1] == ')') { rparen = &buf[i - 1]; break; }
    }
    if (!rparen) return -1;

    /* "pid (comm)" 추출 */
    char *lparen = strchr(buf, '(');
    if (!lparen || lparen >= rparen) return -1;
    size_t comm_len = (size_t)(rparen - lparen - 1);
    if (comm_len >= IG_PA_COMM_LEN) comm_len = IG_PA_COMM_LEN - 1;
    memcpy(info->comm, lparen + 1, comm_len);
    info->comm[comm_len] = '\0';

    /* 필드: 3=state, 4=ppid, 5=pgrp, 6=sid, 7=tty_nr, ..., 22=starttime */
    char *p = rparen + 1;
    while (*p == ' ') p++;
    while (*p && *p != ' ') p++;            /* skip state */

    long ppid = 0, sid = 0;
    unsigned long tty_nr = 0;
    unsigned long long starttime = 0;
    int field = 4;
    while (*p && field <= 22) {
        while (*p == ' ') p++;
        char *next = p;
        while (*next && *next != ' ') next++;
        char saved = *next;
        *next = '\0';

        switch (field) {
        case 4:  ppid       = strtol(p, NULL, 10); break;
        case 6:  sid        = strtol(p, NULL, 10); break;
        case 7:  tty_nr     = strtoul(p, NULL, 10); break;
        case 22: starttime  = strtoull(p, NULL, 10); break;
        default: break;
        }

        *next = saved;
        p = next;
        field++;
    }

    info->ppid        = (pid_t)ppid;
    info->sid         = (pid_t)sid;
    info->start_ticks = (uint64_t)starttime;
    format_tty(tty_nr, info->tty, sizeof(info->tty));

    /* start_time_ns = boot_epoch_ns + ticks * (1e9 / CLK_TCK) */
    if (g_boot_epoch_s && g_clock_tck > 0) {
        uint64_t ns_per_tick = 1000000000ULL / (uint64_t)g_clock_tck;
        info->start_time_ns = g_boot_epoch_s * 1000000000ULL
                             + info->start_ticks * ns_per_tick;
    } else {
        info->start_time_ns = 0;
    }
    return 0;
}

/* /proc/<pid>/status 의 "Uid: real eff sav fs" — real, effective 둘 다 추출 */
static void parse_status_uid(pid_t pid, ig_proc_info_t *info)
{
    char path[64], buf[2048];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    if (read_file_buf(path, buf, sizeof(buf), NULL) < 0) return;
    char *p = strstr(buf, "\nUid:");
    if (!p) {
        if (strncmp(buf, "Uid:", 4) == 0) p = buf;
        else return;
    } else {
        p += 1;
    }
    p += 4;
    while (*p == ' ' || *p == '\t') p++;

    char *end = NULL;
    unsigned long real_uid = strtoul(p, &end, 10);
    info->uid = (uid_t)real_uid;
    if (!end) return;
    while (*end == ' ' || *end == '\t') end++;
    if (*end == '\0' || *end == '\n') return;
    unsigned long eff_uid = strtoul(end, NULL, 10);
    info->euid = (uid_t)eff_uid;
}

static void parse_exe(pid_t pid, ig_proc_info_t *info)
{
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t n = readlink(link, info->exe, IG_PA_EXE_LEN - 1);
    if (n < 0) { info->exe[0] = '\0'; return; }
    info->exe[n] = '\0';
}

static void parse_cmdline(pid_t pid, ig_proc_info_t *info)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    size_t n = 0;
    if (read_file_buf(path, info->cmdline, IG_PA_CMDLINE_LEN, &n) < 0) {
        info->cmdline[0] = '\0';
        return;
    }
    if (n == 0) { info->cmdline[0] = '\0'; return; }
    /* NUL 구분자 → space, 마지막 NUL 제거 */
    for (size_t i = 0; i < n - 1; i++) {
        if (info->cmdline[i] == '\0') info->cmdline[i] = ' ';
    }
    /* trailing space 정리 */
    size_t end = strlen(info->cmdline);
    while (end > 0 && info->cmdline[end - 1] == ' ') info->cmdline[--end] = '\0';
}

static int load_proc_info(pid_t pid, ig_proc_info_t *info)
{
    memset(info, 0, sizeof(*info));
    info->pid = pid;
    if (parse_stat(pid, info) < 0) return -1;
    parse_status_uid(pid, info);
    parse_exe(pid, info);
    parse_cmdline(pid, info);
    return 0;
}

/* exe/cmdline만 in-place 채움 (lkm chain 보강용) */
void ig_pa_enrich_entry(ig_proc_info_t *info)
{
    if (!info || info->pid <= 0) return;
    if (info->exe[0] == '\0')      parse_exe(info->pid, info);
    if (info->cmdline[0] == '\0')  parse_cmdline(info->pid, info);
}

/* ── 공개 API: resolve ──────────────────────────────── */

int ig_pa_resolve(pid_t pid, ig_pid_chain_t *out)
{
    memset(out, 0, sizeof(*out));
    if (pid <= 0) return 0;
    load_boot_meta();

    pid_t cur = pid;
    for (int i = 0; i < IG_PA_MAX_DEPTH; i++) {
        ig_proc_info_t *e = &out->chain[i];
        if (load_proc_info(cur, e) < 0) {
            /* /proc/<pid> 사라짐 → 부모 추적 종료 */
            out->truncated = 1;
            break;
        }
        out->depth = i + 1;

        /* 종결 조건: init/kthreadd/self-loop */
        if (e->ppid <= 1 || e->ppid == cur) break;
        cur = e->ppid;

        if (i == IG_PA_MAX_DEPTH - 1) out->truncated = 1;
    }
    return out->depth;
}

int ig_pa_format(const ig_pid_chain_t *c, char *buf, size_t buflen)
{
    if (!c || !buf || buflen == 0) return -1;
    buf[0] = '\0';
    size_t off = 0;
    for (int i = 0; i < c->depth; i++) {
        const ig_proc_info_t *e = &c->chain[i];
        const char *sep = (i == 0) ? "" : "<-";
        int n = snprintf(buf + off, buflen - off, "%s%s(%d)",
                         sep, e->comm[0] ? e->comm : "?", (int)e->pid);
        if (n < 0 || (size_t)n >= buflen - off) {
            /* 잘림: 잘림 표시만 */
            if (buflen >= 4) {
                size_t e_off = (off + 3 < buflen) ? off : buflen - 4;
                buf[e_off]     = '.';
                buf[e_off + 1] = '.';
                buf[e_off + 2] = '.';
                buf[e_off + 3] = '\0';
            }
            return -1;
        }
        off += (size_t)n;
    }
    if (c->truncated && off + 4 < buflen) {
        memcpy(buf + off, "<-?", 4);
    }
    return (int)off;
}

int ig_pa_format_full(const ig_pid_chain_t *c, char *buf, size_t buflen)
{
    if (!c || !buf || buflen == 0) return -1;
    buf[0] = '\0';
    size_t off = 0;

    #define APPEND(...) do {                                         \
        int _n = snprintf(buf + off, buflen - off, __VA_ARGS__);     \
        if (_n < 0 || (size_t)_n >= buflen - off) goto trunc;        \
        off += (size_t)_n;                                           \
    } while (0)

    if (c->depth == 0) {
        APPEND("(no chain)");
        return (int)off;
    }

    for (int i = 0; i < c->depth; i++) {
        const ig_proc_info_t *e = &c->chain[i];
        APPEND("\n  [%d] %s(%d) ppid=%d uid=%u/%u sid=%d",
               i,
               e->comm[0] ? e->comm : "?",
               (int)e->pid,
               (int)e->ppid,
               (unsigned)e->uid, (unsigned)e->euid,
               (int)e->sid);
        if (e->tty[0]) APPEND(" tty=%s", e->tty);
        if (e->exe[0]) APPEND(" exe=%s", e->exe);
        if (e->start_time_ns) APPEND(" start=%lluns",
                                     (unsigned long long)e->start_time_ns);
        if (e->cmdline[0]) APPEND("\n      cmdline: %s", e->cmdline);
    }
    if (c->truncated) APPEND("\n  [..] (truncated)");
    #undef APPEND
    return (int)off;

trunc:
    if (buflen >= 5) {
        size_t e_off = (off + 4 < buflen) ? off : buflen - 5;
        memcpy(buf + e_off, "...", 4);
    }
    return -1;
}

/* ── LRU 캐시 ───────────────────────────────────────
 *
 * 단순 doubly-linked list + open-address hash.
 * lookups가 많지 않을 거라 (file event rate 자체가 낮음) 잠금은
 * 단일 mutex로 충분. 정합성 우선.
 */

typedef struct cache_node {
    pid_t              pid;
    uint64_t           start_ticks;
    ig_pid_chain_t     chain;
    struct cache_node *prev;
    struct cache_node *next;
    int                in_use;       /* slot 점유 여부 */
} cache_node_t;

static struct {
    cache_node_t  *nodes;            /* size = capacity */
    int            capacity;
    int            count;
    cache_node_t  *lru_head;         /* most recent */
    cache_node_t  *lru_tail;         /* eviction target */
    pthread_mutex_t lock;
    ig_pa_cache_stats_t stats;
    int            initialized;
} g_pa_cache;

static void lru_unlink(cache_node_t *n)
{
    if (n->prev) n->prev->next = n->next;
    else         g_pa_cache.lru_head = n->next;
    if (n->next) n->next->prev = n->prev;
    else         g_pa_cache.lru_tail = n->prev;
    n->prev = n->next = NULL;
}

static void lru_push_front(cache_node_t *n)
{
    n->prev = NULL;
    n->next = g_pa_cache.lru_head;
    if (g_pa_cache.lru_head) g_pa_cache.lru_head->prev = n;
    g_pa_cache.lru_head = n;
    if (!g_pa_cache.lru_tail) g_pa_cache.lru_tail = n;
}

static cache_node_t *cache_find(pid_t pid)
{
    /* 선형 탐색 — capacity가 크면 hash 추가하면 됨 */
    for (int i = 0; i < g_pa_cache.capacity; i++) {
        cache_node_t *n = &g_pa_cache.nodes[i];
        if (n->in_use && n->pid == pid) return n;
    }
    return NULL;
}

static cache_node_t *cache_alloc_slot(void)
{
    /* 빈 슬롯 → LRU tail eviction */
    for (int i = 0; i < g_pa_cache.capacity; i++) {
        cache_node_t *n = &g_pa_cache.nodes[i];
        if (!n->in_use) return n;
    }
    cache_node_t *victim = g_pa_cache.lru_tail;
    if (victim) {
        lru_unlink(victim);
        victim->in_use = 0;
        g_pa_cache.count--;
        g_pa_cache.stats.evictions++;
    }
    return victim;
}

int ig_pa_cache_init(int capacity)
{
    if (g_pa_cache.initialized) return 0;
    if (capacity <= 0) {
        memset(&g_pa_cache, 0, sizeof(g_pa_cache));
        g_pa_cache.initialized = 1;
        return 0;
    }
    g_pa_cache.nodes = calloc((size_t)capacity, sizeof(cache_node_t));
    if (!g_pa_cache.nodes) return -1;
    g_pa_cache.capacity = capacity;
    g_pa_cache.count    = 0;
    g_pa_cache.lru_head = NULL;
    g_pa_cache.lru_tail = NULL;
    pthread_mutex_init(&g_pa_cache.lock, NULL);
    memset(&g_pa_cache.stats, 0, sizeof(g_pa_cache.stats));
    g_pa_cache.initialized = 1;
    return 0;
}

void ig_pa_cache_free(void)
{
    if (!g_pa_cache.initialized) return;
    if (g_pa_cache.nodes) {
        free(g_pa_cache.nodes);
        g_pa_cache.nodes = NULL;
    }
    if (g_pa_cache.capacity > 0) pthread_mutex_destroy(&g_pa_cache.lock);
    memset(&g_pa_cache, 0, sizeof(g_pa_cache));
}

void ig_pa_cache_get_stats(ig_pa_cache_stats_t *s)
{
    if (!s) return;
    if (!g_pa_cache.initialized || g_pa_cache.capacity <= 0) {
        memset(s, 0, sizeof(*s));
        return;
    }
    pthread_mutex_lock(&g_pa_cache.lock);
    *s = g_pa_cache.stats;
    pthread_mutex_unlock(&g_pa_cache.lock);
}

int ig_pa_resolve_cached(pid_t pid, ig_pid_chain_t *out)
{
    if (!g_pa_cache.initialized || g_pa_cache.capacity <= 0)
        return ig_pa_resolve(pid, out);

    /* 시작 PID의 start_ticks를 먼저 읽어 캐시 키 비교 */
    ig_proc_info_t probe;
    memset(&probe, 0, sizeof(probe));
    probe.pid = pid;
    if (parse_stat(pid, &probe) < 0) {
        memset(out, 0, sizeof(*out));
        return 0;
    }

    pthread_mutex_lock(&g_pa_cache.lock);
    g_pa_cache.stats.lookups++;

    cache_node_t *n = cache_find(pid);
    if (n && n->start_ticks == probe.start_ticks) {
        /* hit */
        *out = n->chain;
        lru_unlink(n);
        lru_push_front(n);
        g_pa_cache.stats.hits++;
        pthread_mutex_unlock(&g_pa_cache.lock);
        return out->depth;
    }
    /* PID reuse 또는 진짜 miss */
    if (n) {
        lru_unlink(n);
        n->in_use = 0;
        g_pa_cache.count--;
    }
    g_pa_cache.stats.misses++;
    pthread_mutex_unlock(&g_pa_cache.lock);

    /* lock 밖에서 /proc 읽기 (수십us 걸릴 수 있음) */
    ig_pa_resolve(pid, out);

    pthread_mutex_lock(&g_pa_cache.lock);
    cache_node_t *slot = cache_alloc_slot();
    if (slot) {
        slot->pid         = pid;
        slot->start_ticks = probe.start_ticks;
        slot->chain       = *out;
        slot->in_use      = 1;
        lru_push_front(slot);
        g_pa_cache.count++;
    }
    pthread_mutex_unlock(&g_pa_cache.lock);

    return out->depth;
}
