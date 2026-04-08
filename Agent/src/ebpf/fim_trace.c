#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

/* st_dev(userspace OLD: major<<8) → 커널 dev_t(NEW: major<<20) 변환 */
static inline uint64_t stat_dev_to_kernel(uint64_t st_dev)
{
    return ((uint64_t)major((dev_t)st_dev) << 20) | minor((dev_t)st_dev);
}

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "realtime/monitor.h"
#include "fim_trace_api.h"
#include "fim_trace.skel.h"

struct inode_key {
    __u64 dev;
    __u64 ino;
};

struct inode_policy {
    __u32 mask;
    __u32 block;
};

struct audit_event {
    __u64 dev;
    __u64 ino;
    __u32 pid;
    __u32 uid;
    __u32 op_mask;
    __u32 hook_id;
    __u32 denied;
    char comm[16];
    __u64 ts_ns;
};

static volatile sig_atomic_t g_running = 1;
static struct fim_trace_bpf *g_skel = NULL;
static struct ring_buffer   *g_rb   = NULL;

/* ── 유저랜드 역방향 경로 캐시 {dev, ino} → path ──
 * 정책 등록 시 채워지고, 이벤트 수신 시 경로 조회에 사용된다.
 * 크기는 policy_map(16384)과 동일하게 유지한다. */
#define PATH_CACHE_CAP  16384   /* 반드시 2의 거듭제곱 */
#define PATH_CACHE_MASK (PATH_CACHE_CAP - 1)

#define SLOT_EMPTY   0
#define SLOT_USED    1
#define SLOT_DELETED 2  /* tombstone: 삭제됐지만 probe chain을 끊지 않음 */

struct path_cache_entry {
    __u64 dev;
    __u64 ino;
    char  path[FIM_MAX_PATH];
    int   used;  /* SLOT_EMPTY / SLOT_USED / SLOT_DELETED */
};

static struct path_cache_entry  g_path_cache[PATH_CACHE_CAP];
static pthread_mutex_t          g_path_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t path_cache_hash(__u64 dev, __u64 ino)
{
    uint64_t h = dev * 2654435761ULL ^ ino * 2246822519ULL;
    return (uint32_t)((h ^ (h >> 32)) & PATH_CACHE_MASK);
}

static void path_cache_put(__u64 dev, __u64 ino, const char *path)
{
    uint32_t idx = path_cache_hash(dev, ino);
    pthread_mutex_lock(&g_path_cache_lock);
    int32_t first_tomb = -1;  /* 첫 번째 tombstone 슬롯 위치 */
    for (uint32_t i = 0; i < PATH_CACHE_CAP; i++) {
        uint32_t slot = (idx + i) & PATH_CACHE_MASK;
        struct path_cache_entry *e = &g_path_cache[slot];
        if (e->used == SLOT_EMPTY) {
            /* 빈 슬롯: tombstone이 있으면 거기에, 없으면 여기에 삽입 */
            uint32_t target = (first_tomb >= 0) ? (uint32_t)first_tomb : slot;
            struct path_cache_entry *t = &g_path_cache[target];
            t->dev  = dev;
            t->ino  = ino;
            t->used = SLOT_USED;
            strncpy(t->path, path, FIM_MAX_PATH - 1);
            t->path[FIM_MAX_PATH - 1] = '\0';
            break;
        }
        if (e->used == SLOT_DELETED) {
            if (first_tomb < 0) first_tomb = (int32_t)slot;
            continue;
        }
        /* SLOT_USED: 동일 키면 덮어쓰기 (경로 갱신) */
        if (e->dev == dev && e->ino == ino) {
            strncpy(e->path, path, FIM_MAX_PATH - 1);
            e->path[FIM_MAX_PATH - 1] = '\0';
            break;
        }
    }
    pthread_mutex_unlock(&g_path_cache_lock);
}

static void path_cache_get(__u64 dev, __u64 ino, char *out, size_t out_sz)
{
    uint32_t idx = path_cache_hash(dev, ino);
    pthread_mutex_lock(&g_path_cache_lock);
    for (uint32_t i = 0; i < PATH_CACHE_CAP; i++) {
        uint32_t slot = (idx + i) & PATH_CACHE_MASK;
        struct path_cache_entry *e = &g_path_cache[slot];
        if (e->used == SLOT_EMPTY)
            break;                  /* 진짜 빈 슬롯 → 존재하지 않음 */
        if (e->used == SLOT_DELETED)
            continue;               /* tombstone → probe chain 유지 */
        if (e->dev == dev && e->ino == ino) {
            strncpy(out, e->path, out_sz - 1);
            out[out_sz - 1] = '\0';
            pthread_mutex_unlock(&g_path_cache_lock);
            return;
        }
    }
    pthread_mutex_unlock(&g_path_cache_lock);
    snprintf(out, out_sz, "<ino=%llu>", (unsigned long long)ino);
}

static void path_cache_remove(__u64 dev, __u64 ino)
{
    uint32_t idx = path_cache_hash(dev, ino);
    pthread_mutex_lock(&g_path_cache_lock);
    for (uint32_t i = 0; i < PATH_CACHE_CAP; i++) {
        uint32_t slot = (idx + i) & PATH_CACHE_MASK;
        struct path_cache_entry *e = &g_path_cache[slot];
        if (e->used == SLOT_EMPTY)
            break;
        if (e->used == SLOT_DELETED)
            continue;
        if (e->dev == dev && e->ino == ino) {
            e->used = SLOT_DELETED;  /* tombstone: probe chain 유지 */
            break;
        }
    }
    pthread_mutex_unlock(&g_path_cache_lock);
}

/* ── 훅 레벨 중복 제거 {dev, ino, op_mask} 기반 ──
 * 같은 파일 조작에서 여러 LSM 훅이 동일 op_mask로 연속 발화하는 경우 억제.
 * (예: file_open + file_permission 모두 WRITE로 발화)
 *
 * op_mask가 다른 이벤트(WRITE vs ATTR)는 의미가 다르므로 별도 처리.
 *
 * 직접 인덱스 방식(lossy cache): 충돌 시 덮어씀.
 * 200ms 이내 같은 키 → suppress. 최악의 경우 false positive는
 * 200ms간 이벤트 1개 누락 (허용 범위).  */
#define HOOK_DEDUP_CAP    4096
#define HOOK_DEDUP_MASK   (HOOK_DEDUP_CAP - 1)
#define HOOK_DEDUP_WIN_NS 200000000ULL   /* 200ms */

struct hook_dedup_entry {
    __u64 dev;
    __u64 ino;
    __u32 op_mask;
    int   used;
    __u64 last_ts_ns;
};

static struct hook_dedup_entry g_hook_dedup[HOOK_DEDUP_CAP];
static pthread_mutex_t         g_hook_dedup_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t hook_dedup_hash(__u64 dev, __u64 ino, __u32 op_mask)
{
    uint64_t h = dev * 2654435761ULL ^ ino * 2246822519ULL ^ (uint64_t)op_mask * 374761393ULL;
    return (uint32_t)((h ^ (h >> 32)) & HOOK_DEDUP_MASK);
}

/* 반환값: 1 = suppress (중복), 0 = 통과 (새 이벤트) */
static int hook_dedup_check(__u64 dev, __u64 ino, __u32 op_mask, __u64 ts_ns)
{
    uint32_t slot = hook_dedup_hash(dev, ino, op_mask);
    struct hook_dedup_entry *e = &g_hook_dedup[slot];
    int suppress;

    pthread_mutex_lock(&g_hook_dedup_lock);
    suppress = (e->used &&
                e->dev     == dev  &&
                e->ino     == ino  &&
                e->op_mask == op_mask &&
                ts_ns - e->last_ts_ns < HOOK_DEDUP_WIN_NS);
    if (!suppress) {
        e->dev        = dev;
        e->ino        = ino;
        e->op_mask    = op_mask;
        e->used       = 1;
        e->last_ts_ns = ts_ns;
    }
    pthread_mutex_unlock(&g_hook_dedup_lock);
    return suppress;
}

static const char *op_mask_to_str(__u32 mask)
{
    switch (mask) {
        case FIM_EBPF_OP_READ:   return "READ";
        case FIM_EBPF_OP_WRITE:  return "WRITE";
        case FIM_EBPF_OP_DELETE: return "DELETE";
        case FIM_EBPF_OP_ATTR:   return "ATTR";
        default:                 return "MULTI";
    }
}

static const char *hook_id_to_str(__u32 hook_id)
{
    switch (hook_id) {
        case 1: return "file_permission";
        case 2: return "file_open";
        case 3: return "path_unlink";
        case 4: return "path_rename";
        case 5: return "path_truncate";
        case 6: return "path_chmod";
        case 7: return "inode_setattr";
        default: return "unknown";
    }
}

static int add_policy_inode(__u64 dev, __u64 ino, __u32 mask, __u32 block)
{
    struct inode_key key = {
        .dev = dev,
        .ino = ino,
    };
    struct inode_policy value = {
        .mask  = mask,
        .block = block,
    };
    int fd;

    if (!g_skel)
        return -1;

    fd = bpf_map__fd(g_skel->maps.policy_map);
    if (fd < 0)
        return -1;

    return bpf_map_update_elem(fd, &key, &value, BPF_ANY);
}

static int remove_policy_inode(__u64 dev, __u64 ino)
{
    struct inode_key key = {
        .dev = dev,
        .ino = ino,
    };
    int fd;

    if (!g_skel)
        return -1;

    fd = bpf_map__fd(g_skel->maps.policy_map);
    if (fd < 0)
        return -1;

    return bpf_map_delete_elem(fd, &key);
}

static int remove_path_internal(const char *path, int recursive)
{
    struct stat st;

    if (lstat(path, &st) < 0)
        return -1;

    __u64 kdev = stat_dev_to_kernel((uint64_t)st.st_dev);
    __u64 kino = (__u64)st.st_ino;
    path_cache_remove(kdev, kino);
    remove_policy_inode(kdev, kino);

    if (!recursive || !S_ISDIR(st.st_mode))
        return 0;

    DIR *dir = opendir(path);
    if (!dir)
        return -1;

    for (;;) {
        struct dirent *ent = readdir(dir);
        if (!ent)
            break;
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[FIM_MAX_PATH];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        remove_path_internal(child, 1);
    }

    closedir(dir);
    return 0;
}

static int add_path_internal(const char *path, __u32 mask, __u32 block, int recursive)
{
    struct stat st;

    if (lstat(path, &st) < 0) {
        LOG_WARN_FIM("[ebpf] stat failed: %s (%s)", path, strerror(errno));
        return -1;
    }

    __u64 kdev = stat_dev_to_kernel((uint64_t)st.st_dev);
    __u64 kino = (__u64)st.st_ino;
    if (add_policy_inode(kdev, kino, mask, block) == 0) {
        path_cache_put(kdev, kino, path);
        LOG_INFO_FIM("[ebpf] policy add: %s dev=%llu ino=%llu mask=0x%x block=%u",
                     path, (unsigned long long)kdev, (unsigned long long)kino,
                     mask, block);
    } else {
        LOG_WARN_FIM("[ebpf] policy add failed: %s (%s)", path, strerror(errno));
    }

    if (!recursive || !S_ISDIR(st.st_mode))
        return 0;

    DIR *dir = opendir(path);
    if (!dir) {
        LOG_WARN_FIM("[ebpf] opendir failed: %s (%s)", path, strerror(errno));
        return -1;
    }

    for (;;) {
        struct dirent *ent = readdir(dir);
        if (!ent)
            break;

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char child[FIM_MAX_PATH];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        add_path_internal(child, mask, block, 1);
    }

    closedir(dir);
    return 0;
}

static fim_event_type_t op_to_fim_type(__u32 op_mask)
{
    if (op_mask & FIM_EBPF_OP_DELETE) return FIM_EVENT_DELETE;
    if (op_mask & FIM_EBPF_OP_WRITE)  return FIM_EVENT_MODIFY;
    if (op_mask & FIM_EBPF_OP_ATTR)   return FIM_EVENT_ATTRIB;
    return FIM_EVENT_ACCESS;
}

static int handle_audit_event(void *ctx, void *data, size_t data_sz)
{
    fim_event_queue_t       *queue = ctx;
    const struct audit_event *e    = data;
    char path[FIM_MAX_PATH];

    if (data_sz < sizeof(*e))
        return 0;

    /* 같은 {dev, ino, op_mask}가 200ms 이내 재발화 → 중복 훅 suppress */
    if (hook_dedup_check(e->dev, e->ino, e->op_mask, e->ts_ns))
        return 0;

    path_cache_get(e->dev, e->ino, path, sizeof(path));

    /* eBPF 고유 정보 (DENY/AUDIT 여부, 훅 이름) 로그 */
    LOG_ALERT_FIM("[ebpf] %s %s hook=%s path=%s pid=%u uid=%u comm=%s",
                  e->denied ? "DENY" : "AUDIT",
                  op_mask_to_str(e->op_mask),
                  hook_id_to_str(e->hook_id),
                  path,
                  e->pid,
                  e->uid,
                  e->comm);

    /* 파일 삭제 이벤트: inode 해제 → policy_map + path_cache 즉시 제거
     * (제거하지 않으면 OS의 inode 재사용 시 다른 파일이 삭제된 파일로 오인됨) */
    if (e->hook_id == FIM_HOOK_PATH_UNLINK && !(e->denied)) {
        remove_policy_inode(e->dev, e->ino);
        path_cache_remove(e->dev, e->ino);
    }

    /* 큐가 있으면 fim_event_t로 변환해서 push → 무결성 검사 + transport 전송 */
    if (queue) {
        fim_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.type      = op_to_fim_type(e->op_mask);
        ev.source    = FIM_SOURCE_EBPF;
        ev.timestamp = (time_t)(e->ts_ns / 1000000000ULL);
        ev.pid       = (pid_t)e->pid;
        ev.uid       = (uid_t)e->uid;
        strncpy(ev.path, path, FIM_MAX_PATH - 1);
        strncpy(ev.comm, e->comm, sizeof(ev.comm) - 1);

        /* filename: path의 마지막 '/' 이후 */
        const char *slash = strrchr(path, '/');
        strncpy(ev.filename, slash ? slash + 1 : path, sizeof(ev.filename) - 1);

        fim_queue_push(queue, &ev);
    }

    return 0;
}

int ebpf_policy_init(fim_event_queue_t *queue)
{
    int err;

    g_skel = fim_trace_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "eBPF open failed\n");
        return -1;
    }

    err = fim_trace_bpf__load(g_skel);
    if (err) {
        fprintf(stderr, "eBPF load failed: %d\n", err);
        fim_trace_bpf__destroy(g_skel);
        g_skel = NULL;
        return -1;
    }

    err = fim_trace_bpf__attach(g_skel);
    if (err) {
        fprintf(stderr, "eBPF attach failed: %d\n", err);
        fim_trace_bpf__destroy(g_skel);
        g_skel = NULL;
        return -1;
    }

    /* queue를 ctx로 전달 → handle_audit_event에서 fim_queue_push 사용 */
    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.audit_rb),
                            handle_audit_event,
                            queue,
                            NULL);
    if (!g_rb) {
        fprintf(stderr, "Ring buffer create failed\n");
        fim_trace_bpf__destroy(g_skel);
        g_skel = NULL;
        return -1;
    }

    return 0;
}

void *ebpf_poll_thread(void *arg)
{
    (void)arg;

    while (g_running) {
        int err = ring_buffer__poll(g_rb, 100);
        if (err == -EINTR)
            continue;
        if (err < 0) {
            fprintf(stderr, "Ring buffer poll error: %d\n", err);
            break;
        }
    }

    return NULL;
}

void ebpf_policy_stop(void)
{
    g_running = 0;  /* poll thread의 while(g_running) 루프 탈출 */
}

void ebpf_policy_cleanup(void)
{
    /* 반드시 ebpf_policy_stop() + pthread_join() 이후에 호출할 것.
     * poll thread가 g_rb를 쓰는 중에 해제하면 use-after-free 발생. */
    if (g_rb) {
        ring_buffer__free(g_rb);
        g_rb = NULL;
    }

    if (g_skel) {
        fim_trace_bpf__destroy(g_skel);
        g_skel = NULL;
    }
}

int ebpf_policy_add_path_recursive(const char *path, uint32_t mask, uint32_t block)
{
    return add_path_internal(path, mask, block, 1);
}

int ebpf_policy_add_path(const char *path, uint32_t mask, uint32_t block)
{
    return add_path_internal(path, mask, block, 0);
}

int ebpf_policy_remove_path(const char *path)
{
    return remove_path_internal(path, 0);
}

int ebpf_policy_remove_path_recursive(const char *path)
{
    return remove_path_internal(path, 1);
}

int ebpf_policy_has_path(const char *path, uint32_t *mask, uint32_t *block)
{
    struct stat st;
    struct inode_key key;
    struct inode_policy value;
    int fd;

    if (!g_skel)
        return -1;
    if (lstat(path, &st) < 0)
        return -1;

    fd = bpf_map__fd(g_skel->maps.policy_map);
    if (fd < 0)
        return -1;

    key.dev = stat_dev_to_kernel((uint64_t)st.st_dev);
    key.ino = (__u64)st.st_ino;
    if (bpf_map_lookup_elem(fd, &key, &value) < 0)
        return 0;

    if (mask)
        *mask = value.mask;
    if (block)
        *block = value.block;
    return 1;
}

