/*
 * main.c — IM Monitor 데몬
 *
 * 구조:
 *   ┌──────────────────────────────────────────────────────┐
 *   │                   IM Monitor 데몬                    │
 *   │                                                      │
 *   │  [LKM 이벤트 스레드]        [eBPF poll 스레드]        │
 *   │   /dev/im_lkm 수신         LSM 훅 → audit 이벤트    │
 *   │          │                     │                     │
 *   │          └─────────────────────┘                     │
 *   │                      ▼                               │
 *   │              [공유 이벤트 큐]                          │
 *   │                  pop  ▼                               │
 *   │          [메인 스레드: 통합 이벤트 처리기]              │
 *   │           - 무결성 검사 (SHA-256)                     │
 *   │           - im_tcp_send_event() → Go 서버            │
 *   │                                                      │
 *   │  [스레드 3: heartbeat]  30초 주기 HEARTBEAT 전송       │
 *   └──────────────────────────────────────────────────────┘
 *
 * 우선순위:
 *   eBPF 가능 → eBPF
 *   eBPF 불가 + /dev/im_lkm 존재 → LKM
 *   둘 다 불가 → 시작 중단
 *
 * 환경변수 (transport 설정):
 *   IM_SERVER_HOST   서버 IP/호스트 (기본: 127.0.0.1)
 *   IM_SERVER_PORT   서버 포트      (기본: 9000)
 *   IM_CA_CRT        CA 인증서 경로  (기본: /etc/im_monitor/certs/ca.crt)
 *   IM_AGENT_CRT     에이전트 인증서 (기본: /etc/im_monitor/certs/agent.crt)
 *   IM_AGENT_KEY     에이전트 개인키 (기본: /etc/im_monitor/certs/agent.key)
 *
 * 시그널:
 *   SIGTERM/SIGINT  → 정상 종료
 *   SIGHUP          → 설정 재로드
 *   SIGUSR1         → 예약됨 (현재 런타임 watch 변경 미사용)
 */

#include <stdarg.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/utsname.h>
#include "core/daemon.h"       /* daemon_start, daemon_notify_ready, daemon_cleanup */
#include "core/pid_lock.h"     /* pid_lock_acquire, pid_lock_release */
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "realtime/monitor.h"
#ifdef HAVE_LIBBPF
#include "ebpf/im_trace_api.h"
#else
/* eBPF 비활성 환경에서도 g_ebpf_block 타입 일관성 유지 */
#define IM_EBPF_BLOCK_AUDIT 0u
#define IM_EBPF_BLOCK_DENY  1u
#endif
#include "transport/tls_context.h"
#include "transport/tcp_client.h"
#include "transport/heartbeat.h"
#include "scanner/baseline.h"
#include "lkm/lkm_client.h"

/* ── 전역 변수 ─────────────────────────────────── */
FILE            *g_log_fp    = NULL;
int              g_use_syslog = 0;
int              g_verbose    = 0;
pthread_mutex_t  g_log_lock   = PTHREAD_MUTEX_INITIALIZER;

static volatile sig_atomic_t g_running   = 1;
static volatile sig_atomic_t g_reload    = 0;
static volatile sig_atomic_t g_scan_req  = 0;  /* SIGUSR1 온디맨드 watch 변경 */

/* 에이전트 로컬 베이스라인 DB — MODIFY 이벤트 시 자동 무결성 검사 */
static im_baseline_db_t g_baseline_db;

/* 백엔드를 전역으로 — handle_scan_request(), reload_config()에서 접근 필요 */
static im_backend_t *g_be_inotify  = NULL;
static int            g_ebpf_active = 0;
static int            g_lkm_active  = 0;
static uint32_t       g_ebpf_block  = IM_EBPF_BLOCK_DENY;

/* 설정 재로드를 위한 전역 — SIGHUP 핸들러에서 접근 */
static im_config_t  *g_cfg         = NULL;
static char           g_config_path[IM_MAX_PATH];

/* ── transport 전역 상태 ───────────────────────── */
static im_tls_ctx_t    g_tls_ctx;
static im_tcp_client_t g_tcp_client;
static char             g_agent_id[128] = {0};
static int              g_transport_ok  = 0;

/* ── 외부 함수 ─────────────────────────────────── */
extern im_backend_t *im_inotify_create(void);
extern int  im_config_load(im_config_t *cfg, const char *path);
extern void im_config_dump(im_config_t *cfg);

static int current_transport_monitor_type(uint8_t *monitor_type)
{
    if (!monitor_type) return -1;
    if (g_ebpf_active) {
        *monitor_type = IM_MON_EBPF;
        return 0;
    }
    if (g_lkm_active) {
        *monitor_type = IM_MON_LKM;
        return 0;
    }
    return -1;
}

/* ── 커널 버전 체크 ────────────────────────────── */
static int get_kernel_version(void) {
    struct utsname uts;
    if (uname(&uts) < 0) return 0;

    int major = 0, minor = 0, patch = 0;
    sscanf(uts.release, "%d.%d.%d", &major, &minor, &patch);
    return KERNEL_VER(major, minor) + patch;
}

/* ── 시그널 ────────────────────────────────────── */
static void signal_handler(int sig) {
    switch (sig) {
        case SIGTERM: case SIGINT: g_running  = 0; break;
        case SIGHUP:               g_reload   = 1; break;
        case SIGUSR1:              g_scan_req = 1; break;
    }
}

static void setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/* ── 로깅 ──────────────────────────────────────── */
static int init_logging(im_config_t *cfg) {
    if (cfg->log_to_syslog) {
        openlog("im_monitor", LOG_PID | LOG_NDELAY, LOG_DAEMON);
        g_use_syslog = 1;
    }
    g_verbose = cfg->verbose;
    g_log_fp  = fopen(cfg->log_file, "a");
    if (!g_log_fp) {
        g_log_fp = stderr;
        fprintf(stderr, "log file open failed: %s\n", cfg->log_file);
    }
    return 0;
}

static void close_logging(void) {
    if (g_log_fp && g_log_fp != stderr) fclose(g_log_fp);
    g_log_fp = NULL;
    if (g_use_syslog) closelog();
}

/* ── LKM 이벤트 수신 스레드 ──────────────────── */
static void *lkm_event_thread(void *arg)
{
    im_event_queue_t    *queue = (im_event_queue_t *)arg;
    struct im_lkm_event  lev;

    LOG_INFO_FIM("[lkm] 이벤트 수신 스레드 시작 (tid=%ld)", (long)pthread_self());
    while (g_running) {
        int ret = lkm_read_event_timeout(&lev, 500);
        if (ret == -ETIMEDOUT) continue;
        if (ret != 0)          break;   /* fd 닫힘 또는 오류 */

        im_event_t ev = {0};
        switch (lev.op) {
        case IM_OP_WRITE:  ev.type = IM_EVENT_MODIFY; break;
        case IM_OP_DELETE: ev.type = IM_EVENT_DELETE; break;
        case IM_OP_RENAME: ev.type = IM_EVENT_MOVE;   break;
        default:            ev.type = IM_EVENT_UNKNOWN; break;
        }
        ev.source    = IM_SOURCE_LKM;
        ev.pid       = (pid_t)lev.pid;
        ev.uid       = (uid_t)lev.uid;
        ev.timestamp = (time_t)(lev.timestamp_ns / 1000000000LL);
        strncpy(ev.path, lev.path, sizeof(ev.path) - 1);
        strncpy(ev.comm, lev.comm, sizeof(ev.comm) - 1);

        LOG_ALERT_FIM("[lkm] %s %s %s(pid=%d uid=%d comm=%s)",
                      ev.path, im_event_type_str(ev.type),
                      lev.blocked ? "  [BLOCKED]" : "",
                      ev.pid, ev.uid, ev.comm);

        im_queue_push(queue, &ev);
    }
    LOG_INFO_FIM("[lkm] 이벤트 수신 스레드 종료");
    return NULL;
}


static void send_event_with_reconnect(const im_event_t *ev) {
    if (!g_transport_ok || !g_agent_id[0]) return;
    int ret = im_tcp_send_event(&g_tcp_client, ev);
    if (ret == -2) {
        LOG_WARN_FIM("[transport] FILE_EVENT 전송 실패 — 재연결 시도");
        g_transport_ok = 0;
        if (im_tcp_reconnect(&g_tcp_client) == 0) {
            snprintf(g_agent_id, sizeof(g_agent_id), "%llu",
                     (unsigned long long)g_tcp_client.agent_id);
            g_transport_ok = 1;
            im_tcp_send_event(&g_tcp_client, ev);
        }
    } else if (ret < 0) {
        LOG_WARN_FIM("[transport] FILE_EVENT 전송 실패 (재시도 예정)");
    }
}

static void process_event(const im_event_t *ev) {
    /* eBPF·LKM 이벤트는 각 수신 스레드에서 이미 로그 출력 완료 → 중복 스킵 */
    if (ev->source != IM_SOURCE_EBPF && ev->source != IM_SOURCE_LKM) {
        if (ev->pid > 0) {
            LOG_ALERT_FIM("[%s] %s %s  (pid=%d uid=%d sid=%d comm=%s)",
                          im_source_str(ev->source),
                          ev->path, im_event_type_str(ev->type),
                          ev->pid, ev->uid, ev->sid, ev->comm);
        } else {
            LOG_ALERT_FIM("[%s] %s %s",
                          im_source_str(ev->source),
                          ev->path, im_event_type_str(ev->type));
        }
    }

    /* 베이스라인 갱신 및 무결성 검사 */
    switch (ev->type) {
    case IM_EVENT_MODIFY: {
        char expected[65] = {0}, actual[65] = {0};
        im_integrity_result_t r = im_baseline_check_file(&g_baseline_db,
                                                           ev->path,
                                                           expected, actual);
        if (r == IM_INTEGRITY_MISMATCH) {
            LOG_ALERT_FIM("[integrity] 변조 감지: %s  expected=%s  actual=%s",
                          ev->path, expected, actual);
        } else if (r == IM_INTEGRITY_NEW) {
            LOG_INFO_FIM("[baseline] 베이스라인 미등록 파일 수정 감지 — 신규 등록: %s",
                         ev->path);
        }
        /* 변조 여부와 무관하게 현재 상태를 베이스라인에 반영 */
        im_baseline_db_update(&g_baseline_db, ev->path);
        break;
    }
    case IM_EVENT_CREATE:
        im_baseline_db_update(&g_baseline_db, ev->path);
        LOG_INFO_FIM("[baseline] 신규 파일 등록: %s", ev->path);
        break;
    case IM_EVENT_DELETE: {
        char expected[65] = {0}, actual[65] = {0};
        im_integrity_result_t r = im_baseline_check_file(&g_baseline_db,
                                                            ev->path,
                                                            expected, actual);
        /* DENY로 차단된 삭제: 파일이 실제로 존재 → MATCH → 베이스라인 유지 */
        if (r == IM_INTEGRITY_MATCH) break;
        im_baseline_db_remove(&g_baseline_db, ev->path);
        LOG_INFO_FIM("[baseline] 파일 삭제 — 베이스라인 제거: %s", ev->path);
        break;
    }
    default:
        break;
    }

    /* transport: 서버로 FILE_EVENT 전송 */
    send_event_with_reconnect(ev);
}

/* ── 설정 재로드 (SIGHUP) ───────────────────────── */
static void reload_config(void) {
    im_config_t *new_cfg = calloc(1, sizeof(im_config_t));
    if (!new_cfg) {
        LOG_ERROR_FIM("configuration reload failed: Out of Memory");
        return;
    }

    if (im_config_load(new_cfg, g_config_path) < 0) {
        LOG_ERROR_FIM("configuration reload failed: %s", g_config_path);
        free(new_cfg);
        return;
    }

    LOG_INFO_FIM("SIGHUP — configuration reload start: %s", g_config_path);

    /* 로그 파일 경로 또는 verbose 변경 처리 */
    if (strcmp(g_cfg->log_file, new_cfg->log_file) != 0 ||
        g_cfg->log_to_syslog != new_cfg->log_to_syslog) {
        close_logging();
        strncpy(g_cfg->log_file, new_cfg->log_file, sizeof(g_cfg->log_file) - 1);
        g_cfg->log_file[sizeof(g_cfg->log_file) - 1] = '\0';
        g_cfg->log_to_syslog = new_cfg->log_to_syslog;
        g_cfg->verbose       = new_cfg->verbose;
        init_logging(g_cfg);
        LOG_INFO_FIM("log file config changes applied");
    } else if (g_cfg->verbose != new_cfg->verbose) {
        g_cfg->verbose = new_cfg->verbose;
        g_verbose      = new_cfg->verbose;
        LOG_INFO_FIM("verbose config changed: %d", g_verbose);
    }

    /* inotify watch 목록 diff 적용 */
    if (g_be_inotify) {
        /* 새 목록에 없는 기존 watch → 제거 */
        for (int i = 0; i < g_cfg->watch_count; i++) {
            int found = 0;
            for (int j = 0; j < new_cfg->watch_count; j++) {
                if (strcmp(g_cfg->watches[i].path,
                           new_cfg->watches[j].path) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                LOG_INFO_FIM("inotify watch removed: %s", g_cfg->watches[i].path);
                g_be_inotify->remove_watch(g_be_inotify, g_cfg->watches[i].path);
            }
        }
        /* 기존 목록에 없는 새 watch → 추가 */
        for (int j = 0; j < new_cfg->watch_count; j++) {
            int found = 0;
            for (int i = 0; i < g_cfg->watch_count; i++) {
                if (strcmp(new_cfg->watches[j].path,
                           g_cfg->watches[i].path) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                LOG_INFO_FIM("inotify watch added: %s (recursive=%d)",
                             new_cfg->watches[j].path,
                             new_cfg->watches[j].recursive);
                g_be_inotify->add_watch(g_be_inotify,
                                        new_cfg->watches[j].path,
                                        new_cfg->watches[j].recursive);
            }
        }
        g_cfg->watch_count = new_cfg->watch_count;
        memcpy(g_cfg->watches, new_cfg->watches,
               sizeof(im_watch_entry_t) * (size_t)new_cfg->watch_count);
    }

    /* eBPF policy diff — inotify와 동일한 기준으로 policy_map 갱신 */
#ifdef HAVE_LIBBPF
    if (g_ebpf_active) {
        uint32_t protect_mask = IM_EBPF_OP_WRITE | IM_EBPF_OP_DELETE | IM_EBPF_OP_ATTR;

        /* 새 목록에 없는 기존 경로 → eBPF policy 제거 */
        for (int i = 0; i < g_cfg->watch_count; i++) {
            int found = 0;
            for (int j = 0; j < new_cfg->watch_count; j++) {
                if (strcmp(g_cfg->watches[i].path, new_cfg->watches[j].path) == 0) {
                    found = 1; break;
                }
            }
            if (!found) {
                ebpf_policy_remove_path_recursive(g_cfg->watches[i].path);
                LOG_INFO_FIM("[ebpf] policy removed: %s", g_cfg->watches[i].path);
            }
        }

        /* 기존 목록에 없는 새 경로 → eBPF policy 추가 */
        for (int j = 0; j < new_cfg->watch_count; j++) {
            int found = 0;
            for (int i = 0; i < g_cfg->watch_count; i++) {
                if (strcmp(new_cfg->watches[j].path, g_cfg->watches[i].path) == 0) {
                    found = 1; break;
                }
            }
            if (!found) {
                ebpf_policy_add_path_recursive(new_cfg->watches[j].path,
                                               protect_mask, g_ebpf_block);
                LOG_INFO_FIM("[ebpf] policy added: %s", new_cfg->watches[j].path);
            }
        }
    }
#endif /* HAVE_LIBBPF */

    /* LKM 정책 갱신 — 변경된 경로 설정 반영
     * 가장 단순한 방법: 전체 초기화 후 현재 베이스라인 재주입 */
    if (g_lkm_active) {
        lkm_clear_all();
        int n = lkm_add_from_baseline(&g_baseline_db,
                                      g_ebpf_block ? IM_BLOCK_DENY
                                                    : IM_BLOCK_AUDIT);
        LOG_INFO_FIM("[lkm] 정책 재주입 완료 — %d개 inode", n);
    }

    free(new_cfg);
    LOG_INFO_FIM("configuration reload complete");
}

/* ── 온디맨드 watch 변경 (SIGUSR1) ─────────────── */
#define IM_SCAN_REQUEST_FILE "/tmp/im_scan_request"

static void handle_scan_request(void) {
    if (!g_be_inotify) {
        LOG_WARN_FIM("inotify backend does not exist — watch cannot be change");
        return;
    }
    FILE *fp = fopen(IM_SCAN_REQUEST_FILE, "r");
    if (!fp) {
        LOG_WARN_FIM("scan request fle does not exist: %s", IM_SCAN_REQUEST_FILE);
        return;
    }
    char line[IM_MAX_PATH];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == ' '))
            line[--len] = '\0';
        if (len == 0) continue;

        if (line[0] == '+') {
            char *path = line + 1;
            while (*path == ' ') path++;
            LOG_INFO_FIM("On-demand watch add: %s", path);
            g_be_inotify->add_watch(g_be_inotify, path, 1);
        } else if (line[0] == '-') {
            char *path = line + 1;
            while (*path == ' ') path++;
            LOG_INFO_FIM("On-demand watch remove: %s", path);
            g_be_inotify->remove_watch(g_be_inotify, path);
        } else {
            LOG_INFO_FIM("On-demand watch add: %s", line);
            g_be_inotify->add_watch(g_be_inotify, line, 1);
        }
    }
    fclose(fp);
    unlink(IM_SCAN_REQUEST_FILE);
}

/* ── 보안 파일 오픈 ────────────────────────────── */
/* open() + fstat()으로 TOCTOU 방지
 * root 소유 + other-writable 아님 검증 후 FILE* 반환
 * 실패 시 NULL 반환 */
static FILE *secure_open(const char *path) {
    if (!path) return NULL;
    int fd = open(path, O_RDONLY | O_NOFOLLOW); /* 심링크 추적 금지 */
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }
    /* root 소유 확인 */
    if (st.st_uid != 0) {
        fprintf(stderr, "[보안] %s: root 소유 파일이 아님 (uid=%d)\n",
                path, (int)st.st_uid);
        close(fd); return NULL;
    }
    /* other-writable 차단 */
    if (st.st_mode & S_IWOTH) {
        fprintf(stderr, "[보안] %s: other-writable 권한 거부\n", path);
        close(fd); return NULL;
    }
    /* 일반 파일만 허용 */
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[보안] %s: 일반 파일이 아님\n", path);
        close(fd); return NULL;
    }
    FILE *fp = fdopen(fd, "r");
    if (!fp) close(fd);
    return fp;
}

/* 탐색 경로: -c/-e 플래그 > /etc/im_monitor/ 만 허용 (CWD·HOME 제거) */
static const char *find_system_file(const char *flag_path,
                                     const char *system_path) {
    if (flag_path) {
        FILE *fp = secure_open(flag_path);
        if (fp) { fclose(fp); return flag_path; }
        fprintf(stderr, "[보안] 지정 경로 사용 불가: %s\n", flag_path);
        return NULL;
    }
    FILE *fp = secure_open(system_path);
    if (fp) { fclose(fp); return system_path; }
    return NULL;
}

/* ── .env 로더 ─────────────────────────────────── */
static void load_env(const char *path) {
    FILE *fp = secure_open(path);
    if (!fp) return;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        /* 개행 제거 */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        /* 빈 줄 / 주석 무시 */
        if (len == 0 || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;
        /* 이미 환경변수에 있으면 덮어쓰지 않음 */
        if (!getenv(key))
            setenv(key, val, 0);
    }
    fclose(fp);
}

/* ── transport 헬퍼 ────────────────────────────── */
static void build_cert_path(char *buf, size_t len, const char *filename) {
    /* 인증서 기본 경로: /etc/im_monitor/certs/ */
    snprintf(buf, len, "/etc/im_monitor/certs/%s", filename);
}

static void get_hostname(char *buf, size_t len) {
    if (gethostname(buf, len) != 0)
        strncpy(buf, "unknown-host", len);
    buf[len - 1] = '\0';
}

static void get_local_ip(const char *server_host, int port, char *buf, size_t len) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        strncpy(buf, "0.0.0.0", len); return;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    inet_pton(AF_INET, server_host, &addr.sin_addr);
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    getsockname(sock, (struct sockaddr *)&local, &local_len);
    inet_ntop(AF_INET, &local.sin_addr, buf, (socklen_t)len);
    close(sock);
}

/* ── 사용법 ────────────────────────────────────── */
static void print_usage(const char *prog) {
    printf("사용법: %s [옵션]\n\n", prog);
    printf("옵션:\n");
    printf("\t-c <path>\t설정 파일 경로 (기본: %s)\n", IM_CONFIG_PATH);
    printf("\t-m <mode>\teBPF 동작 모드 (기본: lock)\n");
    printf("\t\t\t  maintenance  — 감사만 (AUDIT, 차단 없음)\n");
    printf("\t\t\t  lock         — 보호 경로 접근 차단 (DENY)\n");
    printf("\t-f\t\t포그라운드 실행\n");
    printf("\t-v\t\t상세 로그\n");
    printf("\t-h\t\t도움말\n\n");
    printf("환경변수 (transport):\n");
    printf("\tIM_SERVER_HOST\t서버 IP (기본: 127.0.0.1)\n");
    printf("\tIM_SERVER_PORT\t서버 포트 (기본: 9000)\n");
    printf("\tIM_CA_CRT\tCA 인증서 경로\n");
    printf("\tIM_AGENT_CRT\t에이전트 인증서 경로\n");
    printf("\tIM_AGENT_KEY\t에이전트 개인키 경로\n\n");
}
/* ── 메인 ──────────────────────────────────────── */
int main(int argc, char *argv[]) {
    /* -c / -e 플래그로 명시된 경로 (없으면 NULL → 자동 탐색) */
    const char *flag_conf = NULL;
    const char *flag_env  = NULL;
    int opt_foreground = 0;
    int opt_verbose    = 0;
    g_ebpf_block = IM_EBPF_BLOCK_DENY;  /* 기본: lock 모드 */

    int opt;
    while ((opt = getopt(argc, argv, "c:e:m:fvh")) != -1) {
        switch (opt) {
            case 'c': flag_conf = optarg; break;
            case 'e': flag_env  = optarg; break;
            case 'm':
                if (strcmp(optarg, "maintenance") == 0)
                    g_ebpf_block = IM_EBPF_BLOCK_AUDIT;
                else if (strcmp(optarg, "lock") == 0)
                    g_ebpf_block = IM_EBPF_BLOCK_DENY;
                else {
                    fprintf(stderr, "알 수 없는 모드: %s (maintenance|lock)\n", optarg);
                    return 1;
                }
                break;
            case 'f': opt_foreground = 1; break;
            case 'v': opt_verbose    = 1; break;
            case 'h': default: print_usage(argv[0]); return (opt == 'h') ? 0 : 1;
        }
    }

    /* conf 탐색: -c 플래그 > /etc/im_monitor/im.conf (CWD·HOME 제거) */
    const char *found_conf = find_system_file(flag_conf, "/etc/im_monitor/im.conf");
    if (!found_conf) found_conf = IM_CONFIG_PATH; /* 최후 fallback */

    // char config_path[IM_MAX_PATH];
    strncpy(g_config_path, found_conf, sizeof(g_config_path) - 1);

    /* env 탐색: -e 플래그 > /etc/im_monitor/im.env */
    const char *env_path = find_system_file(flag_env, "/etc/im_monitor/im.env");

    /* .env 로드 — 환경변수 우선, .env는 기본값 역할 */
    if (env_path) load_env(env_path);

    im_config_t *cfg = calloc(1, sizeof(im_config_t));
    if (!cfg) { fprintf(stderr, "Out of Memory\n"); return 1; }
    g_cfg = cfg;

    if (im_config_load(cfg, g_config_path) < 0) {
        fprintf(stderr, "configuration loading failed\n");
        free(cfg);
        return 1;
    }

    if (opt_foreground) cfg->daemonize = 0;
    if (opt_verbose)    cfg->verbose   = 1;
    if (!cfg->daemonize && strcmp(cfg->log_file, IM_LOG_FILE) == 0)
        strncpy(cfg->log_file, "/dev/stderr", sizeof(cfg->log_file) - 1);

    init_logging(cfg);

    /* 커널 버전 체크 */
    int kver = get_kernel_version();
    int kver_major = kver / 65536;
    int kver_minor = (kver % 65536) / 256;

    LOG_INFO_FIM("╔══════════════════════════════════════╗");
    LOG_INFO_FIM("║   KGU-FIMS                           ║");
    LOG_INFO_FIM("║   pid=%d  kernel=%d.%d  mode=%s",
                 getpid(), kver_major, kver_minor,
                 g_ebpf_block ? "lock" : "maintenance");
    LOG_INFO_FIM("╚══════════════════════════════════════╝");
    im_config_dump(cfg);

    if (cfg->watch_count == 0) {
        LOG_ERROR_FIM("target does not exist ([watch] section check) — exit");
        close_logging();
        free(cfg);
        return 1;
    }

    if (daemon_start(cfg->daemonize ? 0 : 1) < 0) {
        LOG_ERROR_FIM("demonize failed");
        close_logging();
        free(cfg);
        return 1;
    }
    if (cfg->daemonize) {
        close_logging();
        init_logging(cfg);
        LOG_INFO_FIM("daemon PID=%d", getpid());
    }

    if (pid_lock_acquire(IM_PID_FILE) < 0) {
        LOG_ERROR_FIM("Already running or PID lock failed");
        close_logging();
        free(cfg);
        return 1;
    }

    setup_signals();

    /* ── 이벤트 큐 초기화 ─────────────────────── */
    im_event_queue_t *queue = calloc(1, sizeof(im_event_queue_t));
    if (!queue || im_queue_init(queue) < 0) {
        LOG_ERROR_FIM("event queue initialize failed");
        free(queue);
        goto done;
    }

    /* eBPF / LKM 가용성 판단 — 큐 초기화 이후에 수행 */
#ifdef HAVE_LIBBPF
    pthread_t ebpf_thread = 0;
#endif
    pthread_t lkm_thread  = 0;
    pthread_t hb_thread   = 0;
    int tls_inited        = 0;
    int transport_inited  = 0;
    im_heartbeat_arg_t hb_arg = {0};

#ifdef HAVE_LIBBPF
    if (cfg->ebpf_enabled && kver >= KERNEL_VER(5, 8)) {
        LOG_INFO_FIM("eBPF inode policy backend activate (kernel %d.%d)",
                     kver_major, kver_minor);
        if (ebpf_policy_init(queue) < 0) {
            LOG_WARN_FIM("eBPF init failed — inode policy disabled");
        } else {
            g_ebpf_active = 1;
            pthread_create(&ebpf_thread, NULL, ebpf_poll_thread, NULL);
        }
    } else {
        LOG_INFO_FIM("eBPF Disabled (kernel %d.%d, required: 5.8+)",
                     kver_major, kver_minor);
    }
#else
    {
        LOG_INFO_FIM("eBPF Disabled (kernel %d.%d, required: 5.8+)",
                     kver_major, kver_minor);
    }
#endif

    if (!g_ebpf_active) {
        /* LKM 가용 여부 확인 — /dev/im_lkm 존재 시 활성화 */
        if (access(IM_LKM_DEV_PATH, F_OK) == 0) {
            if (lkm_client_init() == 0) {
                g_lkm_active = 1;
                LOG_INFO_FIM("[lkm] im_lkm.ko 감지 — LKM 모드 활성 (mode=%s)",
                             g_ebpf_block ? "lock(DENY)" : "maintenance(AUDIT)");
            } else {
                LOG_WARN_FIM("[lkm] %s 열기 실패 — LKM 비활성", IM_LKM_DEV_PATH);
            }
        } else {
            LOG_INFO_FIM("[lkm] %s 없음 — LKM 비활성", IM_LKM_DEV_PATH);
        }
    }

    if (!g_ebpf_active && !g_lkm_active) {
        LOG_ERROR_FIM("eBPF/LKM 모두 비활성 — inotify fallback은 사용하지 않음. eBPF 또는 LKM 환경을 먼저 설정하세요.");
        goto done;
    }

    /* ── transport 초기화 (비필수) ─────────────── */
    uint8_t transport_monitor_type = 0;
    const char *server_host = getenv("IM_SERVER_HOST");
    if (!server_host) server_host = "127.0.0.1";
    int server_port = 9000;
    const char *port_env = getenv("IM_SERVER_PORT");
    if (port_env) server_port = atoi(port_env);

    char ca_crt[512], agent_crt[512], agent_key[512];
    const char *e;
    if ((e = getenv("IM_CA_CRT")))    strncpy(ca_crt,    e, sizeof(ca_crt) - 1);
    else build_cert_path(ca_crt,    sizeof(ca_crt),    "ca.crt");
    if ((e = getenv("IM_AGENT_CRT"))) strncpy(agent_crt, e, sizeof(agent_crt) - 1);
    else build_cert_path(agent_crt, sizeof(agent_crt), "agent.crt");
    if ((e = getenv("IM_AGENT_KEY"))) strncpy(agent_key, e, sizeof(agent_key) - 1);
    else build_cert_path(agent_key, sizeof(agent_key), "agent.key");

    LOG_INFO_FIM("[transport] 서버: %s:%d", server_host, server_port);

    if (current_transport_monitor_type(&transport_monitor_type) < 0) {
        LOG_WARN_FIM("[transport] eBPF/LKM 미활성 — transport 등록 생략");
    } else {
        char hostname[256] = {0};
        char local_ip[64] = {0};
        get_hostname(hostname, sizeof(hostname));
        get_local_ip(server_host, server_port, local_ip, sizeof(local_ip));

        if (tls_context_init(&g_tls_ctx, ca_crt, agent_crt, agent_key) < 0) {
            LOG_WARN_FIM("[transport] TLS 컨텍스트 초기화 실패 — transport 비활성화");
        } else {
            tls_inited = 1;

            if (im_tcp_init(&g_tcp_client, &g_tls_ctx, server_host,
                             (uint16_t)server_port) < 0) {
                LOG_WARN_FIM("[transport] TCP 클라이언트 초기화 실패");
            } else {
                transport_inited = 1;
                snprintf(g_tcp_client.reg_hostname, sizeof(g_tcp_client.reg_hostname),
                         "%s", hostname);
                snprintf(g_tcp_client.reg_ip, sizeof(g_tcp_client.reg_ip),
                         "%s", local_ip);
                snprintf(g_tcp_client.reg_os, sizeof(g_tcp_client.reg_os),
                         "%s", "Linux");
                g_tcp_client.reg_monitor_type = transport_monitor_type;
                g_tcp_client.reg_cached = 1;
            }

            if (transport_inited && im_tcp_connect(&g_tcp_client) < 0) {
                LOG_WARN_FIM("[transport] 서버 연결 실패 — 백그라운드 재연결 시도");
                if (im_tcp_reconnect(&g_tcp_client) == 0) {
                    snprintf(g_agent_id, sizeof(g_agent_id), "%llu",
                             (unsigned long long)g_tcp_client.agent_id);
                    LOG_INFO_FIM("[transport] 등록 완료 — agent_id: %s", g_agent_id);
                    g_transport_ok = 1;
                }
            } else if (transport_inited) {
                if (im_tcp_register(&g_tcp_client, hostname, local_ip,
                                     transport_monitor_type,
                                     "Linux", g_agent_id, sizeof(g_agent_id)) == 0) {
                    LOG_INFO_FIM("[transport] 등록 완료 — agent_id: %s", g_agent_id);
                    g_transport_ok = 1;
                } else {
                    LOG_WARN_FIM("[transport] REGISTER 실패");
                }
            }
        }
    }

    /* ── heartbeat 스레드 ─────────────────────── */
    if (g_transport_ok) {
        hb_arg.cli = &g_tcp_client;
        hb_arg.interval_sec = IM_HEARTBEAT_DEFAULT_SEC;
        hb_arg.running = 1;
        if (pthread_create(&hb_thread, NULL, im_heartbeat_thread, &hb_arg) != 0)
            LOG_WARN_FIM("[transport] heartbeat 스레드 생성 실패");
        else
            LOG_INFO_FIM("[transport] heartbeat 스레드 시작 완료");
    }

    /* ── 로컬 베이스라인 구축 ─────────────────── */
    if (im_baseline_db_init(&g_baseline_db) < 0) {
        LOG_ERROR_FIM("[baseline] DB 초기화 실패");
        goto done;
    }
    LOG_INFO_FIM("[baseline] 초기 스캔 시작 — 모든 감시 경로 해시 수집...");
    int baseline_count = im_baseline_db_build(&g_baseline_db, cfg);
    if (baseline_count < 0)
        LOG_WARN_FIM("[baseline] 초기 스캔 실패 — 무결성 검사 불완전할 수 있음");
    else
        LOG_INFO_FIM("[baseline] 초기 스캔 완료 — %d개 파일 등록", baseline_count);

    /* LKM: 베이스라인 inode 정책 주입 + 이벤트 스레드 */
    if (g_lkm_active) {
        int n = lkm_add_from_baseline(&g_baseline_db,
                                      g_ebpf_block ? IM_BLOCK_DENY
                                                    : IM_BLOCK_AUDIT);
        if (n < 0)
            LOG_WARN_FIM("[lkm] 정책 주입 실패");
        else
            LOG_INFO_FIM("[lkm] %d개 inode 정책 등록 완료", n);

        if (pthread_create(&lkm_thread, NULL, lkm_event_thread, queue) != 0) {
            LOG_WARN_FIM("[lkm] 이벤트 스레드 생성 실패");
        }
    }

#ifdef HAVE_LIBBPF
    if (g_ebpf_active) {
        uint32_t protect_mask = IM_EBPF_OP_WRITE | IM_EBPF_OP_DELETE | IM_EBPF_OP_ATTR;
        LOG_INFO_FIM("[ebpf] mode=%s — 보호 경로 %d개 등록 중...",
                     g_ebpf_block ? "lock (DENY)" : "maintenance (AUDIT)",
                     cfg->watch_count);
        for (int i = 0; i < cfg->watch_count; i++) {
            if (ebpf_policy_add_path_recursive(cfg->watches[i].path,
                                               protect_mask,
                                               g_ebpf_block) < 0) {
                LOG_WARN_FIM("[ebpf] policy 등록 실패: %s", cfg->watches[i].path);
            }
        }
    }
#endif /* HAVE_LIBBPF */

    if (g_ebpf_active) {
        LOG_INFO_FIM("inotify fallback 비활성화 — eBPF 전용 모드 (kernel %d.%d)",
                     kver_major, kver_minor);
    } else {
        LOG_INFO_FIM("inotify fallback 비활성화 — LKM 전용 모드 (kernel %d.%d)",
                     kver_major, kver_minor);
    }

    daemon_notify_ready();

    /* ── 메인 루프: 이벤트 큐에서 꺼내서 처리 ── */
    LOG_INFO_FIM("event process start..");

    uint64_t last_dropped = 0;

    while (g_running) {
        if (g_scan_req) { g_scan_req = 0; handle_scan_request(); }
        if (g_reload)   { g_reload   = 0; reload_config(); }

        im_event_t ev;
        if (im_queue_pop(queue, &ev, 500) == 0)
            process_event(&ev);

        /* 이벤트 드롭 감지 — 큐 오버플로우 발생 시 경고 */
        uint64_t cur_dropped = im_queue_dropped(queue);
        if (cur_dropped != last_dropped) {
            LOG_WARN_FIM("event queue overflow: dropped %llu (+%llu)",
                         (unsigned long long)cur_dropped,
                         (unsigned long long)(cur_dropped - last_dropped));
            last_dropped = cur_dropped;
        }

        /* systemd watchdog 핑 — 500ms 루프마다 전송
         * WatchdogSec 미설정 시 no-op */
        daemon_watchdog_ping();
    }

    /* ── 정상 종료 ─────────────────────────────── */
    LOG_INFO_FIM("received termination signal");

    if (hb_arg.running) hb_arg.running = 0;
    if (hb_thread)    { pthread_join(hb_thread,    NULL); LOG_INFO_FIM("heartbeat 스레드 합류"); }
    /* eBPF: stop → join → cleanup 순서를 지켜야 use-after-free 없음 */
#ifdef HAVE_LIBBPF
    if (g_ebpf_active) ebpf_policy_stop();
    if (ebpf_thread)  { pthread_join(ebpf_thread,  NULL); LOG_INFO_FIM("eBPF 스레드 합류"); }
    if (g_ebpf_active) ebpf_policy_cleanup();
#endif /* HAVE_LIBBPF */
    /* LKM: fd 닫으면 lkm_event_thread의 select()가 풀림 */
    if (g_lkm_active)  lkm_client_cleanup();
    if (lkm_thread)   { pthread_join(lkm_thread,   NULL); LOG_INFO_FIM("LKM 스레드 합류"); }

    if (g_be_inotify)  { g_be_inotify->cleanup(g_be_inotify); free(g_be_inotify); }

    if (transport_inited) {
        im_tcp_disconnect(&g_tcp_client);
        im_tcp_free(&g_tcp_client);
    }
    if (tls_inited) {
        tls_context_free(&g_tls_ctx);
        LOG_INFO_FIM("[transport] 연결 종료");
    }

    im_queue_destroy(queue);
    free(queue);

    im_baseline_db_free(&g_baseline_db);

done:
    pid_lock_release();    /* fcntl 잠금 해제 + PID 파일 삭제 */
    daemon_cleanup();      /* syslog closelog() */
    LOG_INFO_FIM("IM Monitor stopped");
    close_logging();
    free(cfg);
    return 0;
}
