/*
 * im_config.c — 설정 파일 파서 (inotify + eBPF 구조)
 *
 * 설정 파일 형식:
 *
 *   daemonize = 0
 *   log_file = /var/log/im_monitor.log
 *   verbose = 1
 *   ebpf = 1          # eBPF who-data 추적 (kernel 5.8+에서만 실제 활성화)
 *
 *   # 감시 대상 디렉토리
 *   [watch]
 *   /etc = recursive
 *   /usr/bin = single
 *
 *   # 자체 보호 (변경 시 ALERT)
 *   [protect]
 *   /usr/local/bin/agent = file
 *   /etc/im_monitor/im.conf = file
 *
 * 하위호환: [watch_inotify] 도 [watch] 와 동일하게 처리됨.
 */

#include <stdarg.h>
#include "realtime/monitor.h"

static void trim(char *s) {
    char *start = s;
    while (*start == ' ' || *start == '\t') start++;
    if (start != s) memmove(s, start, strlen(start) + 1);

    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == ' ' || s[len-1] == '\t' ||
                       s[len-1] == '\n' || s[len-1] == '\r'))
        s[--len] = '\0';
}

typedef enum {
    SECTION_GLOBAL = 0,
    SECTION_WATCH,
    SECTION_PROTECT
} config_section_t;

int im_config_load(im_config_t *cfg, const char *path) {
    memset(cfg, 0, sizeof(im_config_t));

    /* 기본값 */
    strncpy(cfg->log_file, IM_LOG_FILE, sizeof(cfg->log_file) - 1);
    cfg->daemonize    = 1;
    cfg->log_to_syslog = 0;
    cfg->verbose       = 0;
    cfg->ebpf_enabled  = 1;   /* 기본 활성화 (커널 버전 조건은 런타임에 판단) */

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "설정 파일을 열 수 없습니다: %s (%s)\n",
                path, strerror(errno));
        return -1;
    }

    char line[1024];
    config_section_t section = SECTION_GLOBAL;

    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';')
            continue;

        /* 섹션 헤더 */
        if (line[0] == '[') {
            if (strncmp(line, "[watch]", 7) == 0 ||
                strncmp(line, "[watch_inotify]", 15) == 0)  /* 하위호환 */
                section = SECTION_WATCH;
            else if (strncmp(line, "[protect]", 9) == 0)
                section = SECTION_PROTECT;
            else
                section = SECTION_GLOBAL;
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);

        switch (section) {
        case SECTION_GLOBAL:
            if (strcmp(key, "log_file") == 0)
                strncpy(cfg->log_file, val, sizeof(cfg->log_file) - 1);
            else if (strcmp(key, "syslog") == 0)
                cfg->log_to_syslog = atoi(val);
            else if (strcmp(key, "verbose") == 0)
                cfg->verbose = atoi(val);
            else if (strcmp(key, "daemonize") == 0)
                cfg->daemonize = atoi(val);
            else if (strcmp(key, "ebpf") == 0)
                cfg->ebpf_enabled = atoi(val);
            break;

        case SECTION_WATCH:
            if (cfg->watch_count < IM_MAX_WATCHES) {
                im_watch_entry_t *w = &cfg->watches[cfg->watch_count];
                strncpy(w->path, key, IM_MAX_PATH - 1);
                w->recursive = (strcmp(val, "recursive") == 0) ? 1 : 0;
                cfg->watch_count++;
            }
            break;

        case SECTION_PROTECT:
            if (cfg->protect_count < 32) {
                im_watch_entry_t *w = &cfg->protect_paths[cfg->protect_count];
                strncpy(w->path, key, IM_MAX_PATH - 1);
                w->recursive = 0;
                cfg->protect_count++;
            }
            break;
        }
    }

    fclose(fp);
    return 0;
}

void im_config_dump(im_config_t *cfg) {
    LOG_INFO_FIM("╔══════════════════════════════════════╗");
    LOG_INFO_FIM("║           IM Monitor config          ║");
    LOG_INFO_FIM("╠══════════════════════════════════════╣");
    LOG_INFO_FIM("║ daemonize : %d", cfg->daemonize);
    LOG_INFO_FIM("║ log_file  : %s", cfg->log_file);
    LOG_INFO_FIM("║ syslog    : %d", cfg->log_to_syslog);
    LOG_INFO_FIM("║ verbose   : %d", cfg->verbose);
    LOG_INFO_FIM("║ ebpf      : %d (Runtime Kernel Check Applied)",
                 cfg->ebpf_enabled);
    LOG_INFO_FIM("╠══════════════════════════════════════╣");

    LOG_INFO_FIM("║ [watch] %d-targets", cfg->watch_count);
    for (int i = 0; i < cfg->watch_count; i++)
        LOG_INFO_FIM("║   → %s (%s)", cfg->watches[i].path,
                     cfg->watches[i].recursive ? "recursive" : "simple");

    LOG_INFO_FIM("║ [self-protection] %d-targets", cfg->protect_count);
    for (int i = 0; i < cfg->protect_count; i++)
        LOG_INFO_FIM("║   → %s", cfg->protect_paths[i].path);

    LOG_INFO_FIM("╚══════════════════════════════════════╝");
}
