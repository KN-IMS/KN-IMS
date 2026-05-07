/*
 * periodic.c — 주기 무결성 스캐너
 */

#include "periodic.h"
#include "../realtime/monitor.h"

#include <pthread.h>
#include <unistd.h>
#include <string.h>

static void scan_once(fim_periodic_t *p)
{
    /* baseline DB 스냅샷 — wlock 길게 잡지 않으려고 path만 추출 */
    pthread_rwlock_rdlock(&p->db->lock);
    int n = p->db->data.count;
    char (*paths)[FIM_MAX_PATH] = NULL;
    if (n > 0) {
        paths = malloc((size_t)n * sizeof(*paths));
        if (paths) {
            for (int i = 0; i < n; i++) {
                strncpy(paths[i], p->db->data.entries[i].path, FIM_MAX_PATH - 1);
                paths[i][FIM_MAX_PATH - 1] = '\0';
            }
        }
    }
    pthread_rwlock_unlock(&p->db->lock);

    if (!paths) return;

    int mismatched = 0, restored = 0, missing = 0;
    for (int i = 0; i < n; i++) {
        if (p->running_flag && !*p->running_flag) break;

        char expected[65] = {0}, actual[65] = {0};
        fim_integrity_result_t r = fim_baseline_check_file(p->db, paths[i],
                                                           expected, actual);

        if (r == FIM_INTEGRITY_MISMATCH) {
            mismatched++;
            LOG_ALERT_FIM("[periodic] *** 변조 탐지(이벤트 누락): %s "
                          "expected=%.16s... actual=%.16s... ***",
                          paths[i], expected, actual);
            if (p->on_mismatch) p->on_mismatch(paths[i], expected, actual);
            if (p->vault && fim_vault_has(p->vault, paths[i])) {
                if (fim_vault_restore(p->vault, paths[i]) == 0)
                    restored++;
            }
        } else if (r == FIM_INTEGRITY_ERROR) {
            /* 파일 없음 — 삭제 우회 */
            missing++;
            LOG_ALERT_FIM("[periodic] *** 파일 소실(이벤트 누락): %s ***",
                          paths[i]);
            if (p->vault && fim_vault_has(p->vault, paths[i])) {
                if (fim_vault_restore(p->vault, paths[i]) == 0)
                    restored++;
            }
        }
    }

    if (mismatched || missing) {
        LOG_INFO_FIM("[periodic] 스캔: total=%d mismatch=%d missing=%d restored=%d",
                     n, mismatched, missing, restored);
    }
    free(paths);
}

static void *worker(void *arg)
{
    fim_periodic_t *p = (fim_periodic_t *)arg;
    LOG_INFO_FIM("[periodic] 주기 스캐너 시작 (interval=%ds)", p->interval_sec);

    while (p->running_flag ? *p->running_flag : 1) {
        /* sleep을 짧게 쪼개서 종료 신호에 빠르게 반응 */
        for (int s = 0; s < p->interval_sec; s++) {
            if (p->running_flag && !*p->running_flag) goto done;
            sleep(1);
        }
        scan_once(p);
    }
done:
    LOG_INFO_FIM("[periodic] 주기 스캐너 정지");
    return NULL;
}

int fim_periodic_start(fim_periodic_t *p)
{
    if (!p || !p->db || p->interval_sec <= 0) return -1;
    if (p->started) return 0;
    if (pthread_create(&p->tid, NULL, worker, p) != 0) return -1;
    p->started = 1;
    return 0;
}

void fim_periodic_stop(fim_periodic_t *p)
{
    if (!p || !p->started) return;
    pthread_join(p->tid, NULL);
    p->started = 0;
}
