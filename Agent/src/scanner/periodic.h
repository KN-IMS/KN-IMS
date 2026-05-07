#ifndef FIM_PERIODIC_H
#define FIM_PERIODIC_H

#include "baseline.h"
#include "vault.h"

/*
 * periodic — 주기 무결성 스캐너
 *
 * 목적:
 *   실시간 hook(fanotify/LKM/eBPF) 우회 시도 탐지.
 *   N초마다 baseline DB 순회하며 현재 해시와 비교.
 *   mismatch → vault 복원 + 알림.
 */

typedef struct {
    fim_baseline_db_t *db;
    fim_vault_t       *vault;
    int                interval_sec;   /* 0 또는 음수면 비활성 */
    volatile int      *running_flag;   /* 외부에서 종료 신호 */
    /* 콜백: 변조 감지 시 서버 전송 등에 사용 (NULL 가능) */
    void (*on_mismatch)(const char *path, const char *expected, const char *actual);
    pthread_t          tid;
    int                started;
} fim_periodic_t;

int  fim_periodic_start(fim_periodic_t *p);
void fim_periodic_stop(fim_periodic_t *p);

#endif
