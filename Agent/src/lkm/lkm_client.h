#ifndef LKM_CLIENT_H
#define LKM_CLIENT_H

/*
 * lkm_client.h — im_monitor 유저스페이스 ↔ im_lkm.ko 통신 인터페이스
 *
 * 사용 순서:
 *   1. lkm_client_init()           — /dev/im_lkm 열기
 *   2. lkm_add_from_baseline()     — 베이스라인 inode 정책 일괄 주입
 *   3. lkm_read_event_timeout()    — 이벤트 수신 루프 (별도 스레드)
 *   4. lkm_client_cleanup()        — 종료 시 fd 닫기
 */

#include <sys/types.h>
#include <stdint.h>
#include "lkm/im_lkm_common.h"
#include "scanner/baseline.h"

/* ── 초기화 / 정리 ──────────────────────────────── */
int  lkm_client_init(void);
void lkm_client_cleanup(void);
int  lkm_client_ready(void);          /* 1: 사용 가능, 0: 미초기화 */

/* ── 정책 조작 ───────────────────────────────────── */
int  lkm_add_inode(dev_t st_dev, ino_t st_ino,
                   uint32_t mask, uint32_t block,
                   const char *path);
int  lkm_remove_inode(dev_t st_dev, ino_t st_ino);
int  lkm_clear_all(void);

/*
 * lkm_add_from_baseline — 베이스라인 DB 전체를 LKM 정책으로 주입
 *   db    : im_baseline_db_build() 완료된 DB
 *   block : IM_BLOCK_DENY(차단) or IM_BLOCK_AUDIT(탐지만)
 *   반환  : 등록된 inode 수, 음수는 오류
 */
int  lkm_add_from_baseline(im_baseline_db_t *db, uint32_t block);

/* ── 이벤트 수신 ────────────────────────────────── */
int  lkm_read_event(struct im_lkm_event *ev);           /* 무한 대기 */
int  lkm_read_event_timeout(struct im_lkm_event *ev,
                             int timeout_ms);             /* 타임아웃 */

#endif /* LKM_CLIENT_H */
