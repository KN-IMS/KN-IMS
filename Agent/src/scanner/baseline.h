#ifndef IG_BASELINE_H
#define IG_BASELINE_H

#include <sys/types.h>
#include <pthread.h>
#include "../realtime/monitor.h"

/* ── 스캔 결과 단일 항목 ─────────────────────────── */
typedef struct {
    char   path[IG_MAX_PATH];
    char   hash[65];        /* SHA-256 hex (64자 + null) */
    time_t mtime;
    off_t  size;
} ig_scan_entry_t;

/* ── 스캔 결과 컬렉션 (동적 배열) ────────────────── */
typedef struct {
    ig_scan_entry_t *entries;
    int               count;
    int               capacity;
    int               errors;   /* 권한 없음 등으로 스킵된 파일 수 */
} ig_scan_result_t;

/* ── 에이전트 로컬 베이스라인 DB (thread-safe) ────── */
typedef struct {
    ig_scan_result_t data;
    pthread_rwlock_t  lock;
} ig_baseline_db_t;

/* ── 무결성 검사 결과 ─────────────────────────────── */
typedef enum {
    IG_INTEGRITY_MATCH    =  0,  /* 해시 일치 */
    IG_INTEGRITY_MISMATCH =  1,  /* 해시 불일치 (변조 의심) */
    IG_INTEGRITY_NEW      =  2,  /* 베이스라인에 없는 신규 파일 */
    IG_INTEGRITY_ERROR    = -1,  /* 해시 계산 실패 */
} ig_integrity_result_t;

/*
 * ig_sha256_file — 파일 SHA-256 계산
 *   out_hex : 65바이트 버퍼 (64자 hex + null)
 *   반환값  : 0 성공, -1 실패
 */
int ig_sha256_file(const char *path, char out_hex[65]);

/*
 * ig_baseline_scan — cfg->watches 경로 전체 순회 후 결과 수집
 *   반환값 : 스캔한 파일 수, -1 오류
 */
int ig_baseline_scan(ig_config_t *cfg, ig_scan_result_t *out);

/* ig_scan_result_free — 동적 할당 해제 */
void ig_scan_result_free(ig_scan_result_t *result);

/* ── 로컬 베이스라인 DB 함수 ────────────────────── */

/* 초기화 (사용 전 반드시 호출) */
int  ig_baseline_db_init(ig_baseline_db_t *db);

/* 모든 감시 경로 스캔 후 DB 구축 (startup 시 호출) */
int  ig_baseline_db_build(ig_baseline_db_t *db, ig_config_t *cfg);

/*
 * ig_baseline_check_file — MODIFY 이벤트 시 무결성 검사
 *   path         : 검사할 파일 경로
 *   out_expected : 베이스라인 해시 (65바이트 버퍼, 없으면 "" 반환)
 *   out_actual   : 현재 파일 해시 (65바이트 버퍼)
 *   반환값       : ig_integrity_result_t
 */
ig_integrity_result_t ig_baseline_check_file(ig_baseline_db_t *db,
                                               const char *path,
                                               char out_expected[65],
                                               char out_actual[65]);

/*
 * ig_baseline_db_update — path 파일의 현재 해시를 DB에 반영
 *   DB에 없으면 추가, 있으면 갱신
 */
void ig_baseline_db_update(ig_baseline_db_t *db, const char *path);

/* ig_baseline_db_remove — path 항목을 DB에서 제거 */
void ig_baseline_db_remove(ig_baseline_db_t *db, const char *path);

/* ig_baseline_db_free — DB 동적 할당 해제 */
void ig_baseline_db_free(ig_baseline_db_t *db);

#endif /* IG_BASELINE_H */
