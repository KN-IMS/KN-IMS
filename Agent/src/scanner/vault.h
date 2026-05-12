#ifndef FIM_VAULT_H
#define FIM_VAULT_H

#include <pthread.h>
#include <linux/limits.h>

/*
 * vault — 정책 대상 파일의 신뢰 백업 저장소
 *
 * 구조:
 *   <vault_dir>/files/<sha256(orig_path)>.bin   원본 바이트
 *   <vault_dir>/meta/<sha256(orig_path)>.meta   mode/uid/gid/size/hash/orig_path
 *
 * 보안 가정:
 *   - vault_dir 자체가 LKM DENY 정책에 등록되어 있어야 함 (외부에서 제공)
 *   - 에이전트만 write, 그 외 차단
 */

typedef struct {
    char             dir[PATH_MAX];   /* 예: /var/lib/im_monitor/vault */
    pthread_rwlock_t lock;
    int              initialized;
} fim_vault_t;

/* 초기화 — 디렉토리 생성, 권한 설정(0700, root:root) */
int  fim_vault_init(fim_vault_t *v, const char *vault_dir);

/* 백업 — 원본 path 를 vault 안에 저장 (해시 다르면 갱신) */
int  fim_vault_store(fim_vault_t *v, const char *path);

/* 복원 — vault → 원본 경로 (mode/uid/gid 보존) */
int  fim_vault_restore(fim_vault_t *v, const char *path);

/* 백업 존재 여부 */
int  fim_vault_has(fim_vault_t *v, const char *path);

/*
 * fim_vault_register_lkm — vault 디렉토리/파일 전체를 LKM DENY로 등록
 *   디렉토리(meta/, files/) 자체 + 내부 모든 파일 → 외부 변조 차단
 *   에이전트 자신은 immutable을 일시 해제하고 쓰므로 영향 없음
 */
int  fim_vault_register_lkm(fim_vault_t *v);

void fim_vault_free(fim_vault_t *v);

#endif
