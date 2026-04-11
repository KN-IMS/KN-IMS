/*
 * baseline.c — SHA-256 해시 계산 + 로컬 베이스라인 DB 관리
 *
 * 에이전트가 베이스라인을 직접 보유 (서버 미전송).
 * inotify MODIFY 이벤트 발생 시 자동으로 무결성 검사 수행.
 */

#include "baseline.h"
#include "walker.h"
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

/*
 * OpenSSL 1.0.x 호환 래퍼
 * EVP_MD_CTX_new / EVP_MD_CTX_free 는 OpenSSL 1.1.0+에서 추가됨.
 * 1.0.x 에서는 EVP_MD_CTX_create / EVP_MD_CTX_destroy 사용.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define EVP_MD_CTX_new()     EVP_MD_CTX_create()
#  define EVP_MD_CTX_free(ctx) EVP_MD_CTX_destroy(ctx)
#endif

/* ── SHA-256 계산 ────────────────────────────────── */

int im_sha256_file(const char *path, char out_hex[65]) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(fp); return -1; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx); fclose(fp); return -1;
    }

    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx); fclose(fp); return -1;
        }
    }

    unsigned char digest[32];
    unsigned int  dlen = 0;
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    fclose(fp);

    for (unsigned int i = 0; i < dlen; i++)
        snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
    out_hex[64] = '\0';
    return 0;
}

/* ── 동적 배열 헬퍼 ──────────────────────────────── */

static int result_grow(im_scan_result_t *r) {
    int new_cap = (r->capacity == 0) ? 256 : r->capacity * 2;
    im_scan_entry_t *p = realloc(r->entries,
                                   (size_t)new_cap * sizeof(im_scan_entry_t));
    if (!p) return -1;
    r->entries  = p;
    r->capacity = new_cap;
    return 0;
}

/* ── walker 콜백 ─────────────────────────────────── */

static int scan_cb(const char *path, const struct stat *st, void *userdata) {
    im_scan_result_t *result = (im_scan_result_t *)userdata;

    if (result->count >= result->capacity) {
        if (result_grow(result) < 0) {
            LOG_WARN_FIM("[baseline] 메모리 부족 — %s 스킵", path);
            result->errors++;
            return 0;
        }
    }

    im_scan_entry_t *e = &result->entries[result->count];
    strncpy(e->path, path, IM_MAX_PATH - 1);
    e->path[IM_MAX_PATH - 1] = '\0';
    e->mtime = st->st_mtime;
    e->size  = st->st_size;

    if (im_sha256_file(path, e->hash) < 0) {
        LOG_WARN_FIM("[baseline] 해시 실패 (권한?): %s", path);
        result->errors++;
        return 0;  /* 스킵하고 계속 */
    }

    result->count++;
    return 0;
}

/* ── 전체 스캔 함수 (내부 빌드에서 재사용) ──────── */

int im_baseline_scan(im_config_t *cfg, im_scan_result_t *out) {
    memset(out, 0, sizeof(*out));

    for (int i = 0; i < cfg->watch_count; i++) {
        const char *path      = cfg->watches[i].path;
        int         recursive = cfg->watches[i].recursive;

        LOG_INFO_FIM("[baseline] 스캔 시작: %s (recursive=%d)", path, recursive);

        int n = im_walk(path, recursive, scan_cb, out);
        if (n < 0) {
            LOG_WARN_FIM("[baseline] 순회 실패: %s", path);
            continue;
        }

        LOG_INFO_FIM("[baseline] %s 완료 — %d개 파일", path, n);
    }

    LOG_INFO_FIM("[baseline] 전체 스캔 완료 — 총 %d개 (오류 %d개)",
                 out->count, out->errors);
    return out->count;
}

void im_scan_result_free(im_scan_result_t *result) {
    if (result->entries) {
        free(result->entries);
        result->entries = NULL;
    }
    result->count    = 0;
    result->capacity = 0;
    result->errors   = 0;
}

/* ── 로컬 베이스라인 DB 구현 ─────────────────────── */

int im_baseline_db_init(im_baseline_db_t *db) {
    memset(db, 0, sizeof(*db));
    if (pthread_rwlock_init(&db->lock, NULL) != 0) return -1;
    return 0;
}

int im_baseline_db_build(im_baseline_db_t *db, im_config_t *cfg) {
    pthread_rwlock_wrlock(&db->lock);
    im_scan_result_free(&db->data);
    int n = im_baseline_scan(cfg, &db->data);
    pthread_rwlock_unlock(&db->lock);
    return n;
}

im_integrity_result_t im_baseline_check_file(im_baseline_db_t *db,
                                               const char *path,
                                               char out_expected[65],
                                               char out_actual[65]) {
    char actual[65];
    if (im_sha256_file(path, actual) < 0) {
        if (out_actual)   out_actual[0]   = '\0';
        if (out_expected) out_expected[0] = '\0';
        return IM_INTEGRITY_ERROR;
    }
    if (out_actual) strncpy(out_actual, actual, 65);

    pthread_rwlock_rdlock(&db->lock);
    for (int i = 0; i < db->data.count; i++) {
        if (strcmp(db->data.entries[i].path, path) == 0) {
            const char *expected = db->data.entries[i].hash;
            if (out_expected) strncpy(out_expected, expected, 65);
            im_integrity_result_t r = (strcmp(actual, expected) == 0)
                                     ? IM_INTEGRITY_MATCH
                                     : IM_INTEGRITY_MISMATCH;
            pthread_rwlock_unlock(&db->lock);
            return r;
        }
    }
    pthread_rwlock_unlock(&db->lock);

    if (out_expected) out_expected[0] = '\0';
    return IM_INTEGRITY_NEW;
}

void im_baseline_db_update(im_baseline_db_t *db, const char *path) {
    char hash[65];
    struct stat st;

    if (im_sha256_file(path, hash) < 0) return;
    if (stat(path, &st) < 0) return;

    pthread_rwlock_wrlock(&db->lock);

    /* 기존 항목 업데이트 */
    for (int i = 0; i < db->data.count; i++) {
        if (strcmp(db->data.entries[i].path, path) == 0) {
            strncpy(db->data.entries[i].hash, hash, 65);
            db->data.entries[i].mtime = st.st_mtime;
            db->data.entries[i].size  = st.st_size;
            pthread_rwlock_unlock(&db->lock);
            return;
        }
    }

    /* 신규 항목 추가 */
    if (db->data.count >= db->data.capacity) {
        int new_cap = (db->data.capacity == 0) ? 256 : db->data.capacity * 2;
        im_scan_entry_t *p = realloc(db->data.entries,
                                       (size_t)new_cap * sizeof(im_scan_entry_t));
        if (!p) {
            pthread_rwlock_unlock(&db->lock);
            LOG_WARN_FIM("[baseline] 메모리 부족 — %s 등록 실패", path);
            return;
        }
        db->data.entries  = p;
        db->data.capacity = new_cap;
    }

    im_scan_entry_t *e = &db->data.entries[db->data.count];
    strncpy(e->path, path, IM_MAX_PATH - 1);
    e->path[IM_MAX_PATH - 1] = '\0';
    strncpy(e->hash, hash, 65);
    e->mtime = st.st_mtime;
    e->size  = st.st_size;
    db->data.count++;

    pthread_rwlock_unlock(&db->lock);
}

void im_baseline_db_remove(im_baseline_db_t *db, const char *path) {
    pthread_rwlock_wrlock(&db->lock);
    for (int i = 0; i < db->data.count; i++) {
        if (strcmp(db->data.entries[i].path, path) == 0) {
            /* 마지막 항목으로 교체 후 count 감소 */
            if (i < db->data.count - 1)
                db->data.entries[i] = db->data.entries[db->data.count - 1];
            db->data.count--;
            break;
        }
    }
    pthread_rwlock_unlock(&db->lock);
}

void im_baseline_db_free(im_baseline_db_t *db) {
    pthread_rwlock_wrlock(&db->lock);
    im_scan_result_free(&db->data);
    pthread_rwlock_unlock(&db->lock);
    pthread_rwlock_destroy(&db->lock);
}
