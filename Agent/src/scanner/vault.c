/*
 * vault.c — 신뢰 백업 저장소
 */

#include "vault.h"
#include "baseline.h"
#include "../realtime/monitor.h"
#include "../lkm/lkm_client.h"
#include "../lkm/fim_lkm_common.h"

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/fs.h>     /* FS_IOC_GETFLAGS / FS_IOC_SETFLAGS / FS_IMMUTABLE_FL */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define EVP_MD_CTX_new()     EVP_MD_CTX_create()
#  define EVP_MD_CTX_free(ctx) EVP_MD_CTX_destroy(ctx)
#endif

/* ── 경로 해시 (파일명용) ───────────────────────── */
static int sha256_str(const char *s, char out_hex[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    unsigned char digest[32];
    unsigned int  dlen = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, s, strlen(s)) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &dlen) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < dlen; i++)
        snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
    out_hex[64] = '\0';
    return 0;
}

static int build_paths(fim_vault_t *v, const char *orig,
                       char *bin_path, size_t bin_sz,
                       char *meta_path, size_t meta_sz)
{
    char key[65];
    if (sha256_str(orig, key) < 0) return -1;
    snprintf(bin_path,  bin_sz,  "%s/files/%s.bin",  v->dir, key);
    snprintf(meta_path, meta_sz, "%s/meta/%s.meta",  v->dir, key);
    return 0;
}

/* ── meta I/O ────────────────────────────────────── */
typedef struct {
    char     path[PATH_MAX];
    mode_t   mode;
    uid_t    uid;
    gid_t    gid;
    off_t    size;
    char     hash[65];
} vault_meta_t;

static int meta_write(const char *meta_path, const vault_meta_t *m)
{
    FILE *fp = fopen(meta_path, "w");
    if (!fp) return -1;
    fprintf(fp, "path=%s\n",  m->path);
    fprintf(fp, "mode=%u\n",  (unsigned)m->mode);
    fprintf(fp, "uid=%u\n",   (unsigned)m->uid);
    fprintf(fp, "gid=%u\n",   (unsigned)m->gid);
    fprintf(fp, "size=%lld\n",(long long)m->size);
    fprintf(fp, "hash=%s\n",  m->hash);
    fclose(fp);
    chmod(meta_path, 0600);
    return 0;
}

static int meta_read(const char *meta_path, vault_meta_t *m)
{
    FILE *fp = fopen(meta_path, "r");
    if (!fp) return -1;
    memset(m, 0, sizeof(*m));

    char line[PATH_MAX + 64];
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *val = eq + 1;
        size_t vlen = strlen(val);
        if (vlen > 0 && val[vlen-1] == '\n') val[vlen-1] = '\0';

        if      (!strcmp(line, "path")) strncpy(m->path, val, sizeof(m->path)-1);
        else if (!strcmp(line, "mode")) m->mode = (mode_t)strtoul(val, NULL, 10);
        else if (!strcmp(line, "uid"))  m->uid  = (uid_t)strtoul(val, NULL, 10);
        else if (!strcmp(line, "gid"))  m->gid  = (gid_t)strtoul(val, NULL, 10);
        else if (!strcmp(line, "size")) m->size = (off_t)strtoll(val, NULL, 10);
        else if (!strcmp(line, "hash")) strncpy(m->hash, val, sizeof(m->hash)-1);
    }
    fclose(fp);
    return 0;
}

/* ── immutable flag 토글 ─────────────────────────── */
static int set_immutable(const char *path, int enable)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return -1;

    int flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0) {
        close(fd);
        return -1;
    }
    int newf = enable ? (flags | FS_IMMUTABLE_FL)
                      : (flags & ~FS_IMMUTABLE_FL);
    if (newf == flags) { close(fd); return 0; }

    int rc = ioctl(fd, FS_IOC_SETFLAGS, &newf);
    close(fd);
    return rc;
}

/* ── 파일 복사 (원자적 쓰기: tmp → rename) ────────── */
static int copy_file_atomic(const char *src, const char *dst)
{
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) return -1;

    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", dst, getpid());

    int dfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (dfd < 0) { close(sfd); return -1; }

    char buf[8192];
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(dfd, buf + off, (size_t)(n - off));
            if (w < 0) { close(sfd); close(dfd); unlink(tmp); return -1; }
            off += w;
        }
    }
    fsync(dfd);
    close(sfd);
    close(dfd);

    if (rename(tmp, dst) < 0) { unlink(tmp); return -1; }
    return 0;
}

static int mkdir_p(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
    return 0;
}

/* ── public API ──────────────────────────────────── */

int fim_vault_init(fim_vault_t *v, const char *vault_dir)
{
    memset(v, 0, sizeof(*v));
    if (pthread_rwlock_init(&v->lock, NULL) != 0) return -1;

    strncpy(v->dir, vault_dir, sizeof(v->dir) - 1);

    char files_dir[PATH_MAX], meta_dir[PATH_MAX];
    snprintf(files_dir, sizeof(files_dir), "%s/files", v->dir);
    snprintf(meta_dir,  sizeof(meta_dir),  "%s/meta",  v->dir);

    if (mkdir_p(files_dir, 0700) < 0 || mkdir_p(meta_dir, 0700) < 0) {
        LOG_ERROR_FIM("[vault] 디렉토리 생성 실패: %s (%s)",
                      v->dir, strerror(errno));
        return -1;
    }
    chmod(v->dir, 0700);

    v->initialized = 1;
    LOG_INFO_FIM("[vault] 초기화 완료: %s", v->dir);
    return 0;
}

int fim_vault_store(fim_vault_t *v, const char *path)
{
    if (!v->initialized) return -1;

    struct stat st;
    if (stat(path, &st) < 0) return -1;
    if (!S_ISREG(st.st_mode)) return -1;   /* 일반 파일만 백업 */

    char bin_path[PATH_MAX], meta_path[PATH_MAX];
    if (build_paths(v, path, bin_path, sizeof(bin_path),
                            meta_path, sizeof(meta_path)) < 0) return -1;

    char hash[65];
    if (fim_sha256_file(path, hash) < 0) return -1;

    pthread_rwlock_wrlock(&v->lock);

    /* 동일 해시면 스킵 */
    vault_meta_t old;
    if (meta_read(meta_path, &old) == 0 && strcmp(old.hash, hash) == 0) {
        pthread_rwlock_unlock(&v->lock);
        return 0;
    }

    /* 기존 백업본이 immutable 이면 일시 해제 → 덮어쓰기 → 재설정 */
    set_immutable(bin_path, 0);
    set_immutable(meta_path, 0);

    if (copy_file_atomic(path, bin_path) < 0) {
        pthread_rwlock_unlock(&v->lock);
        LOG_WARN_FIM("[vault] 백업 실패: %s", path);
        return -1;
    }

    vault_meta_t m;
    memset(&m, 0, sizeof(m));
    strncpy(m.path, path, sizeof(m.path) - 1);
    m.mode = st.st_mode & 07777;
    m.uid  = st.st_uid;
    m.gid  = st.st_gid;
    m.size = st.st_size;
    strncpy(m.hash, hash, sizeof(m.hash) - 1);
    meta_write(meta_path, &m);

    /* immutable 설정 — root조차 unlink/write 불가 */
    if (set_immutable(bin_path, 1) < 0)
        LOG_WARN_FIM("[vault] immutable 설정 실패: %s (%s)", bin_path, strerror(errno));
    if (set_immutable(meta_path, 1) < 0)
        LOG_WARN_FIM("[vault] immutable 설정 실패: %s (%s)", meta_path, strerror(errno));

    pthread_rwlock_unlock(&v->lock);
    LOG_INFO_FIM("[vault] 백업 저장: %s (%lld bytes, immutable)", path, (long long)st.st_size);
    return 0;
}

int fim_vault_restore(fim_vault_t *v, const char *path)
{
    if (!v->initialized) return -1;

    char bin_path[PATH_MAX], meta_path[PATH_MAX];
    if (build_paths(v, path, bin_path, sizeof(bin_path),
                            meta_path, sizeof(meta_path)) < 0) return -1;

    pthread_rwlock_rdlock(&v->lock);

    vault_meta_t m;
    if (meta_read(meta_path, &m) < 0) {
        pthread_rwlock_unlock(&v->lock);
        LOG_WARN_FIM("[vault] 메타 없음 — 복원 불가: %s", path);
        return -1;
    }

    if (access(bin_path, R_OK) < 0) {
        pthread_rwlock_unlock(&v->lock);
        LOG_WARN_FIM("[vault] 백업본 없음 — 복원 불가: %s", path);
        return -1;
    }

    /* 부모 디렉토리 보장 */
    char parent[PATH_MAX];
    strncpy(parent, path, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = '\0';
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = '\0';
        mkdir_p(parent, 0755);
    }

    if (copy_file_atomic(bin_path, path) < 0) {
        pthread_rwlock_unlock(&v->lock);
        LOG_ERROR_FIM("[vault] 복원 쓰기 실패: %s", path);
        return -1;
    }

    chmod(path, m.mode);
    if (chown(path, m.uid, m.gid) < 0) {
        /* 비치명 — 로그만 */
        LOG_WARN_FIM("[vault] chown 실패: %s (%s)", path, strerror(errno));
    }

    pthread_rwlock_unlock(&v->lock);
    LOG_ALERT_FIM("[vault] *** 복원 완료: %s (size=%lld) ***",
                  path, (long long)m.size);
    return 0;
}

int fim_vault_has(fim_vault_t *v, const char *path)
{
    if (!v->initialized) return 0;
    char bin_path[PATH_MAX], meta_path[PATH_MAX];
    if (build_paths(v, path, bin_path, sizeof(bin_path),
                            meta_path, sizeof(meta_path)) < 0) return 0;
    return (access(bin_path, R_OK) == 0 && access(meta_path, R_OK) == 0);
}

/* ── LKM DENY 등록 (vault 자체 보호) ─────────────── */
static int lkm_deny_path(const char *path)
{
    if (!lkm_client_ready()) return -1;
    struct stat st;
    if (stat(path, &st) < 0) return -1;
    uint32_t mask = FIM_OP_WRITE | FIM_OP_DELETE | FIM_OP_RENAME;
    return lkm_add_inode(st.st_dev, st.st_ino, mask, FIM_BLOCK_DENY, path);
}

static int register_dir_recursive(const char *dir, int *count)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    char child[PATH_MAX];
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(child, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (lkm_deny_path(child) == 0) (*count)++;
            register_dir_recursive(child, count);
        } else if (S_ISREG(st.st_mode)) {
            if (lkm_deny_path(child) == 0) (*count)++;
        }
    }
    closedir(d);
    return 0;
}

int fim_vault_register_lkm(fim_vault_t *v)
{
    if (!v->initialized) return -1;
    if (!lkm_client_ready()) {
        LOG_WARN_FIM("[vault] LKM 미초기화 — DENY 등록 스킵");
        return -1;
    }

    int n = 0;
    pthread_rwlock_rdlock(&v->lock);

    /* vault 루트 + files/ + meta/ 디렉토리 inode */
    if (lkm_deny_path(v->dir) == 0) n++;

    char files_dir[PATH_MAX], meta_dir[PATH_MAX];
    snprintf(files_dir, sizeof(files_dir), "%s/files", v->dir);
    snprintf(meta_dir,  sizeof(meta_dir),  "%s/meta",  v->dir);
    if (lkm_deny_path(files_dir) == 0) n++;
    if (lkm_deny_path(meta_dir)  == 0) n++;

    /* 내부 백업본 전부 */
    register_dir_recursive(files_dir, &n);
    register_dir_recursive(meta_dir,  &n);

    pthread_rwlock_unlock(&v->lock);
    LOG_INFO_FIM("[vault] LKM DENY 등록: %d개 inode", n);
    return n;
}

void fim_vault_free(fim_vault_t *v)
{
    if (!v->initialized) return;
    pthread_rwlock_destroy(&v->lock);
    v->initialized = 0;
}
