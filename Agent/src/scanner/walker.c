/*
 * walker.c — 디렉토리 트리 순회
 *
 * - lstat() 기반: 심링크는 따라가지 않음 (루프 방지)
 * - 방문한 디렉토리 inode를 추적하여 심링크 루프 차단
 * - 최대 재귀 깊이 64
 */

#include "walker.h"
#include "../realtime/monitor.h"
#include <stdarg.h>
#include <dirent.h>

#define WALK_MAX_DEPTH    64
#define WALK_VISITED_MAX  4096

typedef struct {
    ino_t inodes[WALK_VISITED_MAX];
    int   count;
} visited_set_t;

static int visited_check_add(visited_set_t *vs, ino_t ino) {
    for (int i = 0; i < vs->count; i++)
        if (vs->inodes[i] == ino) return 1;  /* 이미 방문 */
    if (vs->count < WALK_VISITED_MAX)
        vs->inodes[vs->count++] = ino;
    return 0;
}

static int walk_impl(const char *path, int recursive,
                     im_walk_cb cb, void *userdata,
                     visited_set_t *vs, int depth)
{
    if (depth > WALK_MAX_DEPTH) return 0;

    struct stat st;
    if (lstat(path, &st) < 0) return 0;

    /* 일반 파일 → 콜백 */
    if (S_ISREG(st.st_mode))
        return (cb(path, &st, userdata) == 0) ? 1 : 0;

    /* 디렉토리가 아니면 (심링크, 특수파일 등) 무시 */
    if (!S_ISDIR(st.st_mode)) return 0;

    /* 심링크 루프 방지 */
    if (visited_check_add(vs, st.st_ino)) return 0;

    DIR *dir = opendir(path);
    if (!dir) {
        LOG_WARN_FIM("[walker] opendir 실패: %s (%s)", path, strerror(errno));
        return 0;
    }

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' &&
            (entry->d_name[1] == '\0' ||
             (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
            continue;

        char sub[IM_MAX_PATH];
        if (snprintf(sub, sizeof(sub), "%s/%s", path, entry->d_name)
                >= (int)sizeof(sub))
            continue;  /* 경로 너무 김 */

        struct stat sub_st;
        if (lstat(sub, &sub_st) < 0) continue;

        if (S_ISREG(sub_st.st_mode)) {
            if (cb(sub, &sub_st, userdata) == 0) count++;
        } else if (S_ISDIR(sub_st.st_mode) && recursive) {
            count += walk_impl(sub, recursive, cb, userdata, vs, depth + 1);
        }
        /* 심링크·특수파일 무시 */
    }

    closedir(dir);
    return count;
}

int im_walk(const char *base, int recursive, im_walk_cb cb, void *userdata) {
    /* trailing slash 정규화 — baseline 경로가 inotify 이벤트 경로와 일치하도록 */
    char nbase[IM_MAX_PATH];
    strncpy(nbase, base, IM_MAX_PATH - 1);
    nbase[IM_MAX_PATH - 1] = '\0';
    size_t plen = strlen(nbase);
    while (plen > 1 && nbase[plen - 1] == '/') nbase[--plen] = '\0';

    visited_set_t vs = { .count = 0 };
    return walk_impl(nbase, recursive, cb, userdata, &vs, 0);
}
