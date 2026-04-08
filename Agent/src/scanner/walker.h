#ifndef FIM_WALKER_H
#define FIM_WALKER_H

#include <sys/stat.h>

/*
 * fim_walk_cb — 파일 발견 시 호출되는 콜백
 *   path     : 절대 경로
 *   st       : lstat() 결과
 *   userdata : 호출자가 넘긴 임의 포인터
 *   반환값 0 : 계속, -1 : 순회 중단
 */
typedef int (*fim_walk_cb)(const char *path, const struct stat *st, void *userdata);

/*
 * fim_walk — 경로를 순회하며 일반 파일마다 cb 호출
 *   recursive : 1이면 하위 디렉토리 재귀, 0이면 단일 레벨
 *   반환값    : 방문한 파일 수 (에러 시 -1)
 */
int fim_walk(const char *base, int recursive, fim_walk_cb cb, void *userdata);

#endif /* FIM_WALKER_H */
