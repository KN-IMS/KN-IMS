/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IG_LKM_PROC_CACHE_H
#define IG_LKM_PROC_CACHE_H

/*
 * ig_lkm_proc_cache — fork-time process tree cache
 *
 * sched_process_fork/exec/exit tracepoint으로 시스템 전체 프로세스의
 * (pid, ppid, uid, euid, sid, comm, exe, cmdline, start_time_ns) 를 항상 유지.
 * exit 후 5분 grace 보존 → 죽은 부모 chain 복원 가능.
 *
 * 이벤트 발생 시 ig_collect_chain은 task_struct 대신 이 캐시를 따라간다.
 */

#include <linux/types.h>
#include "ig_lkm_common.h"

/* module init/exit */
int  ig_proc_cache_init(void);
void ig_proc_cache_exit(void);

/*
 * chain 수집 — pid 부터 ppid 따라 max_depth 까지 lookup.
 *   start_pid    : 보통 task_pid_nr(current)
 *   out          : ig_lkm_chain_entry[max_depth]
 *   max_depth    : 16 권장
 *   truncated    : 종결 사유 (cache miss 또는 depth 한계)
 * 반환: 채운 entry 수
 *
 * 캐시 miss 시 task_struct fallback 호출(살아있으면 채움).
 */
int  ig_proc_cache_collect_chain(uint32_t start_pid,
                                  struct ig_lkm_chain_entry *out,
                                  int max_depth,
                                  uint8_t *truncated_out);

/* 디버그/모니터링 — module init 로그 등에 사용 */
void ig_proc_cache_get_stats(uint32_t *count,
                              uint32_t *inserts,
                              uint32_t *hits,
                              uint32_t *misses,
                              uint32_t *evictions,
                              uint32_t *throttled);

#endif
