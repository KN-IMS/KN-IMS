#ifndef IG_LKM_EVENTS_H
#define IG_LKM_EVENTS_H

#include <linux/wait.h>
#include "ig_lkm_common.h"

/*
 * kprobe atomic context에서 호출 가능.
 * wake_up은 workqueue로 defer하므로 스케줄러 데드락 없음.
 */
void ig_event_enqueue(uint64_t dev, uint64_t ino,
                       uint32_t op, uint32_t blocked);

/* char device read()에서 사용 */
int  ig_event_pop(struct ig_lkm_event *ev);
bool ig_event_empty(void);

/* module exit 시 pending work 취소 */
void ig_events_flush_cancel(void);

/* wait_queue — ig_lkm_chardev.c에서 read() 대기에 사용 */
extern wait_queue_head_t ig_wq;

#endif /* IG_LKM_EVENTS_H */
