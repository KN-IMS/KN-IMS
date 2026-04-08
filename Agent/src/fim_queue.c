/*
 * fim_queue.c — 스레드 안전 이벤트 큐
 *
 * fanotify 스레드와 inotify 스레드가 각각 이벤트를 push하고,
 * 메인 스레드(이벤트 처리기)가 pop해서 통합 처리합니다.
 *
 *   [fanotify 스레드] ──push──┐
 *                              ├──→ [이벤트 큐] ──pop──→ [메인: 통합 처리/로깅]
 *   [inotify 스레드]  ──push──┘
 */

#include <stdarg.h>
#include <sys/time.h>
#include "realtime/monitor.h"

int fim_queue_init(fim_event_queue_t *q) {
    memset(q, 0, sizeof(fim_event_queue_t));
    q->head  = 0;
    q->tail  = 0;
    q->count = 0;

    if (pthread_mutex_init(&q->lock, NULL) != 0) return -1;
    if (pthread_cond_init(&q->not_empty, NULL) != 0) return -1;

    return 0;
}

void fim_queue_destroy(fim_event_queue_t *q) {
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
}

int fim_queue_push(fim_event_queue_t *q, const fim_event_t *ev) {
    pthread_mutex_lock(&q->lock);

    if (q->count >= FIM_EVENT_QUEUE_SIZE) {
        /* 큐 가득 참 → 가장 오래된 이벤트 드롭, 카운터 증가 */
        q->head = (q->head + 1) % FIM_EVENT_QUEUE_SIZE;
        q->count--;
        q->dropped++;
    }

    q->events[q->tail] = *ev;
    q->tail = (q->tail + 1) % FIM_EVENT_QUEUE_SIZE;
    q->count++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

uint64_t fim_queue_dropped(fim_event_queue_t *q) {
    pthread_mutex_lock(&q->lock);
    uint64_t n = q->dropped;
    pthread_mutex_unlock(&q->lock);
    return n;
}

int fim_queue_pop(fim_event_queue_t *q, fim_event_t *ev, int timeout_ms) {
    pthread_mutex_lock(&q->lock);

    while (q->count == 0) {
        if (timeout_ms <= 0) {
            pthread_mutex_unlock(&q->lock);
            return -1;
        }

        struct timespec ts;
        struct timeval  tv;
        gettimeofday(&tv, NULL);
        ts.tv_sec  = tv.tv_sec + timeout_ms / 1000;
        ts.tv_nsec = tv.tv_usec * 1000 + (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        int rc = pthread_cond_timedwait(&q->not_empty, &q->lock, &ts);
        if (rc != 0) {
            pthread_mutex_unlock(&q->lock);
            return -1;
        }
    }

    *ev = q->events[q->head];
    q->head = (q->head + 1) % FIM_EVENT_QUEUE_SIZE;
    q->count--;

    pthread_mutex_unlock(&q->lock);
    return 0;
}
