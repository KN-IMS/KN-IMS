#ifndef FIM_HEARTBEAT_H
#define FIM_HEARTBEAT_H

#include "tcp_client.h"

typedef struct {
    fim_tcp_client_t *client;
    const char       *agent_id;
    volatile int      running;
} fim_heartbeat_t;

/* 30초 주기 HEARTBEAT 전송 스레드 (pthread로 실행) */
void *heartbeat_thread(void *arg);

#endif /* FIM_HEARTBEAT_H */
