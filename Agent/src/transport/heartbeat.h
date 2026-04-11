#ifndef IM_HEARTBEAT_H
#define IM_HEARTBEAT_H

#include "tcp_client.h"

#define IM_HEARTBEAT_DEFAULT_SEC 30

typedef struct {
    im_tcp_client_t *cli;
    uint16_t          interval_sec;
    volatile int      running;
} im_heartbeat_arg_t;

void *im_heartbeat_thread(void *arg);

#endif /* IM_HEARTBEAT_H */
