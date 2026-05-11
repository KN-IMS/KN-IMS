#ifndef IG_HEARTBEAT_H
#define IG_HEARTBEAT_H

#include "tcp_client.h"

#define IG_HEARTBEAT_DEFAULT_SEC 30

typedef struct {
    ig_tcp_client_t *cli;
    uint16_t          interval_sec;
    volatile int      running;
} ig_heartbeat_arg_t;

void *ig_heartbeat_thread(void *arg);

#endif /* IG_HEARTBEAT_H */
