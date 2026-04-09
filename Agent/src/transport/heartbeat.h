#ifndef FIM_HEARTBEAT_H
#define FIM_HEARTBEAT_H

#include "tcp_client.h"

#define FIM_HEARTBEAT_DEFAULT_SEC 30

typedef struct {
    fim_tcp_client_t *cli;
    uint16_t          interval_sec;
    volatile int      running;
} fim_heartbeat_arg_t;

void *fim_heartbeat_thread(void *arg);

#endif /* FIM_HEARTBEAT_H */
