#ifndef FIM_SCAN_STATE_H
#define FIM_SCAN_STATE_H

#include <pthread.h>

typedef enum {
    SCAN_CMD_NONE            = 0,
    SCAN_CMD_CREATE_BASELINE = 1,
    SCAN_CMD_INTEGRITY_SCAN  = 2,
} scan_cmd_t;

extern volatile scan_cmd_t  g_integrity_cmd;
extern volatile int         g_integrity_requested;
extern char                 g_integrity_scan_id[64];
extern pthread_mutex_t      g_integrity_lock;

#endif /* FIM_SCAN_STATE_H */
