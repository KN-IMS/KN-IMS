#include "scan_state.h"

volatile scan_cmd_t  g_integrity_cmd       = SCAN_CMD_NONE;
volatile int         g_integrity_requested = 0;
char                 g_integrity_scan_id[64] = {0};
pthread_mutex_t      g_integrity_lock       = PTHREAD_MUTEX_INITIALIZER;
