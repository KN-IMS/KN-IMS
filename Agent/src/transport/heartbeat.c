#define _POSIX_C_SOURCE 200809L
#include "heartbeat.h"
#include <time.h>
#include <syslog.h>
#include <string.h>

void *fim_heartbeat_thread(void *arg)
{
    fim_heartbeat_arg_t *hb = (fim_heartbeat_arg_t *)arg;
    if (!hb || !hb->cli) return NULL;

    syslog(LOG_INFO, "fim-hb: heartbeat 스레드 시작");

    while (hb->running) {
        uint16_t interval = hb->interval_sec;
        if (interval == 0) interval = FIM_HEARTBEAT_DEFAULT_SEC;

        struct timespec ts;
        ts.tv_sec = interval;
        ts.tv_nsec = 0;
        nanosleep(&ts, NULL);

        if (!hb->running) break;

        fim_msg_heartbeat_t msg;
        msg.agent_id = hb->cli->agent_id;
        msg.status = FIM_STATUS_HEALTHY;
        msg.timestamp = (uint32_t)time(NULL);

        uint8_t buf[13];
        int len = fim_heartbeat_encode(&msg, buf, sizeof(buf));
        if (len < 0) {
            syslog(LOG_ERR, "fim-hb: 직렬화 실패");
            continue;
        }

        int ret = fim_tcp_send_frame(hb->cli, FIM_MSG_HEARTBEAT, buf, (uint32_t)len);
        if (ret == -2) {
            syslog(LOG_WARNING, "fim-hb: 전송 실패 — 재연결 시도");
            if (fim_tcp_reconnect(hb->cli) < 0) {
                syslog(LOG_ERR, "fim-hb: 재연결 실패 — 서버 종료 판단");
                hb->running = 0;
                break;
            }
        } else if (ret < 0) {
            syslog(LOG_WARNING, "fim-hb: 전송 실패 (재시도 예정)");
        }
    }

    syslog(LOG_INFO, "fim-hb: heartbeat 스레드 종료");
    return NULL;
}
