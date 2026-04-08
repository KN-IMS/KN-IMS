#include "heartbeat.h"
#include "protocol.h"
#include <stdio.h>
#include <time.h>
#include <syslog.h>

void *heartbeat_thread(void *arg)
{
    fim_heartbeat_t *hb = (fim_heartbeat_t *)arg;

    syslog(LOG_INFO, "heartbeat: 스레드 시작 (30초 주기)");

    while (hb->running) {
        /* HEARTBEAT JSON 조립 */
        char json[256];
        snprintf(json, sizeof(json),
            "{\"agent_id\":\"%s\","
            "\"status\":\"online\","
            "\"timestamp\":%ld}",
            hb->agent_id,
            (long)time(NULL));

        if (hb->client->connected) {
            if (fim_send_frame(hb->client->ssl, FIM_MSG_HEARTBEAT, json) < 0) {
                syslog(LOG_WARNING, "heartbeat: 전송 실패 → 재연결 대기");
                hb->client->connected = 0;
                tcp_client_disconnect(hb->client);
                tcp_client_reconnect_loop(hb->client);
            } else {
                syslog(LOG_DEBUG, "heartbeat: 전송 완료");
            }
        }

        /* 30초 대기 (1초씩 나눠서 종료 신호 빠르게 감지) */
        for (int i = 0; i < 30 && hb->running; i++)
            sleep(1);
    }

    syslog(LOG_INFO, "heartbeat: 스레드 종료");
    return NULL;
}
