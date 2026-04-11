/*
 * grpc_client.c — 서버로 이벤트 전송
 *
 * TODO:
 *   - im-proto 레포의 .proto 정의로 생성된 stub 사용
 *   - im_event_t → protobuf FimEvent 메시지 직렬화
 *   - gRPC 단방향 스트리밍(ReportEvent RPC)으로 서버에 전송
 *   - 연결 실패 시 재시도 / 버퍼링 처리
 */

#include "../realtime/monitor.h"

/* TODO: grpc_client_init() — 채널 및 stub 초기화 */
/* TODO: grpc_client_send() — 이벤트 단건 전송 */
/* TODO: grpc_client_flush() — 버퍼링된 이벤트 일괄 전송 */
/* TODO: grpc_client_cleanup() — 채널 종료 */
