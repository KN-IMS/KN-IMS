// Per-build configuration. Edit before building for a specific customer / Mirror Server.
//   backendUrl  Mirror Server HTTP URL (예: http://192.168.64.10:8080)
//               빌드의 절대 출처 — 빈 값이거나 도달 실패 시 콘솔이 connection-error 화면을 표시.
//
// 향후 customer 이름·branding·locale 등 빌드별 설정도 이 객체에 추가.

window.IG_CONFIG = {
    backendUrl: "http://192.168.64.10:8080",
};
