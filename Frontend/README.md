# Frontend

KN-IG 콘솔(브라우저 + Tauri 데스크톱)의 UI 레이어. 전체 데이터 흐름은 [`architecture.png`](architecture.png) 참고.

## 구성

```
Frontend/
├── architecture.png            # 콘솔 ↔ Mirror Server ↔ Backend 데이터 흐름 다이어그램
├── public/                     # 브라우저에서 그대로 서빙되는 정적 자산
│   ├── index.html              # 메인 대시보드 (Agents / Events / Alerts)
│   ├── login.html              # PIN 기반 로그인 페이지
│   ├── assets/                 # 빌드된 tailwind.css 등
│   └── js/
│       ├── api.js              # Mock 데이터 + API 클라이언트
│       ├── app.js              # 대시보드 라우팅/페이징/테마
│       ├── ui.js               # 공통 렌더 헬퍼
│       └── auth.js             # 로그인 페이지 상태 머신
├── desktop/                    # Tauri 2 데스크톱 셸 (별도 README 참고)
├── tailwind.config.js
└── tailwind.input.css
```

## 인증 (`login.html` + `auth.js`)

상태 머신: `loading → { setup | login | locked } → success → /index.html`

- 첫 진입 시 `Auth.getStatus()` 결과로 분기 (`unconfigured`이면 setup, `configured`면 login).
- 현재 백엔드는 모킹된 `MockAuthApi`로, PIN을 `localStorage`에 저장해 setup/login 흐름만 형상 검증.
- 실제 Mirror Server 연동은 `auth.js` 상단의 TODO 블록 참고:
  - `GET  /auth/status`  → `{ state: 'unconfigured' | 'configured' | 'locked' }`
  - `POST /auth/setup`   body: `{ pin }` → `{ token }`
  - `POST /auth/login`   body: `{ pin }` → `{ token }`
- 발급된 토큰은 `localStorage["ig.session.token"]`에 저장되어 이후 콘솔 API 호출에 사용된다.

## Tailwind 빌드

```bash
# Frontend/
npx tailwindcss -i tailwind.input.css -o public/assets/tailwind.css --watch
```

## 데스크톱 셸

`desktop/`은 위 `public/`을 그대로 wrap하는 Tauri 2 프로젝트. 자체 빌드 절차는 `desktop/README.md` 참고.
