# Frontend

KN-IG 콘솔(브라우저 + Tauri 데스크톱)의 UI 레이어. 데이터 흐름은 [`architecture.png`](architecture.png) 참고.

## 구성

```
Frontend/
├── public/                 # 정적 자산 — Tauri가 그대로 wrap
│   ├── index.html          # 대시보드 (Agents / Events)
│   ├── login.html          # PIN 로그인
│   ├── config.js           # 빌드별 설정 (Mirror URL 등) — 빌드 직전 수정
│   ├── assets/             # tailwind.css, 브랜드 자산
│   └── js/
│       ├── api.js          # Mirror Server REST 클라이언트 (Bearer + 401 redirect)
│       ├── app.js          # 라우팅·페이징·테마 + 5초 주기 refresh
│       ├── ui.js           # 렌더 헬퍼
│       └── auth.js         # 로그인 상태 머신
├── desktop/                # Tauri 2 데스크톱 셸
├── tailwind.config.js
└── tailwind.input.css
```

## 빌드

사전 요구사항: Node 18+, Rust toolchain, Xcode CLI tools (macOS).

| 작업 | 명령 |
|---|---|
| dev (UI 반복) | `cd desktop && npm run tauri dev` |
| Tailwind watch | `npx tailwindcss -i tailwind.input.css -o public/assets/tailwind.css --watch` |
| 릴리스 (.app/.dmg) | `cd desktop && npm run tauri build` |

산출물 (Apple Silicon 기본):
- `desktop/src-tauri/target/release/bundle/macos/KN-IG Console.app`
- `desktop/src-tauri/target/release/bundle/dmg/KN-IG Console_<v>_aarch64.dmg`

Universal 빌드: `rustup target add x86_64-apple-darwin` 후 `npm run tauri build -- --target universal-apple-darwin`.

### 로컬 설치 / 갱신
처음은 dmg 마운트 → 드래그. 갱신:
```bash
cd desktop && npm run tauri build
osascript -e 'tell application "KN-IG Console" to quit' 2>/dev/null
rm -rf "/Applications/KN-IG Console.app"
cp -R "src-tauri/target/release/bundle/macos/KN-IG Console.app" /Applications/
open "/Applications/KN-IG Console.app"
```

## 빌드별 설정 — `public/config.js`

각 Mirror Server(=고객 사이트)별 설정 단일 출처. UI에서 수정 불가, 빌드 직전 직접 편집.

```js
window.IG_CONFIG = {
    backendUrl: "http://192.168.64.10:8080",  // 그 사이트의 Mirror Server URL
};
```

- 다른 자산보다 먼저 로드되어 `window.IG_CONFIG`로 전역 노출.
- 빈 값/도달 실패 → 콘솔이 `Connection error` 화면 + Retry 버튼.
- 고객별 빌드는 `customer/<name>` 브랜치에서 `backendUrl` 수정 → `npm run tauri build`.

## 인증 & 데이터 흐름

상태 머신: `load → /auth/status → { setup | login | locked | config-error } → /index.html`

| Mirror Server endpoint | 응답 |
|---|---|
| `GET  /auth/status` | `{ state: 'unconfigured' \| 'configured' \| 'locked' }` |
| `POST /auth/setup`  | `{ pin }` → `201 { token }` (최초 1회) |
| `POST /auth/login`  | `{ pin }` → `200 { token }` |

- PIN 4–8자리 숫자, bcrypt 저장.
- 잠금: 10회 연속 실패 → 5분.
- 토큰: `localStorage["ig.session.token"]` → 모든 `/api/*` 호출에 `Authorization: Bearer ...`.
- 401 응답 또는 토큰 부재 → `login.html` 자동 리다이렉트.

대시보드는 5초 주기로 `Api.refresh()` → `/api/agents`, `/api/events?limit=200` 동시 fetch → 캐시 갱신 → 다시 렌더. Backend PascalCase → UI camelCase 정규화는 `normalizeAgent` / `normalizeEvent`. EventType 매핑: `MODIFY/DELETE/CREATE/...` → 과거형 `MODIFIED/DELETED/...`.

## 배포 시 추가 작업

| 항목 | 내용 |
|---|---|
| 코드 서명 | Apple Developer ID + `tauri.conf.json::bundle.macOS.signingIdentity` |
| 공증 | `xcrun notarytool submit` → `xcrun stapler staple` |
| 자동 업데이트 | [Tauri Updater](https://v2.tauri.app/plugin/updater/) — 매니페스트 호스팅 필요 |
| 고객별 URL | `public/config.js::backendUrl` 수정 후 빌드 |
| (향후) mTLS | 콘솔 ↔ Mirror Server 간 클라이언트 인증서 |

미서명 dmg 사내 배포 시 Gatekeeper 회피:
```bash
xattr -d com.apple.quarantine "/Applications/KN-IG Console.app"
```
