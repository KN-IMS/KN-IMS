// Tauri 윈도 사이즈 토글. Rust 측 set_window_login / set_window_main 커맨드를
// invoke로 호출. 브라우저(__TAURI__ 미존재) 환경은 no-op.

const TauriWin = (() => {
    const noop = { setLoginSize: async () => {}, setMainSize: async () => {} };
    const t = (typeof window !== 'undefined') && window.__TAURI__;
    const invoke = t && t.core && t.core.invoke;
    if (!invoke) return noop;

    return {
        async setLoginSize() {
            try { await invoke('set_window_login'); }
            catch (err) { console.error('setLoginSize failed:', err); }
        },
        async setMainSize() {
            try { await invoke('set_window_main'); }
            catch (err) { console.error('setMainSize failed:', err); }
        },
    };
})();
