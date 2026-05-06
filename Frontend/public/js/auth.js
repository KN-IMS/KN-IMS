// Auth flow for IG Console
//
// Mirror Server URL은 빌드 시 박힌 config.js의 IG_CONFIG.backendUrl을 절대 출처로 사용.
// 사용자 측에서 URL을 변경할 수 없음 — 미설정/도달 실패 시 config-error 화면(재시도 버튼).
//
// 상태 머신: load → /auth/status → { setup | login | locked } → success → /index.html
//
// Mirror Server endpoints:
//   GET  /auth/status   → { state: 'unconfigured' | 'configured' | 'locked' }
//   POST /auth/setup    body { pin } → 201 { token }
//   POST /auth/login    body { pin } → 200 { token }

const TOKEN_KEY = 'ig.session.token';

function getBackendURL() {
    return ((window.IG_CONFIG && window.IG_CONFIG.backendUrl) || '').replace(/\/+$/, '');
}

async function authFetch(path, opts = {}) {
    const base = getBackendURL();
    if (!base) throw new Error('backend URL not configured');
    const res = await fetch(base + path, {
        ...opts,
        headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    });
    return res;
}

const Auth = {
    async getStatus() {
        const res = await authFetch('/auth/status');
        if (!res.ok) throw new Error(`status ${res.status}`);
        return res.json();
    },

    async setup(pin) {
        const res = await authFetch('/auth/setup', {
            method: 'POST',
            body: JSON.stringify({ pin }),
        });
        if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            const err = new Error(body.error || `status ${res.status}`);
            err.status = res.status;
            throw err;
        }
        return res.json();
    },

    async login(pin) {
        const res = await authFetch('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ pin }),
        });
        if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            const err = new Error(body.error || `status ${res.status}`);
            err.status = res.status;
            if (res.status === 401) err.code = 'invalid_pin';
            else if (res.status === 423) err.code = 'locked';
            throw err;
        }
        return res.json();
    },
};

const els = {
    title:        document.getElementById('title'),
    subtitle:     document.getElementById('subtitle'),
    form:         document.getElementById('auth-form'),
    pin:          document.getElementById('pin-input'),
    confirmWrap:  document.getElementById('confirm-wrap'),
    confirm:      document.getElementById('pin-confirm'),
    error:        document.getElementById('error-msg'),
    submit:       document.getElementById('submit-btn'),
    locked:       document.getElementById('locked-msg'),
    configError:  document.getElementById('config-error'),
    configErrMsg: document.getElementById('config-error-msg'),
    configRetry:  document.getElementById('config-retry'),
    themeToggle:  document.getElementById('theme-toggle'),
};

let mode = 'login';

function showError(msg) {
    els.error.textContent = msg;
    els.error.classList.remove('hidden');
}

function clearError() {
    els.error.classList.add('hidden');
    els.error.textContent = '';
}

function isValidPin(pin) {
    return /^[0-9]{4,8}$/.test(pin);
}

function hideAllPanels() {
    els.form.classList.add('hidden');
    els.locked.classList.add('hidden');
    els.configError.classList.add('hidden');
}

function showConfigError(msg) {
    hideAllPanels();
    els.title.textContent = 'Connection error';
    els.subtitle.textContent = '';
    els.configErrMsg.textContent = msg;
    els.configError.classList.remove('hidden');
}

function renderMode(state) {
    hideAllPanels();

    if (state === 'locked') {
        els.locked.classList.remove('hidden');
        els.title.textContent = 'Locked';
        els.subtitle.textContent = 'Too many failed attempts.';
        return;
    }

    mode = state === 'unconfigured' ? 'setup' : 'login';

    if (mode === 'setup') {
        els.title.textContent = 'Setup PIN';
        els.subtitle.textContent = 'Choose a PIN for first-time login.';
        els.confirmWrap.classList.remove('hidden');
        els.submit.textContent = 'Create PIN';
    } else {
        els.title.textContent = 'Login';
        els.subtitle.textContent = 'Enter your PIN to continue.';
        els.confirmWrap.classList.add('hidden');
        els.submit.textContent = 'Login';
    }

    els.form.classList.remove('hidden');
    els.pin.focus();
}

async function handleSubmit(e) {
    e.preventDefault();
    clearError();

    const pin = els.pin.value.trim();
    if (!isValidPin(pin)) {
        showError('PIN must be 4-8 digits.');
        return;
    }

    if (mode === 'setup') {
        const confirmPin = els.confirm.value.trim();
        if (pin !== confirmPin) {
            showError('PINs do not match.');
            return;
        }
    }

    els.submit.disabled = true;
    try {
        const res = mode === 'setup'
            ? await Auth.setup(pin)
            : await Auth.login(pin);
        localStorage.setItem(TOKEN_KEY, res.token);
        window.location.href = 'index.html';
    } catch (err) {
        if (err.code === 'invalid_pin') {
            showError('Invalid PIN.');
        } else if (err.code === 'locked') {
            renderMode('locked');
        } else {
            showError(err.message || 'Server error. Try again.');
        }
        els.pin.value = '';
        if (els.confirm) els.confirm.value = '';
        els.pin.focus();
    } finally {
        els.submit.disabled = false;
    }
}

function setupTheme() {
    els.themeToggle.addEventListener('click', () => {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
    });
}

async function loadStatusAndRender() {
    if (!getBackendURL()) {
        showConfigError('Console build is not configured. Contact your administrator.');
        return;
    }

    try {
        const { state } = await Auth.getStatus();
        renderMode(state);
    } catch (err) {
        showConfigError('Cannot reach Mirror Server. Check your network and retry.');
    }
}

async function init() {
    setupTheme();
    els.form.addEventListener('submit', handleSubmit);
    els.configRetry.addEventListener('click', loadStatusAndRender);

    if (localStorage.getItem(TOKEN_KEY)) {
        window.location.href = 'index.html';
        return;
    }

    await loadStatusAndRender();
}

init();
