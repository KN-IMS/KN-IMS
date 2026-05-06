// Auth flow for IG Console
// State machine: loading -> { setup | login | locked } -> success -> redirect to index.html
//
// Backend integration (TODO): replace MockAuthApi with real Mirror Server calls.
//   GET  /auth/status   -> { state: 'unconfigured' | 'configured' | 'locked' }
//   POST /auth/setup    -> { token } body: { pin }
//   POST /auth/login    -> { token } body: { pin }

const TOKEN_KEY = 'ig.session.token';
const MOCK_PIN_KEY = 'ig.mock.pin';

const MockAuthApi = {
    async getStatus() {
        await delay(150);
        const stored = localStorage.getItem(MOCK_PIN_KEY);
        return { state: stored ? 'configured' : 'unconfigured' };
    },

    async setup(pin) {
        await delay(200);
        localStorage.setItem(MOCK_PIN_KEY, pin);
        return { token: 'mock-token-' + Date.now() };
    },

    async login(pin) {
        await delay(200);
        const stored = localStorage.getItem(MOCK_PIN_KEY);
        if (stored !== pin) {
            const err = new Error('Invalid PIN');
            err.code = 'invalid_pin';
            throw err;
        }
        return { token: 'mock-token-' + Date.now() };
    },
};

const Auth = MockAuthApi;

const els = {
    title: document.getElementById('title'),
    subtitle: document.getElementById('subtitle'),
    form: document.getElementById('auth-form'),
    pin: document.getElementById('pin-input'),
    confirmWrap: document.getElementById('confirm-wrap'),
    confirm: document.getElementById('pin-confirm'),
    error: document.getElementById('error-msg'),
    submit: document.getElementById('submit-btn'),
    locked: document.getElementById('locked-msg'),
    serverInfo: document.getElementById('server-info'),
    themeToggle: document.getElementById('theme-toggle'),
};

let mode = 'login';

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

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

function renderMode(state) {
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
        const confirm = els.confirm.value.trim();
        if (pin !== confirm) {
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
        } else {
            showError('Server error. Try again.');
        }
        els.pin.value = '';
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

async function init() {
    setupTheme();
    els.form.addEventListener('submit', handleSubmit);

    if (localStorage.getItem(TOKEN_KEY)) {
        window.location.href = 'index.html';
        return;
    }

    try {
        const { state } = await Auth.getStatus();
        renderMode(state);
        els.serverInfo.textContent = 'Connected';
    } catch (err) {
        els.title.textContent = 'Connection error';
        els.subtitle.textContent = 'Could not reach server.';
        els.serverInfo.textContent = 'Disconnected';
    }
}

init();
