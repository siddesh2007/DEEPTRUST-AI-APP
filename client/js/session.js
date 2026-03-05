/**
 * session.js
 * Secure session module for token lifecycle control.
 *
 * Security design notes:
 * - Keeps auth material in browser storage with optional persistence when remember-me is enabled.
 * - Decodes JWT exp and enforces proactive auto-logout.
 * - Exposes minimal API and avoids leaking implementation details globally.
 * - Emits typed auth events so UI can respond without tight coupling.
 */

const SESSION_TOKEN_KEY = 'dt_admin_token';
const SESSION_EXP_KEY = 'dt_admin_token_exp';
const SESSION_STORAGE_MODE_KEY = 'dt_admin_token_storage';
const SESSION_IDLE_TIMEOUT_MS = 15 * 60 * 1000;

const authEvents = new EventTarget();
let expiryTimerId = null;
let idleTimerId = null;

const storageProviders = {
    session: sessionStorage,
    local: localStorage
};

const getStorageMode = () => {
    const mode = localStorage.getItem(SESSION_STORAGE_MODE_KEY) || sessionStorage.getItem(SESSION_STORAGE_MODE_KEY);
    return mode === 'local' ? 'local' : 'session';
};

const getActiveStorage = () => storageProviders[getStorageMode()];

const clearStoredToken = () => {
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
    sessionStorage.removeItem(SESSION_EXP_KEY);
    sessionStorage.removeItem(SESSION_STORAGE_MODE_KEY);

    localStorage.removeItem(SESSION_TOKEN_KEY);
    localStorage.removeItem(SESSION_EXP_KEY);
    localStorage.removeItem(SESSION_STORAGE_MODE_KEY);
};

const decodeJwtPayload = (token) => {
    try {
        const payloadSegment = token.split('.')[1];
        if (!payloadSegment) {
            return null;
        }

        const base64 = payloadSegment.replace(/-/g, '+').replace(/_/g, '/');
        const json = decodeURIComponent(
            atob(base64)
                .split('')
                .map((char) => `%${`00${char.charCodeAt(0).toString(16)}`.slice(-2)}`)
                .join('')
        );
        return JSON.parse(json);
    } catch {
        return null;
    }
};

const clearTimers = () => {
    if (expiryTimerId) {
        clearTimeout(expiryTimerId);
        expiryTimerId = null;
    }

    if (idleTimerId) {
        clearTimeout(idleTimerId);
        idleTimerId = null;
    }
};

const scheduleExpiryLogout = () => {
    const expMs = Number(getActiveStorage().getItem(SESSION_EXP_KEY) || 0);
    if (!expMs) {
        return;
    }

    const delay = expMs - Date.now();
    if (delay <= 0) {
        clearSession('expired');
        return;
    }

    expiryTimerId = setTimeout(() => {
        clearSession('expired');
    }, delay);
};

const scheduleIdleLogout = () => {
    if (idleTimerId) {
        clearTimeout(idleTimerId);
    }

    idleTimerId = setTimeout(() => {
        clearSession('idle-timeout');
    }, SESSION_IDLE_TIMEOUT_MS);
};

export const setSessionToken = (token, options = {}) => {
    if (!token || typeof token !== 'string') {
        throw new Error('Invalid auth token');
    }

    const payload = decodeJwtPayload(token);
    const expMs = payload?.exp ? payload.exp * 1000 : Date.now() + 10 * 60 * 1000;
    const persistent = Boolean(options?.persistent);
    const mode = persistent ? 'local' : 'session';
    const storage = persistent ? localStorage : sessionStorage;

    clearStoredToken();
    storage.setItem(SESSION_TOKEN_KEY, token);
    storage.setItem(SESSION_EXP_KEY, String(expMs));
    storage.setItem(SESSION_STORAGE_MODE_KEY, mode);
    localStorage.setItem(SESSION_STORAGE_MODE_KEY, mode);

    clearTimers();
    scheduleExpiryLogout();
    scheduleIdleLogout();

    authEvents.dispatchEvent(new CustomEvent('auth:login', { detail: { expMs, persistent } }));
};

export const getSessionToken = () => {
    const storage = getActiveStorage();
    const token = storage.getItem(SESSION_TOKEN_KEY);
    const expMs = Number(storage.getItem(SESSION_EXP_KEY) || 0);

    if (!token || !expMs || Date.now() >= expMs) {
        clearSession('expired');
        return null;
    }

    return token;
};

export const getAuthorizationHeader = () => {
    const token = getSessionToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
};

export const refreshSessionActivity = () => {
    if (getSessionToken()) {
        scheduleIdleLogout();
    }
};

export const clearSession = (reason = 'manual-logout') => {
    clearStoredToken();
    clearTimers();
    authEvents.dispatchEvent(new CustomEvent('auth:logout', { detail: { reason } }));
};

export const requireValidSession = () => {
    const token = getSessionToken();
    if (!token) {
        return false;
    }

    scheduleIdleLogout();
    return true;
};

export const onAuthEvent = (eventName, handler) => {
    authEvents.addEventListener(eventName, handler);
    return () => authEvents.removeEventListener(eventName, handler);
};
