/**
 * ============================================================
 * session.js — JWT Session Management
 * ============================================================
 * Responsibilities:
 *   - Store JWT token securely using sessionStorage
 *     (sessionStorage is cleared when the browser tab closes,
 *      unlike localStorage which persists indefinitely)
 *   - Provide helpers to read, check, and clear the session
 *   - Guard the dashboard by redirecting unauthenticated users
 *
 * Security notes:
 *   - Storing JWTs in sessionStorage protects against XSS
 *     persistence, but you MUST still sanitize all DOM inputs.
 *   - In high-security systems, prefer HttpOnly cookies —
 *     the server sets them and JS can't read them at all.
 * ============================================================
 */

const Session = (() => {

  // ── Storage keys ───────────────────────────────────────────
  const KEYS = {
    token:     'admin_jwt_token',
    user:      'admin_user_info',
    loginTime: 'admin_login_time',
  };

  // Session expiry: auto-logout after this many minutes of inactivity
  const SESSION_TIMEOUT_MINUTES = 30;

  // ── Save session ───────────────────────────────────────────

  /**
   * save()
   * Persists the JWT and user info after a successful login.
   *
   * @param {string} token - JWT string from the backend
   * @param {object} [user] - optional user metadata { id, role, ... }
   */
  function save(token, user = {}) {
    if (!token) {
      console.error('[Session] Cannot save: token is empty.');
      return;
    }

    sessionStorage.setItem(KEYS.token,     token);
    sessionStorage.setItem(KEYS.user,      JSON.stringify(user));
    sessionStorage.setItem(KEYS.loginTime, Date.now().toString());

    console.log('[Session] ✅ Session saved successfully.');
  }

  // ── Read session ───────────────────────────────────────────

  /**
   * getToken()
   * Returns the stored JWT, or null if not logged in.
   *
   * @returns {string|null}
   */
  function getToken() {
    return sessionStorage.getItem(KEYS.token);
  }

  /**
   * getUser()
   * Returns the stored user object, or null.
   *
   * @returns {object|null}
   */
  function getUser() {
    const raw = sessionStorage.getItem(KEYS.user);
    try {
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  /**
   * getLoginTime()
   * Returns the timestamp (ms) when the session was created, or null.
   *
   * @returns {number|null}
   */
  function getLoginTime() {
    const raw = sessionStorage.getItem(KEYS.loginTime);
    return raw ? parseInt(raw, 10) : null;
  }

  // ── Check session ──────────────────────────────────────────

  /**
   * isActive()
   * Returns true only if a token exists AND the session hasn't expired.
   *
   * @returns {boolean}
   */
  function isActive() {
    const token     = getToken();
    const loginTime = getLoginTime();

    if (!token || !loginTime) return false;

    const elapsed = (Date.now() - loginTime) / 1000 / 60; // minutes
    if (elapsed > SESSION_TIMEOUT_MINUTES) {
      console.warn('[Session] Session expired after inactivity. Clearing.');
      clear();
      return false;
    }

    return true;
  }

  /**
   * refreshActivity()
   * Resets the login timestamp to "now", effectively extending the session.
   * Call this on meaningful user interactions in the dashboard.
   */
  function refreshActivity() {
    if (getToken()) {
      sessionStorage.setItem(KEYS.loginTime, Date.now().toString());
    }
  }

  // ── Clear session ──────────────────────────────────────────

  /**
   * clear()
   * Removes all session data (logout).
   */
  function clear() {
    sessionStorage.removeItem(KEYS.token);
    sessionStorage.removeItem(KEYS.user);
    sessionStorage.removeItem(KEYS.loginTime);
    console.log('[Session] Session cleared.');
  }

  // ── Route guards ───────────────────────────────────────────

  /**
   * requireAuth()
   * Call this at the TOP of dashboard.html's <script>.
   * Redirects to the login page if the user isn't authenticated.
   *
   * Usage in dashboard.html:
   *   <script src="js/session.js"></script>
   *   <script>Session.requireAuth();</script>
   *
   * @param {string} [loginPath='/index.html']
   */
  function requireAuth(loginPath = '/index.html') {
    if (!isActive()) {
      console.warn('[Session] Unauthenticated access attempt. Redirecting…');
      window.location.replace(loginPath);
    }
  }

  /**
   * redirectIfAuthenticated()
   * Call this at the TOP of login.html's <script>.
   * Prevents already-logged-in users from seeing the login page again.
   *
   * @param {string} [dashboardPath='/dashboard.html']
   */
  function redirectIfAuthenticated(dashboardPath = '/dashboard.html') {
    if (isActive()) {
      console.log('[Session] Already authenticated. Redirecting to dashboard…');
      window.location.replace(dashboardPath);
    }
  }

  /**
   * logout()
   * Clears session and sends user back to login.
   *
   * @param {string} [loginPath='/index.html']
   */
  function logout(loginPath = '/index.html') {
    clear();
    window.location.replace(loginPath);
  }

  // ── Public interface ───────────────────────────────────────
  return {
    save,
    getToken,
    getUser,
    isActive,
    refreshActivity,
    clear,
    requireAuth,
    redirectIfAuthenticated,
    logout,
  };

})();
