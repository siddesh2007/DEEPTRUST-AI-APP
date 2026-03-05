/**
 * dashboardGuard.js
 * Dashboard route protection and secure logout handler.
 *
 * Security design notes:
 * - Prevents direct dashboard access without a valid session token.
 * - Subscribes to auth expiry/logout events for immediate redirect.
 * - Refreshes inactivity timeout on user actions.
 */

import {
    requireValidSession,
    clearSession,
    refreshSessionActivity,
    onAuthEvent
} from './session.js';

const redirectToLogin = () => {
    window.location.replace('login.html');
};

const enforceDashboardAccess = () => {
    if (!requireValidSession()) {
        redirectToLogin();
        return false;
    }

    return true;
};

const bindLogoutButton = () => {
    const logoutButton = document.getElementById('logoutBtn');
    if (!logoutButton) {
        return;
    }

    logoutButton.addEventListener('click', () => {
        clearSession('manual-logout');
    });
};

const bindActivityRefresh = () => {
    ['click', 'keypress', 'mousemove', 'scroll'].forEach((eventName) => {
        document.addEventListener(eventName, () => {
            refreshSessionActivity();
        }, { passive: true });
    });
};

if (enforceDashboardAccess()) {
    bindLogoutButton();
    bindActivityRefresh();
}

onAuthEvent('auth:logout', () => {
    redirectToLogin();
});
