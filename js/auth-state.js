/**
 * Auth State - Frontend-only authentication state handling
 * Uses localStorage for state persistence
 */

var AuthState = (function() {
  'use strict';

  var STORAGE_KEY = 'aspd_auth';
  var TOKEN_KEY = 'authToken';
  var REFRESH_TOKEN_KEY = 'authRefreshToken';
  
  // Auto-detect API base: use current origin in production, localhost for dev
  var API_BASE = window.location.hostname === 'localhost' 
    ? 'http://localhost:3001' 
    : window.location.origin;

  /**
   * Validate state object structure
   * @param {Object} state - State to validate
   * @returns {boolean} True if valid
   */
  function isValidState(state) {
    if (!state || typeof state !== 'object') return false;
    if (typeof state.authenticated !== 'boolean') return false;
    if (state.authenticated && typeof state.alias !== 'string') return false;
    if (typeof state.avatarSet !== 'boolean') return false;
    return true;
  }

  /**
   * Get current auth state
   * @returns {Object} Auth state object
   */
  function get() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        var parsed = JSON.parse(saved);
        if (isValidState(parsed)) {
          return parsed;
        }
      }
    } catch (e) {}
    return {
      authenticated: false,
      alias: null,
      avatarSet: false
    };
  }

  /**
   * Set auth state
   * @param {Object} state - State object to merge
   */
  function set(state) {
    try {
      var current = get();
      var updated = Object.assign({}, current, state);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch (e) {}
  }

  /**
   * Clear auth state (logout)
   */
  function clear() {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (e) {}
  }

  /**
   * Check if user is authenticated
   * @returns {boolean}
   */
  function isAuthenticated() {
    var state = get();
    return state.authenticated === true;
  }

  /**
   * Check if avatar is set
   * @returns {boolean}
   */
  function hasAvatar() {
    var state = get();
    return state.avatarSet === true;
  }

  /**
   * Get current alias
   * @returns {string|null}
   */
  function getAlias() {
    var state = get();
    return state.alias || null;
  }

  /**
   * Check if user is admin
   * @returns {boolean}
   */
  function isAdmin() {
    var state = get();
    return state.isAdmin === true;
  }

  /**
   * Login - set authenticated state
   * @param {string} alias - User alias
   * @param {boolean} isAdmin - Whether user is admin
   */
  function login(alias, isAdmin) {
    set({
      authenticated: true,
      alias: alias,
      avatarSet: true, // Assume existing users have avatar
      isAdmin: isAdmin || false
    });
  }

  /**
   * Register - set authenticated but avatar not set
   * @param {string} alias - User alias
   */
  function register(alias) {
    set({
      authenticated: true,
      alias: alias,
      avatarSet: false
    });
  }

  /**
   * Mark avatar as set
   */
  function setAvatar() {
    set({ avatarSet: true });
  }

  /**
   * Require authentication - redirect if not authenticated
   * @param {string} redirectUrl - URL to redirect to (default: login.html)
   * @returns {boolean} True if authenticated
   */
  function requireAuth(redirectUrl) {
    redirectUrl = redirectUrl || 'login.html';
    if (!isAuthenticated()) {
      window.location.href = redirectUrl;
      return false;
    }
    return true;
  }

  /**
   * Require avatar - redirect if avatar not set
   * @param {string} redirectUrl - URL to redirect to (default: avatar.html)
   * @returns {boolean} True if avatar is set
   */
  function requireAvatar(redirectUrl) {
    redirectUrl = redirectUrl || 'avatar.html';
    if (!hasAvatar()) {
      window.location.href = redirectUrl;
      return false;
    }
    return true;
  }

  /**
   * Gate protected pages - check JWT, auth state, and avatar
   * @returns {boolean} True if access granted
   */
  function gateProtected() {
    if (!hasToken()) {
      window.location.href = 'login.html?notify=' + encodeURIComponent('UNAUTHORIZED') + '&notify_type=warn';
      return false;
    }
    if (!requireAuth()) return false;
    if (!requireAvatar()) return false;
    return true;
  }

  /**
   * Logout - clear state and redirect
   * @param {string} redirectUrl - URL to redirect to (default: index.html)
   */
  function logout(redirectUrl) {
    redirectUrl = redirectUrl || 'index.html';
    clear();
    clearToken();
    window.location.href = redirectUrl;
  }

  /**
   * Get stored JWT token
   * @returns {string|null}
   */
  function getToken() {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch (e) {
      return null;
    }
  }

  /**
   * Set JWT token
   * @param {string} token
   */
  function setToken(token) {
    try {
      localStorage.setItem(TOKEN_KEY, token);
    } catch (e) {}
  }

  /**
   * Clear JWT token
   */
  function clearToken() {
    try {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(REFRESH_TOKEN_KEY);
    } catch (e) {}
  }

  /**
   * Get stored refresh token
   * @returns {string|null}
   */
  function getRefreshToken() {
    try {
      return localStorage.getItem(REFRESH_TOKEN_KEY);
    } catch (e) {
      return null;
    }
  }

  /**
   * Set refresh token
   * @param {string} token
   */
  function setRefreshToken(token) {
    try {
      localStorage.setItem(REFRESH_TOKEN_KEY, token);
    } catch (e) {}
  }

  /**
   * Refresh the access token using refresh token
   * @returns {Promise<boolean>} True if refresh successful
   */
  var isRefreshing = false;
  var refreshPromise = null;
  
  function refreshAccessToken() {
    if (isRefreshing) return refreshPromise;
    
    var refreshToken = getRefreshToken();
    if (!refreshToken) return Promise.resolve(false);
    
    isRefreshing = true;
    refreshPromise = fetch(API_BASE + '/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: refreshToken })
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      isRefreshing = false;
      if (data.success && data.token) {
        setToken(data.token);
        return true;
      }
      return false;
    })
    .catch(function() {
      isRefreshing = false;
      return false;
    });
    
    return refreshPromise;
  }

  /**
   * Check if token exists
   * @returns {boolean}
   */
  function hasToken() {
    return !!getToken();
  }

  /**
   * Get authorization headers for API calls
   * @returns {Object}
   */
  function getAuthHeaders() {
    var token = getToken();
    if (!token) return {};
    return {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'
    };
  }

  /**
   * Make authenticated API request with automatic token refresh
   * @param {string} endpoint - API endpoint
   * @param {Object} options - Fetch options
   * @returns {Promise}
   */
  function apiRequest(endpoint, options) {
    options = options || {};
    options.headers = Object.assign({}, getAuthHeaders(), options.headers || {});
    
    return fetch(API_BASE + endpoint, options)
      .then(function(res) {
        if (res.status === 401) {
          // Try to refresh the token
          return refreshAccessToken().then(function(refreshed) {
            if (refreshed) {
              // Retry the request with new token
              options.headers = Object.assign({}, getAuthHeaders(), options.headers || {});
              return fetch(API_BASE + endpoint, options).then(function(retryRes) {
                if (retryRes.status === 401) {
                  logout();
                  return Promise.reject(new Error('unauthorized'));
                }
                return retryRes.json();
              });
            } else {
              logout();
              return Promise.reject(new Error('unauthorized'));
            }
          });
        }
        return res.json();
      });
  }

  /**
   * Send heartbeat to update last_seen_at
   * Called every 60 seconds when user is active
   */
  var heartbeatInterval = null;
  
  function startHeartbeat() {
    if (heartbeatInterval) return;
    
    // Send initial heartbeat
    sendHeartbeat();
    
    // Send heartbeat every 60 seconds
    heartbeatInterval = setInterval(sendHeartbeat, 60000);
  }
  
  function sendHeartbeat() {
    if (!hasToken()) return;
    fetch(API_BASE + '/api/my/heartbeat', {
      method: 'POST',
      headers: getAuthHeaders()
    }).catch(function() {});
  }
  
  function stopHeartbeat() {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
      heartbeatInterval = null;
    }
  }
  
  // Auto-start heartbeat if authenticated
  if (hasToken()) {
    startHeartbeat();
  }

  return {
    get: get,
    set: set,
    clear: clear,
    isAuthenticated: isAuthenticated,
    hasAvatar: hasAvatar,
    getAlias: getAlias,
    isAdmin: isAdmin,
    login: login,
    register: register,
    setAvatar: setAvatar,
    requireAuth: requireAuth,
    requireAvatar: requireAvatar,
    gateProtected: gateProtected,
    logout: logout,
    getToken: getToken,
    setToken: setToken,
    clearToken: clearToken,
    hasToken: hasToken,
    getAuthHeaders: getAuthHeaders,
    apiRequest: apiRequest,
    startHeartbeat: startHeartbeat,
    stopHeartbeat: stopHeartbeat,
    getRefreshToken: getRefreshToken,
    setRefreshToken: setRefreshToken,
    refreshAccessToken: refreshAccessToken,
    API_BASE: API_BASE
  };

})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = AuthState;
}
