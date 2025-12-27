/**
 * Notify - Minimal system notification utility
 * Frontend-only, no backend integration
 */

var Notify = (function() {
  'use strict';

  var CONTAINER_ID = 'sys-notify';
  var DEFAULT_DURATION = 3000;

  /**
   * Get or create notification container
   */
  function getContainer() {
    var container = document.getElementById(CONTAINER_ID);
    if (!container) {
      container = document.createElement('div');
      container.id = CONTAINER_ID;
      container.className = 'sys-notify-container';
      document.body.appendChild(container);
    }
    return container;
  }

  /**
   * Show a notification
   * @param {string} message - Notification text
   * @param {Object} options - Optional settings
   * @param {number} options.duration - Auto-dismiss time in ms (0 = no auto-dismiss)
   * @param {string} options.type - Notification type: 'info', 'warn', 'error'
   */
  function show(message, options) {
    options = options || {};
    var duration = options.duration !== undefined ? options.duration : DEFAULT_DURATION;
    var type = options.type || 'info';

    var container = getContainer();

    var el = document.createElement('div');
    el.className = 'sys-notify sys-notify-' + type;
    el.textContent = '> ' + message;

    container.appendChild(el);

    if (duration > 0) {
      setTimeout(function() {
        if (el.parentNode) {
          el.parentNode.removeChild(el);
        }
      }, duration);
    }

    return el;
  }

  /**
   * Show info notification
   */
  function info(message, duration) {
    return show(message, { type: 'info', duration: duration });
  }

  /**
   * Show warning notification
   */
  function warn(message, duration) {
    return show(message, { type: 'warn', duration: duration });
  }

  /**
   * Show error notification
   */
  function error(message, duration) {
    return show(message, { type: 'error', duration: duration });
  }

  /**
   * Check URL for notification parameter and display
   */
  function checkUrlNotify() {
    var params = new URLSearchParams(window.location.search);
    var msg = params.get('notify');
    var type = params.get('notify_type') || 'info';
    if (msg) {
      show(decodeURIComponent(msg), { type: type });
      // Clean URL
      params.delete('notify');
      params.delete('notify_type');
      var newUrl = window.location.pathname;
      if (params.toString()) {
        newUrl += '?' + params.toString();
      }
      window.history.replaceState({}, '', newUrl);
    }
  }

  return {
    show: show,
    info: info,
    warn: warn,
    error: error,
    checkUrlNotify: checkUrlNotify
  };

})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Notify;
}
