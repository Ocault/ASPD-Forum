/**
 * Notifications System
 * Handles notification fetching, display, and management
 */

const NotificationSystem = (function() {
  'use strict';

  let isDropdownOpen = false;
  let dropdownElement = null;

  /**
   * Fetch unread notification count
   */
  function fetchUnreadCount() {
    return AuthState.apiRequest('/api/notifications/unread-count')
      .then(function(data) {
        if (data.success) {
          updateBadge(data.count);
        }
        return data.count || 0;
      })
      .catch(function() {
        return 0;
      });
  }

  /**
   * Update notification badge
   */
  function updateBadge(count) {
    var badge = document.getElementById('notif-badge');
    if (badge) {
      if (count > 0) {
        badge.textContent = count > 99 ? '99+' : count;
        badge.style.display = 'inline';
      } else {
        badge.style.display = 'none';
      }
    }
  }

  /**
   * Fetch notifications
   */
  function fetchNotifications(page) {
    page = page || 1;
    return AuthState.apiRequest('/api/notifications?page=' + page)
      .then(function(data) {
        if (data.success) {
          return data;
        }
        return { notifications: [], unreadCount: 0 };
      })
      .catch(function() {
        return { notifications: [], unreadCount: 0 };
      });
  }

  /**
   * Mark notification as read
   */
  function markAsRead(notificationId) {
    return AuthState.apiRequest('/api/notifications/' + notificationId + '/read', {
      method: 'PUT'
    });
  }

  /**
   * Mark all as read
   */
  function markAllAsRead() {
    return AuthState.apiRequest('/api/notifications/read-all', {
      method: 'PUT'
    }).then(function() {
      updateBadge(0);
    });
  }

  /**
   * Create dropdown HTML
   */
  function createDropdown(notifications) {
    var html = '<div class="notif-dropdown">';
    html += '<div class="notif-header"><span>NOTIFICATIONS</span>';
    if (notifications.length > 0) {
      html += '<button class="notif-mark-all" id="mark-all-read">MARK ALL READ</button>';
    }
    html += '</div>';
    html += '<div class="notif-list">';
    
    if (notifications.length === 0) {
      html += '<div class="notif-empty">NO NOTIFICATIONS</div>';
    } else {
      notifications.forEach(function(notif) {
        var readClass = notif.is_read ? 'notif-item--read' : '';
        var timeAgo = formatTimeAgo(new Date(notif.created_at));
        
        html += '<a href="' + (notif.link || '#') + '" class="notif-item ' + readClass + '" data-notif-id="' + notif.id + '">';
        html += '<div class="notif-item-title">' + escapeHtml(notif.title) + '</div>';
        if (notif.message) {
          html += '<div class="notif-item-message">' + escapeHtml(notif.message) + '</div>';
        }
        html += '<div class="notif-item-time">' + timeAgo + '</div>';
        html += '</a>';
      });
    }
    
    html += '</div></div>';
    return html;
  }

  /**
   * Format time ago
   */
  function formatTimeAgo(date) {
    var seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return 'JUST NOW';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'M AGO';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'H AGO';
    if (seconds < 604800) return Math.floor(seconds / 86400) + 'D AGO';
    return Math.floor(seconds / 604800) + 'W AGO';
  }

  /**
   * Escape HTML
   */
  function escapeHtml(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Show dropdown
   */
  function showDropdown() {
    if (isDropdownOpen) {
      hideDropdown();
      return;
    }

    fetchNotifications().then(function(data) {
      var bell = document.getElementById('notif-bell');
      if (!bell) return;

      // Remove existing dropdown
      hideDropdown();

      // Create dropdown
      var wrapper = document.createElement('div');
      wrapper.innerHTML = createDropdown(data.notifications || []);
      dropdownElement = wrapper.firstChild;
      
      // Position dropdown
      bell.parentNode.style.position = 'relative';
      bell.parentNode.appendChild(dropdownElement);
      
      isDropdownOpen = true;

      // Bind mark all read
      var markAllBtn = dropdownElement.querySelector('#mark-all-read');
      if (markAllBtn) {
        markAllBtn.addEventListener('click', function(e) {
          e.preventDefault();
          e.stopPropagation();
          markAllAsRead().then(function() {
            dropdownElement.querySelectorAll('.notif-item').forEach(function(item) {
              item.classList.add('notif-item--read');
            });
          });
        });
      }

      // Bind notification clicks
      dropdownElement.querySelectorAll('.notif-item').forEach(function(item) {
        item.addEventListener('click', function() {
          var notifId = item.dataset.notifId;
          if (notifId && !item.classList.contains('notif-item--read')) {
            markAsRead(notifId);
          }
        });
      });

      // Close on outside click
      setTimeout(function() {
        document.addEventListener('click', handleOutsideClick);
      }, 0);
    });
  }

  /**
   * Hide dropdown
   */
  function hideDropdown() {
    if (dropdownElement && dropdownElement.parentNode) {
      dropdownElement.parentNode.removeChild(dropdownElement);
    }
    dropdownElement = null;
    isDropdownOpen = false;
    document.removeEventListener('click', handleOutsideClick);
  }

  /**
   * Handle outside click
   */
  function handleOutsideClick(e) {
    if (dropdownElement && !dropdownElement.contains(e.target) && e.target.id !== 'notif-bell' && !e.target.closest('#notif-bell')) {
      hideDropdown();
    }
  }

  /**
   * Initialize notifications
   */
  function init() {
    // Fetch initial count
    fetchUnreadCount();

    // Bind bell click
    var bell = document.getElementById('notif-bell');
    if (bell) {
      bell.addEventListener('click', function(e) {
        e.preventDefault();
        showDropdown();
      });
    }

    // Poll for new notifications every 60 seconds (fallback if WebSocket disconnected)
    setInterval(function() {
      // Only poll if WebSocket is not connected
      if (typeof ForumWS === 'undefined' || !ForumWS.isConnected()) {
        fetchUnreadCount();
      }
    }, 60000);
    
    // Listen for WebSocket notifications
    if (typeof ForumWS !== 'undefined') {
      ForumWS.on('notification', function(notification) {
        // Increment badge count
        var badge = document.getElementById('notif-badge');
        if (badge) {
          var current = parseInt(badge.textContent) || 0;
          updateBadge(current + 1);
        }
        
        // Show toast notification
        if (typeof Notify !== 'undefined') {
          Notify.show(notification.title, 'info');
        }
        
        // If dropdown is open, refresh it
        if (isDropdownOpen) {
          fetchNotifications();
        }
      });
    }
  }

  return {
    init: init,
    fetchUnreadCount: fetchUnreadCount,
    fetchNotifications: fetchNotifications,
    markAsRead: markAsRead,
    markAllAsRead: markAllAsRead,
    updateBadge: updateBadge
  };

})();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function() {
    if (typeof AuthState !== 'undefined' && AuthState.hasToken()) {
      NotificationSystem.init();
    }
  });
} else {
  if (typeof AuthState !== 'undefined' && AuthState.hasToken()) {
    NotificationSystem.init();
  }
}
