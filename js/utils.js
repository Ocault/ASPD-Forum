/**
 * Utils - Performance utilities and helper functions
 */

var Utils = (function() {
  'use strict';

  /**
   * Debounce function - limits how often a function can fire
   * @param {Function} func - Function to debounce
   * @param {number} wait - Wait time in ms
   * @param {boolean} immediate - Fire immediately on leading edge
   * @returns {Function} Debounced function
   */
  function debounce(func, wait, immediate) {
    var timeout;
    return function() {
      var context = this;
      var args = arguments;
      var later = function() {
        timeout = null;
        if (!immediate) func.apply(context, args);
      };
      var callNow = immediate && !timeout;
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
      if (callNow) func.apply(context, args);
    };
  }

  /**
   * Throttle function - ensures function fires at most once per interval
   * @param {Function} func - Function to throttle
   * @param {number} limit - Minimum time between calls in ms
   * @returns {Function} Throttled function
   */
  function throttle(func, limit) {
    var inThrottle;
    return function() {
      var context = this;
      var args = arguments;
      if (!inThrottle) {
        func.apply(context, args);
        inThrottle = true;
        setTimeout(function() {
          inThrottle = false;
        }, limit);
      }
    };
  }

  /**
   * Request idle callback polyfill
   */
  var requestIdleCallback = window.requestIdleCallback || function(cb) {
    var start = Date.now();
    return setTimeout(function() {
      cb({
        didTimeout: false,
        timeRemaining: function() {
          return Math.max(0, 50 - (Date.now() - start));
        }
      });
    }, 1);
  };

  /**
   * Cancel idle callback polyfill
   */
  var cancelIdleCallback = window.cancelIdleCallback || function(id) {
    clearTimeout(id);
  };

  /**
   * Escape HTML to prevent XSS
   * @param {string} text - Text to escape
   * @returns {string} Escaped text
   */
  function escapeHtml(text) {
    if (!text) return '';
    var map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, function(m) { return map[m]; });
  }

  /**
   * Format relative time (e.g., "2 hours ago")
   * @param {Date|string} date - Date to format
   * @returns {string} Relative time string
   */
  function relativeTime(date) {
    if (!date) return '';
    var d = date instanceof Date ? date : new Date(date);
    var now = new Date();
    var diff = Math.floor((now - d) / 1000);
    
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    return d.toLocaleDateString();
  }

  /**
   * Local storage wrapper with JSON support and error handling
   */
  var storage = {
    get: function(key, defaultValue) {
      try {
        var item = localStorage.getItem(key);
        return item ? JSON.parse(item) : defaultValue;
      } catch (e) {
        return defaultValue;
      }
    },
    set: function(key, value) {
      try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
      } catch (e) {
        return false;
      }
    },
    remove: function(key) {
      try {
        localStorage.removeItem(key);
        return true;
      } catch (e) {
        return false;
      }
    }
  };

  /**
   * Draft manager for auto-saving form content
   */
  var drafts = {
    STORAGE_KEY: 'aspd_drafts',
    
    get: function(key) {
      var all = storage.get(this.STORAGE_KEY, {});
      var entry = all[key];
      if (entry && typeof entry === 'object' && entry.content) {
        return entry.content;
      }
      return entry || null;
    },
    
    getAll: function() {
      return storage.get(this.STORAGE_KEY, {});
    },
    
    set: function(key, content) {
      var all = storage.get(this.STORAGE_KEY, {});
      all[key] = {
        content: content,
        timestamp: Date.now()
      };
      storage.set(this.STORAGE_KEY, all);
    },
    
    remove: function(key) {
      var all = storage.get(this.STORAGE_KEY, {});
      delete all[key];
      storage.set(this.STORAGE_KEY, all);
    },
    
    clear: function() {
      storage.remove(this.STORAGE_KEY);
    },
    
    // Clean up drafts older than 24 hours
    cleanup: function() {
      var all = storage.get(this.STORAGE_KEY, {});
      var now = Date.now();
      var maxAge = 24 * 60 * 60 * 1000; // 24 hours
      var changed = false;
      
      for (var key in all) {
        if (all.hasOwnProperty(key) && all[key].timestamp) {
          if (now - all[key].timestamp > maxAge) {
            delete all[key];
            changed = true;
          }
        }
      }
      
      if (changed) {
        storage.set(this.STORAGE_KEY, all);
      }
    }
  };

  /**
   * Lazy load images using Intersection Observer
   * @param {string} selector - CSS selector for images
   */
  function lazyLoadImages(selector) {
    selector = selector || 'img[data-src]';
    
    if (!('IntersectionObserver' in window)) {
      // Fallback: load all images immediately
      document.querySelectorAll(selector).forEach(function(img) {
        if (img.dataset.src) {
          img.src = img.dataset.src;
          img.removeAttribute('data-src');
        }
      });
      return;
    }
    
    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting) {
          var img = entry.target;
          if (img.dataset.src) {
            img.src = img.dataset.src;
            img.removeAttribute('data-src');
            img.classList.add('loaded');
          }
          observer.unobserve(img);
        }
      });
    }, {
      rootMargin: '50px 0px',
      threshold: 0.01
    });
    
    document.querySelectorAll(selector).forEach(function(img) {
      observer.observe(img);
    });
    
    return observer;
  }

  /**
   * Lazy load elements (for avatars, etc.)
   * @param {string} selector - CSS selector
   * @param {Function} loadFn - Function to call when element is visible
   */
  function lazyLoad(selector, loadFn) {
    if (!('IntersectionObserver' in window)) {
      document.querySelectorAll(selector).forEach(loadFn);
      return;
    }
    
    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting) {
          loadFn(entry.target);
          observer.unobserve(entry.target);
        }
      });
    }, {
      rootMargin: '100px 0px',
      threshold: 0.01
    });
    
    document.querySelectorAll(selector).forEach(function(el) {
      observer.observe(el);
    });
    
    return observer;
  }

  /**
   * Batch DOM updates using requestAnimationFrame
   * @param {Function} updateFn - Function that performs DOM updates
   */
  function batchUpdate(updateFn) {
    requestAnimationFrame(function() {
      updateFn();
    });
  }

  /**
   * Create document fragment for efficient DOM insertion
   * @param {string} html - HTML string
   * @returns {DocumentFragment} Fragment with parsed HTML
   */
  function createFragment(html) {
    var template = document.createElement('template');
    template.innerHTML = html.trim();
    return template.content;
  }

  /**
   * Copy text to clipboard
   * @param {string} text - Text to copy
   * @returns {Promise} Resolves on success
   */
  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    
    // Fallback for older browsers
    return new Promise(function(resolve, reject) {
      var textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand('copy');
        resolve();
      } catch (e) {
        reject(e);
      } finally {
        document.body.removeChild(textarea);
      }
    });
  }

  /**
   * Initialize @mentions autocomplete on a textarea
   * @param {HTMLTextAreaElement} textarea - The textarea element
   * @param {Function} apiRequest - Function to make API requests (e.g., AuthState.apiRequest)
   */
  function initMentions(textarea, apiRequest) {
    if (!textarea || !apiRequest) return;
    
    var container = textarea.parentElement;
    container.classList.add('mentions-container');
    
    var dropdown = document.createElement('div');
    dropdown.className = 'mentions-dropdown';
    dropdown.setAttribute('role', 'listbox');
    dropdown.setAttribute('aria-label', 'User suggestions');
    container.insertBefore(dropdown, textarea);
    
    var mentionStart = -1;
    var selectedIndex = 0;
    var users = [];
    
    var searchUsers = debounce(function(query) {
      if (query.length < 1) {
        dropdown.classList.remove('active');
        return;
      }
      
      apiRequest('/api/users/autocomplete?q=' + encodeURIComponent(query))
        .then(function(data) {
          if (data.success && data.users.length > 0) {
            users = data.users;
            selectedIndex = 0;
            renderDropdown();
            dropdown.classList.add('active');
          } else {
            dropdown.classList.remove('active');
            users = [];
          }
        })
        .catch(function() {
          dropdown.classList.remove('active');
        });
    }, 150);
    
    function renderDropdown() {
      dropdown.innerHTML = users.map(function(user, index) {
        return '<div class="mention-item' + (index === selectedIndex ? ' selected' : '') + '" data-index="' + index + '" role="option">' +
          '<canvas class="mention-item-avatar" width="24" height="24" data-avatar=\'' + JSON.stringify(user.avatarConfig || {}) + '\'></canvas>' +
          '<span class="mention-item-alias">@' + escapeHtml(user.alias) + '</span>' +
          '<span class="mention-item-hint">TAB to select</span>' +
          '</div>';
      }).join('');
      
      // Render avatars if AvatarRenderer exists
      if (typeof AvatarRenderer !== 'undefined') {
        dropdown.querySelectorAll('[data-avatar]').forEach(function(canvas) {
          try {
            var config = JSON.parse(canvas.dataset.avatar);
            AvatarRenderer.draw(canvas, config);
          } catch (e) {}
        });
      }
    }
    
    function insertMention(user) {
      var value = textarea.value;
      var before = value.substring(0, mentionStart);
      var after = value.substring(textarea.selectionStart);
      textarea.value = before + '@' + user.alias + ' ' + after;
      textarea.focus();
      var cursorPos = mentionStart + user.alias.length + 2;
      textarea.setSelectionRange(cursorPos, cursorPos);
      dropdown.classList.remove('active');
      mentionStart = -1;
      users = [];
    }
    
    textarea.addEventListener('input', function() {
      var value = this.value;
      var cursorPos = this.selectionStart;
      
      // Find @ symbol before cursor
      var textBeforeCursor = value.substring(0, cursorPos);
      var lastAtIndex = textBeforeCursor.lastIndexOf('@');
      
      if (lastAtIndex >= 0) {
        // Check if @ is at start or after whitespace
        var charBefore = lastAtIndex > 0 ? value[lastAtIndex - 1] : ' ';
        if (/\s/.test(charBefore) || lastAtIndex === 0) {
          var query = textBeforeCursor.substring(lastAtIndex + 1);
          // Only search if query doesn't contain spaces
          if (!/\s/.test(query)) {
            mentionStart = lastAtIndex;
            searchUsers(query);
            return;
          }
        }
      }
      
      dropdown.classList.remove('active');
      mentionStart = -1;
    });
    
    textarea.addEventListener('keydown', function(e) {
      if (!dropdown.classList.contains('active')) return;
      
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        selectedIndex = (selectedIndex + 1) % users.length;
        renderDropdown();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        selectedIndex = (selectedIndex - 1 + users.length) % users.length;
        renderDropdown();
      } else if (e.key === 'Tab' || e.key === 'Enter') {
        if (users[selectedIndex]) {
          e.preventDefault();
          insertMention(users[selectedIndex]);
        }
      } else if (e.key === 'Escape') {
        dropdown.classList.remove('active');
        mentionStart = -1;
      }
    });
    
    dropdown.addEventListener('click', function(e) {
      var item = e.target.closest('.mention-item');
      if (item) {
        var index = parseInt(item.dataset.index);
        if (users[index]) {
          insertMention(users[index]);
        }
      }
    });
    
    // Close on blur (with delay for click to register)
    textarea.addEventListener('blur', function() {
      setTimeout(function() {
        dropdown.classList.remove('active');
      }, 200);
    });
  }

  // Clean up old drafts on load
  requestIdleCallback(function() {
    drafts.cleanup();
  });

  return {
    debounce: debounce,
    throttle: throttle,
    requestIdleCallback: requestIdleCallback,
    cancelIdleCallback: cancelIdleCallback,
    escapeHtml: escapeHtml,
    relativeTime: relativeTime,
    storage: storage,
    drafts: drafts,
    lazyLoadImages: lazyLoadImages,
    lazyLoad: lazyLoad,
    batchUpdate: batchUpdate,
    createFragment: createFragment,
    copyToClipboard: copyToClipboard,
    initMentions: initMentions
  };

})();

// Export for module systems if available
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Utils;
}
