/**
 * WebSocket Client for ASPD Forum
 * Real-time notifications, online status, and live updates
 */
(function() {
  'use strict';

  var ws = null;
  var reconnectAttempts = 0;
  var maxReconnectAttempts = 5;
  var reconnectDelay = 1000; // Start with 1 second
  var heartbeatInterval = null;
  var subscribers = {};

  // Determine WebSocket URL - connect to Railway backend
  function getWsUrl() {
    var wsBase = window.location.hostname === 'localhost'
      ? 'ws://localhost:3001'
      : 'wss://aspd-forum-production.up.railway.app';
    var token = localStorage.getItem('authToken');
    return wsBase + '/ws' + (token ? '?token=' + encodeURIComponent(token) : '');
  }

  // Connect to WebSocket server
  function connect() {
    if (ws && ws.readyState === WebSocket.OPEN) {
      return; // Already connected
    }

    try {
      ws = new WebSocket(getWsUrl());

      ws.onopen = function() {
        console.log('[WS] Connected');
        reconnectAttempts = 0;
        reconnectDelay = 1000;
        
        // Start heartbeat
        startHeartbeat();
        
        // Notify subscribers
        emit('connected', {});
      };

      ws.onmessage = function(event) {
        try {
          var message = JSON.parse(event.data);
          handleMessage(message);
        } catch (err) {
          console.error('[WS] Invalid message:', err);
        }
      };

      ws.onclose = function(event) {
        console.log('[WS] Disconnected:', event.code, event.reason);
        stopHeartbeat();
        emit('disconnected', { code: event.code, reason: event.reason });
        
        // Attempt to reconnect
        if (reconnectAttempts < maxReconnectAttempts) {
          reconnectAttempts++;
          console.log('[WS] Reconnecting in ' + reconnectDelay + 'ms (attempt ' + reconnectAttempts + ')');
          setTimeout(connect, reconnectDelay);
          reconnectDelay = Math.min(reconnectDelay * 2, 30000); // Exponential backoff, max 30s
        } else {
          console.log('[WS] Max reconnect attempts reached');
          emit('reconnectFailed', {});
        }
      };

      ws.onerror = function(error) {
        console.error('[WS] Error:', error);
        emit('error', { error: error });
      };

    } catch (err) {
      console.error('[WS] Connection failed:', err);
    }
  }

  // Disconnect from WebSocket server
  function disconnect() {
    if (ws) {
      ws.close();
      ws = null;
    }
    stopHeartbeat();
  }

  // Send message to server
  function send(message) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
      return true;
    }
    return false;
  }

  // Handle incoming messages
  function handleMessage(message) {
    switch (message.type) {
      case 'connected':
        console.log('[WS] Authenticated as:', message.alias || 'anonymous');
        break;

      case 'pong':
        // Heartbeat response
        break;

      case 'notification':
        // New notification received
        emit('notification', message.notification);
        showNotificationBadge();
        break;

      case 'newPost':
        // New post in subscribed thread
        emit('newPost', message);
        break;

      case 'feedUpdate':
        // New post from someone user follows (for feed page)
        emit('feedUpdate', message);
        break;

      case 'typing':
        // Someone is typing
        emit('typing', message);
        break;

      case 'stopTyping':
        // Someone stopped typing
        emit('stopTyping', message);
        break;

      case 'viewerList':
        // Initial list of viewers when joining a thread
        emit('viewerList', message);
        break;

      case 'viewerJoined':
        // Someone joined the thread
        emit('viewerJoined', message);
        break;

      case 'viewerLeft':
        // Someone left the thread
        emit('viewerLeft', message);
        break;

      case 'userStatus':
        // User online/offline status
        emit('userStatus', message);
        break;

      case 'error':
        console.error('[WS] Server error:', message.message);
        break;

      default:
        console.log('[WS] Unknown message:', message.type);
    }
  }

  // Heartbeat to keep connection alive
  function startHeartbeat() {
    if (heartbeatInterval) return;
    heartbeatInterval = setInterval(function() {
      send({ type: 'ping' });
    }, 25000); // Every 25 seconds
  }

  function stopHeartbeat() {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
      heartbeatInterval = null;
    }
  }

  // Subscribe to thread updates
  function subscribeToThread(threadId) {
    send({ type: 'subscribe', threadId: parseInt(threadId) });
  }

  function unsubscribeFromThread(threadId) {
    send({ type: 'unsubscribe', threadId: parseInt(threadId) });
  }

  // Send typing indicator
  function sendTyping(threadId) {
    send({ type: 'typing', threadId: parseInt(threadId) });
  }

  // Send stop typing indicator
  function sendStopTyping(threadId) {
    send({ type: 'stopTyping', threadId: parseInt(threadId) });
  }

  // Join a thread (for presence tracking)
  function viewThread(threadId, avatarConfig) {
    send({ 
      type: 'viewThread', 
      threadId: parseInt(threadId),
      avatarConfig: avatarConfig || null
    });
  }

  // Leave a thread
  function leaveThread(threadId) {
    send({ type: 'leaveThread', threadId: parseInt(threadId) });
  }

  // Event subscription system
  function on(event, callback) {
    if (!subscribers[event]) {
      subscribers[event] = [];
    }
    subscribers[event].push(callback);
  }

  function off(event, callback) {
    if (subscribers[event]) {
      subscribers[event] = subscribers[event].filter(function(cb) {
        return cb !== callback;
      });
    }
  }

  function emit(event, data) {
    if (subscribers[event]) {
      subscribers[event].forEach(function(callback) {
        try {
          callback(data);
        } catch (err) {
          console.error('[WS] Event handler error:', err);
        }
      });
    }
  }

  // Show notification badge update
  function showNotificationBadge() {
    var badge = document.getElementById('notif-count');
    if (badge) {
      var current = parseInt(badge.textContent) || 0;
      badge.textContent = current + 1;
      badge.style.display = 'inline';
    }
  }

  // Auto-connect if authenticated
  function init() {
    var token = localStorage.getItem('authToken');
    if (token) {
      // Small delay to ensure page is ready
      setTimeout(connect, 500);
    }
  }

  // Reconnect when user logs in
  function reconnectWithAuth() {
    disconnect();
    setTimeout(connect, 100);
  }

  // Check connection status
  function isConnected() {
    return ws && ws.readyState === WebSocket.OPEN;
  }

  // Export
  window.ForumWS = {
    connect: connect,
    disconnect: disconnect,
    send: send,
    on: on,
    off: off,
    isConnected: isConnected,
    subscribeToThread: subscribeToThread,
    unsubscribeFromThread: unsubscribeFromThread,
    sendTyping: sendTyping,
    sendStopTyping: sendStopTyping,
    viewThread: viewThread,
    leaveThread: leaveThread,
    reconnectWithAuth: reconnectWithAuth,
    init: init
  };

  // Auto-initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
