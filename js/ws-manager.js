/**
 * WebSocket Manager for Real-time Updates
 * Handles connection, reconnection, subscriptions, and event dispatching
 */
const WSManager = (function() {
  let ws = null;
  let reconnectAttempts = 0;
  const MAX_RECONNECT_ATTEMPTS = 5;
  const RECONNECT_DELAY_BASE = 1000; // Start with 1 second
  let pingInterval = null;
  let isConnected = false;
  let pendingSubscriptions = [];
  const eventHandlers = new Map();

  /**
   * Get WebSocket URL based on current location
   */
  function getWsUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Use API_BASE if defined, otherwise construct from location
    if (typeof API_BASE !== 'undefined') {
      const apiUrl = new URL(API_BASE);
      return `${protocol}//${apiUrl.host}`;
    }
    return `${protocol}//${window.location.hostname}:3001`;
  }

  /**
   * Connect to WebSocket server
   */
  function connect() {
    if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
      return;
    }

    const token = localStorage.getItem('token');
    if (!token) {
      console.log('[WS] No auth token, skipping WebSocket connection');
      return;
    }

    const wsUrl = getWsUrl();
    console.log('[WS] Connecting to', wsUrl);

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = function() {
        console.log('[WS] Connected');
        isConnected = true;
        reconnectAttempts = 0;

        // Authenticate
        send({ type: 'auth', token: token });

        // Process pending subscriptions
        while (pendingSubscriptions.length > 0) {
          const sub = pendingSubscriptions.shift();
          send(sub);
        }

        // Start ping interval to keep connection alive
        if (pingInterval) clearInterval(pingInterval);
        pingInterval = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            send({ type: 'ping' });
          }
        }, 30000);

        // Dispatch connected event
        dispatchEvent('connected', {});
      };

      ws.onmessage = function(event) {
        try {
          const data = JSON.parse(event.data);
          handleMessage(data);
        } catch (err) {
          console.error('[WS] Failed to parse message:', err);
        }
      };

      ws.onclose = function(event) {
        console.log('[WS] Disconnected', event.code, event.reason);
        isConnected = false;
        ws = null;

        if (pingInterval) {
          clearInterval(pingInterval);
          pingInterval = null;
        }

        // Dispatch disconnected event
        dispatchEvent('disconnected', {});

        // Attempt reconnection
        if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
          const delay = RECONNECT_DELAY_BASE * Math.pow(2, reconnectAttempts);
          console.log(`[WS] Reconnecting in ${delay}ms (attempt ${reconnectAttempts + 1}/${MAX_RECONNECT_ATTEMPTS})`);
          setTimeout(connect, delay);
          reconnectAttempts++;
        } else {
          console.log('[WS] Max reconnection attempts reached');
        }
      };

      ws.onerror = function(error) {
        console.error('[WS] Error:', error);
      };

    } catch (err) {
      console.error('[WS] Connection failed:', err);
    }
  }

  /**
   * Send message to server
   */
  function send(data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
      return true;
    }
    return false;
  }

  /**
   * Handle incoming message
   */
  function handleMessage(data) {
    const { type, payload } = data;

    switch (type) {
      case 'auth_success':
        console.log('[WS] Authenticated as user', payload.userId);
        break;

      case 'auth_error':
        console.error('[WS] Authentication failed:', payload.message);
        disconnect();
        break;

      case 'pong':
        // Connection is alive
        break;

      case 'new_entry':
        dispatchEvent('new_entry', payload);
        break;

      case 'entry_edited':
        dispatchEvent('entry_edited', payload);
        break;

      case 'entry_deleted':
        dispatchEvent('entry_deleted', payload);
        break;

      case 'new_thread':
        dispatchEvent('new_thread', payload);
        break;

      default:
        console.log('[WS] Unknown message type:', type);
    }
  }

  /**
   * Subscribe to a thread for real-time updates
   */
  function subscribeThread(threadId) {
    const msg = { type: 'subscribe_thread', threadId: threadId };
    if (isConnected) {
      send(msg);
    } else {
      pendingSubscriptions.push(msg);
    }
  }

  /**
   * Unsubscribe from a thread
   */
  function unsubscribeThread(threadId) {
    send({ type: 'unsubscribe_thread', threadId: threadId });
  }

  /**
   * Subscribe to a room for new thread notifications
   */
  function subscribeRoom(roomId) {
    const msg = { type: 'subscribe_room', roomId: roomId };
    if (isConnected) {
      send(msg);
    } else {
      pendingSubscriptions.push(msg);
    }
  }

  /**
   * Unsubscribe from a room
   */
  function unsubscribeRoom(roomId) {
    send({ type: 'unsubscribe_room', roomId: roomId });
  }

  /**
   * Register event handler
   */
  function on(eventType, handler) {
    if (!eventHandlers.has(eventType)) {
      eventHandlers.set(eventType, []);
    }
    eventHandlers.get(eventType).push(handler);
  }

  /**
   * Remove event handler
   */
  function off(eventType, handler) {
    if (eventHandlers.has(eventType)) {
      const handlers = eventHandlers.get(eventType);
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }

  /**
   * Dispatch event to registered handlers
   */
  function dispatchEvent(eventType, payload) {
    if (eventHandlers.has(eventType)) {
      eventHandlers.get(eventType).forEach(handler => {
        try {
          handler(payload);
        } catch (err) {
          console.error('[WS] Event handler error:', err);
        }
      });
    }
  }

  /**
   * Disconnect from WebSocket server
   */
  function disconnect() {
    reconnectAttempts = MAX_RECONNECT_ATTEMPTS; // Prevent reconnection
    if (pingInterval) {
      clearInterval(pingInterval);
      pingInterval = null;
    }
    if (ws) {
      ws.close();
      ws = null;
    }
    isConnected = false;
  }

  /**
   * Check if connected
   */
  function getConnectionStatus() {
    return isConnected;
  }

  // Public API
  return {
    connect,
    disconnect,
    subscribeThread,
    unsubscribeThread,
    subscribeRoom,
    unsubscribeRoom,
    on,
    off,
    isConnected: getConnectionStatus
  };
})();

// Auto-connect when page loads if user is logged in
document.addEventListener('DOMContentLoaded', function() {
  if (localStorage.getItem('token')) {
    // Small delay to ensure other scripts have loaded
    setTimeout(() => WSManager.connect(), 500);
  }
});
