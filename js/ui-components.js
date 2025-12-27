/**
 * UI Components - Centralized UI element generation
 * Prepared for backend integration
 */

const UIComponents = (function() {
  'use strict';

  /**
   * Generate noise overlay element
   * @returns {string} HTML string
   */
  function noiseOverlay() {
    return '<div class="noise"></div>';
  }

  /**
   * Generate forum header
   * @param {Object} options
   * @param {string} options.logoHref - URL for logo link
   * @param {string} options.logoText - Logo text (default: 'ASPD.FORUM')
   * @param {string} options.status - Status text
   * @returns {string} HTML string
   */
  function forumHeader(options = {}) {
    const logoHref = options.logoHref || 'index.html';
    const logoText = options.logoText || 'ASPD.FORUM';
    const status = options.status || '';
    
    return `
    <header class="forum-header">
      <a href="${logoHref}" class="forum-logo">${logoText}</a>
      <span class="forum-status">${status}</span>
    </header>`;
  }

  /**
   * Generate forum footer
   * @param {Object} options
   * @param {string} options.version - Version string
   * @param {string} options.nodeCount - Node count display
   * @param {string} options.connectionStatus - Connection status
   * @returns {string} HTML string
   */
  function forumFooter(options = {}) {
    const version = options.version || 'SYS.1.0.0';
    const nodeCount = options.nodeCount || 'NODES: 0';
    const connectionStatus = options.connectionStatus || 'CONN.ACTIVE';
    
    return `
    <footer class="forum-footer">
      <span>${version}</span>
      <span>${nodeCount}</span>
      <span>${connectionStatus}</span>
    </footer>`;
  }

  /**
   * Generate room header with back navigation
   * @param {Object} options
   * @param {string} options.backHref - URL for back link
   * @param {string} options.backText - Back link text
   * @param {string} options.roomName - Room/node name
   * @param {string} options.signalCount - Signal count display
   * @returns {string} HTML string
   */
  function roomHeader(options = {}) {
    const backHref = options.backHref || 'forum.html';
    const backText = options.backText || '← NODES';
    const roomName = options.roomName || 'NODE.000';
    const signalCount = options.signalCount || '0 SIGNALS';
    
    return `
    <header class="room-header">
      <div class="room-header-left">
        <a href="${backHref}" class="room-back">${backText}</a>
        <span class="room-divider">/</span>
        <span class="room-name">${roomName}</span>
      </div>
      <span class="room-signal-count">${signalCount}</span>
    </header>`;
  }

  /**
   * Generate room footer
   * @param {Object} options
   * @param {string} options.nodeId - Node identifier
   * @param {string} options.viewType - Current view type
   * @param {string} options.connectionStatus - Connection status
   * @returns {string} HTML string
   */
  function roomFooter(options = {}) {
    const nodeId = options.nodeId || 'NODE.000';
    const viewType = options.viewType || 'INDEX';
    const connectionStatus = options.connectionStatus || 'CONN.ACTIVE';
    
    return `
    <footer class="room-footer">
      <span>${nodeId}</span>
      <span>${viewType}</span>
      <span>${connectionStatus}</span>
    </footer>`;
  }

  /**
   * Generate thread header
   * @param {Object} options
   * @param {string} options.backHref - URL for back link
   * @param {string} options.backText - Back link text
   * @param {string} options.roomName - Room/node name
   * @param {string} options.entryCount - Entry count display
   * @returns {string} HTML string
   */
  function threadHeader(options = {}) {
    const backHref = options.backHref || 'room.html';
    const backText = options.backText || '← INDEX';
    const roomName = options.roomName || 'NODE.000';
    const entryCount = options.entryCount || '0 RECORDS';
    
    return `
    <header class="thread-header">
      <div class="thread-header-left">
        <a href="${backHref}" class="thread-back">${backText}</a>
        <span class="thread-divider">/</span>
        <span class="thread-room">${roomName}</span>
      </div>
      <span class="thread-entry-count">${entryCount}</span>
    </header>`;
  }

  /**
   * Generate thread footer
   * @param {Object} options
   * @param {string} options.signalId - Signal identifier
   * @param {string} options.viewType - Current view type
   * @param {string} options.connectionStatus - Connection status
   * @returns {string} HTML string
   */
  function threadFooter(options = {}) {
    const signalId = options.signalId || 'SIG.000';
    const viewType = options.viewType || 'RECORD VIEW';
    const connectionStatus = options.connectionStatus || 'CONN.ACTIVE';
    
    return `
    <footer class="thread-footer">
      <span>${signalId}</span>
      <span>${viewType}</span>
      <span>${connectionStatus}</span>
    </footer>`;
  }

  /**
   * Generate a room node element
   * @param {Object} room
   * @param {string} room.id - Room ID
   * @param {string} room.title - Room title
   * @param {string} room.href - Room URL
   * @returns {string} HTML string
   */
  function roomNode(room) {
    const id = room.id || '';
    const title = room.title || 'UNTITLED';
    const href = room.href || '#';
    
    return `
      <a href="${href}" class="room-node" data-room-id="${id}">
        <span class="room-title">${title}</span>
        <div class="scanline"></div>
      </a>`;
  }

  /**
   * Generate a signal row element
   * @param {Object} signal
   * @param {string} signal.id - Signal/thread ID
   * @param {string} signal.title - Signal title
   * @param {string} signal.href - Signal URL
   * @param {string} signal.meta - Meta information (entry count, status)
   * @returns {string} HTML string
   */
  function signalRow(signal) {
    const id = signal.id || '';
    const title = signal.title || 'UNTITLED';
    const href = signal.href || '#';
    const meta = signal.meta || '';
    
    return `
      <a href="${href}" class="signal-row" data-signal-id="${id}">
        <span class="signal-title">${title}</span>
        <span class="signal-meta">${meta}</span>
      </a>`;
  }

  /**
   * Generate an entry element
   * @param {Object} entry
   * @param {string} entry.id - Entry ID
   * @param {string} entry.content - Entry text content
   * @param {string} entry.userId - User ID for avatar
   * @param {Object} entry.avatarConfig - Avatar configuration (optional)
   * @returns {string} HTML string
   */
  function entryElement(entry) {
    const id = entry.id || '';
    const content = entry.content || '';
    const userId = entry.userId || '';
    
    return `
      <div class="entry" data-entry-id="${id}" data-user-id="${userId}">
        <div class="entry-avatar">
          <canvas class="avatar-mini" width="28" height="28"></canvas>
        </div>
        <div class="entry-content">
          <p>${content}</p>
        </div>
      </div>`;
  }

  // Public API
  return {
    noiseOverlay,
    forumHeader,
    forumFooter,
    roomHeader,
    roomFooter,
    threadHeader,
    threadFooter,
    roomNode,
    signalRow,
    entryElement
  };

})();

// Export for module systems if available
if (typeof module !== 'undefined' && module.exports) {
  module.exports = UIComponents;
}
