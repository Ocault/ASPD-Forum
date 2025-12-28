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
   * @param {boolean} isAdmin - Whether current user is admin
   * @returns {string} HTML string
   */
  function signalRow(signal, isAdmin) {
    const id = signal.id || '';
    const title = signal.title || 'UNTITLED';
    const href = signal.href || '#';
    const meta = signal.meta || '';
    const deleteBtn = isAdmin ? `<button class="signal-delete-btn" data-thread-id="${id}" title="Delete Thread">×</button>` : '';
    
    return `
      <div class="signal-row-wrapper" data-signal-id="${id}">
        <a href="${href}" class="signal-row">
          <span class="signal-title">${title}</span>
          <span class="signal-meta">${meta}</span>
        </a>
        ${deleteBtn}
      </div>`;
  }

  /**
   * Generate an entry element
   * @param {Object} entry
   * @param {string} entry.id - Entry ID
   * @param {string} entry.content - Entry text content
   * @param {string} entry.user_id - User ID who created entry
   * @param {string} entry.alias - Alias for anonymous posts
   * @param {Object} entry.avatar_config - Avatar configuration (optional)
   * @param {boolean} entry.exceedsCharLimit - Whether content exceeds character limit
   * @param {string} entry.created_at - Creation timestamp
   * @param {string} entry.edited_at - Edit timestamp (if edited)
   * @param {number} currentUserId - Current logged-in user's ID
   * @returns {string} HTML string
   */
  function entryElement(entry, currentUserId) {
    const id = entry.id || '';
    const content = entry.content || '';
    const alias = entry.alias || null;
    const userId = entry.user_id || null;
    const avatarConfig = entry.avatar_config ? JSON.stringify(entry.avatar_config).replace(/"/g, '&quot;') : '';
    const exceedsLimit = entry.exceedsCharLimit || false;
    const createdAt = entry.created_at ? new Date(entry.created_at) : null;
    const editedAt = entry.edited_at ? new Date(entry.edited_at) : null;
    
    // Check if current user owns this entry (for edit/delete buttons)
    const isOwner = currentUserId && userId && currentUserId === userId;
    
    // Check if within 15-minute edit window
    const canEdit = isOwner && createdAt && ((new Date() - createdAt) / (1000 * 60) < 15);
    
    // Determine entry type: anonymous (has alias) or system (no alias)
    const isAnonymous = alias !== null;
    let entryClass = isAnonymous ? 'entry entry--anonymous' : 'entry entry--system';
    if (exceedsLimit) entryClass += ' entry--long';
    const identityClass = isAnonymous ? 'entry-alias' : 'entry-system-label';
    
    // Make alias a clickable link to profile
    const identityLabel = isAnonymous 
      ? `<a href="profile.html?alias=${encodeURIComponent(alias)}" class="entry-alias-link">${alias}</a>` 
      : 'ARCHIVE';
    
    // Format timestamp
    const timeStr = createdAt ? createdAt.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : '';
    const editedStr = editedAt ? ' (edited)' : '';
    
    // Edit/Delete buttons (only show if owner)
    const actionsHtml = isOwner ? `
        <div class="entry-actions">
          ${canEdit ? `<button class="entry-action-btn entry-edit-btn" data-entry-id="${id}" title="Edit">EDIT</button>` : ''}
          <button class="entry-action-btn entry-delete-btn" data-entry-id="${id}" title="Delete">DEL</button>
        </div>` : '';
    
    return `
      <div class="${entryClass}" data-entry-id="${id}" data-user-id="${userId || ''}" data-avatar-config="${avatarConfig}">
        <div class="entry-avatar">
          <canvas class="avatar-mini" width="28" height="28"></canvas>
        </div>
        <div class="entry-body">
          <div class="entry-header">
            <span class="${identityClass}">${identityLabel}</span>
            <span class="entry-time">${timeStr}${editedStr}</span>
            ${actionsHtml}
          </div>
          <div class="entry-content">
            <p>${content}</p>
          </div>
        </div>
      </div>`;
  }

  /**
   * Generate pagination controls
   * @param {Object} pagination
   * @param {number} pagination.page - Current page
   * @param {number} pagination.totalPages - Total pages
   * @param {number} pagination.total - Total items
   * @returns {string} HTML string
   */
  function paginationControls(pagination) {
    if (!pagination || pagination.totalPages <= 1) return '';
    
    const { page, totalPages, total } = pagination;
    const prevDisabled = page <= 1 ? 'disabled' : '';
    const nextDisabled = page >= totalPages ? 'disabled' : '';
    
    return `
      <div class="pagination">
        <button class="pagination-btn" data-page="${page - 1}" ${prevDisabled}>← PREV</button>
        <span class="pagination-info">${page} / ${totalPages}</span>
        <button class="pagination-btn" data-page="${page + 1}" ${nextDisabled}>NEXT →</button>
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
    entryElement,
    paginationControls
  };

})();

// Export for module systems if available
if (typeof module !== 'undefined' && module.exports) {
  module.exports = UIComponents;
}
