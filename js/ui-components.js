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
    const version = options.version || 'v1.0';
    const nodeCount = options.nodeCount || 'FORUMS: 0';
    const connectionStatus = options.connectionStatus || 'ONLINE';
    
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
    const backText = options.backText || '← FORUMS';
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
    const connectionStatus = options.connectionStatus || 'ONLINE';
    
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
    const connectionStatus = options.connectionStatus || 'ONLINE';
    
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
   * @param {string} room.description - Room description
   * @param {number} room.thread_count - Number of threads
   * @param {boolean} room.is_locked - Whether room is locked
   * @param {number} room.slow_mode_seconds - Slow mode interval in seconds
   * @returns {string} HTML string
   */
  function roomNode(room) {
    const id = room.id || '';
    const title = room.title || 'UNTITLED';
    const href = room.href || '#';
    const description = room.description || '';
    const threadCount = room.thread_count || 0;
    const isLocked = room.is_locked || false;
    const slowMode = room.slow_mode_seconds || 0;
    
    // Build status badges
    let badges = '';
    if (isLocked) badges += '<span class="room-badge room-badge--locked" title="Room is locked">🔒</span>';
    if (slowMode > 0) badges += `<span class="room-badge room-badge--slow" title="Slow mode: ${slowMode}s">⏱</span>`;
    
    return `
      <a href="${href}" class="room-node${isLocked ? ' room-node--locked' : ''}${slowMode > 0 ? ' room-node--slow' : ''}" data-room-id="${id}">
        <div class="room-header">
          <span class="room-title">${title}</span>
          ${badges ? `<span class="room-badges">${badges}</span>` : ''}
        </div>
        ${description ? `<span class="room-description">${description}</span>` : ''}
        <span class="room-stats">${threadCount} THREADS</span>
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
    const title = Utils.escapeHtml(signal.title || 'UNTITLED');
    const href = signal.href || '#';
    const meta = signal.meta || '';
    const isPinned = signal.is_pinned || false;
    const isLocked = signal.is_locked || false;
    const tags = signal.tags || [];
    const deleteBtn = isAdmin ? `<button class="signal-delete-btn" data-thread-id="${id}" title="Delete Thread">×</button>` : '';
    
    // Build badges
    let badges = '';
    if (isPinned) badges += '<span class="signal-badge pinned">📌</span>';
    if (isLocked) badges += '<span class="signal-badge locked">🔒</span>';
    
    // Build tags
    let tagsHtml = '';
    if (tags.length > 0) {
      tagsHtml = '<span class="signal-tags">' + tags.map(function(tag) {
        return '<span class="signal-tag" style="background-color:' + (tag.color || '#4a9') + '">' + Utils.escapeHtml((tag.name || '').toUpperCase()) + '</span>';
      }).join('') + '</span>';
    }
    
    return `
      <div class="signal-row-wrapper ${isPinned ? 'pinned' : ''}" data-signal-id="${id}">
        <a href="${href}" class="signal-row">
          ${badges}
          ${tagsHtml}
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
   * @param {number} opUserId - Original poster's user ID (for OP badge)
   * @returns {string} HTML string
   */
  function entryElement(entry, currentUserId, opUserId) {
    const id = entry.id || '';
    const content = entry.content || '';
    const alias = entry.alias || null;
    const userId = entry.user_id || null;
    const avatarConfig = entry.avatar_config ? JSON.stringify(entry.avatar_config).replace(/"/g, '&quot;') : '';
    const exceedsLimit = entry.exceedsCharLimit || false;
    const createdAt = entry.created_at ? new Date(entry.created_at) : null;
    const editedAt = entry.edited_at ? new Date(entry.edited_at) : null;
    const isGhost = entry.is_ghost === true;
    const ghostModVisible = entry.ghost_mode_visible === true; // Mods can see real identity
    const vaultLevel = entry.vault_level || null;
    const vaultLocked = entry.vault_locked === true;
    const vaultRequired = entry.vault_required || null;
    
    // Check if this user is the original poster
    const isOP = opUserId && userId && opUserId === userId;
    
    // Check if current user owns this entry (for edit/delete buttons)
    const isOwner = currentUserId && userId && currentUserId === userId;
    
    // Check if within 15-minute edit window
    const canEdit = isOwner && createdAt && ((new Date() - createdAt) / (1000 * 60) < 15);
    
    // Determine entry type: anonymous (has alias) or system (no alias)
    const isAnonymous = alias !== null;
    let entryClass = isAnonymous ? 'entry entry--anonymous' : 'entry entry--system';
    if (exceedsLimit) entryClass += ' entry--long';
    if (isGhost) entryClass += ' ghost-post';
    if (vaultLocked) entryClass += ' vault-locked';
    if (vaultLevel) entryClass += ' vault-post';
    const identityClass = isAnonymous ? 'entry-alias' : 'entry-system-label';
    
    // Vault indicator
    const vaultHtml = vaultLevel ? `<span class="vault-indicator" title="Vault post: ${vaultLevel}+ reputation required">[V]</span>` : '';
    
    // Get rank badge and custom title - custom title replaces rank
    const rank = entry.rank || '';
    const customTitle = entry.custom_title || '';
    const epithet = entry.epithet || '';
    const isAdmin = entry.is_admin === true;
    
    // Rank tier explanations
    const rankExplanations = {
      'NEWCOMER': 'New user • <10 posts',
      'ACTIVE': 'Active • 10+ posts',
      'MEMBER': 'Member • 50+ posts',
      'REGULAR': 'Regular • 100+ posts',
      'EXPERT': 'Expert • 200+ posts',
      'VETERAN': 'Veteran • 500+ posts',
      'GHOST': 'Anonymous post'
    };
    
    // If user has custom title, show that instead of rank
    // For ghost posts, show GHOST rank unless mod can see real identity
    let displayRank = rank;
    if (isGhost && !ghostModVisible) {
      displayRank = 'GHOST';
    }
    
    const badgeHtml = customTitle && !isGhost
      ? `<span class="user-title">${Utils.escapeHtml(customTitle)}</span>` 
      : (displayRank ? `<span class="entry-rank rank-badge rank-${displayRank.toLowerCase()}" title="${rankExplanations[displayRank] || displayRank}">${displayRank}<span class="rank-info-tooltip">${rankExplanations[displayRank] || displayRank}</span></span>` : '');
    
    // OP badge for original poster (hidden on ghost posts unless mod)
    const opBadgeHtml = (isOP && (!isGhost || ghostModVisible)) ? '<span class="op-badge" title="Original Poster">OP</span>' : '';
    
    // Mod indicator for ghost posts (shows real alias to mods)
    const ghostModIndicator = ghostModVisible 
      ? `<span class="ghost-mod-indicator" title="Anonymous post — You can see the real identity">ANON</span>` 
      : '';
    
    // Make alias a clickable link to profile (not for ghost posts unless mod)
    let identityLabel;
    if (isGhost && !ghostModVisible) {
      // Ghost post - no link, just the ghost alias
      identityLabel = `<span class="entry-alias">${Utils.escapeHtml(alias)}</span>${badgeHtml}`;
    } else if (isAnonymous) {
      identityLabel = `<a href="profile.html?alias=${encodeURIComponent(alias)}" class="entry-alias-link">${Utils.escapeHtml(alias)}</a>${ghostModIndicator}${opBadgeHtml}${badgeHtml}`;
    } else {
      identityLabel = 'ARCHIVE';
    }
    
    // Format timestamp
    const timeStr = createdAt ? createdAt.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : '';
    const editedStr = editedAt ? ` <a href="#" class="entry-history-link" data-entry-id="${id}" title="View edit history">(edited)</a>` : '';
    
    // Edit/Delete buttons (only show if owner), Quote/Report for all
    const ownerActionsHtml = isOwner ? `
          ${canEdit ? `<button class="entry-action-btn entry-edit-btn" data-entry-id="${id}" title="Edit">EDIT</button>` : ''}
          <button class="entry-action-btn entry-delete-btn" data-entry-id="${id}" title="Delete">DEL</button>` : '';
    
    const commonActionsHtml = isAnonymous ? `
          <button class="entry-action-btn entry-quote-btn" data-entry-id="${id}" data-alias="${alias}" title="Quote">QUOTE</button>
          <button class="entry-action-btn entry-report-btn" data-entry-id="${id}" title="Report">REPORT</button>` : '';
    
    const actionsHtml = (ownerActionsHtml || commonActionsHtml) ? `
        <div class="entry-actions">${ownerActionsHtml}${commonActionsHtml}
        </div>` : '';
    
    // Enhanced markdown formatting
    let formattedContent = content;
    // Escape HTML first
    formattedContent = formattedContent.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    
    // Code blocks ```code``` (must be before inline code)
    formattedContent = formattedContent.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
    // Inline code `text`
    formattedContent = formattedContent.replace(/`(.+?)`/g, '<code>$1</code>');
    
    // Headers (# ## ###)
    formattedContent = formattedContent.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    formattedContent = formattedContent.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    formattedContent = formattedContent.replace(/^# (.+)$/gm, '<h1>$1</h1>');
    
    // Bold **text** or __text__
    formattedContent = formattedContent.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    formattedContent = formattedContent.replace(/__(.+?)__/g, '<strong>$1</strong>');
    // Italic *text* or _text_
    formattedContent = formattedContent.replace(/\*(.+?)\*/g, '<em>$1</em>');
    formattedContent = formattedContent.replace(/_(.+?)_/g, '<em>$1</em>');
    // Strikethrough ~~text~~
    formattedContent = formattedContent.replace(/~~(.+?)~~/g, '<del>$1</del>');
    
    // Horizontal rule ---
    formattedContent = formattedContent.replace(/^---$/gm, '<hr>');
    
    // Links [text](url)
    formattedContent = formattedContent.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" class="auto-link" target="_blank" rel="noopener">$1</a>');
    
    // Auto-link URLs
    formattedContent = formattedContent.replace(/(https?:\/\/[^\s<]+)/g, function(match) {
      // Don't double-link already linked URLs
      if (formattedContent.indexOf('href="' + match) !== -1) return match;
      return '<a href="' + match + '" class="auto-link" target="_blank" rel="noopener">' + match + '</a>';
    });
    
    // Lists (simple - and * for unordered, 1. for ordered)
    formattedContent = formattedContent.replace(/^[\-\*] (.+)$/gm, '<li>$1</li>');
    formattedContent = formattedContent.replace(/^(\d+)\. (.+)$/gm, '<li>$2</li>');
    // Wrap consecutive li elements
    formattedContent = formattedContent.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');
    
    // @mentions
    formattedContent = formattedContent.replace(/@([a-zA-Z0-9_]+)/g, '<a href="profile.html?alias=$1" class="mention-link">@$1</a>');
    
    // Spoiler tags ||hidden text||
    formattedContent = formattedContent.replace(/\|\|(.+?)\|\|/g, '<span class="spoiler" onclick="this.classList.toggle(\'revealed\')" title="Click to reveal">$1</span>');
    
    // Image embeds - auto-embed image URLs
    formattedContent = formattedContent.replace(/<a href="(https?:\/\/[^\s"]+\.(jpg|jpeg|png|gif|webp)(\?[^"]*)?)" class="auto-link"[^>]*>[^<]*<\/a>/gi, 
      '<div class="embedded-image"><img src="$1" alt="Embedded image" loading="lazy" onclick="window.open(this.src, \'_blank\')"><a href="$1" class="image-link" target="_blank" rel="noopener">[view full]</a></div>');
    
    // Quote lines starting with > (blockquote style)
    formattedContent = formattedContent.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>');
    // Merge consecutive blockquotes
    formattedContent = formattedContent.replace(/<\/blockquote>\n<blockquote>/g, '\n');
    
    // Check if this is a reply to another post (quoted content)
    let quotedHtml = '';
    const quoteMatch = content.match(/^@(\w+) said:\n&gt; ([\s\S]*?)\n\n/);
    if (quoteMatch) {
      const quotedAlias = quoteMatch[1];
      const quotedText = quoteMatch[2].substring(0, 150);
      quotedHtml = `
        <div class="quoted-content">
          <span class="quote-author">@${quotedAlias}</span>: ${quotedText}${quoteMatch[2].length > 150 ? '...' : ''}
        </div>`;
      // Remove the quote from main content display
      formattedContent = formattedContent.replace(/^@\w+ said:\n&gt;[\s\S]*?\n\n/, '');
    }
    
    // Reactions row - replaced with vote system
    const score = entry.score || 0;
    const userVote = entry.userVote || 0;
    const votesHtml = `
          <div class="entry-votes" data-entry-id="${id}">
            <button class="vote-btn vote-up${userVote === 1 ? ' voted' : ''}" data-vote="1" title="Upvote">
              <span class="vote-icon">▲</span>
            </button>
            <span class="vote-score${score > 0 ? ' positive' : (score < 0 ? ' negative' : '')}">${score}</span>
            <button class="vote-btn vote-down${userVote === -1 ? ' voted' : ''}" data-vote="-1" title="Downvote">
              <span class="vote-icon">▼</span>
            </button>
          </div>`;
    
    // Avatar rank class for animated borders (use selectedBorder from avatar_config if set, otherwise use rank)
    let avatarRankClass = '';
    // Handle avatar_config whether it's a string or object
    let avatarConfigObj = entry.avatar_config || {};
    if (typeof avatarConfigObj === 'string') {
      try {
        avatarConfigObj = JSON.parse(avatarConfigObj);
      } catch (e) {
        avatarConfigObj = {};
      }
    }
    const selectedBorder = avatarConfigObj.selectedBorder;
    
    if (selectedBorder && selectedBorder !== 'none') {
      // User has a selected border preference
      avatarRankClass = ` avatar-rank-${selectedBorder}`;
    } else if (isAdmin) {
      // Admin without preference gets owner border by default
      avatarRankClass = ' avatar-rank-owner';
    } else if (rank && rank !== 'NEWCOMER') {
      // Use the user's rank for border (newcomers get no border)
      avatarRankClass = ` avatar-rank-${rank.toLowerCase()}`;
    }
    // If no preference and newcomer, no border is shown
    
    // Vault locked content replacement
    let displayContent = formattedContent;
    if (vaultLocked) {
      displayContent = `<div class="vault-locked-message">[VAULT LOCKED] This post requires ${vaultRequired}+ reputation to view.</div>`;
    }
    
    return `
      <div class="${entryClass}" data-entry-id="${id}" data-user-id="${userId || ''}" data-avatar-config="${avatarConfig}">
        <div class="entry-avatar${avatarRankClass}">
          <canvas class="avatar-mini" width="28" height="28"></canvas>
        </div>
        <div class="entry-body">
          <div class="entry-header">
            <span class="${identityClass}">${identityLabel}</span>
            ${vaultHtml}
            <span class="entry-time">${timeStr}${editedStr}</span>
            ${actionsHtml}
          </div>
          ${quotedHtml}
          <div class="entry-content">
            <p>${displayContent}</p>
          </div>
          ${vaultLocked ? '' : votesHtml}
          ${entry.signature ? `<div class="entry-signature">— ${entry.signature}</div>` : ''}
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
    const firstDisabled = page <= 1 ? 'disabled' : '';
    const lastDisabled = page >= totalPages ? 'disabled' : '';
    
    return `
      <div class="pagination">
        <button class="pagination-btn" data-page="1" ${firstDisabled}>« FIRST</button>
        <button class="pagination-btn" data-page="${page - 1}" ${prevDisabled}>← PREV</button>
        <span class="pagination-info">${page} / ${totalPages}</span>
        <button class="pagination-btn" data-page="${page + 1}" ${nextDisabled}>NEXT →</button>
        <button class="pagination-btn" data-page="${totalPages}" ${lastDisabled}>LAST »</button>
        <div class="pagination-jump">
          <input type="number" class="pagination-jump-input" min="1" max="${totalPages}" placeholder="#" title="Jump to page">
          <button class="pagination-btn pagination-go-btn">GO</button>
        </div>
      </div>`;
  }

  /**
   * Generate skeleton room cards for loading state
   * @param {number} count - Number of skeleton cards to generate
   * @returns {string} HTML string
   */
  function skeletonRooms(count) {
    count = count || 6;
    var html = '';
    for (var i = 0; i < count; i++) {
      html += `
        <div class="skeleton-room">
          <div class="skeleton skeleton-room-title"></div>
          <div class="skeleton skeleton-room-desc"></div>
          <div class="skeleton skeleton-room-stats"></div>
        </div>`;
    }
    return html;
  }

  /**
   * Generate skeleton signal rows for loading state
   * @param {number} count - Number of skeleton rows to generate
   * @returns {string} HTML string
   */
  function skeletonSignals(count) {
    count = count || 8;
    var html = '';
    for (var i = 0; i < count; i++) {
      html += `
        <div class="skeleton-signal">
          <div class="skeleton skeleton-signal-title"></div>
          <div class="skeleton skeleton-signal-meta"></div>
        </div>`;
    }
    return html;
  }

  /**
   * Generate skeleton entry elements for loading state
   * @param {number} count - Number of skeleton entries to generate
   * @returns {string} HTML string
   */
  function skeletonEntries(count) {
    count = count || 5;
    var html = '';
    for (var i = 0; i < count; i++) {
      html += `
        <div class="skeleton-entry">
          <div class="skeleton skeleton-avatar"></div>
          <div class="skeleton-entry-body">
            <div class="skeleton skeleton-entry-header"></div>
            <div class="skeleton skeleton-entry-content"></div>
            <div class="skeleton skeleton-entry-content-2"></div>
          </div>
        </div>`;
    }
    return html;
  }

  /**
   * Generate mobile bottom navigation
   * @param {string} activePage - Current active page identifier
   * @param {boolean} hasNotifications - Whether to show notification badge
   * @returns {string} HTML string
   */
  function mobileNav(activePage, hasNotifications) {
    activePage = activePage || '';
    var items = [
      { id: 'home', icon: '⌂', label: 'Home', href: 'forum.html' },
      { id: 'search', icon: '⌕', label: 'Search', href: 'search.html' },
      { id: 'notif', icon: '!', label: 'Alerts', href: '#', isNotif: true },
      { id: 'messages', icon: '✉', label: 'Msg', href: 'messages.html' },
      { id: 'profile', icon: '◉', label: 'Profile', href: 'profile.html' }
    ];
    
    var html = '<nav class="mobile-nav" aria-label="Mobile navigation">';
    items.forEach(function(item) {
      var activeClass = activePage === item.id ? ' active' : '';
      var badge = item.isNotif && hasNotifications ? '<span class="nav-badge visible"></span>' : '';
      var clickAttr = item.isNotif ? ' id="mobile-notif-btn"' : '';
      html += `
        <a href="${item.href}" class="mobile-nav-item${activeClass}"${clickAttr}>
          <span class="mobile-nav-icon">${item.icon}</span>
          <span class="mobile-nav-label">${item.label}</span>
          ${badge}
        </a>`;
    });
    html += '</nav>';
    return html;
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
    paginationControls,
    skeletonRooms,
    skeletonSignals,
    skeletonEntries,
    mobileNav
  };

})();

// Export for module systems if available
if (typeof module !== 'undefined' && module.exports) {
  module.exports = UIComponents;
}
