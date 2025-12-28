require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3001;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = '1h';

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '2mb' }));

// Serve static frontend files from parent directory
app.use(express.static(path.join(__dirname, '..')));

// Auth middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

// Hash IP address for privacy-preserving slow-mode tracking
function hashIp(ip) {
  if (!ip) return null;
  return crypto.createHash('sha256').update(ip + (process.env.IP_SALT || 'aspd')).digest('hex').slice(0, 16);
}

// Get client IP from request
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || null;
}

// Admin middleware - requires is_admin = true
async function adminMiddleware(req, res, next) {
  if (!req.user || !req.user.userId) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  try {
    const result = await db.query(
      'SELECT is_admin FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (result.rows.length === 0 || !result.rows[0].is_admin) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
}

// Audit log helper
async function logAudit(action, targetType, targetId, adminId, details = null) {
  try {
    await db.query(
      `INSERT INTO audit_log (action, target_type, target_id, admin_id, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [action, targetType, targetId, adminId, details ? JSON.stringify(details) : null]
    );
  } catch (err) {
    // Silent fail - audit logging should not break main operations
  }
}

// Content character limit for flagging
const CONTENT_CHAR_LIMIT = 2000;

// Health check
app.get('/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected' });
  } catch (err) {
    res.status(503).json({ status: 'error', db: 'disconnected' });
  }
});

// Register
app.post('/register', async (req, res) => {
  const { alias, password } = req.body;

  if (!alias || !password) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await db.query(
      'INSERT INTO users (alias, password_hash) VALUES ($1, $2)',
      [alias, hash]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('[REGISTER ERROR]', err.message);
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: 'alias_exists' });
    }
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { alias, password } = req.body;

  if (!alias || !password) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }

  try {
    const result = await db.query(
      'SELECT id, alias, password_hash, is_admin FROM users WHERE alias = $1',
      [alias]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'invalid_credentials' });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ success: false, error: 'invalid_credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, alias: user.alias, isAdmin: user.is_admin || false },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({ success: true, token, isAdmin: user.is_admin || false });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get current user info
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, alias, is_admin, bio, avatar_config, created_at FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const user = result.rows[0];
    res.json({ 
      success: true, 
      user: { 
        id: user.id, 
        alias: user.alias, 
        isAdmin: user.is_admin || false,
        bio: user.bio || '',
        avatarConfig: user.avatar_config || null,
        createdAt: user.created_at
      } 
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get user profile by alias
app.get('/api/profile/:alias', authMiddleware, async (req, res) => {
  const alias = req.params.alias;
  
  try {
    // Get user info
    const userResult = await db.query(
      'SELECT id, alias, bio, avatar_config, created_at FROM users WHERE alias = $1',
      [alias]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const user = userResult.rows[0];
    
    // Get post count
    const postCountResult = await db.query(
      'SELECT COUNT(*) FROM entries WHERE user_id = $1 AND (is_deleted = FALSE OR is_deleted IS NULL)',
      [user.id]
    );
    const postCount = parseInt(postCountResult.rows[0].count);
    
    // Get thread count
    const threadCountResult = await db.query(
      'SELECT COUNT(*) FROM threads WHERE user_id = $1',
      [user.id]
    );
    const threadCount = parseInt(threadCountResult.rows[0].count);
    
    // Get recent posts (last 5)
    const recentPostsResult = await db.query(
      `SELECT e.id, e.content, e.created_at, t.id AS thread_id, t.title AS thread_title
       FROM entries e
       JOIN threads t ON t.id = e.thread_id
       WHERE e.user_id = $1 AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)
       ORDER BY e.created_at DESC
       LIMIT 5`,
      [user.id]
    );
    
    res.json({
      success: true,
      profile: {
        alias: user.alias,
        bio: user.bio || '',
        avatarConfig: user.avatar_config || null,
        createdAt: user.created_at,
        stats: {
          posts: postCount,
          threads: threadCount
        },
        recentPosts: recentPostsResult.rows.map(p => ({
          id: p.id,
          content: p.content.substring(0, 100) + (p.content.length > 100 ? '...' : ''),
          createdAt: p.created_at,
          threadId: p.thread_id,
          threadTitle: p.thread_title
        }))
      }
    });
  } catch (err) {
    console.error('[PROFILE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Update own profile
app.put('/api/profile', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { bio, avatar_config, custom_avatar } = req.body;
  
  try {
    // Validate bio length
    if (bio && bio.length > 500) {
      return res.status(400).json({ success: false, error: 'bio_too_long', message: 'Bio must be 500 characters or less' });
    }
    
    // Check if user is admin for custom avatar upload
    let finalAvatarConfig = avatar_config || null;
    
    if (custom_avatar) {
      // Only admins can upload custom avatars
      const adminCheck = await db.query('SELECT is_admin FROM users WHERE id = $1', [userId]);
      if (!adminCheck.rows[0]?.is_admin) {
        return res.status(403).json({ success: false, error: 'admin_only', message: 'Custom avatars are admin-only' });
      }
      
      // Validate base64 image (should be data:image/...)
      if (!custom_avatar.startsWith('data:image/')) {
        return res.status(400).json({ success: false, error: 'invalid_image', message: 'Invalid image format' });
      }
      
      // Limit size (roughly 1.5MB base64 = 1MB image)
      if (custom_avatar.length > 2000000) {
        return res.status(400).json({ success: false, error: 'image_too_large', message: 'Image must be under 1.5MB' });
      }
      
      // Store custom avatar in avatar_config
      finalAvatarConfig = { customImage: custom_avatar };
    }
    
    const result = await db.query(
      'UPDATE users SET bio = $1, avatar_config = $2 WHERE id = $3 RETURNING id, alias, bio, avatar_config',
      [bio || '', finalAvatarConfig, userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('[UPDATE PROFILE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get all rooms
app.get('/api/rooms', authMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT slug AS id, title FROM rooms ORDER BY id'
    );
    res.json({ success: true, rooms: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get threads in a room (with pagination)
app.get('/api/room/:id', authMiddleware, async (req, res) => {
  const roomSlug = req.params.id;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const offset = (page - 1) * limit;
  const search = req.query.search || '';
  
  try {
    const roomResult = await db.query(
      'SELECT id, slug, title FROM rooms WHERE slug = $1',
      [roomSlug]
    );
    
    if (roomResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'room_not_found' });
    }
    
    const room = roomResult.rows[0];

    // Count total threads (with search filter)
    let countQuery = `SELECT COUNT(*) FROM threads WHERE room_id = $1`;
    let countParams = [room.id];
    if (search) {
      countQuery += ` AND (title ILIKE $2 OR slug ILIKE $2)`;
      countParams.push('%' + search + '%');
    }
    const countResult = await db.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].count);
    
    // Get paginated threads
    let threadsQuery = `SELECT t.id, t.title, COUNT(e.id) FILTER (WHERE e.shadow_banned = FALSE OR e.shadow_banned IS NULL)::int AS "entriesCount"
       FROM threads t
       LEFT JOIN entries e ON e.thread_id = t.id
       WHERE t.room_id = $1`;
    let queryParams = [room.id];
    
    if (search) {
      threadsQuery += ` AND t.title ILIKE $2`;
      queryParams.push('%' + search + '%');
    }
    
    threadsQuery += ` GROUP BY t.id ORDER BY t.id LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);
    
    const threadsResult = await db.query(threadsQuery, queryParams);
    
    res.json({
      success: true,
      room: { id: room.slug, title: room.title },
      threads: threadsResult.rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get entries in a thread (with pagination)
app.get('/api/thread/:id', authMiddleware, async (req, res) => {
  const threadId = req.params.id;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 30, 100);
  const offset = (page - 1) * limit;
  
  try {
    // Support both numeric ID and slug lookup
    const isNumeric = /^\d+$/.test(threadId);
    const threadResult = await db.query(
      `SELECT t.id, t.title, t.slow_mode_interval, r.slug AS room_slug
       FROM threads t
       JOIN rooms r ON r.id = t.room_id
       WHERE ${isNumeric ? 't.id = $1' : 't.slug = $1'}`,
      [isNumeric ? parseInt(threadId) : threadId]
    );
    
    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }
    
    const thread = threadResult.rows[0];

    // Count total entries (exclude deleted)
    const countResult = await db.query(
      `SELECT COUNT(*) FROM entries WHERE thread_id = $1 AND (shadow_banned = FALSE OR shadow_banned IS NULL) AND (is_deleted = FALSE OR is_deleted IS NULL)`,
      [thread.id]
    );
    const total = parseInt(countResult.rows[0].count);
    
    const entriesResult = await db.query(
      `SELECT e.id, e.user_id, COALESCE(u.alias, e.alias) AS alias, e.content, 
              COALESCE(u.avatar_config, e.avatar_config) AS avatar_config,
              e.created_at, e.edited_at,
              LENGTH(e.content) > $2 AS "exceedsCharLimit"
       FROM entries e
       LEFT JOIN users u ON u.id = e.user_id
       WHERE e.thread_id = $1 AND (e.shadow_banned = FALSE OR e.shadow_banned IS NULL) AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)
       ORDER BY e.created_at
       LIMIT $3 OFFSET $4`,
      [thread.id, CONTENT_CHAR_LIMIT, limit, offset]
    );
    
    // Fetch reactions for all entries
    const entryIds = entriesResult.rows.map(e => e.id);
    let reactionsMap = {};
    
    if (entryIds.length > 0) {
      const reactionsResult = await db.query(
        `SELECT entry_id, reaction_type, COUNT(*) as count
         FROM reactions
         WHERE entry_id = ANY($1)
         GROUP BY entry_id, reaction_type`,
        [entryIds]
      );
      
      reactionsResult.rows.forEach(row => {
        if (!reactionsMap[row.entry_id]) {
          reactionsMap[row.entry_id] = {};
        }
        reactionsMap[row.entry_id][row.reaction_type] = parseInt(row.count);
      });
    }
    
    // Attach reactions to entries
    const entriesWithReactions = entriesResult.rows.map(entry => ({
      ...entry,
      reactions: reactionsMap[entry.id] || {}
    }));
    
    res.json({
      success: true,
      thread: {
        id: thread.id,
        title: thread.title,
        roomId: thread.room_slug,
        slowModeInterval: thread.slow_mode_interval || null
      },
      entries: entriesWithReactions,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('[THREAD ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Create new thread
app.post('/api/threads', authMiddleware, async (req, res) => {
  const { roomId, title, content } = req.body;
  const userId = req.user.userId;

  if (!roomId || !title || !content) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }

  try {
    // Get room id from slug
    const roomResult = await db.query('SELECT id FROM rooms WHERE slug = $1', [roomId]);
    if (roomResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'room_not_found' });
    }
    const roomDbId = roomResult.rows[0].id;

    // Create thread
    const threadResult = await db.query(
      'INSERT INTO threads (room_id, title, user_id) VALUES ($1, $2, $3) RETURNING id',
      [roomDbId, title, userId]
    );
    const threadId = threadResult.rows[0].id;

    // Create initial entry
    await db.query(
      'INSERT INTO entries (thread_id, user_id, content) VALUES ($1, $2, $3)',
      [threadId, userId, content]
    );

    res.json({ success: true, threadId: threadId });
  } catch (err) {
    console.error('[CREATE THREAD ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Rate limiter for posting entries
const entriesLimiter = rateLimit({
  windowMs: 30 * 1000,
  max: 1,
  message: { success: false, error: 'rate_limit_exceeded' },
  standardHeaders: true,
  legacyHeaders: false
});

// API: Create entry (authenticated posting)
app.post('/api/entries', authMiddleware, entriesLimiter, async (req, res) => {
  const { threadId, thread_id, content, alias, avatar_config } = req.body;
  const userId = req.user.userId;
  const userAlias = req.user.alias;
  
  // Support both threadId (new) and thread_id (legacy)
  const threadIdentifier = threadId || thread_id;

  if (!threadIdentifier || !content) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }

  const clientIp = getClientIp(req);
  const ipHash = hashIp(clientIp);

  try {
    // Support both numeric ID and slug lookup
    const isNumeric = /^\d+$/.test(String(threadIdentifier));
    const threadResult = await db.query(
      `SELECT id, slow_mode_interval FROM threads WHERE ${isNumeric ? 'id = $1' : 'slug = $1'}`,
      [isNumeric ? parseInt(threadIdentifier) : threadIdentifier]
    );

    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }

    const threadDbId = threadResult.rows[0].id;
    const slowModeInterval = threadResult.rows[0].slow_mode_interval;

    // Enforce slow-mode if active
    if (slowModeInterval && slowModeInterval > 0 && ipHash) {
      const lastPostResult = await db.query(
        `SELECT created_at FROM entries 
         WHERE thread_id = $1 AND ip_hash = $2 
         ORDER BY created_at DESC LIMIT 1`,
        [threadDbId, ipHash]
      );

      if (lastPostResult.rows.length > 0) {
        const lastPostTime = new Date(lastPostResult.rows[0].created_at);
        const now = new Date();
        const elapsedSeconds = (now - lastPostTime) / 1000;
        const remaining = Math.ceil(slowModeInterval - elapsedSeconds);

        if (elapsedSeconds < slowModeInterval) {
          return res.status(429).json({
            success: false,
            error: 'slow_mode',
            message: `Slow mode active. Wait ${remaining} seconds before posting again in this thread.`,
            retryAfter: remaining
          });
        }
      }
    }

    // Use provided alias or user's alias
    const entryAlias = alias || userAlias;

    const insertResult = await db.query(
      `INSERT INTO entries (thread_id, content, alias, avatar_config, user_id, ip_hash, shadow_banned)
       VALUES ($1, $2, $3, $4, $5, $6, FALSE)
       RETURNING id, thread_id AS "threadId", content, alias, avatar_config AS "avatarConfig", created_at AS "createdAt", user_id`,
      [threadDbId, content, entryAlias, avatar_config || null, userId, ipHash]
    );

    // Audit log for post tracking
    const entryId = insertResult.rows[0].id;
    try {
      await db.query(
        `INSERT INTO post_audit (entry_id, ip_hash, alias, content_length)
         VALUES ($1, $2, $3, $4)`,
        [entryId, ipHash, entryAlias, content.length]
      );
    } catch (auditErr) {
      // Silent fail - audit should not break posting
    }

    // Process @mentions and create notifications
    try {
      const mentionRegex = /@([a-zA-Z0-9_]+)/g;
      const mentions = [...content.matchAll(mentionRegex)].map(m => m[1]);
      const uniqueMentions = [...new Set(mentions)];
      
      for (const mentionedAlias of uniqueMentions) {
        // Find the mentioned user
        const mentionedUser = await db.query(
          'SELECT id FROM users WHERE LOWER(alias) = LOWER($1)',
          [mentionedAlias]
        );
        
        if (mentionedUser.rows.length > 0 && mentionedUser.rows[0].id !== userId) {
          const mentionedUserId = mentionedUser.rows[0].id;
          
          await db.query(
            `INSERT INTO notifications (user_id, type, title, message, link, related_entry_id, related_user_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [mentionedUserId, 'mention', `${entryAlias} mentioned you`, 
             content.substring(0, 100) + (content.length > 100 ? '...' : ''),
             `thread.html?id=${threadDbId}`,
             entryId, userId]
          );
        }
      }
    } catch (mentionErr) {
      // Silent fail - mentions should not break posting
      console.error('[MENTION NOTIFICATION ERROR]', mentionErr.message);
    }

    res.json({ success: true, entry: insertResult.rows[0] });
  } catch (err) {
    console.error('[CREATE ENTRY ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Edit entry (owner only, within 15 minutes)
app.put('/api/entries/:id', authMiddleware, async (req, res) => {
  const entryId = parseInt(req.params.id);
  const { content } = req.body;
  const userId = req.user.userId;

  if (!content || content.trim().length === 0) {
    return res.status(400).json({ success: false, error: 'content_required' });
  }

  try {
    // Get entry and check ownership
    const entryResult = await db.query(
      'SELECT id, user_id, created_at FROM entries WHERE id = $1',
      [entryId]
    );

    if (entryResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'entry_not_found' });
    }

    const entry = entryResult.rows[0];

    // Check ownership
    if (entry.user_id !== userId) {
      return res.status(403).json({ success: false, error: 'not_owner' });
    }

    // Check edit window (15 minutes)
    const createdAt = new Date(entry.created_at);
    const now = new Date();
    const minutesElapsed = (now - createdAt) / (1000 * 60);
    
    if (minutesElapsed > 15) {
      return res.status(403).json({ success: false, error: 'edit_window_expired', message: 'Posts can only be edited within 15 minutes' });
    }

    // Update entry
    await db.query(
      'UPDATE entries SET content = $1, edited_at = NOW() WHERE id = $2',
      [content.trim(), entryId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('[EDIT ENTRY ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Delete entry (owner or admin)
app.delete('/api/entries/:id', authMiddleware, async (req, res) => {
  const entryId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    // Get entry and check ownership
    const entryResult = await db.query(
      'SELECT id, user_id FROM entries WHERE id = $1',
      [entryId]
    );

    if (entryResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'entry_not_found' });
    }

    const entry = entryResult.rows[0];

    // Check if user is owner or admin
    const userResult = await db.query('SELECT is_admin FROM users WHERE id = $1', [userId]);
    const isAdmin = userResult.rows[0]?.is_admin || false;

    if (entry.user_id !== userId && !isAdmin) {
      return res.status(403).json({ success: false, error: 'not_authorized' });
    }

    // Soft delete - mark as deleted instead of removing
    await db.query(
      'UPDATE entries SET is_deleted = TRUE, deleted_at = NOW(), deleted_by = $1 WHERE id = $2',
      [userId, entryId]
    );

    // Audit log
    await logAuditAction('delete_entry', 'entry', entryId, userId, { reason: isAdmin ? 'admin_delete' : 'owner_delete' });

    res.json({ success: true });
  } catch (err) {
    console.error('[DELETE ENTRY ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// REPORT SYSTEM
// ========================================

// Submit a report
app.post('/api/reports', authMiddleware, async (req, res) => {
  const { entry_id, reason, details } = req.body;
  const userId = req.user.userId;

  if (!entry_id || !reason) {
    return res.status(400).json({ success: false, error: 'entry_id and reason required' });
  }

  const validReasons = ['spam', 'harassment', 'inappropriate', 'misinformation', 'other'];
  if (!validReasons.includes(reason)) {
    return res.status(400).json({ success: false, error: 'invalid_reason' });
  }

  try {
    // Check if entry exists
    const entryResult = await db.query('SELECT id FROM entries WHERE id = $1 AND is_deleted = FALSE', [entry_id]);
    if (entryResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'entry_not_found' });
    }

    // Check if user already reported this entry
    const existingReport = await db.query(
      'SELECT id FROM reports WHERE entry_id = $1 AND reporter_id = $2',
      [entry_id, userId]
    );
    if (existingReport.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'already_reported' });
    }

    // Create report
    await db.query(
      `INSERT INTO reports (entry_id, reporter_id, reason, details)
       VALUES ($1, $2, $3, $4)`,
      [entry_id, userId, reason, details || null]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('[REPORT ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get reports
app.get('/api/admin/reports', authMiddleware, adminMiddleware, async (req, res) => {
  const status = req.query.status || 'pending';
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const offset = (page - 1) * limit;

  try {
    const countResult = await db.query(
      'SELECT COUNT(*) FROM reports WHERE status = $1',
      [status]
    );
    const total = parseInt(countResult.rows[0].count);

    const result = await db.query(
      `SELECT r.id, r.entry_id, r.reason, r.details, r.status, r.created_at,
              e.content AS entry_content, e.alias AS entry_alias,
              u.alias AS reporter_alias
       FROM reports r
       JOIN entries e ON e.id = r.entry_id
       JOIN users u ON u.id = r.reporter_id
       WHERE r.status = $1
       ORDER BY r.created_at DESC
       LIMIT $2 OFFSET $3`,
      [status, limit, offset]
    );

    res.json({
      success: true,
      reports: result.rows,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('[GET REPORTS ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Resolve report
app.put('/api/admin/reports/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const reportId = parseInt(req.params.id);
  const { status, action } = req.body;
  const adminId = req.user.userId;

  if (!['resolved', 'dismissed'].includes(status)) {
    return res.status(400).json({ success: false, error: 'invalid_status' });
  }

  try {
    const reportResult = await db.query('SELECT id, entry_id FROM reports WHERE id = $1', [reportId]);
    if (reportResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'report_not_found' });
    }

    // Update report status
    await db.query(
      'UPDATE reports SET status = $1, resolved_by = $2, resolved_at = NOW() WHERE id = $3',
      [status, adminId, reportId]
    );

    // If action is to delete the entry
    if (action === 'delete_entry') {
      const entryId = reportResult.rows[0].entry_id;
      await db.query(
        'UPDATE entries SET is_deleted = TRUE, deleted_at = NOW(), deleted_by = $1 WHERE id = $2',
        [adminId, entryId]
      );
      await logAuditAction('delete_entry', 'entry', entryId, adminId, { reason: 'report_action' });
    }

    await logAuditAction('resolve_report', 'report', reportId, adminId, { status, action });

    res.json({ success: true });
  } catch (err) {
    console.error('[RESOLVE REPORT ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// REACTIONS SYSTEM
// ========================================

const VALID_REACTIONS = ['like', 'dislike'];

// Toggle reaction on an entry
app.post('/api/entries/:id/react', authMiddleware, async (req, res) => {
  const entryId = parseInt(req.params.id);
  const { reaction_type } = req.body;
  const userId = req.user.userId;

  if (!reaction_type || !VALID_REACTIONS.includes(reaction_type)) {
    return res.status(400).json({ success: false, error: 'invalid_reaction' });
  }

  try {
    // Check if entry exists
    const entryResult = await db.query(
      'SELECT id, user_id FROM entries WHERE id = $1 AND (is_deleted = FALSE OR is_deleted IS NULL)',
      [entryId]
    );
    if (entryResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'entry_not_found' });
    }

    // Check if user already has this reaction
    const existingReaction = await db.query(
      'SELECT id FROM reactions WHERE entry_id = $1 AND user_id = $2 AND reaction_type = $3',
      [entryId, userId, reaction_type]
    );

    if (existingReaction.rows.length > 0) {
      // Remove reaction (toggle off)
      await db.query('DELETE FROM reactions WHERE id = $1', [existingReaction.rows[0].id]);
      res.json({ success: true, action: 'removed' });
    } else {
      // Add reaction
      await db.query(
        'INSERT INTO reactions (entry_id, user_id, reaction_type) VALUES ($1, $2, $3)',
        [entryId, userId, reaction_type]
      );

      // Create notification for entry owner (if not self)
      const entryOwner = entryResult.rows[0].user_id;
      if (entryOwner && entryOwner !== userId) {
        // Get reactor alias
        const reactorResult = await db.query('SELECT alias FROM users WHERE id = $1', [userId]);
        const reactorAlias = reactorResult.rows[0]?.alias || 'Someone';
        
        // Get thread info for link
        const threadResult = await db.query(
          'SELECT t.id FROM threads t JOIN entries e ON e.thread_id = t.id WHERE e.id = $1',
          [entryId]
        );
        const threadId = threadResult.rows[0]?.id;

        await db.query(
          `INSERT INTO notifications (user_id, type, title, message, link, related_entry_id, related_user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [entryOwner, 'reaction', `${reactorAlias} reacted to your post`, 
           `${reaction_type.toUpperCase()} reaction`, 
           threadId ? `thread.html?id=${threadId}` : null,
           entryId, userId]
        );
      }

      res.json({ success: true, action: 'added' });
    }
  } catch (err) {
    console.error('[REACTION ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get reactions for an entry
app.get('/api/entries/:id/reactions', async (req, res) => {
  const entryId = parseInt(req.params.id);

  try {
    const result = await db.query(
      `SELECT reaction_type, COUNT(*) as count
       FROM reactions WHERE entry_id = $1
       GROUP BY reaction_type`,
      [entryId]
    );

    const reactions = {};
    result.rows.forEach(row => {
      reactions[row.reaction_type] = parseInt(row.count);
    });

    res.json({ success: true, reactions });
  } catch (err) {
    console.error('[GET REACTIONS ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// NOTIFICATIONS SYSTEM
// ========================================

// Get user notifications
app.get('/api/notifications', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const offset = (page - 1) * limit;

  try {
    const countResult = await db.query(
      'SELECT COUNT(*) FROM notifications WHERE user_id = $1',
      [userId]
    );
    const total = parseInt(countResult.rows[0].count);

    const unreadResult = await db.query(
      'SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = FALSE',
      [userId]
    );
    const unreadCount = parseInt(unreadResult.rows[0].count);

    const result = await db.query(
      `SELECT id, type, title, message, link, is_read, created_at
       FROM notifications
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    res.json({
      success: true,
      notifications: result.rows,
      unreadCount,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('[GET NOTIFICATIONS ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authMiddleware, async (req, res) => {
  const notificationId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    await db.query(
      'UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2',
      [notificationId, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('[MARK READ ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Mark all notifications as read
app.put('/api/notifications/read-all', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    await db.query(
      'UPDATE notifications SET is_read = TRUE WHERE user_id = $1',
      [userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('[MARK ALL READ ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get unread notification count
app.get('/api/notifications/unread-count', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    const result = await db.query(
      'SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = FALSE',
      [userId]
    );
    res.json({ success: true, count: parseInt(result.rows[0].count) });
  } catch (err) {
    console.error('[UNREAD COUNT ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// BOOKMARKS SYSTEM
// ========================================

// Get user's bookmarks
app.get('/api/bookmarks', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    const result = await db.query(
      `SELECT b.id, b.thread_id, b.created_at, t.title, t.slug, r.slug as room_slug,
              (SELECT COUNT(*) FROM entries e WHERE e.thread_id = t.id AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)) as entry_count
       FROM bookmarks b
       JOIN threads t ON t.id = b.thread_id
       JOIN rooms r ON r.id = t.room_id
       WHERE b.user_id = $1
       ORDER BY b.created_at DESC`,
      [userId]
    );

    res.json({ success: true, bookmarks: result.rows });
  } catch (err) {
    console.error('[GET BOOKMARKS ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Toggle bookmark
app.post('/api/bookmarks/:threadId', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.threadId);
  const userId = req.user.userId;

  try {
    // Check if thread exists
    const threadResult = await db.query('SELECT id FROM threads WHERE id = $1', [threadId]);
    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }

    // Check if already bookmarked
    const existing = await db.query(
      'SELECT id FROM bookmarks WHERE user_id = $1 AND thread_id = $2',
      [userId, threadId]
    );

    if (existing.rows.length > 0) {
      // Remove bookmark
      await db.query('DELETE FROM bookmarks WHERE id = $1', [existing.rows[0].id]);
      res.json({ success: true, action: 'removed' });
    } else {
      // Add bookmark
      await db.query(
        'INSERT INTO bookmarks (user_id, thread_id) VALUES ($1, $2)',
        [userId, threadId]
      );
      res.json({ success: true, action: 'added' });
    }
  } catch (err) {
    console.error('[TOGGLE BOOKMARK ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Check if thread is bookmarked
app.get('/api/bookmarks/:threadId/check', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.threadId);
  const userId = req.user.userId;

  try {
    const result = await db.query(
      'SELECT id FROM bookmarks WHERE user_id = $1 AND thread_id = $2',
      [userId, threadId]
    );
    res.json({ success: true, isBookmarked: result.rows.length > 0 });
  } catch (err) {
    console.error('[CHECK BOOKMARK ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// PRIVATE MESSAGES SYSTEM
// ========================================

// Get conversations (inbox)
app.get('/api/messages', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const folder = req.query.folder || 'inbox'; // inbox or sent

  try {
    let result;
    if (folder === 'sent') {
      result = await db.query(
        `SELECT pm.id, pm.subject, pm.content, pm.is_read, pm.created_at,
                u.id as recipient_id, u.alias as recipient_alias
         FROM private_messages pm
         JOIN users u ON u.id = pm.recipient_id
         WHERE pm.sender_id = $1 AND pm.deleted_by_sender = FALSE
         ORDER BY pm.created_at DESC`,
        [userId]
      );
    } else {
      result = await db.query(
        `SELECT pm.id, pm.subject, pm.content, pm.is_read, pm.created_at,
                u.id as sender_id, u.alias as sender_alias
         FROM private_messages pm
         JOIN users u ON u.id = pm.sender_id
         WHERE pm.recipient_id = $1 AND pm.deleted_by_recipient = FALSE
         ORDER BY pm.created_at DESC`,
        [userId]
      );
    }

    res.json({ success: true, messages: result.rows, folder });
  } catch (err) {
    console.error('[GET MESSAGES ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get single message
app.get('/api/messages/:id', authMiddleware, async (req, res) => {
  const messageId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    const result = await db.query(
      `SELECT pm.*, 
              sender.alias as sender_alias, 
              recipient.alias as recipient_alias
       FROM private_messages pm
       JOIN users sender ON sender.id = pm.sender_id
       JOIN users recipient ON recipient.id = pm.recipient_id
       WHERE pm.id = $1 AND (pm.sender_id = $2 OR pm.recipient_id = $2)`,
      [messageId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'message_not_found' });
    }

    const message = result.rows[0];

    // Mark as read if recipient
    if (message.recipient_id === userId && !message.is_read) {
      await db.query('UPDATE private_messages SET is_read = TRUE WHERE id = $1', [messageId]);
      message.is_read = true;
    }

    res.json({ success: true, message });
  } catch (err) {
    console.error('[GET MESSAGE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Send message
app.post('/api/messages', authMiddleware, async (req, res) => {
  const { recipient_alias, subject, content } = req.body;
  const senderId = req.user.userId;

  if (!recipient_alias || !content) {
    return res.status(400).json({ success: false, error: 'recipient and content required' });
  }

  if (content.length > 5000) {
    return res.status(400).json({ success: false, error: 'message too long (max 5000 chars)' });
  }

  try {
    // Find recipient
    const recipientResult = await db.query(
      'SELECT id, alias FROM users WHERE LOWER(alias) = LOWER($1)',
      [recipient_alias]
    );

    if (recipientResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }

    const recipientId = recipientResult.rows[0].id;

    // Can't message yourself
    if (recipientId === senderId) {
      return res.status(400).json({ success: false, error: 'cannot_message_self' });
    }

    // Create message
    const insertResult = await db.query(
      `INSERT INTO private_messages (sender_id, recipient_id, subject, content)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [senderId, recipientId, subject || null, content]
    );

    // Create notification for recipient
    const senderResult = await db.query('SELECT alias FROM users WHERE id = $1', [senderId]);
    const senderAlias = senderResult.rows[0]?.alias || 'Someone';

    await db.query(
      `INSERT INTO notifications (user_id, type, title, message, link, related_user_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [recipientId, 'private_message', `New message from ${senderAlias}`,
       subject || content.substring(0, 50),
       'messages.html', senderId]
    );

    res.json({ success: true, messageId: insertResult.rows[0].id });
  } catch (err) {
    console.error('[SEND MESSAGE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Delete message
app.delete('/api/messages/:id', authMiddleware, async (req, res) => {
  const messageId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    const result = await db.query(
      'SELECT sender_id, recipient_id FROM private_messages WHERE id = $1',
      [messageId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'message_not_found' });
    }

    const message = result.rows[0];

    if (message.sender_id === userId) {
      await db.query('UPDATE private_messages SET deleted_by_sender = TRUE WHERE id = $1', [messageId]);
    } else if (message.recipient_id === userId) {
      await db.query('UPDATE private_messages SET deleted_by_recipient = TRUE WHERE id = $1', [messageId]);
    } else {
      return res.status(403).json({ success: false, error: 'not_authorized' });
    }

    res.json({ success: true });
  } catch (err) {
    console.error('[DELETE MESSAGE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get unread message count
app.get('/api/messages/unread-count', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    const result = await db.query(
      'SELECT COUNT(*) FROM private_messages WHERE recipient_id = $1 AND is_read = FALSE AND deleted_by_recipient = FALSE',
      [userId]
    );
    res.json({ success: true, count: parseInt(result.rows[0].count) });
  } catch (err) {
    console.error('[UNREAD MSG COUNT ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Legacy protected routes (kept for compatibility)
app.get('/forum', authMiddleware, (req, res) => {
  res.json({ user: req.user, data: null });
});

app.get('/room/:id', authMiddleware, (req, res) => {
  res.json({ user: req.user, roomId: req.params.id, data: null });
});

app.get('/thread/:id', authMiddleware, (req, res) => {
  res.json({ user: req.user, threadId: req.params.id, data: null });
});

// ========================================
// ADMIN ENDPOINTS
// ========================================

// Admin: Get all shadow-banned posts
app.get('/api/admin/entries/shadow-banned', authMiddleware, adminMiddleware, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const offset = (page - 1) * limit;

  try {
    const countResult = await db.query(
      'SELECT COUNT(*) FROM entries WHERE shadow_banned = TRUE'
    );
    const total = parseInt(countResult.rows[0].count);

    const result = await db.query(
      `SELECT e.id, e.alias, e.content, e.ip_hash, e.created_at, t.slug AS thread_slug, t.title AS thread_title
       FROM entries e
       JOIN threads t ON t.id = e.thread_id
       WHERE e.shadow_banned = TRUE
       ORDER BY e.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    res.json({
      success: true,
      entries: result.rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Update entry shadow_banned status
app.patch('/api/admin/entries/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const entryId = parseInt(req.params.id);
  const { shadow_banned } = req.body;

  if (typeof shadow_banned !== 'boolean') {
    return res.status(400).json({ success: false, error: 'invalid_shadow_banned' });
  }

  try {
    const result = await db.query(
      `UPDATE entries SET shadow_banned = $1 WHERE id = $2 RETURNING id, shadow_banned`,
      [shadow_banned, entryId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'entry_not_found' });
    }

    await logAudit(
      shadow_banned ? 'shadow_ban' : 'unshadow_ban',
      'entry',
      entryId,
      req.user.userId,
      { shadow_banned }
    );

    res.json({ success: true, entry: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get threads with slow_mode settings
app.get('/api/admin/threads', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT t.id, t.slug, t.title, t.slow_mode_interval, r.slug AS room_slug, r.title AS room_title
       FROM threads t
       JOIN rooms r ON r.id = t.room_id
       ORDER BY t.id`
    );

    res.json({ success: true, threads: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Update thread slow_mode_interval
app.patch('/api/admin/threads/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const threadSlug = req.params.id;
  const { slow_mode_interval } = req.body;

  // Validate: null (disabled) or positive integer
  if (slow_mode_interval !== null && (!Number.isInteger(slow_mode_interval) || slow_mode_interval < 0)) {
    return res.status(400).json({ success: false, error: 'invalid_slow_mode_interval' });
  }

  try {
    const result = await db.query(
      `UPDATE threads SET slow_mode_interval = $1 WHERE slug = $2 RETURNING id, slug, slow_mode_interval`,
      [slow_mode_interval, threadSlug]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }

    await logAudit(
      'update_slow_mode',
      'thread',
      result.rows[0].id,
      req.user.userId,
      { slow_mode_interval }
    );

    res.json({ success: true, thread: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Delete thread and all its entries
app.delete('/api/admin/threads/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const threadId = req.params.id;
  const isNumeric = /^\d+$/.test(threadId);

  try {
    // Find thread
    const threadResult = await db.query(
      `SELECT id, title FROM threads WHERE ${isNumeric ? 'id = $1' : 'slug = $1'}`,
      [isNumeric ? parseInt(threadId) : threadId]
    );

    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }

    const thread = threadResult.rows[0];

    // Delete all entries in the thread first
    await db.query('DELETE FROM entries WHERE thread_id = $1', [thread.id]);

    // Delete the thread
    await db.query('DELETE FROM threads WHERE id = $1', [thread.id]);

    await logAudit(
      'delete_thread',
      'thread',
      thread.id,
      req.user.userId,
      { title: thread.title }
    );

    res.json({ success: true, message: 'Thread deleted' });
  } catch (err) {
    console.error('[DELETE THREAD ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get audit log
app.get('/api/admin/audit', authMiddleware, adminMiddleware, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const offset = (page - 1) * limit;

  try {
    const countResult = await db.query('SELECT COUNT(*) FROM audit_log');
    const total = parseInt(countResult.rows[0].count);

    const result = await db.query(
      `SELECT a.*, u.alias AS admin_alias
       FROM audit_log a
       LEFT JOIN users u ON u.id = a.admin_id
       ORDER BY a.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    res.json({
      success: true,
      logs: result.rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get post audit (ip_hash, alias tracking)
app.get('/api/admin/post-audit', authMiddleware, adminMiddleware, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const offset = (page - 1) * limit;
  const ipHash = req.query.ip_hash || null;
  const aliasFilter = req.query.alias || null;

  try {
    let countQuery = 'SELECT COUNT(*) FROM post_audit';
    let dataQuery = `SELECT pa.*, e.content, t.slug AS thread_slug
                     FROM post_audit pa
                     JOIN entries e ON e.id = pa.entry_id
                     JOIN threads t ON t.id = e.thread_id`;
    const params = [];
    const conditions = [];

    if (ipHash) {
      conditions.push(`pa.ip_hash = $${params.length + 1}`);
      params.push(ipHash);
    }
    if (aliasFilter) {
      conditions.push(`pa.alias ILIKE $${params.length + 1}`);
      params.push('%' + aliasFilter + '%');
    }

    if (conditions.length > 0) {
      const whereClause = ' WHERE ' + conditions.join(' AND ');
      countQuery += whereClause;
      dataQuery += whereClause;
    }

    dataQuery += ` ORDER BY pa.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    
    const countResult = await db.query(countQuery, params);
    const total = parseInt(countResult.rows[0].count);

    params.push(limit, offset);
    const result = await db.query(dataQuery, params);

    res.json({
      success: true,
      posts: result.rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Auto-migrate database tables on startup
async function migrate() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        alias VARCHAR(50) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        bio TEXT,
        avatar_config JSONB,
        is_admin BOOLEAN DEFAULT FALSE,
        is_shadow_banned BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Add columns if they don't exist
      ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_config JSONB;
      
      CREATE TABLE IF NOT EXISTS rooms (
        id SERIAL PRIMARY KEY,
        slug VARCHAR(50) UNIQUE NOT NULL,
        title VARCHAR(100) NOT NULL,
        slow_mode_seconds INTEGER DEFAULT 0
      );
      
      CREATE TABLE IF NOT EXISTS threads (
        id SERIAL PRIMARY KEY,
        room_id INTEGER REFERENCES rooms(id),
        title VARCHAR(200) NOT NULL,
        slug VARCHAR(100),
        user_id INTEGER REFERENCES users(id),
        slow_mode_interval INTEGER DEFAULT 0,
        is_locked BOOLEAN DEFAULT FALSE,
        is_pinned BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Add columns if they don't exist
      ALTER TABLE threads ADD COLUMN IF NOT EXISTS slug VARCHAR(100);
      ALTER TABLE threads ADD COLUMN IF NOT EXISTS slow_mode_interval INTEGER DEFAULT 0;
      
      CREATE TABLE IF NOT EXISTS entries (
        id SERIAL PRIMARY KEY,
        thread_id INTEGER REFERENCES threads(id),
        user_id INTEGER REFERENCES users(id),
        content TEXT NOT NULL,
        alias VARCHAR(50),
        avatar_config JSONB,
        ip_hash VARCHAR(64),
        is_hidden BOOLEAN DEFAULT FALSE,
        is_deleted BOOLEAN DEFAULT FALSE,
        shadow_banned BOOLEAN DEFAULT FALSE,
        edited_at TIMESTAMP,
        deleted_at TIMESTAMP,
        deleted_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Add columns if they don't exist (for existing databases)
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS alias VARCHAR(50);
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS avatar_config JSONB;
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS ip_hash VARCHAR(64);
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS shadow_banned BOOLEAN DEFAULT FALSE;
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE;
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS edited_at TIMESTAMP;
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);
      
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        action VARCHAR(50) NOT NULL,
        target_type VARCHAR(20),
        target_id INTEGER,
        admin_id INTEGER REFERENCES users(id),
        details JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS reports (
        id SERIAL PRIMARY KEY,
        entry_id INTEGER REFERENCES entries(id),
        reporter_id INTEGER REFERENCES users(id),
        reason VARCHAR(50) NOT NULL,
        details TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        resolved_by INTEGER REFERENCES users(id),
        resolved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS reactions (
        id SERIAL PRIMARY KEY,
        entry_id INTEGER REFERENCES entries(id),
        user_id INTEGER REFERENCES users(id),
        reaction_type VARCHAR(20) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(entry_id, user_id, reaction_type)
      );
      
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        type VARCHAR(50) NOT NULL,
        title TEXT NOT NULL,
        message TEXT,
        link TEXT,
        is_read BOOLEAN DEFAULT FALSE,
        related_entry_id INTEGER REFERENCES entries(id),
        related_user_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS bookmarks (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        thread_id INTEGER REFERENCES threads(id),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, thread_id)
      );
      
      CREATE TABLE IF NOT EXISTS private_messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id),
        recipient_id INTEGER REFERENCES users(id),
        subject VARCHAR(200),
        content TEXT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        deleted_by_sender BOOLEAN DEFAULT FALSE,
        deleted_by_recipient BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      INSERT INTO rooms (slug, title) VALUES 
        ('general', 'General Discussion'),
        ('tech', 'Technology'),
        ('random', 'Random')
      ON CONFLICT (slug) DO NOTHING;
    `);
    console.log('[MIGRATE] Database tables ready');
  } catch (err) {
    console.error('[MIGRATE ERROR]', err.message);
  }
}

// Start server
migrate().then(() => {
  app.listen(PORT, () => {
    console.log('[SERVER] Port ' + PORT);
  });
});
