require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
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

app.use(express.json());

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
      'SELECT id, alias, password_hash FROM users WHERE alias = $1',
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
      { userId: user.id, alias: user.alias },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({ success: true, token });
  } catch (err) {
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
    let threadsQuery = `SELECT t.slug AS id, t.title, COUNT(e.id) FILTER (WHERE e.shadow_banned = FALSE OR e.shadow_banned IS NULL)::int AS "entriesCount"
       FROM threads t
       LEFT JOIN entries e ON e.thread_id = t.id
       WHERE t.room_id = $1`;
    let queryParams = [room.id];
    
    if (search) {
      threadsQuery += ` AND (t.title ILIKE $2 OR t.slug ILIKE $2)`;
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
  const threadSlug = req.params.id;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 30, 100);
  const offset = (page - 1) * limit;
  
  try {
    const threadResult = await db.query(
      `SELECT t.id, t.slug, t.title, t.slow_mode_interval, r.slug AS room_slug
       FROM threads t
       JOIN rooms r ON r.id = t.room_id
       WHERE t.slug = $1`,
      [threadSlug]
    );
    
    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }
    
    const thread = threadResult.rows[0];

    // Count total entries
    const countResult = await db.query(
      `SELECT COUNT(*) FROM entries WHERE thread_id = $1 AND (shadow_banned = FALSE OR shadow_banned IS NULL)`,
      [thread.id]
    );
    const total = parseInt(countResult.rows[0].count);
    
    const entriesResult = await db.query(
      `SELECT e.id, COALESCE(u.alias, e.alias) AS alias, e.content, e.avatar_config,
              LENGTH(e.content) > $2 AS "exceedsCharLimit"
       FROM entries e
       LEFT JOIN users u ON u.id = e.user_id
       WHERE e.thread_id = $1 AND (e.shadow_banned = FALSE OR e.shadow_banned IS NULL)
       ORDER BY e.created_at
       LIMIT $3 OFFSET $4`,
      [thread.id, CONTENT_CHAR_LIMIT, limit, offset]
    );
    
    res.json({
      success: true,
      thread: {
        id: thread.slug,
        title: thread.title,
        roomId: thread.room_slug,
        slowModeInterval: thread.slow_mode_interval || null
      },
      entries: entriesResult.rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
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

// API: Create entry (anonymous posting)
app.post('/api/entries', authMiddleware, entriesLimiter, async (req, res) => {
  const { thread_id, content, alias, avatar_config } = req.body;

  if (!thread_id || !content || !alias) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }

  // Validate alias format
  const aliasRegex = /^[a-zA-Z0-9_\-.]{3,20}$/;
  if (!aliasRegex.test(alias)) {
    return res.status(400).json({
      success: false,
      error: 'invalid_alias',
      message: 'Alias must be 3-20 characters using only letters, numbers, underscores, hyphens, and periods.'
    });
  }

  const clientIp = getClientIp(req);
  const ipHash = hashIp(clientIp);

  try {
    // Verify thread exists and get slow-mode settings
    const threadResult = await db.query(
      'SELECT id, slow_mode_interval FROM threads WHERE slug = $1',
      [thread_id]
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

    const insertResult = await db.query(
      `INSERT INTO entries (thread_id, content, alias, avatar_config, user_id, ip_hash, shadow_banned)
       VALUES ($1, $2, $3, $4, NULL, $5, FALSE)
       RETURNING id, thread_id AS "threadId", content, alias, avatar_config AS "avatarConfig", created_at AS "createdAt"`,
      [threadDbId, content, alias, avatar_config || null, ipHash]
    );

    // Audit log for post tracking
    const entryId = insertResult.rows[0].id;
    try {
      await db.query(
        `INSERT INTO post_audit (entry_id, ip_hash, alias, content_length)
         VALUES ($1, $2, $3, $4)`,
        [entryId, ipHash, alias, content.length]
      );
    } catch (auditErr) {
      // Silent fail - audit should not break posting
    }

    res.json({ success: true, entry: insertResult.rows[0] });
  } catch (err) {
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

// Start server
app.listen(PORT, () => {
  console.log('[SERVER] Port ' + PORT);
});
