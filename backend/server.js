require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = '1h';

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

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

// API: Get threads in a room
app.get('/api/room/:id', authMiddleware, async (req, res) => {
  const roomSlug = req.params.id;
  
  try {
    const roomResult = await db.query(
      'SELECT id, slug, title FROM rooms WHERE slug = $1',
      [roomSlug]
    );
    
    if (roomResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'room_not_found' });
    }
    
    const room = roomResult.rows[0];
    
    const threadsResult = await db.query(
      `SELECT t.slug AS id, t.title, COUNT(e.id)::int AS "entriesCount"
       FROM threads t
       LEFT JOIN entries e ON e.thread_id = t.id
       WHERE t.room_id = $1
       GROUP BY t.id
       ORDER BY t.id`,
      [room.id]
    );
    
    res.json({
      success: true,
      room: { id: room.slug, title: room.title },
      threads: threadsResult.rows
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get entries in a thread
app.get('/api/thread/:id', authMiddleware, async (req, res) => {
  const threadSlug = req.params.id;
  
  try {
    const threadResult = await db.query(
      `SELECT t.id, t.slug, t.title, r.slug AS room_slug
       FROM threads t
       JOIN rooms r ON r.id = t.room_id
       WHERE t.slug = $1`,
      [threadSlug]
    );
    
    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }
    
    const thread = threadResult.rows[0];
    
    const entriesResult = await db.query(
      `SELECT e.id, e.user_id AS "userId", u.alias, e.content, e.avatar_config AS "avatarConfig"
       FROM entries e
       JOIN users u ON u.id = e.user_id
       WHERE e.thread_id = $1
       ORDER BY e.created_at`,
      [thread.id]
    );
    
    res.json({
      success: true,
      thread: {
        id: thread.slug,
        title: thread.title,
        roomId: thread.room_slug
      },
      entries: entriesResult.rows
    });
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

// Start server
app.listen(PORT, () => {
  console.log('[SERVER] Port ' + PORT);
});
