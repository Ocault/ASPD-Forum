require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const path = require('path');
const fs = require('fs');
const db = require('./db');

// Optional 2FA dependencies - gracefully degrade if not installed
let speakeasy = null;
let qrcode = null;
try {
  speakeasy = require('speakeasy');
  qrcode = require('qrcode');
  console.log('[2FA] speakeasy and qrcode loaded successfully');
} catch (err) {
  console.log('[2FA] speakeasy/qrcode not installed - 2FA features disabled');
}

// Optional web-push for push notifications
let webpush = null;
try {
  webpush = require('web-push');
  if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    webpush.setVapidDetails(
      process.env.VAPID_SUBJECT || 'mailto:admin@aspdforum.com',
      process.env.VAPID_PUBLIC_KEY,
      process.env.VAPID_PRIVATE_KEY
    );
    console.log('[PUSH] Web push configured successfully');
  } else {
    console.log('[PUSH] VAPID keys not configured - push notifications disabled');
    webpush = null;
  }
} catch (err) {
  console.log('[PUSH] web-push not installed - push notifications disabled');
}

// Optional multer for file uploads
let multer = null;
let upload = null;
try {
  multer = require('multer');
  // Configure multer for image uploads
  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      const uploadDir = path.join(__dirname, '..', 'uploads');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now() + '-' + crypto.randomBytes(8).toString('hex');
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, uniqueSuffix + ext);
    }
  });
  
  const fileFilter = function (req, file, cb) {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.'), false);
    }
  };
  
  upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
      fileSize: 5 * 1024 * 1024 // 5MB max
    }
  });
  console.log('[UPLOAD] Multer configured for image uploads');
} catch (err) {
  console.log('[UPLOAD] multer not installed - image uploads disabled');
}

const app = express();
const PORT = process.env.PORT || 3001;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = '1h';
const JWT_REFRESH_EXPIRES = '7d'; // Refresh tokens last 7 days

// ========================================
// STRUCTURED LOGGING
// ========================================
const LOG_LEVELS = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3 };
const currentLogLevel = LOG_LEVELS[process.env.LOG_LEVEL?.toUpperCase()] ?? LOG_LEVELS.INFO;

function formatLog(level, category, message, meta = {}) {
  const timestamp = new Date().toISOString();
  const reqId = meta.reqId || '-';
  const metaStr = Object.keys(meta).filter(k => k !== 'reqId').length > 0
    ? ' ' + JSON.stringify(meta)
    : '';
  return `${timestamp} [${level}] [${category}] [${reqId}] ${message}${metaStr}`;
}

const logger = {
  error: (category, message, meta = {}) => {
    if (currentLogLevel >= LOG_LEVELS.ERROR) console.error(formatLog('ERROR', category, message, meta));
  },
  warn: (category, message, meta = {}) => {
    if (currentLogLevel >= LOG_LEVELS.WARN) console.warn(formatLog('WARN', category, message, meta));
  },
  info: (category, message, meta = {}) => {
    if (currentLogLevel >= LOG_LEVELS.INFO) console.log(formatLog('INFO', category, message, meta));
  },
  debug: (category, message, meta = {}) => {
    if (currentLogLevel >= LOG_LEVELS.DEBUG) console.log(formatLog('DEBUG', category, message, meta));
  }
};

// Request ID middleware
app.use((req, res, next) => {
  req.reqId = crypto.randomBytes(8).toString('hex');
  res.setHeader('X-Request-ID', req.reqId);
  next();
});

// CRITICAL: Validate JWT_SECRET on startup
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  logger.error('STARTUP', 'JWT_SECRET must be set and at least 32 characters');
  process.exit(1);
}

// Security headers with helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:", "/uploads/"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false, // Disabled to allow images
  crossOriginResourcePolicy: { policy: "same-origin" },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: "deny" },
  hidePoweredBy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: "none" },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  xssFilter: true
}));

// Serve uploaded images
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));

// Email transporter configuration - using Resend HTTP API instead of SMTP
// (Railway blocks outbound SMTP ports)

// Send email helper using Resend HTTP API
async function sendEmail(to, subject, html) {
  if (!process.env.RESEND_API_KEY) {
    console.error('[EMAIL] RESEND_API_KEY not configured');
    return false;
  }
  
  const fromAddress = process.env.EMAIL_FROM || 'ASPD Forum <onboarding@resend.dev>';
  console.log('[EMAIL] Sending from:', fromAddress, 'to:', to);
  
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: fromAddress,
        to: [to],
        subject: subject,
        html: html
      })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      console.log('[EMAIL] Sent successfully:', data.id);
      return true;
    } else {
      console.error('[EMAIL ERROR]', data);
      return false;
    }
  } catch (err) {
    console.error('[EMAIL ERROR]', err.message);
    return false;
  }
}

// Send notification email (for replies, mentions, DMs)
async function sendNotificationEmail(userId, type, title, preview, link) {
  try {
    // Get user's email settings
    const userResult = await db.query(
      'SELECT email, email_verified, notification_replies, notification_mentions, notification_messages FROM users WHERE id = $1',
      [userId]
    );
    
    if (userResult.rows.length === 0) return;
    const user = userResult.rows[0];
    
    // Check if user has verified email and enabled notifications
    if (!user.email || !user.email_verified) return;
    
    // Check notification preferences
    if (type === 'thread_reply' && !user.notification_replies) return;
    if (type === 'mention' && !user.notification_mentions) return;
    if (type === 'private_message' && !user.notification_messages) return;
    
    const siteUrl = 'https://www.aspdforum.com';
    const fullLink = link.startsWith('http') ? link : `${siteUrl}/${link}`;
    
    const emailHtml = `
      <div style="background: #0a0a0a; padding: 40px 20px; font-family: 'Courier New', monospace;">
        <div style="max-width: 500px; margin: 0 auto; background: #0f0f0f; border: 1px solid #1a1a1a; padding: 30px;">
          <div style="text-align: center; margin-bottom: 20px;">
            <svg width="40" height="40" viewBox="0 0 100 100" style="opacity: 0.15;">
              <polygon points="50,5 95,27.5 95,72.5 50,95 5,72.5 5,27.5" fill="none" stroke="#404040" stroke-width="2"/>
            </svg>
          </div>
          <h2 style="color: #606060; font-size: 14px; text-align: center; letter-spacing: 0.1em; margin: 0 0 20px;">
            ${title}
          </h2>
          <p style="color: #404040; font-size: 12px; line-height: 1.6; margin: 0 0 20px;">
            ${preview.substring(0, 200)}${preview.length > 200 ? '...' : ''}
          </p>
          <div style="text-align: center;">
            <a href="${fullLink}" style="display: inline-block; padding: 10px 20px; background: #1a1a1a; border: 1px solid #303030; color: #606060; text-decoration: none; font-size: 11px; letter-spacing: 0.1em;">
              VIEW ON FORUM
            </a>
          </div>
          <p style="color: #303030; font-size: 10px; text-align: center; margin-top: 30px;">
            You can manage your notification settings in your <a href="${siteUrl}/profile.html" style="color: #404040;">profile</a>.
          </p>
        </div>
      </div>
    `;
    
    await sendEmail(user.email, `[ASPD Forum] ${title}`, emailHtml);
  } catch (err) {
    console.error('[NOTIFICATION EMAIL ERROR]', err.message);
  }
}

// XSS Sanitization helper
function sanitizeContent(content) {
  return sanitizeHtml(content, {
    allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre', 'blockquote'],
    allowedAttributes: {
      'a': ['href', 'target', 'rel']
    },
    allowedSchemes: ['http', 'https'],
    transformTags: {
      'a': function(tagName, attribs) {
        return {
          tagName: 'a',
          attribs: {
            href: attribs.href,
            target: '_blank',
            rel: 'noopener noreferrer nofollow'
          }
        };
      }
    }
  });
}

// Middleware
const allowedOrigins = [
  'https://www.aspdforum.com',
  'https://aspdforum.com'
];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (same-origin, mobile apps, curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    return callback(new Error('CORS not allowed'), false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true
}));

app.use(express.json({ limit: '2mb' }));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 400 ? 'warn' : 'info';
    logger[level]('HTTP', `${req.method} ${req.path} ${res.statusCode}`, {
      reqId: req.reqId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${duration}ms`
    });
  });
  next();
});

// CSRF Protection - validate Origin header for state-changing requests
const ALLOWED_ORIGINS = [
  'https://www.aspdforum.com',
  'https://aspdforum.com',
  process.env.CORS_ORIGIN
].filter(Boolean);

app.use((req, res, next) => {
  // Skip for GET, HEAD, OPTIONS (safe methods)
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  const origin = req.get('Origin');
  const referer = req.get('Referer');
  
  // In production, require valid Origin or Referer
  if (process.env.NODE_ENV === 'production') {
    if (!origin && !referer) {
      // Allow requests from same origin (no Origin header means same-origin in some cases)
      return next();
    }
    
    const requestOrigin = origin || (referer ? new URL(referer).origin : null);
    
    if (requestOrigin && !ALLOWED_ORIGINS.includes(requestOrigin)) {
      console.warn('[CSRF] Blocked request from:', requestOrigin);
      return res.status(403).json({ success: false, error: 'forbidden' });
    }
  }
  
  next();
});

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

// Word filter cache (refreshed periodically)
let wordFiltersCache = [];
let wordFiltersCacheTime = 0;
const WORD_FILTER_CACHE_TTL = 60000; // 1 minute

// Rooms cache (refreshed every 5 minutes)
let roomsCache = null;
let roomsCacheTime = 0;
const ROOMS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

async function getCachedRooms() {
  const now = Date.now();
  if (roomsCache && now - roomsCacheTime < ROOMS_CACHE_TTL) {
    return roomsCache;
  }
  try {
    const result = await db.query(
      `SELECT slug AS id, title, description,
              (SELECT COUNT(*) FROM threads WHERE room_id = rooms.id) as thread_count
       FROM rooms ORDER BY display_order, id`
    );
    roomsCache = result.rows;
    roomsCacheTime = now;
    return roomsCache;
  } catch (err) {
    return roomsCache || []; // Return stale cache on error
  }
}

// Tags cache (refreshed every 10 minutes)
let tagsCache = null;
let tagsCacheTime = 0;
const TAGS_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

async function getCachedTags() {
  const now = Date.now();
  if (tagsCache && now - tagsCacheTime < TAGS_CACHE_TTL) {
    return tagsCache;
  }
  try {
    const result = await db.query('SELECT id, name, color FROM tags ORDER BY name');
    tagsCache = result.rows;
    tagsCacheTime = now;
    return tagsCache;
  } catch (err) {
    return tagsCache || []; // Return stale cache on error
  }
}

// Invalidate caches when data changes
function invalidateRoomsCache() { roomsCache = null; roomsCacheTime = 0; }
function invalidateTagsCache() { tagsCache = null; tagsCacheTime = 0; }

async function getWordFilters() {
  const now = Date.now();
  if (now - wordFiltersCacheTime < WORD_FILTER_CACHE_TTL && wordFiltersCache.length > 0) {
    return wordFiltersCache;
  }
  try {
    const result = await db.query('SELECT word, replacement, is_regex FROM word_filters');
    wordFiltersCache = result.rows;
    wordFiltersCacheTime = now;
    return wordFiltersCache;
  } catch (err) {
    return wordFiltersCache; // Return stale cache on error
  }
}

// Apply word filter to content
async function filterContent(content) {
  if (!content) return content;
  const filters = await getWordFilters();
  let filtered = content;
  for (const f of filters) {
    try {
      if (f.is_regex) {
        const regex = new RegExp(f.word, 'gi');
        filtered = filtered.replace(regex, f.replacement || '***');
      } else {
        const regex = new RegExp(f.word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        filtered = filtered.replace(regex, f.replacement || '***');
      }
    } catch (err) {
      // Skip invalid regex
    }
  }
  return filtered;
}

// IP ban check middleware
async function ipBanMiddleware(req, res, next) {
  const ip = getClientIp(req);
  if (!ip) return next();
  
  const ipHash = hashIp(ip);
  try {
    const result = await db.query(
      `SELECT id FROM ip_bans 
       WHERE ip_hash = $1 AND (expires_at IS NULL OR expires_at > NOW())`,
      [ipHash]
    );
    if (result.rows.length > 0) {
      return res.status(403).json({ error: 'ip_banned' });
    }
    next();
  } catch (err) {
    next(); // Don't block on DB errors
  }
}

// User ban check middleware (after auth)
async function userBanMiddleware(req, res, next) {
  if (!req.user || !req.user.userId) return next();
  
  try {
    const result = await db.query(
      `SELECT is_banned, ban_reason, ban_expires_at FROM users WHERE id = $1`,
      [req.user.userId]
    );
    if (result.rows.length > 0) {
      const user = result.rows[0];
      if (user.is_banned) {
        // Check if temp ban expired
        if (user.ban_expires_at && new Date(user.ban_expires_at) < new Date()) {
          // Unban automatically
          await db.query(
            'UPDATE users SET is_banned = FALSE, ban_reason = NULL, ban_expires_at = NULL WHERE id = $1',
            [req.user.userId]
          );
          return next();
        }
        return res.status(403).json({ 
          error: 'user_banned', 
          reason: user.ban_reason,
          expires_at: user.ban_expires_at
        });
      }
    }
    next();
  } catch (err) {
    next();
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

// Rate limiting for auth endpoints (security: prevent brute force)
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: { success: false, error: 'too_many_attempts', message: 'Too many attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => hashIp(getClientIp(req)) || 'unknown'
});

// Strict rate limiter for repeated failures
const strictAuthLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 failed attempts triggers lockout
  message: { success: false, error: 'account_locked', message: 'Too many failed attempts, account temporarily locked' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => hashIp(getClientIp(req)) || 'unknown',
  skipSuccessfulRequests: true // Only count failed requests
});

// Rate limiter for messages (prevent spam)
const messagesLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 messages per minute
  message: { success: false, error: 'rate_limit_exceeded', message: 'Too many messages, slow down' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.userId?.toString() || hashIp(getClientIp(req)) || 'unknown'
});

// Rate limiter for thread creation
const threadsLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // 3 threads per 5 minutes
  message: { success: false, error: 'rate_limit_exceeded', message: 'Too many threads, slow down' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.userId?.toString() || hashIp(getClientIp(req)) || 'unknown'
});

// Rate limiter for reports (prevent report spam)
const reportsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 reports per 15 minutes
  message: { success: false, error: 'rate_limit_exceeded', message: 'Too many reports, slow down' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.userId?.toString() || hashIp(getClientIp(req)) || 'unknown'
});

// Rate limiter for password changes (prevent brute force)
const passwordChangeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 attempts per hour
  message: { success: false, error: 'too_many_attempts', message: 'Too many password change attempts' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.userId?.toString() || hashIp(getClientIp(req)) || 'unknown'
});

// Rate limiter for votes/reactions (prevent spam)
const voteLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 votes per minute (reasonable for browsing)
  message: { success: false, error: 'rate_limit_exceeded', message: 'Too many votes, slow down' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.userId?.toString() || hashIp(getClientIp(req)) || 'unknown'
});

// Password strength validation
function validatePassword(password) {
  const errors = [];
  if (password.length < 8) errors.push('Password must be at least 8 characters');
  if (!/[a-z]/.test(password)) errors.push('Password must contain a lowercase letter');
  if (!/[A-Z]/.test(password)) errors.push('Password must contain an uppercase letter');
  if (!/[0-9]/.test(password)) errors.push('Password must contain a number');
  return errors;
}

// Track failed login attempts in memory (would use Redis in production)
const failedLoginAttempts = new Map();
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

function checkLoginLockout(ipHash) {
  const record = failedLoginAttempts.get(ipHash);
  if (!record) return false;
  if (record.count >= LOCKOUT_THRESHOLD) {
    if (Date.now() - record.lastAttempt < LOCKOUT_DURATION) {
      return true; // Still locked out
    }
    // Lockout expired, clear
    failedLoginAttempts.delete(ipHash);
  }
  return false;
}

function recordFailedLogin(ipHash) {
  const record = failedLoginAttempts.get(ipHash) || { count: 0, lastAttempt: 0 };
  record.count++;
  record.lastAttempt = Date.now();
  failedLoginAttempts.set(ipHash, record);
}

function clearFailedLogin(ipHash) {
  failedLoginAttempts.delete(ipHash);
}

// Periodic cleanup of expired failed login attempts (prevent memory leak)
setInterval(() => {
  const now = Date.now();
  for (const [ipHash, record] of failedLoginAttempts.entries()) {
    if (now - record.lastAttempt > LOCKOUT_DURATION * 2) {
      failedLoginAttempts.delete(ipHash);
    }
  }
}, 5 * 60 * 1000); // Cleanup every 5 minutes

// Verify hCaptcha token
async function verifyCaptcha(token) {
  if (!process.env.HCAPTCHA_SECRET) {
    console.log('[CAPTCHA] HCAPTCHA_SECRET not configured, skipping verification');
    return true; // Skip if not configured
  }
  
  try {
    const response = await fetch('https://hcaptcha.com/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `response=${encodeURIComponent(token)}&secret=${encodeURIComponent(process.env.HCAPTCHA_SECRET)}`
    });
    
    const data = await response.json();
    return data.success === true;
  } catch (err) {
    console.error('[CAPTCHA ERROR]', err.message);
    return false;
  }
}

// Register (with rate limiting, password validation, and captcha)
app.post('/register', authRateLimiter, async (req, res) => {
  const { alias, password, email, captchaToken } = req.body;

  if (!alias || !password) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }

  // Verify CAPTCHA if configured
  if (process.env.HCAPTCHA_SECRET) {
    if (!captchaToken) {
      return res.status(400).json({ success: false, error: 'captcha_required', message: 'Please complete the CAPTCHA' });
    }
    
    const captchaValid = await verifyCaptcha(captchaToken);
    if (!captchaValid) {
      return res.status(400).json({ success: false, error: 'captcha_failed', message: 'CAPTCHA verification failed' });
    }
  }

  // Validate alias format
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(alias)) {
    return res.status(400).json({ success: false, error: 'invalid_alias', message: 'Alias must be 3-20 characters, alphanumeric or underscore only' });
  }

  // Validate email if provided
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, error: 'invalid_email', message: 'Invalid email format' });
  }

  // Validate password strength
  const passwordErrors = validatePassword(password);
  if (passwordErrors.length > 0) {
    return res.status(400).json({ success: false, error: 'weak_password', message: passwordErrors.join('. ') });
  }

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await db.query(
      'INSERT INTO users (alias, password_hash, email) VALUES ($1, $2, $3)',
      [alias, hash, email || null]
    );
    res.json({ success: true });
  } catch (err) {
    logger.error('REGISTER', err.message, { reqId: req.reqId });
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: 'alias_exists' });
    }
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Login (with rate limiting and lockout protection)
app.post('/login', authRateLimiter, strictAuthLimiter, async (req, res) => {
  const { alias, password, totpCode } = req.body;
  const ipHash = hashIp(getClientIp(req));

  // Check for IP-based lockout
  if (checkLoginLockout(ipHash)) {
    return res.status(429).json({ success: false, error: 'too_many_attempts', message: 'Too many failed attempts. Please try again later.' });
  }

  if (!alias || !password) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }

  try {
    // First get basic user info
    const result = await db.query(
      'SELECT id, alias, password_hash, is_admin FROM users WHERE alias = $1',
      [alias]
    );

    if (result.rows.length === 0) {
      recordFailedLogin(ipHash);
      return res.status(401).json({ success: false, error: 'invalid_credentials' });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      recordFailedLogin(ipHash);
      return res.status(401).json({ success: false, error: 'invalid_credentials' });
    }

    // Check if 2FA is enabled (only if speakeasy is available)
    // Query separately to handle case where columns don't exist yet
    let totp_enabled = false;
    let totp_secret = null;
    if (speakeasy) {
      try {
        const totpResult = await db.query(
          'SELECT totp_enabled, totp_secret FROM users WHERE id = $1',
          [user.id]
        );
        if (totpResult.rows.length > 0) {
          totp_enabled = totpResult.rows[0].totp_enabled || false;
          totp_secret = totpResult.rows[0].totp_secret;
        }
      } catch (e) {
        // Columns might not exist yet, ignore
      }
    }
    
    if (totp_enabled && speakeasy) {
      if (!totpCode) {
        // Return special status to indicate 2FA is required
        return res.status(200).json({ success: false, requires2fa: true, message: 'Two-factor authentication required' });
      }
      
      // Verify TOTP code
      const verified = speakeasy.totp.verify({
        secret: totp_secret,
        encoding: 'base32',
        token: totpCode,
        window: 1
      });
      
      if (!verified) {
        // Check if it's a backup code
        const codeHash = crypto.createHash('sha256').update(totpCode.toUpperCase()).digest('hex');
        const backupCheck = await db.query(
          'SELECT id FROM recovery_codes WHERE user_id = $1 AND code_hash = $2 AND used = FALSE',
          [user.id, codeHash]
        );
        
        if (backupCheck.rows.length === 0) {
          recordFailedLogin(ipHash);
          return res.status(401).json({ success: false, error: 'invalid_2fa_code' });
        }
        
        // Mark backup code as used
        await db.query('UPDATE recovery_codes SET used = TRUE WHERE id = $1', [backupCheck.rows[0].id]);
      }
    }

    // Successful login - clear failed attempts
    clearFailedLogin(ipHash);

    const token = jwt.sign(
      { userId: user.id, alias: user.alias, isAdmin: user.is_admin || false },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    // Issue refresh token (longer lived)
    const refreshToken = jwt.sign(
      { userId: user.id, alias: user.alias, isAdmin: user.is_admin || false, type: 'refresh' },
      JWT_SECRET,
      { expiresIn: JWT_REFRESH_EXPIRES }
    );
    
    // Store refresh token hash in database for revocation support
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const refreshExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await db.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [user.id, refreshTokenHash, refreshExpiry]
    );

    res.json({ success: true, token, refreshToken, isAdmin: user.is_admin || false });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Request password reset
app.post('/api/auth/forgot-password', authRateLimiter, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'missing_email' });
  }

  try {
    // Find user by email
    const result = await db.query('SELECT id, alias FROM users WHERE email = $1', [email]);
    
    // Always return success to prevent email enumeration
    if (result.rows.length === 0) {
      return res.json({ success: true, message: 'If an account exists with this email, a reset link has been sent.' });
    }

    const user = result.rows[0];
    
    // Generate secure token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour expiry

    // Invalidate existing tokens for this user
    await db.query('UPDATE password_reset_tokens SET used = TRUE WHERE user_id = $1', [user.id]);

    // Store new token
    await db.query(
      'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, token, expiresAt]
    );

    // Send reset email
    const resetUrl = `${process.env.SITE_URL || 'https://www.aspdforum.com'}/reset-password.html?token=${token}`;
    const emailSent = await sendEmail(
      email,
      'Password Reset — ASPD Forum',
      `
        <div style="font-family: 'Courier New', monospace; background: #050505; max-width: 480px; margin: 0 auto;">
          <div style="border: 1px solid #111111; padding: 40px;">
            <!-- Sigil Header -->
            <div style="text-align: center; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid #0d0d0d;">
              <div style="display: inline-block; width: 48px; height: 48px; margin-bottom: 16px; position: relative;">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" style="width: 48px; height: 48px; opacity: 0.15;">
                  <circle cx="50" cy="50" r="45" fill="none" stroke="#ffffff" stroke-width="1"/>
                  <circle cx="50" cy="50" r="6" fill="#ffffff"/>
                  <circle cx="50" cy="50" r="18" fill="none" stroke="#ffffff" stroke-width="0.5"/>
                  <circle cx="50" cy="50" r="30" fill="none" stroke="#ffffff" stroke-width="0.5"/>
                  <line x1="50" y1="5" x2="50" y2="20" stroke="#ffffff" stroke-width="1"/>
                  <line x1="50" y1="80" x2="50" y2="95" stroke="#ffffff" stroke-width="1"/>
                  <line x1="5" y1="50" x2="20" y2="50" stroke="#ffffff" stroke-width="1"/>
                  <line x1="80" y1="50" x2="95" y2="50" stroke="#ffffff" stroke-width="1"/>
                </svg>
              </div>
              <div style="font-size: 10px; letter-spacing: 0.4em; color: #1a1a1a; text-transform: uppercase;">ASPD FORUM</div>
            </div>
            
            <!-- Content -->
            <div style="color: #2a2a2a; font-size: 12px; line-height: 1.8;">
              <p style="margin: 0 0 16px 0;">Hello <span style="color: #3a3a3a;">${user.alias}</span>,</p>
              <p style="margin: 0 0 24px 0;">A password reset was requested for your account.</p>
              
              <div style="text-align: center; margin: 32px 0;">
                <a href="${resetUrl}" style="display: inline-block; padding: 12px 28px; background: #0a0a0a; color: #3a3a3a; text-decoration: none; border: 1px solid #1a1a1a; font-size: 10px; letter-spacing: 0.25em; text-transform: uppercase;">RESET PASSWORD</a>
              </div>
              
              <p style="margin: 24px 0 0 0; font-size: 10px; color: #1a1a1a;">This link expires in 1 hour.</p>
              <p style="margin: 6px 0 0 0; font-size: 10px; color: #1a1a1a;">If you didn't request this, ignore this email.</p>
            </div>
            
            <!-- Footer -->
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #0d0d0d; text-align: center;">
              <div style="font-size: 9px; letter-spacing: 0.3em; color: #151515;">ASPDFORUM.COM</div>
            </div>
          </div>
        </div>
      `
    );

    if (!emailSent) {
      console.error('[PASSWORD RESET] Failed to send email to', email);
    }

    res.json({ success: true, message: 'If an account exists with this email, a reset link has been sent.' });
  } catch (err) {
    console.error('[FORGOT PASSWORD ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Verify reset token
app.get('/api/auth/verify-reset-token', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ success: false, error: 'missing_token' });
  }

  try {
    const result = await db.query(
      'SELECT prt.*, u.alias FROM password_reset_tokens prt JOIN users u ON prt.user_id = u.id WHERE prt.token = $1 AND prt.used = FALSE AND prt.expires_at > NOW()',
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'invalid_or_expired_token' });
    }

    res.json({ success: true, alias: result.rows[0].alias });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Reset password with token
app.post('/api/auth/reset-password', authRateLimiter, async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }

  // Validate password strength
  const passwordErrors = validatePassword(password);
  if (passwordErrors.length > 0) {
    return res.status(400).json({ success: false, error: 'weak_password', message: passwordErrors.join('. ') });
  }

  try {
    // Find valid token
    const result = await db.query(
      'SELECT user_id FROM password_reset_tokens WHERE token = $1 AND used = FALSE AND expires_at > NOW()',
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'invalid_or_expired_token' });
    }

    const userId = result.rows[0].user_id;
    
    // Hash new password
    const hash = await bcrypt.hash(password, SALT_ROUNDS);

    // Update password
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, userId]);

    // Mark token as used
    await db.query('UPDATE password_reset_tokens SET used = TRUE WHERE token = $1', [token]);

    res.json({ success: true, message: 'Password has been reset successfully.' });
  } catch (err) {
    console.error('[RESET PASSWORD ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Reset password with recovery code (for users without email)
app.post('/api/auth/reset-with-recovery', authRateLimiter, async (req, res) => {
  const { alias, recoveryCode, newPassword } = req.body;

  if (!alias || !recoveryCode || !newPassword) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }

  // Validate password strength
  const passwordErrors = validatePassword(newPassword);
  if (passwordErrors.length > 0) {
    return res.status(400).json({ success: false, error: 'weak_password', message: passwordErrors.join('. ') });
  }

  try {
    // Find user
    const userResult = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'invalid_credentials' });
    }
    
    const userId = userResult.rows[0].id;
    
    // Check recovery code
    const codeHash = crypto.createHash('sha256').update(recoveryCode.toUpperCase()).digest('hex');
    const codeResult = await db.query(
      'SELECT id FROM recovery_codes WHERE user_id = $1 AND code_hash = $2 AND used = FALSE',
      [userId, codeHash]
    );
    
    if (codeResult.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'invalid_recovery_code' });
    }
    
    // Mark code as used
    await db.query('UPDATE recovery_codes SET used = TRUE WHERE id = $1', [codeResult.rows[0].id]);
    
    // Hash new password
    const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    
    // Update password
    await db.query('UPDATE users SET password_hash = $1, password_changed_at = NOW() WHERE id = $2', [hash, userId]);
    
    // Invalidate all refresh tokens
    await db.query('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1', [userId]);
    
    res.json({ success: true, message: 'Password has been reset successfully.' });
  } catch (err) {
    console.error('[RESET WITH RECOVERY ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Generate recovery codes (for users without email, or to regenerate)
app.post('/api/settings/recovery-codes', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { password } = req.body;
  
  if (!password) {
    return res.status(400).json({ success: false, error: 'password_required' });
  }
  
  try {
    // Verify password
    const result = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (!result.rows[0]) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const valid = await bcrypt.compare(password, result.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, error: 'invalid_password' });
    }
    
    // Delete old recovery codes
    await db.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    
    // Generate new recovery codes
    const backupCodes = [];
    for (let i = 0; i < 8; i++) {
      backupCodes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    
    // Store backup codes
    for (const code of backupCodes) {
      const codeHash = crypto.createHash('sha256').update(code).digest('hex');
      await db.query(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)',
        [userId, codeHash]
      );
    }
    
    res.json({ success: true, recoveryCodes: backupCodes });
  } catch (err) {
    console.error('[GENERATE RECOVERY CODES ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// TWO-FACTOR AUTHENTICATION ENDPOINTS
// ========================================

// Check 2FA status
app.get('/api/auth/2fa-status', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  
  if (!speakeasy) {
    return res.status(503).json({ success: false, error: '2fa_not_available' });
  }
  
  try {
    const result = await db.query(
      'SELECT totp_enabled FROM users WHERE id = $1',
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    res.json({ success: true, enabled: result.rows[0].totp_enabled || false });
  } catch (err) {
    logger.error('2FA_STATUS', err.message, { reqId: req.reqId, userId });
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Setup 2FA - generate secret and QR code
app.post('/api/auth/setup-2fa', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const userAlias = req.user.alias;
  
  if (!speakeasy || !qrcode) {
    return res.status(503).json({ success: false, error: '2fa_not_available' });
  }
  
  try {
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `ASPD Forum (${userAlias})`,
      length: 20
    });
    
    // Generate QR code
    const qrCodeDataUrl = await new Promise((resolve, reject) => {
      qrcode.toDataURL(secret.otpauth_url, (err, url) => {
        if (err) reject(err);
        else resolve(url);
      });
    });
    
    res.json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeDataUrl
    });
  } catch (err) {
    logger.error('SETUP_2FA', err.message, { reqId: req.reqId, userId });
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Enable 2FA - verify code and save secret
app.post('/api/auth/enable-2fa', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { secret, code } = req.body;
  
  if (!speakeasy) {
    return res.status(503).json({ success: false, error: '2fa_not_available' });
  }
  
  if (!secret || !code) {
    return res.status(400).json({ success: false, error: 'missing_parameters' });
  }
  
  try {
    // Verify the code first
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: code,
      window: 1
    });
    
    if (!verified) {
      return res.status(400).json({ success: false, error: 'invalid_code' });
    }
    
    // Save the secret and enable 2FA
    await db.query(
      'UPDATE users SET totp_enabled = TRUE, totp_secret = $1 WHERE id = $2',
      [secret, userId]
    );
    
    // Generate recovery codes
    const recoveryCodes = [];
    await db.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    
    for (let i = 0; i < 10; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      recoveryCodes.push(code);
      const codeHash = crypto.createHash('sha256').update(code).digest('hex');
      await db.query(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)',
        [userId, codeHash]
      );
    }
    
    logAudit(userId, 'enable_2fa', { method: 'totp' });
    
    // Award security badge for enabling 2FA
    checkAndAwardBadges(userId).catch(() => {});
    
    res.json({ success: true, recoveryCodes: recoveryCodes });
  } catch (err) {
    logger.error('ENABLE_2FA', err.message, { reqId: req.reqId, userId });
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Disable 2FA
app.post('/api/auth/disable-2fa', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  
  try {
    await db.query(
      'UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1',
      [userId]
    );
    
    // Delete recovery codes
    await db.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    
    logAudit(userId, 'disable_2fa', {});
    res.json({ success: true });
  } catch (err) {
    logger.error('DISABLE_2FA', err.message, { reqId: req.reqId, userId });
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Regenerate recovery codes
app.post('/api/auth/regenerate-recovery-codes', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  
  try {
    // Check if 2FA is enabled
    const userResult = await db.query(
      'SELECT totp_enabled FROM users WHERE id = $1',
      [userId]
    );
    
    if (!userResult.rows[0]?.totp_enabled) {
      return res.status(400).json({ success: false, error: '2fa_not_enabled' });
    }
    
    // Delete old codes and generate new ones
    await db.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    
    const recoveryCodes = [];
    for (let i = 0; i < 10; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      recoveryCodes.push(code);
      const codeHash = crypto.createHash('sha256').update(code).digest('hex');
      await db.query(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)',
        [userId, codeHash]
      );
    }
    
    logAudit(userId, 'regenerate_recovery_codes', {});
    res.json({ success: true, recoveryCodes: recoveryCodes });
  } catch (err) {
    logger.error('REGEN_RECOVERY', err.message, { reqId: req.reqId, userId });
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get recovery codes count (don't expose actual codes)
app.get('/api/auth/recovery-codes', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  
  try {
    const result = await db.query(
      'SELECT COUNT(*) as count FROM recovery_codes WHERE user_id = $1 AND used = FALSE',
      [userId]
    );
    
    res.json({ success: true, count: parseInt(result.rows[0].count) });
  } catch (err) {
    logger.error('GET_RECOVERY_COUNT', err.message, { reqId: req.reqId, userId });
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Refresh token endpoint - get new access token using refresh token
app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ success: false, error: 'missing_refresh_token' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    
    // Verify it's a refresh token
    if (decoded.type !== 'refresh') {
      return res.status(401).json({ success: false, error: 'invalid_token_type' });
    }

    // Validate refresh token against database (check for revocation)
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const tokenResult = await db.query(
      'SELECT id, revoked FROM refresh_tokens WHERE token_hash = $1 AND user_id = $2',
      [tokenHash, decoded.userId]
    );

    if (tokenResult.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'token_not_found' });
    }

    if (tokenResult.rows[0].revoked) {
      return res.status(401).json({ success: false, error: 'token_revoked' });
    }

    // Verify user still exists and isn't banned
    const result = await db.query(
      'SELECT id, alias, is_admin, is_banned FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'user_not_found' });
    }

    const user = result.rows[0];
    if (user.is_banned) {
      return res.status(403).json({ success: false, error: 'user_banned' });
    }

    // Issue new access token
    const newToken = jwt.sign(
      { userId: user.id, alias: user.alias, isAdmin: user.is_admin || false },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({ success: true, token: newToken });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, error: 'refresh_token_expired' });
    }
    return res.status(401).json({ success: false, error: 'invalid_refresh_token' });
  }
});

// Logout endpoint - revoke the current refresh token
app.post('/api/auth/logout', async (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    try {
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      await db.query('UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1', [tokenHash]);
    } catch (err) {
      console.error('[LOGOUT ERROR]', err.message);
    }
  }
  
  res.json({ success: true });
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

// API: Autocomplete user search for @mentions
app.get('/api/users/autocomplete', authMiddleware, async (req, res) => {
  const query = req.query.q || '';
  
  if (query.length < 1) {
    return res.json({ success: true, users: [] });
  }
  
  try {
    const result = await db.query(
      `SELECT id, alias, avatar_config 
       FROM users 
       WHERE alias ILIKE $1 AND is_banned = FALSE
       ORDER BY alias ASC
       LIMIT 8`,
      [query + '%']
    );
    
    res.json({
      success: true,
      users: result.rows.map(u => ({
        id: u.id,
        alias: u.alias,
        avatarConfig: u.avatar_config
      }))
    });
  } catch (err) {
    console.error('[USER AUTOCOMPLETE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get user profile by alias
app.get('/api/profile/:alias', authMiddleware, async (req, res) => {
  const alias = req.params.alias;
  const viewerId = req.user?.userId;
  
  try {
    // Get user info
    const userResult = await db.query(
      'SELECT id, alias, bio, avatar_config, signature, reputation, custom_title, is_admin, created_at FROM users WHERE alias = $1',
      [alias]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const user = userResult.rows[0];
    
    // Check if profile owner has blocked the viewer
    if (viewerId && viewerId !== user.id) {
      const blocked = await db.query(
        'SELECT id FROM blocked_users WHERE user_id = $1 AND blocked_user_id = $2',
        [user.id, viewerId]
      );
      if (blocked.rows.length > 0) {
        return res.status(403).json({ success: false, error: 'profile_blocked', message: 'This user has blocked you.' });
      }
    }
    
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
    
    // Calculate user rank based on post count
    let rank = 'NEWCOMER';
    if (postCount >= 500) rank = 'VETERAN';
    else if (postCount >= 200) rank = 'EXPERT';
    else if (postCount >= 100) rank = 'REGULAR';
    else if (postCount >= 50) rank = 'MEMBER';
    else if (postCount >= 10) rank = 'ACTIVE';
    
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
        id: user.id,
        alias: user.alias,
        bio: user.bio || '',
        signature: user.signature || '',
        customTitle: user.custom_title || null,
        avatarConfig: user.avatar_config || null,
        reputation: user.reputation || 0,
        rank: rank,
        isAdmin: user.is_admin || false,
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
  const { bio, avatar_config, custom_avatar, signature } = req.body;
  
  try {
    // Validate bio length
    if (bio && bio.length > 500) {
      return res.status(400).json({ success: false, error: 'bio_too_long', message: 'Bio must be 500 characters or less' });
    }
    
    // Validate signature length
    if (signature && signature.length > 200) {
      return res.status(400).json({ success: false, error: 'signature_too_long', message: 'Signature must be 200 characters or less' });
    }
    
    // Check if user is admin for custom avatar upload
    let finalAvatarConfig = avatar_config || {};
    
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
      
      // Store custom avatar in avatar_config, preserving selectedBorder
      finalAvatarConfig = { ...finalAvatarConfig, customImage: custom_avatar };
    }
    
    const result = await db.query(
      'UPDATE users SET bio = $1, avatar_config = $2, signature = $3 WHERE id = $4 RETURNING id, alias, bio, avatar_config, signature',
      [bio || '', finalAvatarConfig, signature || null, userId]
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

// API: Get user settings
app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT email, email_verified, notification_replies, notification_mentions, notification_messages FROM users WHERE id = $1',
      [req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    res.json({ success: true, settings: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Update user settings
app.put('/api/settings', authMiddleware, async (req, res) => {
  const { email, notification_replies, notification_mentions, notification_messages } = req.body;
  const userId = req.user.userId;
  
  try {
    // If email is being changed, validate and mark as unverified
    if (email !== undefined) {
      if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ success: false, error: 'invalid_email' });
      }
      
      // Check if email is already used by another user
      if (email) {
        const existing = await db.query('SELECT id FROM users WHERE email = $1 AND id != $2', [email, userId]);
        if (existing.rows.length > 0) {
          return res.status(400).json({ success: false, error: 'email_in_use' });
        }
      }
      
      await db.query(
        'UPDATE users SET email = $1, email_verified = FALSE WHERE id = $2',
        [email || null, userId]
      );
    }
    
    // Update notification preferences
    if (notification_replies !== undefined || notification_mentions !== undefined || notification_messages !== undefined) {
      const updates = [];
      const values = [];
      let paramIndex = 1;
      
      if (notification_replies !== undefined) {
        updates.push(`notification_replies = $${paramIndex++}`);
        values.push(notification_replies);
      }
      if (notification_mentions !== undefined) {
        updates.push(`notification_mentions = $${paramIndex++}`);
        values.push(notification_mentions);
      }
      if (notification_messages !== undefined) {
        updates.push(`notification_messages = $${paramIndex++}`);
        values.push(notification_messages);
      }
      
      if (updates.length > 0) {
        values.push(userId);
        await db.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex}`, values);
      }
    }
    
    // Return updated settings
    const result = await db.query(
      'SELECT email, email_verified, notification_replies, notification_mentions, notification_messages FROM users WHERE id = $1',
      [userId]
    );
    
    res.json({ success: true, settings: result.rows[0] });
  } catch (err) {
    console.error('[UPDATE SETTINGS ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Change password (authenticated)
app.post('/api/settings/change-password', authMiddleware, passwordChangeLimiter, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.userId;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }
  
  // Validate new password strength
  const passwordErrors = validatePassword(newPassword);
  if (passwordErrors.length > 0) {
    return res.status(400).json({ success: false, error: 'weak_password', message: passwordErrors.join('. ') });
  }
  
  try {
    // Get current password hash
    const result = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    // Verify current password
    const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, error: 'invalid_password' });
    }
    
    // Hash and update new password, and update password_changed_at
    const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await db.query(
      'UPDATE users SET password_hash = $1, password_changed_at = NOW() WHERE id = $2',
      [hash, userId]
    );
    
    // Invalidate all refresh tokens for this user (logout all sessions)
    await db.query('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1', [userId]);
    
    res.json({ success: true, message: 'Password changed successfully. Please login again.' });
  } catch (err) {
    logger.error('CHANGE_PASSWORD', err.message, { reqId: req.reqId });
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// TWO-FACTOR AUTHENTICATION (2FA)
// ========================================

// Get 2FA status
app.get('/api/settings/2fa', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  
  try {
    const result = await db.query(
      'SELECT totp_enabled FROM users WHERE id = $1',
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    res.json({ success: true, enabled: result.rows[0].totp_enabled || false });
  } catch (err) {
    console.error('[2FA STATUS ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Generate 2FA secret (setup)
app.post('/api/settings/2fa/setup', authMiddleware, async (req, res) => {
  // Check if 2FA modules are available
  if (!speakeasy || !QRCode) {
    return res.status(503).json({ success: false, error: '2fa_not_available', message: '2FA is not available on this server' });
  }
  
  const userId = req.user.userId;
  const userAlias = req.user.alias;
  
  try {
    // Check if already enabled
    const existing = await db.query('SELECT totp_enabled FROM users WHERE id = $1', [userId]);
    if (existing.rows[0]?.totp_enabled) {
      return res.status(400).json({ success: false, error: '2fa_already_enabled' });
    }
    
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `ASPD Forum (${userAlias})`,
      issuer: 'ASPD Forum'
    });
    
    // Store secret temporarily (not enabled yet)
    await db.query(
      'UPDATE users SET totp_secret = $1, totp_enabled = FALSE WHERE id = $2',
      [secret.base32, userId]
    );
    
    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    
    res.json({ 
      success: true, 
      secret: secret.base32,
      qrCode: qrCodeUrl
    });
  } catch (err) {
    console.error('[2FA SETUP ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});
// Verify and enable 2FA
app.post('/api/settings/2fa/verify', authMiddleware, async (req, res) => {
  // Check if 2FA modules are available
  if (!speakeasy) {
    return res.status(503).json({ success: false, error: '2fa_not_available', message: '2FA is not available on this server' });
  }
  
  const userId = req.user.userId;
  const { code } = req.body;
  
  if (!code) {
    return res.status(400).json({ success: false, error: 'code_required' });
  }
  
  try {
    // Get stored secret
    const result = await db.query('SELECT totp_secret FROM users WHERE id = $1', [userId]);
    if (!result.rows[0]?.totp_secret) {
      return res.status(400).json({ success: false, error: 'setup_required' });
    }
    
    const secret = result.rows[0].totp_secret;
    
    // Verify the code
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: code,
      window: 1 // Allow 1 step tolerance
    });
    
    if (!verified) {
      return res.status(400).json({ success: false, error: 'invalid_code' });
    }
    
    // Enable 2FA
    await db.query('UPDATE users SET totp_enabled = TRUE WHERE id = $1', [userId]);
    
    // Generate backup codes
    const backupCodes = [];
    for (let i = 0; i < 8; i++) {
      backupCodes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    
    // Store backup codes
    for (const code of backupCodes) {
      const codeHash = crypto.createHash('sha256').update(code).digest('hex');
      await db.query(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)',
        [userId, codeHash]
      );
    }
    
    res.json({ success: true, backupCodes });
  } catch (err) {
    console.error('[2FA VERIFY ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Disable 2FA
app.post('/api/settings/2fa/disable', authMiddleware, async (req, res) => {
  // Check if 2FA modules are available
  if (!speakeasy) {
    return res.status(503).json({ success: false, error: '2fa_not_available', message: '2FA is not available on this server' });
  }
  
  const userId = req.user.userId;
  const { password, code } = req.body;
  
  if (!password) {
    return res.status(400).json({ success: false, error: 'password_required' });
  }
  
  try {
    // Verify password
    const result = await db.query('SELECT password_hash, totp_secret, totp_enabled FROM users WHERE id = $1', [userId]);
    if (!result.rows[0]) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const valid = await bcrypt.compare(password, result.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, error: 'invalid_password' });
    }
    
    // If 2FA is enabled, require code
    if (result.rows[0].totp_enabled) {
      if (!code) {
        return res.status(400).json({ success: false, error: 'code_required' });
      }
      
      const verified = speakeasy.totp.verify({
        secret: result.rows[0].totp_secret,
        encoding: 'base32',
        token: code,
        window: 1
      });
      
      if (!verified) {
        return res.status(400).json({ success: false, error: 'invalid_code' });
      }
    }
    
    // Disable 2FA
    await db.query('UPDATE users SET totp_secret = NULL, totp_enabled = FALSE WHERE id = $1', [userId]);
    
    // Delete recovery codes
    await db.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    
    res.json({ success: true });
  } catch (err) {
    console.error('[2FA DISABLE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get active sessions for current user
app.get('/api/settings/sessions', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  
  try {
    const result = await db.query(
      `SELECT id, created_at, expires_at, 
              CASE WHEN token_hash = $2 THEN true ELSE false END AS is_current
       FROM refresh_tokens 
       WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [userId, req.currentTokenHash || '']
    );
    
    res.json({ 
      success: true, 
      sessions: result.rows.map(s => ({
        id: s.id,
        createdAt: s.created_at,
        expiresAt: s.expires_at,
        isCurrent: s.is_current
      }))
    });
  } catch (err) {
    console.error('[GET SESSIONS ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Revoke a specific session
app.delete('/api/settings/sessions/:id', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const sessionId = parseInt(req.params.id);
  
  if (!sessionId || isNaN(sessionId)) {
    return res.status(400).json({ success: false, error: 'invalid_session_id' });
  }
  
  try {
    const result = await db.query(
      'UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1 AND user_id = $2 RETURNING id',
      [sessionId, userId]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'session_not_found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error('[REVOKE SESSION ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Logout all sessions except current
app.post('/api/settings/sessions/logout-all', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { currentTokenHash } = req.body;
  
  try {
    // Revoke all tokens except the current one (if provided)
    if (currentTokenHash) {
      await db.query(
        'UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND token_hash != $2',
        [userId, currentTokenHash]
      );
    } else {
      await db.query('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1', [userId]);
    }
    
    res.json({ success: true, message: 'All other sessions have been logged out.' });
  } catch (err) {
    console.error('[LOGOUT ALL ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Send verification email
app.post('/api/settings/verify-email', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  
  try {
    // Get user's email
    const result = await db.query('SELECT email, email_verified FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const { email, email_verified } = result.rows[0];
    
    if (!email) {
      return res.status(400).json({ success: false, error: 'no_email', message: 'Please save an email address first' });
    }
    
    if (email_verified) {
      return res.status(400).json({ success: false, error: 'already_verified', message: 'Email is already verified' });
    }
    
    // Generate verification token
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    // Delete any existing verification tokens for this user
    await db.query(
      `DELETE FROM password_reset_tokens WHERE user_id = $1 AND token LIKE 'verify_%'`,
      [userId]
    );
    
    // Store new verification token
    await db.query(
      `INSERT INTO password_reset_tokens (user_id, token, expires_at)
       VALUES ($1, $2, $3)`,
      [userId, 'verify_' + token, expires]
    );
    
    // Send verification email
    const verifyUrl = `https://www.aspdforum.com/verify-email.html?token=${token}`;
    const emailSent = await sendEmail(
      email,
      'Verify Email — ASPD Forum',
      `
        <div style="font-family: 'Courier New', monospace; background: #050505; max-width: 480px; margin: 0 auto;">
          <div style="border: 1px solid #111111; padding: 40px;">
            <!-- Sigil Header -->
            <div style="text-align: center; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid #0d0d0d;">
              <div style="display: inline-block; width: 48px; height: 48px; margin-bottom: 16px; position: relative;">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" style="width: 48px; height: 48px; opacity: 0.15;">
                  <circle cx="50" cy="50" r="45" fill="none" stroke="#ffffff" stroke-width="1"/>
                  <circle cx="50" cy="50" r="6" fill="#ffffff"/>
                  <circle cx="50" cy="50" r="18" fill="none" stroke="#ffffff" stroke-width="0.5"/>
                  <circle cx="50" cy="50" r="30" fill="none" stroke="#ffffff" stroke-width="0.5"/>
                  <line x1="50" y1="5" x2="50" y2="20" stroke="#ffffff" stroke-width="1"/>
                  <line x1="50" y1="80" x2="50" y2="95" stroke="#ffffff" stroke-width="1"/>
                  <line x1="5" y1="50" x2="20" y2="50" stroke="#ffffff" stroke-width="1"/>
                  <line x1="80" y1="50" x2="95" y2="50" stroke="#ffffff" stroke-width="1"/>
                </svg>
              </div>
              <div style="font-size: 10px; letter-spacing: 0.4em; color: #1a1a1a; text-transform: uppercase;">ASPD FORUM</div>
            </div>
            
            <!-- Content -->
            <div style="color: #2a2a2a; font-size: 12px; line-height: 1.8;">
              <p style="margin: 0 0 24px 0;">Verify your email address to enable password recovery and notifications.</p>
              
              <div style="text-align: center; margin: 32px 0;">
                <a href="${verifyUrl}" style="display: inline-block; padding: 12px 28px; background: #0a0a0a; color: #3a3a3a; text-decoration: none; border: 1px solid #1a1a1a; font-size: 10px; letter-spacing: 0.25em; text-transform: uppercase;">VERIFY EMAIL</a>
              </div>
              
              <p style="margin: 24px 0 0 0; font-size: 10px; color: #1a1a1a;">This link expires in 24 hours.</p>
              <p style="margin: 6px 0 0 0; font-size: 10px; color: #1a1a1a;">If you didn't request this, ignore this email.</p>
            </div>
            
            <!-- Footer -->
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #0d0d0d; text-align: center;">
              <div style="font-size: 9px; letter-spacing: 0.3em; color: #151515;">ASPDFORUM.COM</div>
            </div>
          </div>
        </div>
      `
    );
    
    if (!emailSent) {
      return res.status(500).json({ success: false, error: 'email_failed', message: 'Failed to send verification email' });
    }
    
    res.json({ success: true, message: 'Verification email sent' });
  } catch (err) {
    console.error('[VERIFY EMAIL ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Confirm email verification
app.post('/api/auth/confirm-email', async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ success: false, error: 'missing_token' });
  }
  
  try {
    // Find token
    const result = await db.query(
      `SELECT user_id, expires_at FROM password_reset_tokens 
       WHERE token = $1`,
      ['verify_' + token]
    );
    
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'invalid_token' });
    }
    
    const { user_id, expires_at } = result.rows[0];
    
    if (new Date() > new Date(expires_at)) {
      await db.query('DELETE FROM password_reset_tokens WHERE token = $1', ['verify_' + token]);
      return res.status(400).json({ success: false, error: 'expired_token' });
    }
    
    // Mark email as verified
    await db.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [user_id]);
    
    // Award verified email badge
    checkAndAwardBadges(user_id).catch(() => {});
    
    // Delete token
    await db.query('DELETE FROM password_reset_tokens WHERE token = $1', ['verify_' + token]);
    
    res.json({ success: true, message: 'Email verified successfully' });
  } catch (err) {
    console.error('[CONFIRM EMAIL ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Delete account
app.delete('/api/settings/account', authMiddleware, async (req, res) => {
  const { password } = req.body;
  const userId = req.user.userId;
  
  if (!password) {
    return res.status(400).json({ success: false, error: 'password_required' });
  }
  
  try {
    // Verify password
    const result = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const valid = await bcrypt.compare(password, result.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, error: 'invalid_password' });
    }
    
    // Delete user (cascade will handle related records)
    await db.query('DELETE FROM users WHERE id = $1', [userId]);
    
    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (err) {
    console.error('[DELETE ACCOUNT ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get all rooms (cached)
app.get('/api/rooms', authMiddleware, async (req, res) => {
  try {
    const rooms = await getCachedRooms();
    res.json({ success: true, rooms });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// GLOBAL SEARCH
// ========================================

// API: Global search across threads and posts
app.get('/api/search', authMiddleware, async (req, res) => {
  const query = req.query.q || '';
  const type = req.query.type || 'all'; // all, threads, posts, users
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const offset = (page - 1) * limit;

  if (!query || query.length < 2) {
    return res.json({ success: true, results: [], total: 0 });
  }

  const searchPattern = '%' + query + '%';

  try {
    let results = [];
    let total = 0;

    if (type === 'all' || type === 'threads') {
      // Search threads
      const threadResult = await db.query(
        `SELECT t.id, t.title, t.slug, t.created_at, r.slug AS room_slug, r.title AS room_title,
                u.alias AS author, 'thread' AS result_type,
                (SELECT COUNT(*) FROM entries WHERE thread_id = t.id AND is_deleted = FALSE) AS entry_count
         FROM threads t
         JOIN rooms r ON r.id = t.room_id
         JOIN users u ON u.id = t.user_id
         WHERE t.title ILIKE $1 OR t.slug ILIKE $1
         ORDER BY t.created_at DESC
         LIMIT $2 OFFSET $3`,
        [searchPattern, limit, offset]
      );
      
      if (type === 'threads') {
        const countResult = await db.query(
          `SELECT COUNT(*) FROM threads WHERE title ILIKE $1 OR slug ILIKE $1`,
          [searchPattern]
        );
        total = parseInt(countResult.rows[0].count);
      }
      
      results = results.concat(threadResult.rows);
    }

    if (type === 'all' || type === 'posts') {
      // Search posts/entries
      const postResult = await db.query(
        `SELECT e.id, e.content, e.created_at, e.alias AS author,
                t.id AS thread_id, t.title AS thread_title, t.slug AS thread_slug,
                r.slug AS room_slug, 'post' AS result_type
         FROM entries e
         JOIN threads t ON t.id = e.thread_id
         JOIN rooms r ON r.id = t.room_id
         WHERE e.is_deleted = FALSE AND e.content ILIKE $1
         ORDER BY e.created_at DESC
         LIMIT $2 OFFSET $3`,
        [searchPattern, limit, offset]
      );
      
      if (type === 'posts') {
        const countResult = await db.query(
          `SELECT COUNT(*) FROM entries WHERE is_deleted = FALSE AND content ILIKE $1`,
          [searchPattern]
        );
        total = parseInt(countResult.rows[0].count);
      }
      
      results = results.concat(postResult.rows);
    }

    if (type === 'all' || type === 'users') {
      // Search users
      const userResult = await db.query(
        `SELECT u.id, u.alias, u.bio, u.created_at, u.is_admin, 'user' AS result_type,
                (SELECT COUNT(*) FROM entries WHERE user_id = u.id AND is_deleted = FALSE) AS post_count
         FROM users u
         WHERE u.alias ILIKE $1 AND u.is_banned = FALSE
         ORDER BY u.created_at DESC
         LIMIT $2 OFFSET $3`,
        [searchPattern, limit, offset]
      );
      
      if (type === 'users') {
        const countResult = await db.query(
          `SELECT COUNT(*) FROM users WHERE alias ILIKE $1 AND is_banned = FALSE`,
          [searchPattern]
        );
        total = parseInt(countResult.rows[0].count);
      }
      
      results = results.concat(userResult.rows);
    }

    // For 'all' type, estimate total
    if (type === 'all') {
      const allCountResult = await db.query(
        `SELECT 
           (SELECT COUNT(*) FROM threads WHERE title ILIKE $1 OR slug ILIKE $1) +
           (SELECT COUNT(*) FROM entries WHERE is_deleted = FALSE AND content ILIKE $1) +
           (SELECT COUNT(*) FROM users WHERE alias ILIKE $1 AND is_banned = FALSE) AS total`,
        [searchPattern]
      );
      total = parseInt(allCountResult.rows[0].total);
    }

    res.json({
      success: true,
      results: results,
      total: total,
      pagination: {
        page: page,
        limit: limit,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('[SEARCH ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// ACTIVITY FEED
// ========================================

// Helper: Log activity
async function logActivity(userId, actionType, targetType, targetId, targetTitle, details = null) {
  try {
    await db.query(
      `INSERT INTO activity_feed (user_id, action_type, target_type, target_id, target_title, details)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [userId, actionType, targetType, targetId, targetTitle, details ? JSON.stringify(details) : null]
    );
  } catch (err) {
    // Silent fail
  }
}

// API: Get global activity feed
app.get('/api/activity', authMiddleware, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 30, 50);
  const offset = (page - 1) * limit;
  const userId = req.query.user_id ? parseInt(req.query.user_id) : null;

  try {
    let query = `
      SELECT af.id, af.action_type, af.target_type, af.target_id, af.target_title, af.details, af.created_at,
             u.alias, u.avatar_config
      FROM activity_feed af
      JOIN users u ON u.id = af.user_id
      WHERE u.is_banned = FALSE
    `;
    let params = [];
    let paramIndex = 1;

    if (userId) {
      query += ` AND af.user_id = $${paramIndex}`;
      params.push(userId);
      paramIndex++;
    }

    query += ` ORDER BY af.created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);

    const result = await db.query(query, params);

    // Get total count
    let countQuery = `SELECT COUNT(*) FROM activity_feed af JOIN users u ON u.id = af.user_id WHERE u.is_banned = FALSE`;
    let countParams = [];
    if (userId) {
      countQuery += ` AND af.user_id = $1`;
      countParams.push(userId);
    }
    const countResult = await db.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].count);

    res.json({
      success: true,
      activities: result.rows.map(a => ({
        id: a.id,
        actionType: a.action_type,
        targetType: a.target_type,
        targetId: a.target_id,
        targetTitle: a.target_title,
        details: a.details,
        createdAt: a.created_at,
        user: {
          alias: a.alias,
          avatarConfig: a.avatar_config
        }
      })),
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('[ACTIVITY ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// USER TITLES (Admin only)
// ========================================

// API: Set user custom title (admin only)
app.put('/api/admin/users/:alias/title', authMiddleware, adminMiddleware, async (req, res) => {
  const alias = req.params.alias;
  const { title } = req.body;

  if (title && title.length > 50) {
    return res.status(400).json({ success: false, error: 'title_too_long' });
  }

  try {
    const result = await db.query(
      'UPDATE users SET custom_title = $1 WHERE alias = $2 RETURNING id, alias, custom_title',
      [title || null, alias]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }

    await logAudit('set_user_title', 'user', result.rows[0].id, req.user.userId, { title: title || null });

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('[SET TITLE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// POST HISTORY
// ========================================

// API: Get user's post history (full paginated)
app.get('/api/users/:alias/posts', authMiddleware, async (req, res) => {
  const alias = req.params.alias;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const offset = (page - 1) * limit;

  try {
    // Get user
    const userResult = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const userId = userResult.rows[0].id;

    // Get total count
    const countResult = await db.query(
      'SELECT COUNT(*) FROM entries WHERE user_id = $1 AND (is_deleted = FALSE OR is_deleted IS NULL)',
      [userId]
    );
    const total = parseInt(countResult.rows[0].count);

    // Get posts
    const postsResult = await db.query(
      `SELECT e.id, e.content, e.created_at, e.edited_at,
              t.id AS thread_id, t.title AS thread_title,
              r.slug AS room_slug, r.title AS room_title
       FROM entries e
       JOIN threads t ON t.id = e.thread_id
       JOIN rooms r ON r.id = t.room_id
       WHERE e.user_id = $1 AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)
       ORDER BY e.created_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    res.json({
      success: true,
      posts: postsResult.rows.map(p => ({
        id: p.id,
        content: p.content,
        createdAt: p.created_at,
        editedAt: p.edited_at,
        thread: {
          id: p.thread_id,
          title: p.thread_title
        },
        room: {
          slug: p.room_slug,
          title: p.room_title
        }
      })),
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('[POST HISTORY ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// POLLS
// ========================================

// API: Create a poll for a thread
app.post('/api/threads/:threadId/poll', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.threadId);
  const { question, options, allowMultiple, endsAt } = req.body;

  if (!question || !options || !Array.isArray(options) || options.length < 2) {
    return res.status(400).json({ success: false, error: 'invalid_poll_data' });
  }

  if (options.length > 10) {
    return res.status(400).json({ success: false, error: 'too_many_options' });
  }

  try {
    // Check if thread exists and user is the owner or admin
    const threadResult = await db.query('SELECT user_id FROM threads WHERE id = $1', [threadId]);
    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }

    const isOwner = threadResult.rows[0].user_id === req.user.userId;
    const adminCheck = await db.query('SELECT is_admin FROM users WHERE id = $1', [req.user.userId]);
    const isAdmin = adminCheck.rows.length > 0 && adminCheck.rows[0].is_admin;

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ success: false, error: 'forbidden' });
    }

    // Check if poll already exists
    const existingPoll = await db.query('SELECT id FROM polls WHERE thread_id = $1', [threadId]);
    if (existingPoll.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'poll_already_exists' });
    }

    // Create poll
    const pollResult = await db.query(
      `INSERT INTO polls (thread_id, question, allow_multiple, ends_at, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [threadId, question, allowMultiple || false, endsAt || null, req.user.userId]
    );
    const pollId = pollResult.rows[0].id;

    // Create options
    for (let i = 0; i < options.length; i++) {
      await db.query(
        'INSERT INTO poll_options (poll_id, option_text, display_order) VALUES ($1, $2, $3)',
        [pollId, options[i], i]
      );
    }

    // Log activity
    await logActivity(req.user.userId, 'created_poll', 'thread', threadId, question);

    res.json({ success: true, pollId });
  } catch (err) {
    console.error('[CREATE POLL ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get poll for a thread
app.get('/api/threads/:threadId/poll', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.threadId);
  const userId = req.user.userId;

  try {
    const pollResult = await db.query(
      `SELECT p.id, p.question, p.allow_multiple, p.ends_at, p.created_at,
              u.alias AS created_by
       FROM polls p
       JOIN users u ON u.id = p.created_by
       WHERE p.thread_id = $1`,
      [threadId]
    );

    if (pollResult.rows.length === 0) {
      return res.json({ success: true, poll: null });
    }

    const poll = pollResult.rows[0];
    const isExpired = poll.ends_at && new Date(poll.ends_at) < new Date();

    // Get options with vote counts
    const optionsResult = await db.query(
      `SELECT po.id, po.option_text, po.display_order,
              COUNT(pv.id) AS vote_count
       FROM poll_options po
       LEFT JOIN poll_votes pv ON pv.option_id = po.id
       WHERE po.poll_id = $1
       GROUP BY po.id
       ORDER BY po.display_order`,
      [poll.id]
    );

    // Get user's votes
    const userVotesResult = await db.query(
      'SELECT option_id FROM poll_votes WHERE poll_id = $1 AND user_id = $2',
      [poll.id, userId]
    );
    const userVotes = userVotesResult.rows.map(v => v.option_id);

    // Total votes
    const totalVotesResult = await db.query(
      'SELECT COUNT(DISTINCT user_id) FROM poll_votes WHERE poll_id = $1',
      [poll.id]
    );
    const totalVoters = parseInt(totalVotesResult.rows[0].count);

    res.json({
      success: true,
      poll: {
        id: poll.id,
        question: poll.question,
        allowMultiple: poll.allow_multiple,
        endsAt: poll.ends_at,
        isExpired: isExpired,
        createdBy: poll.created_by,
        createdAt: poll.created_at,
        totalVoters: totalVoters,
        userVotes: userVotes,
        options: optionsResult.rows.map(o => ({
          id: o.id,
          text: o.option_text,
          voteCount: parseInt(o.vote_count),
          percentage: totalVoters > 0 ? Math.round((parseInt(o.vote_count) / totalVoters) * 100) : 0
        }))
      }
    });
  } catch (err) {
    console.error('[GET POLL ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Vote on a poll
app.post('/api/polls/:pollId/vote', authMiddleware, async (req, res) => {
  const pollId = parseInt(req.params.pollId);
  const { optionIds } = req.body;
  const userId = req.user.userId;

  if (!optionIds || !Array.isArray(optionIds) || optionIds.length === 0) {
    return res.status(400).json({ success: false, error: 'no_options_selected' });
  }

  try {
    // Get poll
    const pollResult = await db.query(
      'SELECT id, allow_multiple, ends_at FROM polls WHERE id = $1',
      [pollId]
    );

    if (pollResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'poll_not_found' });
    }

    const poll = pollResult.rows[0];

    // Check if expired
    if (poll.ends_at && new Date(poll.ends_at) < new Date()) {
      return res.status(400).json({ success: false, error: 'poll_expired' });
    }

    // Check multiple votes
    if (!poll.allow_multiple && optionIds.length > 1) {
      return res.status(400).json({ success: false, error: 'single_vote_only' });
    }

    // Clear existing votes
    await db.query('DELETE FROM poll_votes WHERE poll_id = $1 AND user_id = $2', [pollId, userId]);

    // Add new votes
    for (const optionId of optionIds) {
      await db.query(
        'INSERT INTO poll_votes (poll_id, option_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
        [pollId, optionId, userId]
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error('[VOTE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Delete a poll (owner or admin only)
app.delete('/api/polls/:pollId', authMiddleware, async (req, res) => {
  const pollId = parseInt(req.params.pollId);

  try {
    const pollResult = await db.query('SELECT created_by FROM polls WHERE id = $1', [pollId]);
    if (pollResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'poll_not_found' });
    }

    const isOwner = pollResult.rows[0].created_by === req.user.userId;
    const adminCheck = await db.query('SELECT is_admin FROM users WHERE id = $1', [req.user.userId]);
    const isAdmin = adminCheck.rows.length > 0 && adminCheck.rows[0].is_admin;

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ success: false, error: 'forbidden' });
    }

    await db.query('DELETE FROM polls WHERE id = $1', [pollId]);

    res.json({ success: true });
  } catch (err) {
    console.error('[DELETE POLL ERROR]', err.message);
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
  const sort = req.query.sort || 'newest'; // newest, oldest, popular
  const tagFilter = req.query.tag ? parseInt(req.query.tag) : null;
  
  try {
    const roomResult = await db.query(
      'SELECT id, slug, title FROM rooms WHERE slug = $1',
      [roomSlug]
    );
    
    if (roomResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'room_not_found' });
    }
    
    const room = roomResult.rows[0];

    // Build dynamic query with filters
    let whereClause = 't.room_id = $1';
    let queryParams = [room.id];
    let paramIdx = 2;
    
    if (search) {
      whereClause += ` AND t.title ILIKE $${paramIdx}`;
      queryParams.push('%' + search + '%');
      paramIdx++;
    }
    
    if (tagFilter) {
      whereClause += ` AND EXISTS (SELECT 1 FROM thread_tags tt WHERE tt.thread_id = t.id AND tt.tag_id = $${paramIdx})`;
      queryParams.push(tagFilter);
      paramIdx++;
    }

    // Count total threads
    const countResult = await db.query(
      `SELECT COUNT(*) FROM threads t WHERE ${whereClause}`,
      queryParams
    );
    const total = parseInt(countResult.rows[0].count);
    
    // Build ORDER BY clause based on sort
    let orderClause = 't.is_pinned DESC, t.id DESC';
    if (sort === 'oldest') {
      orderClause = 't.is_pinned DESC, t.id ASC';
    } else if (sort === 'popular') {
      orderClause = 't.is_pinned DESC, vote_score DESC, t.id DESC';
    }
    
    // Get paginated threads with vote counts and tags
    const threadsQuery = `
      SELECT t.id, t.title, t.is_pinned, t.is_locked, 
             COUNT(e.id) FILTER (WHERE e.shadow_banned = FALSE OR e.shadow_banned IS NULL)::int AS "entriesCount",
             COALESCE((SELECT SUM(CASE WHEN r.reaction_type = 'like' THEN 1 WHEN r.reaction_type = 'dislike' THEN -1 ELSE 0 END) 
                       FROM reactions r 
                       JOIN entries en ON en.id = r.entry_id 
                       WHERE en.thread_id = t.id), 0)::int AS vote_score,
             (SELECT json_agg(json_build_object('id', tg.id, 'name', tg.name, 'color', tg.color))
              FROM tags tg JOIN thread_tags ttg ON ttg.tag_id = tg.id WHERE ttg.thread_id = t.id) AS tags
       FROM threads t
       LEFT JOIN entries e ON e.thread_id = t.id
       WHERE ${whereClause}
       GROUP BY t.id, t.is_pinned, t.is_locked 
       ORDER BY ${orderClause} 
       LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
    queryParams.push(limit, offset);
    
    const threadsResult = await db.query(threadsQuery, queryParams);
    
    res.json({
      success: true,
      room: { id: room.slug, title: room.title },
      threads: threadsResult.rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('[ROOM ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// API: Get entries in a thread (with pagination)
app.get('/api/thread/:id', authMiddleware, async (req, res) => {
  const threadId = req.params.id;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 30, 100);
  const offset = (page - 1) * limit;
  const afterId = parseInt(req.query.after) || 0; // For polling - get entries after this ID
  
  try {
    // Support both numeric ID and slug lookup
    const isNumeric = /^\d+$/.test(threadId);
    const threadResult = await db.query(
      `SELECT t.id, t.title, t.slow_mode_interval, t.is_locked, t.is_pinned, r.slug AS room_slug
       FROM threads t
       JOIN rooms r ON r.id = t.room_id
       WHERE ${isNumeric ? 't.id = $1' : 't.slug = $1'}`,
      [isNumeric ? parseInt(threadId) : threadId]
    );
    
    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }
    
    const thread = threadResult.rows[0];

    // If polling for new entries only (after parameter provided)
    if (afterId > 0) {
      const newEntriesResult = await db.query(
        `SELECT e.id, e.user_id, COALESCE(u.alias, e.alias) AS alias, e.content, 
                COALESCE(u.avatar_config, e.avatar_config) AS avatar_config,
                u.signature, u.reputation, u.custom_title, u.is_admin,
                e.created_at, e.edited_at,
                (SELECT COUNT(*) FROM entries WHERE user_id = e.user_id AND is_deleted = FALSE) AS post_count,
                LENGTH(e.content) > $3 AS "exceedsCharLimit"
         FROM entries e
         LEFT JOIN users u ON u.id = e.user_id
         WHERE e.thread_id = $1 AND e.id > $2 
           AND (e.shadow_banned = FALSE OR e.shadow_banned IS NULL) 
           AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)
         ORDER BY e.created_at
         LIMIT 20`,
        [thread.id, afterId, CONTENT_CHAR_LIMIT]
      );
      
      // Get reactions for new entries
      const entryIds = newEntriesResult.rows.map(e => e.id);
      let reactionsMap = {};
      
      if (entryIds.length > 0) {
        const reactionsResult = await db.query(
          `SELECT entry_id, reaction_type, COUNT(*) as count
           FROM reactions WHERE entry_id = ANY($1) GROUP BY entry_id, reaction_type`,
          [entryIds]
        );
        reactionsResult.rows.forEach(row => {
          if (!reactionsMap[row.entry_id]) reactionsMap[row.entry_id] = {};
          reactionsMap[row.entry_id][row.reaction_type] = parseInt(row.count);
        });
      }
      
      const entriesWithReactions = newEntriesResult.rows.map(entry => {
        const postCount = parseInt(entry.post_count) || 0;
        let rank = 'NEWCOMER';
        if (postCount >= 500) rank = 'VETERAN';
        else if (postCount >= 200) rank = 'EXPERT';
        else if (postCount >= 100) rank = 'REGULAR';
        else if (postCount >= 50) rank = 'MEMBER';
        else if (postCount >= 10) rank = 'ACTIVE';
        return { ...entry, rank, reactions: reactionsMap[entry.id] || {} };
      });
      
      return res.json({ success: true, entries: entriesWithReactions });
    }

    // Get user's muted list for filtering
    const userId = req.user.userId;
    const mutedResult = await db.query(
      'SELECT muted_user_id FROM muted_users WHERE user_id = $1',
      [userId]
    );
    const mutedUserIds = mutedResult.rows.map(r => r.muted_user_id);

    // Count total entries (exclude deleted and muted users)
    let countQuery = `SELECT COUNT(*) FROM entries e WHERE e.thread_id = $1 AND (e.shadow_banned = FALSE OR e.shadow_banned IS NULL) AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)`;
    let countParams = [thread.id];
    if (mutedUserIds.length > 0) {
      countQuery += ` AND (e.user_id IS NULL OR e.user_id != ALL($2))`;
      countParams.push(mutedUserIds);
    }
    const countResult = await db.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].count);
    
    // Build entries query with muted filter
    let entriesQuery = `SELECT e.id, e.user_id, COALESCE(u.alias, e.alias) AS alias, e.content, 
              COALESCE(u.avatar_config, e.avatar_config) AS avatar_config,
              u.signature, u.reputation, u.custom_title, u.is_admin,
              e.created_at, e.edited_at,
              (SELECT COUNT(*) FROM entries WHERE user_id = e.user_id AND is_deleted = FALSE) AS post_count,
              LENGTH(e.content) > $2 AS "exceedsCharLimit"
       FROM entries e
       LEFT JOIN users u ON u.id = e.user_id
       WHERE e.thread_id = $1 AND (e.shadow_banned = FALSE OR e.shadow_banned IS NULL) AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)`;
    let entriesParams = [thread.id, CONTENT_CHAR_LIMIT];
    
    if (mutedUserIds.length > 0) {
      entriesQuery += ` AND (e.user_id IS NULL OR e.user_id != ALL($3))`;
      entriesParams.push(mutedUserIds);
      entriesQuery += ` ORDER BY e.created_at LIMIT $4 OFFSET $5`;
      entriesParams.push(limit, offset);
    } else {
      entriesQuery += ` ORDER BY e.created_at LIMIT $3 OFFSET $4`;
      entriesParams.push(limit, offset);
    }
    
    const entriesResult = await db.query(entriesQuery, entriesParams);
    
    // Fetch reactions for all entries
    const entryIds = entriesResult.rows.map(e => e.id);
    let reactionsMap = {};
    let votesMap = {};
    let userVotesMap = {};
    
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
      
      // Fetch vote scores for entries
      const votesResult = await db.query(
        `SELECT entry_id, COALESCE(SUM(vote_value), 0) as score
         FROM entry_votes
         WHERE entry_id = ANY($1)
         GROUP BY entry_id`,
        [entryIds]
      );
      
      votesResult.rows.forEach(row => {
        votesMap[row.entry_id] = parseInt(row.score);
      });
      
      // Fetch current user's votes
      if (userId) {
        const userVotesResult = await db.query(
          `SELECT entry_id, vote_value
           FROM entry_votes
           WHERE entry_id = ANY($1) AND user_id = $2`,
          [entryIds, userId]
        );
        
        userVotesResult.rows.forEach(row => {
          userVotesMap[row.entry_id] = row.vote_value;
        });
      }
    }
    
    // Attach reactions, votes, and rank to entries
    const entriesWithReactions = entriesResult.rows.map(entry => {
      const postCount = parseInt(entry.post_count) || 0;
      let rank = 'NEWCOMER';
      if (postCount >= 500) rank = 'VETERAN';
      else if (postCount >= 200) rank = 'EXPERT';
      else if (postCount >= 100) rank = 'REGULAR';
      else if (postCount >= 50) rank = 'MEMBER';
      else if (postCount >= 10) rank = 'ACTIVE';
      
      return {
        ...entry,
        rank: rank,
        reactions: reactionsMap[entry.id] || {},
        score: votesMap[entry.id] || 0,
        userVote: userVotesMap[entry.id] || 0
      };
    });
    
    res.json({
      success: true,
      thread: {
        id: thread.id,
        title: thread.title,
        roomId: thread.room_slug,
        slowModeInterval: thread.slow_mode_interval || null,
        isLocked: thread.is_locked || false,
        isPinned: thread.is_pinned || false
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
app.post('/api/threads', authMiddleware, ipBanMiddleware, userBanMiddleware, threadsLimiter, async (req, res) => {
  const { roomId, title, content, tags } = req.body;
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

    // Apply word filter and XSS sanitization to title and content
    const filteredTitle = sanitizeContent(await filterContent(title));
    const filteredContent = sanitizeContent(await filterContent(content));

    // Create thread
    const threadResult = await db.query(
      'INSERT INTO threads (room_id, title, user_id) VALUES ($1, $2, $3) RETURNING id',
      [roomDbId, filteredTitle, userId]
    );
    const threadId = threadResult.rows[0].id;

    // Create initial entry
    await db.query(
      'INSERT INTO entries (thread_id, user_id, content) VALUES ($1, $2, $3)',
      [threadId, userId, filteredContent]
    );

    // Assign tags if provided
    if (tags && Array.isArray(tags) && tags.length > 0) {
      for (const tagId of tags) {
        await db.query(
          'INSERT INTO thread_tags (thread_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [threadId, tagId]
        );
      }
    }

    // Log activity
    await logActivity(userId, 'created_thread', 'thread', threadId, filteredTitle);

    // Check for badge achievements (async, non-blocking)
    checkAndAwardBadges(userId).catch(() => {});

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
app.post('/api/entries', authMiddleware, ipBanMiddleware, userBanMiddleware, entriesLimiter, async (req, res) => {
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
      `SELECT id, slow_mode_interval, is_locked FROM threads WHERE ${isNumeric ? 'id = $1' : 'slug = $1'}`,
      [isNumeric ? parseInt(threadIdentifier) : threadIdentifier]
    );

    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }

    const threadDbId = threadResult.rows[0].id;
    const slowModeInterval = threadResult.rows[0].slow_mode_interval;
    const isLocked = threadResult.rows[0].is_locked;

    // Check if thread is locked
    if (isLocked) {
      // Allow admins to post in locked threads
      const adminCheck = await db.query('SELECT is_admin FROM users WHERE id = $1', [userId]);
      if (!adminCheck.rows[0]?.is_admin) {
        return res.status(403).json({ success: false, error: 'thread_locked', message: 'This thread is locked' });
      }
    }

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
    
    // Apply word filter and XSS sanitization
    const filteredContent = sanitizeContent(await filterContent(content));

    const insertResult = await db.query(
      `INSERT INTO entries (thread_id, content, alias, avatar_config, user_id, ip_hash, shadow_banned)
       VALUES ($1, $2, $3, $4, $5, $6, FALSE)
       RETURNING id, thread_id AS "threadId", content, alias, avatar_config AS "avatarConfig", created_at AS "createdAt", user_id`,
      [threadDbId, filteredContent, entryAlias, avatar_config || null, userId, ipHash]
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
          
          // Check if blocked (either direction) - blocked users can't mention each other
          const isBlocked = await isBlockedBetween(userId, mentionedUserId);
          if (isBlocked) continue;
          
          const notificationTitle = `${entryAlias} mentioned you`;
          const notificationPreview = content.substring(0, 100) + (content.length > 100 ? '...' : '');
          const notificationLink = `thread.html?id=${threadDbId}#entry-${entryId}`;
          
          await db.query(
            `INSERT INTO notifications (user_id, type, title, message, link, related_entry_id, related_user_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [mentionedUserId, 'mention', notificationTitle, notificationPreview, notificationLink, entryId, userId]
          );
          
          // Send email notification (non-blocking)
          sendNotificationEmail(mentionedUserId, 'mention', notificationTitle, notificationPreview, notificationLink);
        }
      }
    } catch (mentionErr) {
      // Silent fail - mentions should not break posting
      console.error('[MENTION NOTIFICATION ERROR]', mentionErr.message);
    }

    // Log activity
    try {
      const threadTitleResult = await db.query('SELECT title FROM threads WHERE id = $1', [threadDbId]);
      const threadTitle = threadTitleResult.rows[0]?.title || 'Unknown thread';
      await logActivity(userId, 'posted_reply', 'thread', threadDbId, threadTitle);
    } catch (actErr) {
      // Silent fail
    }

    // Notify thread subscribers
    try {
      const threadTitleResult = await db.query('SELECT title FROM threads WHERE id = $1', [threadDbId]);
      const threadTitle = threadTitleResult.rows[0]?.title || 'Unknown thread';
      
      // Get all subscribers except the poster
      const subscribersResult = await db.query(
        `SELECT user_id FROM thread_subscriptions WHERE thread_id = $1 AND user_id != $2`,
        [threadDbId, userId]
      );
      
      for (const sub of subscribersResult.rows) {
        const notificationTitle = `New reply in "${threadTitle.substring(0, 50)}"`;
        const notificationPreview = `${entryAlias} posted: ${content.substring(0, 80)}${content.length > 80 ? '...' : ''}`;
        const notificationLink = `thread.html?id=${threadDbId}#entry-${entryId}`;
        
        await db.query(
          `INSERT INTO notifications (user_id, type, title, message, link, related_entry_id, related_user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [sub.user_id, 'thread_reply', notificationTitle, notificationPreview, notificationLink, entryId, userId]
        );
        
        // Send email notification (non-blocking)
        sendNotificationEmail(sub.user_id, 'thread_reply', notificationTitle, notificationPreview, notificationLink);
      }
    } catch (subErr) {
      // Silent fail - subscription notifications should not break posting
      console.error('[SUBSCRIPTION NOTIFICATION ERROR]', subErr.message);
    }

    // Check for badge achievements (async, non-blocking)
    checkAndAwardBadges(userId).catch(() => {});

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
      'SELECT id, user_id, content, created_at FROM entries WHERE id = $1',
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

    // Save current content to revisions before updating
    const revisionCount = await db.query(
      'SELECT COUNT(*) FROM post_revisions WHERE entry_id = $1',
      [entryId]
    );
    const revisionNumber = parseInt(revisionCount.rows[0].count) + 1;
    
    await db.query(
      'INSERT INTO post_revisions (entry_id, content, edited_by, revision_number) VALUES ($1, $2, $3, $4)',
      [entryId, entry.content, userId, revisionNumber]
    );

    // Update entry
    await db.query(
      'UPDATE entries SET content = $1, edited_at = NOW() WHERE id = $2',
      [content.trim(), entryId]
    );

    res.json({ success: true, revisionNumber });
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
    await logAudit('delete_entry', 'entry', entryId, userId, { reason: isAdmin ? 'admin_delete' : 'owner_delete' });

    res.json({ success: true });
  } catch (err) {
    console.error('[DELETE ENTRY ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// POST REVISION HISTORY
// ========================================

// Get revision history for a post
app.get('/api/entries/:id/revisions', authMiddleware, async (req, res) => {
  const entryId = parseInt(req.params.id);
  
  try {
    const result = await db.query(
      `SELECT pr.id, pr.content, pr.revision_number, pr.created_at,
              u.alias AS edited_by_alias
       FROM post_revisions pr
       LEFT JOIN users u ON u.id = pr.edited_by
       WHERE pr.entry_id = $1
       ORDER BY pr.revision_number DESC`,
      [entryId]
    );
    
    res.json({ 
      success: true, 
      revisions: result.rows.map(r => ({
        id: r.id,
        content: r.content,
        revisionNumber: r.revision_number,
        editedAt: r.created_at,
        editedBy: r.edited_by_alias
      }))
    });
  } catch (err) {
    console.error('[GET REVISIONS ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get a specific revision
app.get('/api/revisions/:id', authMiddleware, async (req, res) => {
  const revisionId = parseInt(req.params.id);
  
  try {
    const result = await db.query(
      `SELECT pr.*, u.alias AS edited_by_alias,
              e.content AS current_content
       FROM post_revisions pr
       LEFT JOIN users u ON u.id = pr.edited_by
       LEFT JOIN entries e ON e.id = pr.entry_id
       WHERE pr.id = $1`,
      [revisionId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'revision_not_found' });
    }
    
    const r = result.rows[0];
    res.json({ 
      success: true, 
      revision: {
        id: r.id,
        entryId: r.entry_id,
        content: r.content,
        currentContent: r.current_content,
        revisionNumber: r.revision_number,
        editedAt: r.created_at,
        editedBy: r.edited_by_alias
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// USER BADGES SYSTEM
// ========================================

// Get all available badges
app.get('/api/badges', authMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, slug, name, description, icon, color, rarity FROM badges ORDER BY rarity, name'
    );
    res.json({ success: true, badges: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get badges for a user
app.get('/api/users/:alias/badges', authMiddleware, async (req, res) => {
  const { alias } = req.params;
  
  try {
    const result = await db.query(
      `SELECT b.id, b.slug, b.name, b.description, b.icon, b.color, b.rarity,
              ub.awarded_at
       FROM badges b
       JOIN user_badges ub ON ub.badge_id = b.id
       JOIN users u ON u.id = ub.user_id
       WHERE u.alias = $1
       ORDER BY ub.awarded_at DESC`,
      [alias]
    );
    res.json({ success: true, badges: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Award badge to user (admin only)
app.post('/api/admin/badges/award', authMiddleware, async (req, res) => {
  const { alias, badge_id } = req.body;
  const adminId = req.user.userId;
  
  try {
    // Check admin
    const adminCheck = await db.query('SELECT is_admin FROM users WHERE id = $1', [adminId]);
    if (!adminCheck.rows[0]?.is_admin) {
      return res.status(403).json({ success: false, error: 'forbidden' });
    }
    
    // Get user by alias
    const user = await db.query('SELECT id, alias FROM users WHERE alias = $1', [alias]);
    if (user.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found', message: 'User not found' });
    }
    
    // Get badge
    const badge = await db.query('SELECT id, name FROM badges WHERE id = $1', [badge_id]);
    if (badge.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'badge_not_found', message: 'Badge not found' });
    }
    
    // Award badge
    const result = await db.query(
      `INSERT INTO user_badges (user_id, badge_id, awarded_by)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, badge_id) DO NOTHING
       RETURNING id`,
      [user.rows[0].id, badge.rows[0].id, adminId]
    );
    
    if (result.rows.length === 0) {
      return res.json({ success: true, message: 'User already has this badge' });
    }
    
    res.json({ success: true, message: 'Badge "' + badge.rows[0].name + '" awarded to ' + user.rows[0].alias });
  } catch (err) {
    console.error('Award badge error:', err);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Helper: Check and award automatic badges
async function checkAndAwardBadges(userId) {
  try {
    // Get user stats
    const stats = await db.query(
      `SELECT 
        (SELECT COUNT(*) FROM entries WHERE user_id = $1 AND is_deleted = FALSE) AS post_count,
        (SELECT COUNT(*) FROM threads WHERE user_id = $1) AS thread_count,
        (SELECT reputation FROM users WHERE id = $1) AS reputation,
        (SELECT email_verified FROM users WHERE id = $1) AS email_verified,
        (SELECT totp_enabled FROM users WHERE id = $1) AS totp_enabled,
        (SELECT created_at FROM users WHERE id = $1) AS created_at,
        (SELECT MAX(vote_value) FROM (
          SELECT COALESCE(SUM(vote_value), 0) AS vote_value 
          FROM entry_votes ev 
          JOIN entries e ON e.id = ev.entry_id 
          WHERE e.user_id = $1 
          GROUP BY ev.entry_id
        ) AS votes) AS max_post_votes`,
      [userId]
    );
    
    if (stats.rows.length === 0) return;
    
    const s = stats.rows[0];
    const postCount = parseInt(s.post_count) || 0;
    const threadCount = parseInt(s.thread_count) || 0;
    const reputation = parseInt(s.reputation) || 0;
    const maxPostVotes = parseInt(s.max_post_votes) || 0;
    
    const badgesToAward = [];
    
    // Post milestones
    if (postCount >= 1) badgesToAward.push('first-post');
    if (postCount >= 10) badgesToAward.push('ten-posts');
    if (postCount >= 50) badgesToAward.push('fifty-posts');
    if (postCount >= 100) badgesToAward.push('hundred-posts');
    if (postCount >= 500) badgesToAward.push('five-hundred-posts');
    if (postCount >= 1000) badgesToAward.push('thousand-posts');
    
    // Thread milestones
    if (threadCount >= 1) badgesToAward.push('first-thread');
    if (threadCount >= 10) badgesToAward.push('ten-threads');
    
    // Reputation milestones
    if (reputation >= 10) badgesToAward.push('reputation-10');
    if (reputation >= 50) badgesToAward.push('reputation-50');
    if (reputation >= 100) badgesToAward.push('reputation-100');
    if (reputation >= 500) badgesToAward.push('reputation-500');
    
    // Helpful badges
    if (maxPostVotes >= 10) badgesToAward.push('helpful');
    if (maxPostVotes >= 50) badgesToAward.push('very-helpful');
    
    // Email verified
    if (s.email_verified) badgesToAward.push('verified-email');
    
    // 2FA enabled
    if (s.totp_enabled) badgesToAward.push('two-factor');
    
    // One year anniversary
    if (s.created_at) {
      const yearAgo = new Date();
      yearAgo.setFullYear(yearAgo.getFullYear() - 1);
      if (new Date(s.created_at) <= yearAgo) {
        badgesToAward.push('one-year');
      }
    }
    
    // Award badges
    for (const slug of badgesToAward) {
      await db.query(
        `INSERT INTO user_badges (user_id, badge_id)
         SELECT $1, id FROM badges WHERE slug = $2
         ON CONFLICT (user_id, badge_id) DO NOTHING`,
        [userId, slug]
      );
    }
  } catch (err) {
    console.error('[BADGE CHECK ERROR]', err.message);
  }
}

// ========================================
// REPORT SYSTEM
// ========================================

// Submit a report
app.post('/api/reports', authMiddleware, reportsLimiter, async (req, res) => {
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
      await logAudit('delete_entry', 'entry', entryId, adminId, { reason: 'report_action' });
    }

    await logAudit('resolve_report', 'report', reportId, adminId, { status, action });

    res.json({ success: true });
  } catch (err) {
    console.error('[RESOLVE REPORT ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// MODERATION TOOLS
// ========================================

// Admin: Get all IP bans
app.get('/api/admin/ip-bans', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT b.*, u.alias AS banned_by_alias 
       FROM ip_bans b
       LEFT JOIN users u ON u.id = b.banned_by
       ORDER BY b.created_at DESC`
    );
    res.json({ success: true, bans: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Add IP ban
app.post('/api/admin/ip-bans', authMiddleware, adminMiddleware, async (req, res) => {
  const { ip_hash, reason, expires_days } = req.body;
  const adminId = req.user.userId;

  if (!ip_hash) {
    return res.status(400).json({ success: false, error: 'ip_hash required' });
  }

  try {
    const expiresAt = expires_days ? new Date(Date.now() + expires_days * 24 * 60 * 60 * 1000) : null;
    await db.query(
      `INSERT INTO ip_bans (ip_hash, reason, banned_by, expires_at) VALUES ($1, $2, $3, $4)`,
      [ip_hash, reason || null, adminId, expiresAt]
    );
    await logAudit('ip_ban', 'ip', null, adminId, { ip_hash, reason, expires_days });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Remove IP ban
app.delete('/api/admin/ip-bans/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const banId = parseInt(req.params.id);
  const adminId = req.user.userId;

  try {
    await db.query('DELETE FROM ip_bans WHERE id = $1', [banId]);
    await logAudit('ip_unban', 'ip', banId, adminId, null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get word filters
app.get('/api/admin/word-filters', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT f.*, u.alias AS created_by_alias
       FROM word_filters f
       LEFT JOIN users u ON u.id = f.created_by
       ORDER BY f.created_at DESC`
    );
    res.json({ success: true, filters: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Add word filter
app.post('/api/admin/word-filters', authMiddleware, adminMiddleware, async (req, res) => {
  const { word, replacement, is_regex } = req.body;
  const adminId = req.user.userId;

  if (!word) {
    return res.status(400).json({ success: false, error: 'word required' });
  }

  try {
    await db.query(
      `INSERT INTO word_filters (word, replacement, is_regex, created_by) VALUES ($1, $2, $3, $4)`,
      [word, replacement || '***', is_regex || false, adminId]
    );
    wordFiltersCacheTime = 0; // Invalidate cache
    await logAudit('add_word_filter', 'filter', null, adminId, { word, replacement, is_regex });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Delete word filter
app.delete('/api/admin/word-filters/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const filterId = parseInt(req.params.id);
  const adminId = req.user.userId;

  try {
    await db.query('DELETE FROM word_filters WHERE id = $1', [filterId]);
    wordFiltersCacheTime = 0; // Invalidate cache
    await logAudit('delete_word_filter', 'filter', filterId, adminId, null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get mod notes for a user
app.get('/api/admin/users/:id/notes', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);

  try {
    const result = await db.query(
      `SELECT n.*, u.alias AS created_by_alias
       FROM mod_notes n
       LEFT JOIN users u ON u.id = n.created_by
       WHERE n.user_id = $1
       ORDER BY n.created_at DESC`,
      [userId]
    );
    res.json({ success: true, notes: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Add mod note
app.post('/api/admin/users/:id/notes', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);
  const { note } = req.body;
  const adminId = req.user.userId;

  if (!note) {
    return res.status(400).json({ success: false, error: 'note required' });
  }

  try {
    await db.query(
      `INSERT INTO mod_notes (user_id, note, created_by) VALUES ($1, $2, $3)`,
      [userId, note, adminId]
    );
    await logAudit('add_mod_note', 'user', userId, adminId, { note: note.substring(0, 100) });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Delete mod note
app.delete('/api/admin/notes/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const noteId = parseInt(req.params.id);
  const adminId = req.user.userId;

  try {
    await db.query('DELETE FROM mod_notes WHERE id = $1', [noteId]);
    await logAudit('delete_mod_note', 'note', noteId, adminId, null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get warnings for a user
app.get('/api/admin/users/:id/warnings', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);

  try {
    const result = await db.query(
      `SELECT w.*, u.alias AS issued_by_alias
       FROM warnings w
       LEFT JOIN users u ON u.id = w.issued_by
       WHERE w.user_id = $1
       ORDER BY w.created_at DESC`,
      [userId]
    );
    res.json({ success: true, warnings: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Issue warning
app.post('/api/admin/users/:id/warnings', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);
  const { reason } = req.body;
  const adminId = req.user.userId;

  if (!reason) {
    return res.status(400).json({ success: false, error: 'reason required' });
  }

  try {
    // Create warning
    await db.query(
      `INSERT INTO warnings (user_id, reason, issued_by) VALUES ($1, $2, $3)`,
      [userId, reason, adminId]
    );

    // Create notification for user
    const userResult = await db.query('SELECT alias FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length > 0) {
      await db.query(
        `INSERT INTO notifications (user_id, type, title, message) VALUES ($1, $2, $3, $4)`,
        [userId, 'warning', 'You have received a warning', reason]
      );
    }

    await logAudit('issue_warning', 'user', userId, adminId, { reason });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Ban user (permanent or temporary)
app.post('/api/admin/users/:id/ban', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);
  const { reason, days } = req.body;
  const adminId = req.user.userId;

  try {
    const expiresAt = days ? new Date(Date.now() + days * 24 * 60 * 60 * 1000) : null;
    await db.query(
      `UPDATE users SET is_banned = TRUE, ban_reason = $1, ban_expires_at = $2, banned_by = $3 WHERE id = $4`,
      [reason || 'Banned by admin', expiresAt, adminId, userId]
    );

    // Notify user
    await db.query(
      `INSERT INTO notifications (user_id, type, title, message) VALUES ($1, $2, $3, $4)`,
      [userId, 'ban', days ? 'You have been temporarily banned' : 'You have been banned', reason || 'Contact admin for details']
    );

    await logAudit('ban_user', 'user', userId, adminId, { reason, days, expires_at: expiresAt });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Unban user
app.post('/api/admin/users/:id/unban', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);
  const adminId = req.user.userId;

  try {
    await db.query(
      `UPDATE users SET is_banned = FALSE, ban_reason = NULL, ban_expires_at = NULL, banned_by = NULL WHERE id = $1`,
      [userId]
    );
    await logAudit('unban_user', 'user', userId, adminId, null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get user details for moderation
app.get('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);

  try {
    const userResult = await db.query(
      `SELECT id, alias, bio, is_admin, is_banned, ban_reason, ban_expires_at, is_shadow_banned, created_at
       FROM users WHERE id = $1`,
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }

    const user = userResult.rows[0];

    // Get warning count
    const warningCount = await db.query(
      'SELECT COUNT(*) FROM warnings WHERE user_id = $1',
      [userId]
    );

    // Get note count
    const noteCount = await db.query(
      'SELECT COUNT(*) FROM mod_notes WHERE user_id = $1',
      [userId]
    );

    // Get recent entries
    const recentEntries = await db.query(
      `SELECT e.id, e.content, e.ip_hash, e.created_at, t.title AS thread_title
       FROM entries e
       JOIN threads t ON t.id = e.thread_id
       WHERE e.user_id = $1 AND e.is_deleted = FALSE
       ORDER BY e.created_at DESC LIMIT 10`,
      [userId]
    );

    res.json({
      success: true,
      user: {
        ...user,
        warning_count: parseInt(warningCount.rows[0].count),
        note_count: parseInt(noteCount.rows[0].count),
        recent_entries: recentEntries.rows
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Search users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const search = req.query.search || '';
  const filter = req.query.filter || 'all'; // all, banned, warned

  try {
    let query = `
      SELECT u.id, u.alias, u.is_admin, u.is_banned, u.ban_expires_at, u.created_at,
             (SELECT COUNT(*) FROM warnings WHERE user_id = u.id) AS warning_count
      FROM users u
      WHERE 1=1
    `;
    const params = [];

    if (search) {
      params.push('%' + search + '%');
      query += ` AND u.alias ILIKE $${params.length}`;
    }

    if (filter === 'banned') {
      query += ` AND u.is_banned = TRUE`;
    } else if (filter === 'warned') {
      query += ` AND (SELECT COUNT(*) FROM warnings WHERE user_id = u.id) > 0`;
    }

    query += ` ORDER BY u.created_at DESC LIMIT 100`;

    const result = await db.query(query, params);
    res.json({ success: true, users: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Move thread to different room
app.put('/api/admin/threads/:id/move', authMiddleware, adminMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.id);
  const { room_slug } = req.body;
  const adminId = req.user.userId;

  if (!room_slug) {
    return res.status(400).json({ success: false, error: 'room_slug required' });
  }

  try {
    // Get new room id
    const roomResult = await db.query('SELECT id FROM rooms WHERE slug = $1', [room_slug]);
    if (roomResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'room_not_found' });
    }
    const newRoomId = roomResult.rows[0].id;

    // Get old room for logging
    const threadResult = await db.query('SELECT room_id FROM threads WHERE id = $1', [threadId]);
    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }
    const oldRoomId = threadResult.rows[0].room_id;

    // Move thread
    await db.query('UPDATE threads SET room_id = $1 WHERE id = $2', [newRoomId, threadId]);
    await logAudit('move_thread', 'thread', threadId, adminId, { from_room_id: oldRoomId, to_room_slug: room_slug });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Pin/Unpin thread
app.put('/api/admin/threads/:id/pin', authMiddleware, adminMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.id);
  const adminId = req.user.userId;

  try {
    const result = await db.query(
      'UPDATE threads SET is_pinned = NOT is_pinned WHERE id = $1 RETURNING is_pinned',
      [threadId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }
    
    const isPinned = result.rows[0].is_pinned;
    await logAudit(isPinned ? 'pin_thread' : 'unpin_thread', 'thread', threadId, adminId, {});

    res.json({ success: true, is_pinned: isPinned });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Lock/Unlock thread
app.put('/api/admin/threads/:id/lock', authMiddleware, adminMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.id);
  const adminId = req.user.userId;

  try {
    const result = await db.query(
      'UPDATE threads SET is_locked = NOT is_locked WHERE id = $1 RETURNING is_locked',
      [threadId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }
    
    const isLocked = result.rows[0].is_locked;
    await logAudit(isLocked ? 'lock_thread' : 'unlock_thread', 'thread', threadId, adminId, {});

    res.json({ success: true, is_locked: isLocked });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get moderation dashboard stats
app.get('/api/admin/mod-stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const pendingReports = await db.query("SELECT COUNT(*) FROM reports WHERE status = 'pending'");
    const totalBans = await db.query('SELECT COUNT(*) FROM users WHERE is_banned = TRUE');
    const activeIpBans = await db.query("SELECT COUNT(*) FROM ip_bans WHERE expires_at IS NULL OR expires_at > NOW()");
    const recentWarnings = await db.query("SELECT COUNT(*) FROM warnings WHERE created_at > NOW() - INTERVAL '7 days'");

    res.json({
      success: true,
      stats: {
        pending_reports: parseInt(pendingReports.rows[0].count),
        total_bans: parseInt(totalBans.rows[0].count),
        active_ip_bans: parseInt(activeIpBans.rows[0].count),
        recent_warnings: parseInt(recentWarnings.rows[0].count)
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get comprehensive dashboard stats
app.get('/api/admin/dashboard-stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    // Basic counts
    const totalUsers = await db.query('SELECT COUNT(*) FROM users');
    const totalThreads = await db.query('SELECT COUNT(*) FROM threads');
    const totalPosts = await db.query('SELECT COUNT(*) FROM entries WHERE is_deleted = FALSE');
    const totalRooms = await db.query('SELECT COUNT(*) FROM rooms');

    // Today's activity
    const todayUsers = await db.query("SELECT COUNT(*) FROM users WHERE created_at > CURRENT_DATE");
    const todayPosts = await db.query("SELECT COUNT(*) FROM entries WHERE created_at > CURRENT_DATE AND is_deleted = FALSE");
    const todayThreads = await db.query("SELECT COUNT(*) FROM threads WHERE created_at > CURRENT_DATE");

    // Last 7 days activity (for graphs)
    const dailyPosts = await db.query(`
      SELECT DATE(created_at) as date, COUNT(*) as count
      FROM entries
      WHERE created_at > NOW() - INTERVAL '7 days' AND is_deleted = FALSE
      GROUP BY DATE(created_at)
      ORDER BY date
    `);

    const dailyUsers = await db.query(`
      SELECT DATE(created_at) as date, COUNT(*) as count
      FROM users
      WHERE created_at > NOW() - INTERVAL '7 days'
      GROUP BY DATE(created_at)
      ORDER BY date
    `);

    const dailyThreads = await db.query(`
      SELECT DATE(created_at) as date, COUNT(*) as count
      FROM threads
      WHERE created_at > NOW() - INTERVAL '7 days'
      GROUP BY DATE(created_at)
      ORDER BY date
    `);

    // Top posters (last 7 days)
    const topPosters = await db.query(`
      SELECT u.alias, COUNT(e.id) as post_count
      FROM entries e
      JOIN users u ON u.id = e.user_id
      WHERE e.created_at > NOW() - INTERVAL '7 days' AND e.is_deleted = FALSE
      GROUP BY u.id, u.alias
      ORDER BY post_count DESC
      LIMIT 10
    `);

    // Most active threads (last 7 days)
    const activeThreads = await db.query(`
      SELECT t.id, t.title, COUNT(e.id) as post_count
      FROM entries e
      JOIN threads t ON t.id = e.thread_id
      WHERE e.created_at > NOW() - INTERVAL '7 days' AND e.is_deleted = FALSE
      GROUP BY t.id, t.title
      ORDER BY post_count DESC
      LIMIT 10
    `);

    // Room activity
    const roomActivity = await db.query(`
      SELECT r.slug, r.title, COUNT(t.id) as thread_count,
             (SELECT COUNT(*) FROM entries e JOIN threads t2 ON t2.id = e.thread_id WHERE t2.room_id = r.id AND e.is_deleted = FALSE) as post_count
      FROM rooms r
      LEFT JOIN threads t ON t.room_id = r.id
      GROUP BY r.id, r.slug, r.title
      ORDER BY post_count DESC
    `);

    res.json({
      success: true,
      stats: {
        totals: {
          users: parseInt(totalUsers.rows[0].count),
          threads: parseInt(totalThreads.rows[0].count),
          posts: parseInt(totalPosts.rows[0].count),
          rooms: parseInt(totalRooms.rows[0].count)
        },
        today: {
          users: parseInt(todayUsers.rows[0].count),
          posts: parseInt(todayPosts.rows[0].count),
          threads: parseInt(todayThreads.rows[0].count)
        },
        graphs: {
          daily_posts: dailyPosts.rows,
          daily_users: dailyUsers.rows,
          daily_threads: dailyThreads.rows
        },
        top_posters: topPosters.rows,
        active_threads: activeThreads.rows,
        room_activity: roomActivity.rows
      }
    });
  } catch (err) {
    console.error('[DASHBOARD STATS ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// ROOM MANAGEMENT
// ========================================

// Admin: Get all rooms with details
app.get('/api/admin/rooms', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT r.*, 
             (SELECT COUNT(*) FROM threads WHERE room_id = r.id) as thread_count,
             (SELECT COUNT(*) FROM entries e JOIN threads t ON t.id = e.thread_id WHERE t.room_id = r.id AND e.is_deleted = FALSE) as post_count
      FROM rooms r
      ORDER BY r.display_order, r.id
    `);
    res.json({ success: true, rooms: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Create room
app.post('/api/admin/rooms', authMiddleware, adminMiddleware, async (req, res) => {
  const { slug, title, description, slow_mode_seconds, is_locked, display_order } = req.body;
  const adminId = req.user.userId;

  if (!slug || !title) {
    return res.status(400).json({ success: false, error: 'slug and title required' });
  }

  // Validate slug format
  if (!/^[a-z0-9-]+$/.test(slug)) {
    return res.status(400).json({ success: false, error: 'slug must be lowercase alphanumeric with hyphens only' });
  }

  try {
    const result = await db.query(
      `INSERT INTO rooms (slug, title, description, slow_mode_seconds, is_locked, display_order)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [slug, title, description || null, slow_mode_seconds || 0, is_locked || false, display_order || 0]
    );
    await logAudit('create_room', 'room', result.rows[0].id, adminId, { slug, title });
    res.json({ success: true, room_id: result.rows[0].id });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: 'slug_exists' });
    }
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Update room
app.put('/api/admin/rooms/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const roomId = parseInt(req.params.id);
  const { title, description, slow_mode_seconds, is_locked, display_order } = req.body;
  const adminId = req.user.userId;

  try {
    await db.query(
      `UPDATE rooms SET title = COALESCE($1, title), description = $2, 
       slow_mode_seconds = COALESCE($3, slow_mode_seconds),
       is_locked = COALESCE($4, is_locked), display_order = COALESCE($5, display_order)
       WHERE id = $6`,
      [title, description, slow_mode_seconds, is_locked, display_order, roomId]
    );
    await logAudit('update_room', 'room', roomId, adminId, { title, description });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Delete room (only if empty)
app.delete('/api/admin/rooms/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const roomId = parseInt(req.params.id);
  const adminId = req.user.userId;

  try {
    // Check if room has threads
    const threadCheck = await db.query('SELECT COUNT(*) FROM threads WHERE room_id = $1', [roomId]);
    if (parseInt(threadCheck.rows[0].count) > 0) {
      return res.status(400).json({ success: false, error: 'room_not_empty', message: 'Move or delete all threads first' });
    }

    const roomResult = await db.query('SELECT slug FROM rooms WHERE id = $1', [roomId]);
    await db.query('DELETE FROM rooms WHERE id = $1', [roomId]);
    await logAudit('delete_room', 'room', roomId, adminId, { slug: roomResult.rows[0]?.slug });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// ANNOUNCEMENTS
// ========================================

// Get active announcements (public)
app.get('/api/announcements', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT id, title, content, type, starts_at, expires_at
      FROM announcements
      WHERE is_active = TRUE 
        AND (starts_at IS NULL OR starts_at <= NOW())
        AND (expires_at IS NULL OR expires_at > NOW())
      ORDER BY created_at DESC
    `);
    res.json({ success: true, announcements: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get all announcements
app.get('/api/admin/announcements', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT a.*, u.alias AS created_by_alias
      FROM announcements a
      LEFT JOIN users u ON u.id = a.created_by
      ORDER BY a.created_at DESC
    `);
    res.json({ success: true, announcements: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Create announcement
app.post('/api/admin/announcements', authMiddleware, adminMiddleware, async (req, res) => {
  const { title, content, type, is_active, starts_at, expires_at } = req.body;
  const adminId = req.user.userId;

  if (!title) {
    return res.status(400).json({ success: false, error: 'title required' });
  }

  const validTypes = ['info', 'warning', 'success', 'error'];
  const announcementType = validTypes.includes(type) ? type : 'info';

  try {
    const result = await db.query(
      `INSERT INTO announcements (title, content, type, is_active, starts_at, expires_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [title, content || null, announcementType, is_active !== false, starts_at || null, expires_at || null, adminId]
    );
    await logAudit('create_announcement', 'announcement', result.rows[0].id, adminId, { title });
    res.json({ success: true, announcement_id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Update announcement
app.put('/api/admin/announcements/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const announcementId = parseInt(req.params.id);
  const { title, content, type, is_active, starts_at, expires_at } = req.body;
  const adminId = req.user.userId;

  try {
    await db.query(
      `UPDATE announcements SET 
       title = COALESCE($1, title), content = $2, type = COALESCE($3, type),
       is_active = COALESCE($4, is_active), starts_at = $5, expires_at = $6
       WHERE id = $7`,
      [title, content, type, is_active, starts_at || null, expires_at || null, announcementId]
    );
    await logAudit('update_announcement', 'announcement', announcementId, adminId, { title });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Delete announcement
app.delete('/api/admin/announcements/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const announcementId = parseInt(req.params.id);
  const adminId = req.user.userId;

  try {
    await db.query('DELETE FROM announcements WHERE id = $1', [announcementId]);
    await logAudit('delete_announcement', 'announcement', announcementId, adminId, null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Update user (edit alias, toggle admin, etc)
app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);
  const { alias, is_admin, bio } = req.body;
  const adminId = req.user.userId;

  try {
    // Build dynamic update
    const updates = [];
    const values = [];
    let paramIndex = 1;

    if (alias !== undefined) {
      updates.push(`alias = $${paramIndex++}`);
      values.push(alias);
    }
    if (is_admin !== undefined) {
      updates.push(`is_admin = $${paramIndex++}`);
      values.push(is_admin);
    }
    if (bio !== undefined) {
      updates.push(`bio = $${paramIndex++}`);
      values.push(bio);
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, error: 'no_fields_to_update' });
    }

    values.push(userId);
    await db.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
      values
    );

    await logAudit('update_user', 'user', userId, adminId, { alias, is_admin, bio });
    res.json({ success: true });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: 'alias_exists' });
    }
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// User: Get own warnings
app.get('/api/my/warnings', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    const result = await db.query(
      `SELECT id, reason, acknowledged, created_at FROM warnings WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    res.json({ success: true, warnings: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// User: Acknowledge warning
app.put('/api/my/warnings/:id/acknowledge', authMiddleware, async (req, res) => {
  const warningId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    await db.query(
      `UPDATE warnings SET acknowledged = TRUE WHERE id = $1 AND user_id = $2`,
      [warningId, userId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// ACCOUNT SETTINGS
// ========================================

// Change password
app.put('/api/my/password', authMiddleware, async (req, res) => {
  const { current_password, new_password } = req.body;
  const userId = req.user.userId;

  if (!current_password || !new_password) {
    return res.status(400).json({ success: false, error: 'both passwords required' });
  }

  const pwErrors = validatePassword(new_password);
  if (pwErrors.length > 0) {
    return res.status(400).json({ success: false, error: pwErrors[0] });
  }

  try {
    const userResult = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }

    const valid = await bcrypt.compare(current_password, userResult.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, error: 'invalid_current_password' });
    }

    const newHash = await bcrypt.hash(new_password, SALT_ROUNDS);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, userId]);

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Delete account (GDPR)
app.delete('/api/my/account', authMiddleware, async (req, res) => {
  const { password } = req.body;
  const userId = req.user.userId;

  if (!password) {
    return res.status(400).json({ success: false, error: 'password required' });
  }

  try {
    const userResult = await db.query('SELECT password_hash, alias FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }

    const valid = await bcrypt.compare(password, userResult.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, error: 'invalid_password' });
    }

    // Anonymize user data instead of hard delete (preserve post integrity)
    const anonAlias = 'deleted_' + Date.now();
    await db.query(
      `UPDATE users SET 
       alias = $1, password_hash = '', bio = NULL, avatar_config = NULL, 
       is_banned = TRUE, ban_reason = 'Account deleted by user'
       WHERE id = $2`,
      [anonAlias, userId]
    );

    // Update all entries to show anonymized alias
    await db.query('UPDATE entries SET alias = $1 WHERE user_id = $2', [anonAlias, userId]);

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// THREAD SUBSCRIPTIONS
// ========================================

// Get subscriptions
app.get('/api/my/subscriptions', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    const result = await db.query(
      `SELECT s.thread_id, t.title, t.slug, r.slug AS room_slug,
              (SELECT COUNT(*) FROM entries WHERE thread_id = t.id AND is_deleted = FALSE) as entry_count,
              (SELECT MAX(created_at) FROM entries WHERE thread_id = t.id AND is_deleted = FALSE) as last_activity
       FROM thread_subscriptions s
       JOIN threads t ON t.id = s.thread_id
       JOIN rooms r ON r.id = t.room_id
       WHERE s.user_id = $1
       ORDER BY last_activity DESC`,
      [userId]
    );
    res.json({ success: true, subscriptions: result.rows });
  } catch (err) {
    logger.error('GET_SUBSCRIPTIONS', err.message, { reqId: req.reqId, userId });
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Subscribe to thread
app.post('/api/threads/:id/subscribe', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    await db.query(
      `INSERT INTO thread_subscriptions (user_id, thread_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [userId, threadId]
    );
    res.json({ success: true, subscribed: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Unsubscribe from thread
app.delete('/api/threads/:id/subscribe', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    await db.query('DELETE FROM thread_subscriptions WHERE user_id = $1 AND thread_id = $2', [userId, threadId]);
    res.json({ success: true, subscribed: false });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Check subscription status
app.get('/api/threads/:id/subscribe', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    const result = await db.query(
      'SELECT id FROM thread_subscriptions WHERE user_id = $1 AND thread_id = $2',
      [userId, threadId]
    );
    res.json({ success: true, subscribed: result.rows.length > 0 });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// READ TRACKING
// ========================================

// Mark thread as read
app.post('/api/threads/:id/read', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.id);
  const userId = req.user.userId;
  const { last_entry_id } = req.body;

  try {
    await db.query(
      `INSERT INTO thread_reads (user_id, thread_id, last_read_entry_id, last_read_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id, thread_id) 
       DO UPDATE SET last_read_entry_id = $3, last_read_at = NOW()`,
      [userId, threadId, last_entry_id || null]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get read status for threads
app.get('/api/my/read-status', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const threadIds = req.query.threads ? req.query.threads.split(',').map(Number) : [];

  if (threadIds.length === 0) {
    return res.json({ success: true, read_status: {} });
  }

  try {
    const result = await db.query(
      `SELECT tr.thread_id, tr.last_read_entry_id, tr.last_read_at,
              (SELECT MAX(id) FROM entries WHERE thread_id = tr.thread_id AND is_deleted = FALSE) as latest_entry_id
       FROM thread_reads tr
       WHERE tr.user_id = $1 AND tr.thread_id = ANY($2)`,
      [userId, threadIds]
    );

    const readStatus = {};
    result.rows.forEach(function(r) {
      readStatus[r.thread_id] = {
        last_read_entry_id: r.last_read_entry_id,
        latest_entry_id: r.latest_entry_id,
        has_unread: r.latest_entry_id > r.last_read_entry_id
      };
    });

    res.json({ success: true, read_status: readStatus });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// LAST SEEN
// ========================================

// Update last seen (called periodically by frontend)
app.post('/api/my/heartbeat', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    await db.query('UPDATE users SET last_seen_at = NOW() WHERE id = $1', [userId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get user's last seen (public for profiles)
app.get('/api/users/:alias/last-seen', async (req, res) => {
  const alias = req.params.alias;

  try {
    const result = await db.query(
      'SELECT last_seen_at FROM users WHERE alias = $1',
      [alias]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    res.json({ success: true, last_seen_at: result.rows[0].last_seen_at });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// WHO'S ONLINE
// ========================================

// Get users who were active in the last 5 minutes
app.get('/api/users/online', authMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT alias, avatar_config, custom_title, 
              (SELECT COUNT(*) FROM entries WHERE user_id = users.id AND is_deleted = FALSE) as post_count
       FROM users 
       WHERE last_seen_at > NOW() - INTERVAL '5 minutes'
       ORDER BY last_seen_at DESC
       LIMIT 50`
    );
    
    // Calculate rank for each user
    const onlineUsers = result.rows.map(u => {
      let rank = 'NEWCOMER';
      const postCount = parseInt(u.post_count);
      if (postCount >= 500) rank = 'VETERAN';
      else if (postCount >= 200) rank = 'EXPERT';
      else if (postCount >= 100) rank = 'REGULAR';
      else if (postCount >= 50) rank = 'MEMBER';
      else if (postCount >= 10) rank = 'ACTIVE';
      
      return {
        alias: u.alias,
        avatarConfig: u.avatar_config,
        customTitle: u.custom_title,
        rank: u.custom_title ? null : rank
      };
    });
    
    // Get total online count
    const countResult = await db.query(
      `SELECT COUNT(*) FROM users WHERE last_seen_at > NOW() - INTERVAL '5 minutes'`
    );
    
    res.json({ 
      success: true, 
      users: onlineUsers,
      count: parseInt(countResult.rows[0].count)
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// FIRST UNREAD POST
// ========================================

// Get the first unread entry ID in a thread
app.get('/api/threads/:id/first-unread', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    // Get last read entry for this user/thread
    const readResult = await db.query(
      `SELECT last_read_entry_id FROM thread_reads 
       WHERE user_id = $1 AND thread_id = $2`,
      [userId, threadId]
    );
    
    const lastReadId = readResult.rows[0]?.last_read_entry_id || 0;
    
    // Find first entry after last read
    const firstUnreadResult = await db.query(
      `SELECT id FROM entries 
       WHERE thread_id = $1 AND id > $2 AND (is_deleted = FALSE OR is_deleted IS NULL)
       ORDER BY id ASC
       LIMIT 1`,
      [threadId, lastReadId]
    );
    
    if (firstUnreadResult.rows.length === 0) {
      return res.json({ success: true, firstUnreadId: null, hasUnread: false });
    }
    
    res.json({ 
      success: true, 
      firstUnreadId: firstUnreadResult.rows[0].id,
      hasUnread: true
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// REACTIONS SYSTEM
// ========================================

const VALID_REACTIONS = ['like', 'dislike'];

// Toggle reaction on an entry
app.post('/api/entries/:id/react', authMiddleware, voteLimiter, async (req, res) => {
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
// THREAD TAGS
// ========================================

// Get all available tags (cached)
app.get('/api/tags', authMiddleware, async (req, res) => {
  try {
    const tags = await getCachedTags();
    res.json({ success: true, tags });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get tags for a thread
app.get('/api/threads/:threadId/tags', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.threadId);
  try {
    const result = await db.query(
      `SELECT t.id, t.name, t.color FROM tags t
       JOIN thread_tags tt ON tt.tag_id = t.id
       WHERE tt.thread_id = $1`,
      [threadId]
    );
    res.json({ success: true, tags: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Set tags for a thread (thread owner or admin)
app.put('/api/threads/:threadId/tags', authMiddleware, async (req, res) => {
  const threadId = parseInt(req.params.threadId);
  const userId = req.user.userId;
  const { tagIds } = req.body;

  if (!Array.isArray(tagIds)) {
    return res.status(400).json({ success: false, error: 'invalid_tags' });
  }

  try {
    // Check thread ownership or admin
    const thread = await db.query('SELECT user_id FROM threads WHERE id = $1', [threadId]);
    if (thread.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }
    
    const userResult = await db.query('SELECT is_admin FROM users WHERE id = $1', [userId]);
    const isAdmin = userResult.rows[0]?.is_admin;
    
    if (thread.rows[0].user_id !== userId && !isAdmin) {
      return res.status(403).json({ success: false, error: 'not_authorized' });
    }

    // Clear existing tags and add new ones
    await db.query('DELETE FROM thread_tags WHERE thread_id = $1', [threadId]);
    
    for (const tagId of tagIds.slice(0, 3)) { // Max 3 tags
      await db.query(
        'INSERT INTO thread_tags (thread_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [threadId, tagId]
      );
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// USER FOLLOWING
// ========================================

// Follow a user
app.post('/api/users/:alias/follow', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { alias } = req.params;

  try {
    const target = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const targetId = target.rows[0].id;
    
    if (targetId === userId) {
      return res.status(400).json({ success: false, error: 'cannot_follow_self' });
    }

    // Toggle follow
    const existing = await db.query(
      'SELECT id FROM user_follows WHERE follower_id = $1 AND following_id = $2',
      [userId, targetId]
    );

    if (existing.rows.length > 0) {
      await db.query('DELETE FROM user_follows WHERE id = $1', [existing.rows[0].id]);
      res.json({ success: true, action: 'unfollowed' });
    } else {
      await db.query(
        'INSERT INTO user_follows (follower_id, following_id) VALUES ($1, $2)',
        [userId, targetId]
      );
      res.json({ success: true, action: 'followed' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Check if following a user
app.get('/api/users/:alias/following', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { alias } = req.params;

  try {
    const target = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const result = await db.query(
      'SELECT id FROM user_follows WHERE follower_id = $1 AND following_id = $2',
      [userId, target.rows[0].id]
    );
    res.json({ success: true, isFollowing: result.rows.length > 0 });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get list of users I follow
app.get('/api/my/following', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    const result = await db.query(
      `SELECT u.alias, u.avatar_config, uf.created_at
       FROM user_follows uf
       JOIN users u ON u.id = uf.following_id
       WHERE uf.follower_id = $1
       ORDER BY uf.created_at DESC`,
      [userId]
    );
    res.json({ success: true, following: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get feed of posts from followed users
app.get('/api/my/feed', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  try {
    const result = await db.query(
      `SELECT e.id, e.content, e.created_at, u.alias, u.avatar_config,
              t.id as thread_id, t.title as thread_title, r.slug as room_slug
       FROM entries e
       JOIN users u ON u.id = e.user_id
       JOIN threads t ON t.id = e.thread_id
       JOIN rooms r ON r.id = t.room_id
       WHERE e.user_id IN (SELECT following_id FROM user_follows WHERE follower_id = $1)
         AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)
       ORDER BY e.created_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    
    const countResult = await db.query(
      `SELECT COUNT(*) FROM entries e
       WHERE e.user_id IN (SELECT following_id FROM user_follows WHERE follower_id = $1)
         AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)`,
      [userId]
    );
    
    res.json({
      success: true,
      posts: result.rows,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].count),
        totalPages: Math.ceil(parseInt(countResult.rows[0].count) / limit)
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// MUTED USERS
// ========================================

// Mute/unmute a user
app.post('/api/users/:alias/mute', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { alias } = req.params;

  try {
    const target = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const targetId = target.rows[0].id;
    
    if (targetId === userId) {
      return res.status(400).json({ success: false, error: 'cannot_mute_self' });
    }

    // Toggle mute
    const existing = await db.query(
      'SELECT id FROM muted_users WHERE user_id = $1 AND muted_user_id = $2',
      [userId, targetId]
    );

    if (existing.rows.length > 0) {
      await db.query('DELETE FROM muted_users WHERE id = $1', [existing.rows[0].id]);
      res.json({ success: true, action: 'unmuted' });
    } else {
      await db.query(
        'INSERT INTO muted_users (user_id, muted_user_id) VALUES ($1, $2)',
        [userId, targetId]
      );
      res.json({ success: true, action: 'muted' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get list of muted users
app.get('/api/my/muted', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    const result = await db.query(
      `SELECT u.alias, u.avatar_config, mu.created_at
       FROM muted_users mu
       JOIN users u ON u.id = mu.muted_user_id
       WHERE mu.user_id = $1
       ORDER BY mu.created_at DESC`,
      [userId]
    );
    res.json({ success: true, muted: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Check if user is muted
app.get('/api/users/:alias/muted', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { alias } = req.params;

  try {
    const target = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const result = await db.query(
      'SELECT id FROM muted_users WHERE user_id = $1 AND muted_user_id = $2',
      [userId, target.rows[0].id]
    );
    res.json({ success: true, isMuted: result.rows.length > 0 });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// BLOCKED USERS
// ========================================

// Block/unblock a user
app.post('/api/users/:alias/block', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { alias } = req.params;

  try {
    const target = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const targetId = target.rows[0].id;
    
    if (targetId === userId) {
      return res.status(400).json({ success: false, error: 'cannot_block_self' });
    }

    // Toggle block
    const existing = await db.query(
      'SELECT id FROM blocked_users WHERE user_id = $1 AND blocked_user_id = $2',
      [userId, targetId]
    );

    if (existing.rows.length > 0) {
      await db.query('DELETE FROM blocked_users WHERE id = $1', [existing.rows[0].id]);
      res.json({ success: true, action: 'unblocked' });
    } else {
      await db.query(
        'INSERT INTO blocked_users (user_id, blocked_user_id) VALUES ($1, $2)',
        [userId, targetId]
      );
      res.json({ success: true, action: 'blocked' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get list of blocked users
app.get('/api/my/blocked', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  try {
    const result = await db.query(
      `SELECT u.alias, u.avatar_config, bu.created_at
       FROM blocked_users bu
       JOIN users u ON u.id = bu.blocked_user_id
       WHERE bu.user_id = $1
       ORDER BY bu.created_at DESC`,
      [userId]
    );
    res.json({ success: true, blocked: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Check if user is blocked
app.get('/api/users/:alias/blocked', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { alias } = req.params;

  try {
    const target = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const result = await db.query(
      'SELECT id FROM blocked_users WHERE user_id = $1 AND blocked_user_id = $2',
      [userId, target.rows[0].id]
    );
    res.json({ success: true, isBlocked: result.rows.length > 0 });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Helper: Check if user A has blocked user B or vice versa
async function isBlockedBetween(userIdA, userIdB) {
  const result = await db.query(
    `SELECT id FROM blocked_users 
     WHERE (user_id = $1 AND blocked_user_id = $2) 
        OR (user_id = $2 AND blocked_user_id = $1)`,
    [userIdA, userIdB]
  );
  return result.rows.length > 0;
}

// ========================================
// DRAFTS LIST
// ========================================

// Note: Drafts are stored in localStorage on the client
// This endpoint just provides a way to sync/backup drafts
app.get('/api/my/drafts-info', authMiddleware, async (req, res) => {
  // Frontend manages drafts in localStorage
  // This is just a placeholder if you want server-side drafts later
  res.json({ 
    success: true, 
    message: 'Drafts are stored locally in your browser',
    hint: 'Check localStorage keys starting with "draft_" or "thread_"'
  });
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
app.post('/api/messages', authMiddleware, messagesLimiter, async (req, res) => {
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

    // Check if blocked (either direction)
    if (await isBlockedBetween(senderId, recipientId)) {
      return res.status(403).json({ success: false, error: 'user_blocked' });
    }

    // Sanitize content for XSS
    const sanitizedContent = sanitizeContent(content);
    const sanitizedSubject = subject ? sanitizeContent(subject) : null;

    // Create message
    const insertResult = await db.query(
      `INSERT INTO private_messages (sender_id, recipient_id, subject, content)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [senderId, recipientId, sanitizedSubject, sanitizedContent]
    );

    // Create notification for recipient
    const senderResult = await db.query('SELECT alias FROM users WHERE id = $1', [senderId]);
    const senderAlias = senderResult.rows[0]?.alias || 'Someone';

    const notificationTitle = `New message from ${senderAlias}`;
    const notificationPreview = sanitizedSubject || sanitizedContent.substring(0, 50);
    
    await db.query(
      `INSERT INTO notifications (user_id, type, title, message, link, related_user_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [recipientId, 'private_message', notificationTitle, notificationPreview, 'messages.html', senderId]
    );
    
    // Send email notification (non-blocking)
    sendNotificationEmail(recipientId, 'private_message', notificationTitle, notificationPreview, 'messages.html');

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

// ========================================
// IMAGE UPLOADS
// ========================================

// Upload image endpoint
app.post('/api/upload/image', authMiddleware, (req, res, next) => {
  if (!upload) {
    return res.status(503).json({ success: false, error: 'uploads_not_available', message: 'Image uploads are not configured on this server' });
  }
  
  upload.single('image')(req, res, async function(err) {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ success: false, error: 'file_too_large', message: 'File size must be less than 5MB' });
      }
      return res.status(400).json({ success: false, error: 'upload_failed', message: err.message });
    }
    
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'no_file', message: 'No file uploaded' });
    }
    
    // Validate magic bytes to ensure it's a real image
    const filePath = req.file.path;
    try {
      const buffer = fs.readFileSync(filePath);
      const bytes = buffer.slice(0, 12);
      
      const isJpeg = bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF;
      const isPng = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47;
      const isGif = bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46;
      const isWebp = bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50;
      
      if (!isJpeg && !isPng && !isGif && !isWebp) {
        fs.unlinkSync(filePath); // Delete suspicious file
        return res.status(400).json({ success: false, error: 'invalid_image', message: 'File does not appear to be a valid image' });
      }
    } catch (readErr) {
      logger.error('UPLOAD', 'Failed to validate image: ' + readErr.message);
      fs.unlinkSync(filePath);
      return res.status(500).json({ success: false, error: 'validation_failed', message: 'Failed to validate image' });
    }
    
    const imageUrl = `/uploads/${req.file.filename}`;
    res.json({ success: true, url: imageUrl });
  });
});

// ========================================
// GDPR DATA EXPORT
// ========================================

app.get('/api/settings/export-data', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  
  try {
    // Fetch all user data
    const userResult = await db.query(
      `SELECT alias, bio, email, email_verified, notification_replies, notification_mentions, 
              notification_messages, reputation, post_count, created_at, last_seen_at, signature
       FROM users WHERE id = $1`,
      [userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const userData = userResult.rows[0];
    
    // Fetch all posts by user
    const postsResult = await db.query(
      `SELECT e.content, e.created_at, e.edited_at, t.title AS thread_title, r.title AS room_title
       FROM entries e
       JOIN threads t ON t.id = e.thread_id
       JOIN rooms r ON r.id = t.room_id
       WHERE e.user_id = $1 AND e.is_deleted = FALSE
       ORDER BY e.created_at DESC`,
      [userId]
    );
    
    // Fetch threads created by user
    const threadsResult = await db.query(
      `SELECT t.title, t.created_at, r.title AS room_title
       FROM threads t
       JOIN rooms r ON r.id = t.room_id
       WHERE t.user_id = $1
       ORDER BY t.created_at DESC`,
      [userId]
    );
    
    // Fetch private messages (sent)
    const sentMessagesResult = await db.query(
      `SELECT pm.subject, pm.content, pm.created_at, u.alias AS recipient
       FROM private_messages pm
       JOIN users u ON u.id = pm.recipient_id
       WHERE pm.sender_id = $1 AND pm.deleted_by_sender = FALSE
       ORDER BY pm.created_at DESC`,
      [userId]
    );
    
    // Fetch private messages (received)
    const receivedMessagesResult = await db.query(
      `SELECT pm.subject, pm.content, pm.created_at, u.alias AS sender
       FROM private_messages pm
       JOIN users u ON u.id = pm.sender_id
       WHERE pm.recipient_id = $1 AND pm.deleted_by_recipient = FALSE
       ORDER BY pm.created_at DESC`,
      [userId]
    );
    
    // Fetch activity log
    const activityResult = await db.query(
      `SELECT action_type, target_type, target_title, created_at
       FROM activity_feed
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );
    
    // Compile export data
    const exportData = {
      exported_at: new Date().toISOString(),
      profile: {
        alias: userData.alias,
        bio: userData.bio,
        email: userData.email,
        email_verified: userData.email_verified,
        signature: userData.signature,
        reputation: userData.reputation,
        post_count: userData.post_count,
        created_at: userData.created_at,
        last_seen_at: userData.last_seen_at
      },
      settings: {
        notification_replies: userData.notification_replies,
        notification_mentions: userData.notification_mentions,
        notification_messages: userData.notification_messages
      },
      posts: postsResult.rows.map(p => ({
        content: p.content,
        thread: p.thread_title,
        room: p.room_title,
        created_at: p.created_at,
        edited_at: p.edited_at
      })),
      threads_created: threadsResult.rows.map(t => ({
        title: t.title,
        room: t.room_title,
        created_at: t.created_at
      })),
      messages: {
        sent: sentMessagesResult.rows.map(m => ({
          to: m.recipient,
          subject: m.subject,
          content: m.content,
          sent_at: m.created_at
        })),
        received: receivedMessagesResult.rows.map(m => ({
          from: m.sender,
          subject: m.subject,
          content: m.content,
          received_at: m.created_at
        }))
      },
      activity_log: activityResult.rows.map(a => ({
        action: a.action_type,
        target_type: a.target_type,
        target: a.target_title,
        at: a.created_at
      }))
    };
    
    // Set headers for file download
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="aspd-forum-data-${userData.alias}-${Date.now()}.json"`);
    res.json(exportData);
  } catch (err) {
    console.error('[EXPORT DATA ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// PUSH NOTIFICATIONS
// ========================================

// Get VAPID public key
app.get('/api/push/vapid-key', (req, res) => {
  if (!webpush || !process.env.VAPID_PUBLIC_KEY) {
    return res.json({ success: false, error: 'push_not_configured' });
  }
  res.json({ success: true, publicKey: process.env.VAPID_PUBLIC_KEY });
});

// Subscribe to push notifications
app.post('/api/push/subscribe', authMiddleware, async (req, res) => {
  if (!webpush) {
    return res.status(503).json({ success: false, error: 'push_not_configured' });
  }
  
  const { subscription } = req.body;
  const userId = req.user.userId;
  
  if (!subscription || !subscription.endpoint) {
    return res.status(400).json({ success: false, error: 'invalid_subscription' });
  }
  
  try {
    // Store subscription (upsert)
    await db.query(
      `INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, endpoint) DO UPDATE SET p256dh = $3, auth = $4`,
      [userId, subscription.endpoint, subscription.keys?.p256dh, subscription.keys?.auth]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error('[PUSH SUBSCRIBE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Unsubscribe from push notifications
app.delete('/api/push/subscribe', authMiddleware, async (req, res) => {
  const { endpoint } = req.body;
  const userId = req.user.userId;
  
  try {
    await db.query(
      'DELETE FROM push_subscriptions WHERE user_id = $1 AND endpoint = $2',
      [userId, endpoint]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Helper: Send push notification to a user
async function sendPushNotification(userId, title, body, url) {
  if (!webpush) return;
  
  try {
    const subs = await db.query(
      'SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = $1',
      [userId]
    );
    
    const payload = JSON.stringify({ title, body, url });
    
    for (const sub of subs.rows) {
      const pushSubscription = {
        endpoint: sub.endpoint,
        keys: { p256dh: sub.p256dh, auth: sub.auth }
      };
      
      try {
        await webpush.sendNotification(pushSubscription, payload);
      } catch (err) {
        // Remove invalid subscription
        if (err.statusCode === 410 || err.statusCode === 404) {
          await db.query('DELETE FROM push_subscriptions WHERE endpoint = $1', [sub.endpoint]);
        }
      }
    }
  } catch (err) {
    console.error('[PUSH SEND ERROR]', err.message);
  }
}

// ========================================
// REPUTATION SYSTEM
// ========================================

// Upvote/downvote an entry
app.post('/api/entries/:entryId/vote', authMiddleware, voteLimiter, async (req, res) => {
  const { entryId } = req.params;
  const { vote } = req.body; // 1 for upvote, -1 for downvote, 0 to remove
  const userId = req.user.userId;
  
  if (![1, -1, 0].includes(vote)) {
    return res.status(400).json({ success: false, error: 'invalid_vote' });
  }
  
  const client = await db.getClient();
  
  try {
    await client.query('BEGIN');
    
    // Get entry info with row lock to prevent race conditions
    const entryResult = await client.query(
      'SELECT user_id FROM entries WHERE id = $1 AND is_deleted = FALSE FOR UPDATE',
      [entryId]
    );
    
    if (entryResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'entry_not_found' });
    }
    
    const entryUserId = entryResult.rows[0].user_id;
    
    // Can't vote on your own posts
    if (entryUserId === userId) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'cannot_vote_own_post' });
    }
    
    // Get current vote if exists
    const existingVote = await client.query(
      'SELECT vote_value FROM entry_votes WHERE entry_id = $1 AND user_id = $2 FOR UPDATE',
      [entryId, userId]
    );
    
    const oldVote = existingVote.rows.length > 0 ? existingVote.rows[0].vote_value : 0;
    
    if (vote === 0) {
      // Remove vote
      await client.query('DELETE FROM entry_votes WHERE entry_id = $1 AND user_id = $2', [entryId, userId]);
    } else {
      // Upsert vote
      await client.query(
        `INSERT INTO entry_votes (entry_id, user_id, vote_value)
         VALUES ($1, $2, $3)
         ON CONFLICT (entry_id, user_id) DO UPDATE SET vote_value = $3`,
        [entryId, userId, vote]
      );
    }
    
    // Update entry author's reputation
    const reputationChange = vote - oldVote;
    if (reputationChange !== 0 && entryUserId) {
      await client.query(
        'UPDATE users SET reputation = GREATEST(0, reputation + $1) WHERE id = $2',
        [reputationChange, entryUserId]
      );
    }
    
    // Get new score for entry
    const scoreResult = await client.query(
      'SELECT COALESCE(SUM(vote_value), 0) AS score FROM entry_votes WHERE entry_id = $1',
      [entryId]
    );
    
    await client.query('COMMIT');
    
    // Check for badge achievements for post author (reputation changes)
    if (reputationChange !== 0 && entryUserId) {
      checkAndAwardBadges(entryUserId).catch(() => {});
    }
    
    res.json({ success: true, score: parseInt(scoreResult.rows[0].score), userVote: vote });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[VOTE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  } finally {
    client.release();
  }
});

// Get vote status for an entry
app.get('/api/entries/:entryId/vote', authMiddleware, async (req, res) => {
  const { entryId } = req.params;
  const userId = req.user.userId;
  
  try {
    const voteResult = await db.query(
      'SELECT vote_value FROM entry_votes WHERE entry_id = $1 AND user_id = $2',
      [entryId, userId]
    );
    
    const scoreResult = await db.query(
      'SELECT COALESCE(SUM(vote_value), 0) AS score FROM entry_votes WHERE entry_id = $1',
      [entryId]
    );
    
    res.json({
      success: true,
      score: parseInt(scoreResult.rows[0].score),
      userVote: voteResult.rows.length > 0 ? voteResult.rows[0].vote_value : 0
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
      ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_replies BOOLEAN DEFAULT TRUE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_mentions BOOLEAN DEFAULT TRUE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_messages BOOLEAN DEFAULT TRUE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT NOW();
      
      -- Refresh tokens table (for session management)
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        revoked BOOLEAN DEFAULT FALSE
      );
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
      
      -- Password reset tokens table
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
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
      
      CREATE TABLE IF NOT EXISTS post_audit (
        id SERIAL PRIMARY KEY,
        entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
        ip_hash VARCHAR(64),
        alias VARCHAR(50),
        content_length INTEGER,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_post_audit_entry ON post_audit(entry_id);
      CREATE INDEX IF NOT EXISTS idx_post_audit_ip ON post_audit(ip_hash);
      
      -- Post edit revisions (history of edits)
      CREATE TABLE IF NOT EXISTS post_revisions (
        id SERIAL PRIMARY KEY,
        entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        edited_by INTEGER REFERENCES users(id),
        revision_number INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_post_revisions_entry ON post_revisions(entry_id);
      
      -- User badges system
      CREATE TABLE IF NOT EXISTS badges (
        id SERIAL PRIMARY KEY,
        slug VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        icon VARCHAR(10) DEFAULT '🏆',
        color VARCHAR(7) DEFAULT '#666666',
        rarity VARCHAR(20) DEFAULT 'common',
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS user_badges (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        badge_id INTEGER REFERENCES badges(id) ON DELETE CASCADE,
        awarded_at TIMESTAMP DEFAULT NOW(),
        awarded_by INTEGER REFERENCES users(id),
        UNIQUE(user_id, badge_id)
      );
      CREATE INDEX IF NOT EXISTS idx_user_badges_user ON user_badges(user_id);
      
      -- Insert default badges
      INSERT INTO badges (slug, name, description, icon, color, rarity) VALUES
        ('first-post', 'First Post', 'Made your first post', '✍️', '#4a9eff', 'common'),
        ('ten-posts', '10 Posts', 'Reached 10 posts', '📝', '#26de81', 'common'),
        ('fifty-posts', '50 Posts', 'Reached 50 posts', '📚', '#45aaf2', 'uncommon'),
        ('hundred-posts', '100 Posts', 'Reached 100 posts', '🗂️', '#a55eea', 'rare'),
        ('five-hundred-posts', '500 Posts', 'Reached 500 posts', '📖', '#fed330', 'epic'),
        ('thousand-posts', '1000 Posts', 'Reached 1000 posts', '🏛️', '#fc5c65', 'legendary'),
        ('first-thread', 'Thread Starter', 'Started your first thread', '🧵', '#4a9eff', 'common'),
        ('ten-threads', '10 Threads', 'Started 10 threads', '🗃️', '#26de81', 'uncommon'),
        ('helpful', 'Helpful', 'Received 10 upvotes on a single post', '🤝', '#20bf6b', 'uncommon'),
        ('very-helpful', 'Very Helpful', 'Received 50 upvotes on a single post', '⭐', '#f7b731', 'rare'),
        ('reputation-10', 'Rising Star', 'Reached 10 reputation', '⬆️', '#45aaf2', 'common'),
        ('reputation-50', 'Respected', 'Reached 50 reputation', '🌟', '#a55eea', 'uncommon'),
        ('reputation-100', 'Esteemed', 'Reached 100 reputation', '💫', '#fed330', 'rare'),
        ('reputation-500', 'Legendary', 'Reached 500 reputation', '👑', '#fc5c65', 'legendary'),
        ('early-adopter', 'Early Adopter', 'Joined during the first month', '🌱', '#26de81', 'rare'),
        ('verified-email', 'Verified', 'Verified email address', '✅', '#20bf6b', 'common'),
        ('night-owl', 'Night Owl', 'Posted between 2am and 5am', '🦉', '#5f27cd', 'uncommon'),
        ('one-year', 'One Year', 'Member for one year', '🎂', '#ff9f43', 'rare'),
        ('two-factor', 'Security Pro', 'Enabled two-factor authentication', '🔐', '#20bf6b', 'uncommon')
      ON CONFLICT (slug) DO NOTHING;
      
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
      
      -- Moderation: IP bans
      CREATE TABLE IF NOT EXISTS ip_bans (
        id SERIAL PRIMARY KEY,
        ip_hash VARCHAR(64) NOT NULL,
        reason TEXT,
        banned_by INTEGER REFERENCES users(id),
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Moderation: Word filters
      CREATE TABLE IF NOT EXISTS word_filters (
        id SERIAL PRIMARY KEY,
        word VARCHAR(100) NOT NULL,
        replacement VARCHAR(100) DEFAULT '***',
        is_regex BOOLEAN DEFAULT FALSE,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Moderation: Mod notes on users
      CREATE TABLE IF NOT EXISTS mod_notes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        note TEXT NOT NULL,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Moderation: Warnings
      CREATE TABLE IF NOT EXISTS warnings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        reason TEXT NOT NULL,
        issued_by INTEGER REFERENCES users(id),
        acknowledged BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Add ban columns to users if not exist
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT FALSE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_expires_at TIMESTAMP;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_by INTEGER REFERENCES users(id);
      
      -- Announcements
      CREATE TABLE IF NOT EXISTS announcements (
        id SERIAL PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        content TEXT,
        type VARCHAR(20) DEFAULT 'info',
        is_active BOOLEAN DEFAULT TRUE,
        starts_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Add description to rooms
      ALTER TABLE rooms ADD COLUMN IF NOT EXISTS description TEXT;
      ALTER TABLE rooms ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT FALSE;
      ALTER TABLE rooms ADD COLUMN IF NOT EXISTS display_order INTEGER DEFAULT 0;
      
      -- Thread subscriptions
      CREATE TABLE IF NOT EXISTS thread_subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        thread_id INTEGER REFERENCES threads(id),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, thread_id)
      );
      
      -- Read tracking
      CREATE TABLE IF NOT EXISTS thread_reads (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        thread_id INTEGER REFERENCES threads(id),
        last_read_entry_id INTEGER,
        last_read_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, thread_id)
      );
      
      -- Add last_seen to users
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP;
      
      -- Add signature to users
      ALTER TABLE users ADD COLUMN IF NOT EXISTS signature VARCHAR(200);
      
      -- Add pin/lock columns to threads (in case they don't exist)
      ALTER TABLE threads ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT FALSE;
      ALTER TABLE threads ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN DEFAULT FALSE;
      
      -- Add reputation system columns
      ALTER TABLE users ADD COLUMN IF NOT EXISTS reputation INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS post_count INTEGER DEFAULT 0;
      
      -- Add user custom title (admin-assignable)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS custom_title VARCHAR(50);
      
      -- Polls table
      CREATE TABLE IF NOT EXISTS polls (
        id SERIAL PRIMARY KEY,
        thread_id INTEGER REFERENCES threads(id) UNIQUE,
        question VARCHAR(300) NOT NULL,
        allow_multiple BOOLEAN DEFAULT FALSE,
        ends_at TIMESTAMP,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS poll_options (
        id SERIAL PRIMARY KEY,
        poll_id INTEGER REFERENCES polls(id) ON DELETE CASCADE,
        option_text VARCHAR(200) NOT NULL,
        display_order INTEGER DEFAULT 0
      );
      
      CREATE TABLE IF NOT EXISTS poll_votes (
        id SERIAL PRIMARY KEY,
        poll_id INTEGER REFERENCES polls(id) ON DELETE CASCADE,
        option_id INTEGER REFERENCES poll_options(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(poll_id, user_id, option_id)
      );
      
      -- Activity feed table
      CREATE TABLE IF NOT EXISTS activity_feed (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action_type VARCHAR(50) NOT NULL,
        target_type VARCHAR(50),
        target_id INTEGER,
        target_title TEXT,
        details JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_activity_feed_created ON activity_feed(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_activity_feed_user ON activity_feed(user_id);
      
      -- Thread tags
      CREATE TABLE IF NOT EXISTS tags (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) UNIQUE NOT NULL,
        color VARCHAR(7) DEFAULT '#666666',
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS thread_tags (
        id SERIAL PRIMARY KEY,
        thread_id INTEGER REFERENCES threads(id) ON DELETE CASCADE,
        tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE,
        UNIQUE(thread_id, tag_id)
      );
      
      -- User following
      CREATE TABLE IF NOT EXISTS user_follows (
        id SERIAL PRIMARY KEY,
        follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(follower_id, following_id)
      );
      CREATE INDEX IF NOT EXISTS idx_user_follows_follower ON user_follows(follower_id);
      CREATE INDEX IF NOT EXISTS idx_user_follows_following ON user_follows(following_id);
      
      -- Muted users
      CREATE TABLE IF NOT EXISTS muted_users (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        muted_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, muted_user_id)
      );
      CREATE INDEX IF NOT EXISTS idx_muted_users ON muted_users(user_id);
      
      -- Blocked users (stronger than mute - prevents DMs, mentions, profile views)
      CREATE TABLE IF NOT EXISTS blocked_users (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        blocked_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, blocked_user_id)
      );
      CREATE INDEX IF NOT EXISTS idx_blocked_users_user ON blocked_users(user_id);
      CREATE INDEX IF NOT EXISTS idx_blocked_users_blocked ON blocked_users(blocked_user_id);
      
      -- Recovery codes for users without email
      CREATE TABLE IF NOT EXISTS recovery_codes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        code_hash VARCHAR(255) NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id);
      
      -- 2FA secrets
      ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(255);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE;
      
      -- Push notification subscriptions
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        endpoint TEXT NOT NULL,
        p256dh TEXT,
        auth TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, endpoint)
      );
      CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id);
      
      -- Entry votes for reputation system
      CREATE TABLE IF NOT EXISTS entry_votes (
        id SERIAL PRIMARY KEY,
        entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        vote_value INTEGER NOT NULL CHECK (vote_value IN (-1, 1)),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(entry_id, user_id)
      );
      CREATE INDEX IF NOT EXISTS idx_entry_votes_entry ON entry_votes(entry_id);
      CREATE INDEX IF NOT EXISTS idx_entry_votes_user ON entry_votes(user_id);
      
      -- Performance indexes for common queries
      CREATE INDEX IF NOT EXISTS idx_threads_room_created ON threads(room_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_entries_thread_created ON entries(thread_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_entries_user ON entries(user_id);
      CREATE INDEX IF NOT EXISTS idx_notifications_user_unread ON notifications(user_id, is_read, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_pm_recipient ON private_messages(recipient_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_pm_sender ON private_messages(sender_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_thread_subs_user ON thread_subscriptions(user_id);
      CREATE INDEX IF NOT EXISTS idx_thread_subs_thread ON thread_subscriptions(thread_id);
      CREATE INDEX IF NOT EXISTS idx_thread_reads_user ON thread_reads(user_id);
      CREATE INDEX IF NOT EXISTS idx_reactions_entry ON reactions(entry_id);
      CREATE INDEX IF NOT EXISTS idx_bookmarks_user ON bookmarks(user_id);
      
      -- Insert default tags
      INSERT INTO tags (name, color) VALUES 
        ('Discussion', '#4a9eff'),
        ('Question', '#ff9f43'),
        ('Guide', '#26de81'),
        ('News', '#fc5c65'),
        ('Meta', '#a55eea')
      ON CONFLICT (name) DO NOTHING;
      
      INSERT INTO rooms (slug, title, description, display_order) VALUES 
        -- Core Discussion
        ('general', 'General Discussion', 'Open discussion for the community', 1),
        ('questions', 'Questions', 'Ask the community anything', 2),
        
        -- Personal
        ('stories', 'Stories', 'Share your experiences and personal accounts', 10),
        ('confessions', 'Confessions', 'Anonymous-style confessions and admissions', 11),
        ('self-awareness', 'Self-Awareness', 'Understanding your own patterns and behaviors', 12),
        
        -- Life & Society
        ('relationships', 'Relationships', 'Navigating relationships, family, and social dynamics', 20),
        ('workplace', 'Work & Career', 'Professional life and career strategies', 21),
        ('coping', 'Coping Strategies', 'Methods for managing impulses and navigating society', 22),
        
        -- Clinical
        ('diagnosis', 'Diagnosis & Treatment', 'Therapy experiences, psychiatric encounters, medication', 30),
        
        -- Other
        ('media', 'Media & Representation', 'ASPD in movies, TV, books - accurate or not', 40),
        ('off-topic', 'Off-Topic', 'Everything else', 99)
      ON CONFLICT (slug) DO UPDATE SET 
        description = EXCLUDED.description,
        display_order = EXCLUDED.display_order;
    `);
    console.log('[MIGRATE] Database tables ready');
  } catch (err) {
    console.error('[MIGRATE ERROR]', err.message);
  }
}

// 404 catch-all route (must be last)
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '..', '404.html'));
});

// Cleanup expired refresh tokens periodically (every hour)
async function cleanupExpiredTokens() {
  try {
    const result = await db.query(
      'DELETE FROM refresh_tokens WHERE expires_at < NOW() OR revoked = TRUE'
    );
    if (result.rowCount > 0) {
      console.log(`[CLEANUP] Removed ${result.rowCount} expired/revoked refresh tokens`);
    }
  } catch (err) {
    console.error('[CLEANUP ERROR]', err.message);
  }
}

// Start server
migrate().then(() => {
  app.listen(PORT, () => {
    console.log('[SERVER] Port ' + PORT);
    
    // Run cleanup on startup and every hour
    cleanupExpiredTokens();
    setInterval(cleanupExpiredTokens, 60 * 60 * 1000);  });
});