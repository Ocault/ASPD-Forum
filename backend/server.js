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
const http = require('http');
const db = require('./db');

// Optional WebSocket for real-time features
let WebSocket = null;
let wss = null;
try {
  WebSocket = require('ws');
  console.log('[WS] WebSocket library loaded successfully');
} catch (err) {
  console.log('[WS] ws not installed - WebSocket features disabled. Run: npm install ws');
}

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

// IMMEDIATE health check - responds before any other middleware
// This helps Railway know the server is alive
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: Date.now() });
});

console.log('[STARTUP] Express app created');

// Trust proxy - essential for getting real client IPs behind Railway/Cloudflare
app.set('trust proxy', true);

const PORT = process.env.PORT || 3001;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = '1h';
const JWT_EXPIRES_REMEMBER = '30d'; // Extended expiry for "remember me"
const JWT_REFRESH_EXPIRES = '7d'; // Refresh tokens last 7 days
const JWT_REFRESH_EXPIRES_REMEMBER = '30d'; // Extended refresh for "remember me"
const DEVICE_TOKEN_EXPIRES_DAYS = 30; // Device trust token validity

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

console.log('[STARTUP] Logger initialized');
console.log('[STARTUP] PORT=' + PORT);
console.log('[STARTUP] DATABASE_URL exists:', !!process.env.DATABASE_URL);
console.log('[STARTUP] JWT_SECRET exists:', !!JWT_SECRET);

// Request ID middleware
app.use((req, res, next) => {
  req.reqId = crypto.randomBytes(8).toString('hex');
  res.setHeader('X-Request-ID', req.reqId);
  next();
});

// CRITICAL: Validate JWT_SECRET on startup
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('[STARTUP] FATAL: JWT_SECRET must be set and at least 32 characters');
  console.error('[STARTUP] JWT_SECRET length:', JWT_SECRET ? JWT_SECRET.length : 0);
  process.exit(1);
}

console.log('[STARTUP] JWT_SECRET validated');

// Security headers with helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'", "wss://aspd-forum-production.up.railway.app", "https://aspd-forum-production.up.railway.app"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
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

// ========================================
// DDOS PROTECTION
// ========================================

// Track suspicious IPs in memory (production: use Redis)
const suspiciousIPs = new Map(); // ip -> { count, firstSeen, blocked }
const DDOS_THRESHOLD = 100; // requests per window
const DDOS_WINDOW = 10 * 1000; // 10 seconds
const DDOS_BLOCK_DURATION = 5 * 60 * 1000; // 5 minute block

// Global rate limiter - catches excessive requests from any single IP
const globalRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 300, // 300 requests per minute per IP (generous for normal use)
  message: { success: false, error: 'rate_limit_exceeded', message: 'Too many requests' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
               req.headers['x-real-ip'] || 
               req.socket?.remoteAddress || 
               'unknown';
    return crypto.createHash('sha256').update(ip + (process.env.IP_SALT || 'salt')).digest('hex').substring(0, 16);
  },
  skip: (req) => {
    // Skip rate limit for health checks, sitemap, robots.txt, and public API
    return req.path === '/health' || 
           req.path === '/sitemap.xml' || 
           req.path === '/robots.txt' ||
           req.path.startsWith('/api/public/');
  }
});

// DDoS detection middleware - detect and block attack patterns
function ddosProtection(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
             req.headers['x-real-ip'] || 
             req.socket?.remoteAddress || 
             'unknown';
  
  const now = Date.now();
  let ipData = suspiciousIPs.get(ip);
  
  // Check if IP is currently blocked
  if (ipData && ipData.blocked && ipData.blockedUntil > now) {
    return res.status(429).json({ 
      success: false, 
      error: 'temporarily_blocked',
      message: 'Too many requests. Please wait before trying again.',
      retryAfter: Math.ceil((ipData.blockedUntil - now) / 1000)
    });
  }
  
  // Initialize or update IP tracking
  if (!ipData || now - ipData.firstSeen > DDOS_WINDOW) {
    ipData = { count: 1, firstSeen: now, blocked: false, blockedUntil: 0 };
  } else {
    ipData.count++;
  }
  
  // Check if threshold exceeded
  if (ipData.count > DDOS_THRESHOLD) {
    ipData.blocked = true;
    ipData.blockedUntil = now + DDOS_BLOCK_DURATION;
    suspiciousIPs.set(ip, ipData);
    logger.warn('DDOS', 'IP temporarily blocked for excessive requests', { ip: ip.substring(0, 8) + '...', count: ipData.count });
    return res.status(429).json({ 
      success: false, 
      error: 'temporarily_blocked',
      message: 'Too many requests. Please wait before trying again.',
      retryAfter: Math.ceil(DDOS_BLOCK_DURATION / 1000)
    });
  }
  
  suspiciousIPs.set(ip, ipData);
  next();
}

// Clean up old entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of suspiciousIPs.entries()) {
    if (now - data.firstSeen > DDOS_WINDOW * 2 && !data.blocked) {
      suspiciousIPs.delete(ip);
    } else if (data.blocked && data.blockedUntil < now) {
      suspiciousIPs.delete(ip);
    }
  }
}, 60 * 1000); // Clean every minute

// Apply DDoS protection first
app.use(ddosProtection);
app.use(globalRateLimiter);

// Slowloris protection - timeout for slow requests
app.use((req, res, next) => {
  req.setTimeout(30000, () => { // 30 second timeout
    res.status(408).json({ success: false, error: 'request_timeout' });
  });
  next();
});

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
    
    const siteUrl = process.env.SITE_URL || 'https://www.aspdforum.com';
    const fullLink = link.startsWith('http') ? link : `${siteUrl}/${link}`;
    
    // Type-specific styling
    const typeStyles = {
      'thread_reply': { icon: '↩', label: 'NEW REPLY' },
      'mention': { icon: '@', label: 'MENTIONED' },
      'private_message': { icon: '✉', label: 'NEW MESSAGE' }
    };
    const style = typeStyles[type] || { icon: '●', label: 'NOTIFICATION' };
    
    const emailHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
</head>
<body style="margin: 0; padding: 0; background-color: #0a0a0a;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #0a0a0a;">
    <tr>
      <td align="center" style="padding: 40px 20px;">
        <table role="presentation" width="500" cellspacing="0" cellpadding="0" style="max-width: 500px; background-color: #0f0f0f; border: 1px solid #1a1a1a;">
          <!-- Header -->
          <tr>
            <td style="padding: 30px 30px 20px; text-align: center; border-bottom: 1px solid #1a1a1a;">
              <div style="font-family: 'Courier New', Courier, monospace; font-size: 24px; color: #3a3a3a; margin-bottom: 10px;">${style.icon}</div>
              <div style="font-family: 'Courier New', Courier, monospace; font-size: 10px; letter-spacing: 0.2em; color: #4a4a4a;">${style.label}</div>
            </td>
          </tr>
          <!-- Title -->
          <tr>
            <td style="padding: 25px 30px 15px;">
              <h1 style="margin: 0; font-family: 'Courier New', Courier, monospace; font-size: 14px; font-weight: normal; color: #9a9a9a; letter-spacing: 0.05em;">
                ${title}
              </h1>
            </td>
          </tr>
          <!-- Preview -->
          <tr>
            <td style="padding: 0 30px 25px;">
              <p style="margin: 0; font-family: 'Courier New', Courier, monospace; font-size: 12px; line-height: 1.7; color: #6a6a6a;">
                ${preview.substring(0, 200).replace(/</g, '&lt;').replace(/>/g, '&gt;')}${preview.length > 200 ? '...' : ''}
              </p>
            </td>
          </tr>
          <!-- Button -->
          <tr>
            <td style="padding: 10px 30px 30px; text-align: center;">
              <a href="${fullLink}" style="display: inline-block; padding: 14px 28px; background-color: #151515; border: 1px solid #2a2a2a; color: #9a9a9a; text-decoration: none; font-family: 'Courier New', Courier, monospace; font-size: 11px; letter-spacing: 0.15em;">
                VIEW ON FORUM →
              </a>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding: 20px 30px; border-top: 1px solid #1a1a1a; text-align: center;">
              <p style="margin: 0 0 10px; font-family: 'Courier New', Courier, monospace; font-size: 10px; color: #3a3a3a; letter-spacing: 0.1em;">
                ASPD FORUM
              </p>
              <p style="margin: 0; font-family: 'Courier New', Courier, monospace; font-size: 10px; color: #4a4a4a;">
                <a href="${siteUrl}/settings.html" style="color: #5a5a5a; text-decoration: none;">Manage notifications</a>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `;
    
    await sendEmail(user.email, `[ASPD Forum] ${title}`, emailHtml);
  } catch (err) {
    console.error('[NOTIFICATION EMAIL ERROR]', err.message);
  }
}

// ========================================
// WEBSOCKET SERVER
// ========================================

// Connected clients map: userId -> Set of WebSocket connections
const wsClients = new Map();

// Thread presence tracking: threadId -> Map of userId -> { alias, avatarConfig, joinedAt }
const threadViewers = new Map();

// Typing indicators: threadId -> Map of userId -> { alias, timestamp }
const threadTyping = new Map();

// Initialize WebSocket server (called after HTTP server starts)
function initWebSocket(server) {
  if (!WebSocket) {
    console.log('[WS] WebSocket not available - skipping initialization');
    return;
  }

  const WebSocketServer = WebSocket.Server;
  wss = new WebSocketServer({ 
    server,
    path: '/ws'
  });

  console.log('[WS] WebSocket server initialized on /ws');

  wss.on('connection', (ws, req) => {
    let userId = null;
    let userAlias = null;

    // Parse token from query string
    const url = new URL(req.url, 'ws://localhost');
    const token = url.searchParams.get('token');

    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.userId;
        userAlias = decoded.alias;
        
        // Add to clients map
        if (!wsClients.has(userId)) {
          wsClients.set(userId, new Set());
        }
        wsClients.get(userId).add(ws);

        // Update last_seen and last_ip
        // Get IP from WebSocket connection (X-Forwarded-For is in upgrade request headers)
        const wsIp = req.headers['cf-connecting-ip'] || 
                     req.headers['x-real-ip'] || 
                     req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                     req.socket?.remoteAddress;
        const ipHash = hashIp(wsIp);
        db.query('UPDATE users SET last_seen_at = NOW(), last_ip = $1, last_ip_raw = $2 WHERE id = $3', [ipHash, wsIp, userId]);

        console.log(`[WS] User ${userAlias} connected (${wsClients.get(userId).size} connections)`);

        // Send connection success
        ws.send(JSON.stringify({ type: 'connected', userId, alias: userAlias }));

        // Broadcast user online status
        broadcastOnlineStatus(userId, userAlias, true);

      } catch (err) {
        console.log('[WS] Invalid token:', err.message);
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
        ws.close();
        return;
      }
    } else {
      // Allow anonymous connections for public broadcasts (optional)
      ws.send(JSON.stringify({ type: 'connected', anonymous: true }));
    }

    // Handle incoming messages
    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data);
        handleWsMessage(ws, userId, userAlias, message);
      } catch (err) {
        console.error('[WS] Invalid message:', err.message);
      }
    });

    // Handle disconnect
    ws.on('close', () => {
      // Clean up thread presence
      if (ws.viewingThread && userId) {
        leaveThreadPresence(ws, userId, userAlias, ws.viewingThread);
      }
      
      if (userId && wsClients.has(userId)) {
        wsClients.get(userId).delete(ws);
        if (wsClients.get(userId).size === 0) {
          wsClients.delete(userId);
          // User fully offline - broadcast status
          broadcastOnlineStatus(userId, userAlias, false);
          console.log(`[WS] User ${userAlias} disconnected (offline)`);
        } else {
          console.log(`[WS] User ${userAlias} tab closed (${wsClients.get(userId).size} remaining)`);
        }
      }
    });

    // Handle errors
    ws.on('error', (err) => {
      console.error('[WS] Connection error:', err.message);
    });
  });

  // Ping clients every 30 seconds to keep connections alive
  setInterval(() => {
    wss.clients.forEach((ws) => {
      if (ws.isAlive === false) {
        return ws.terminate();
      }
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);

  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
  });
}

// Handle incoming WebSocket messages
function handleWsMessage(ws, userId, userAlias, message) {
  switch (message.type) {
    case 'ping':
      ws.send(JSON.stringify({ type: 'pong' }));
      break;

    case 'typing':
      // Broadcast typing indicator to thread viewers
      if (message.threadId && userId) {
        const threadId = parseInt(message.threadId);
        
        // Track typing state
        if (!threadTyping.has(threadId)) {
          threadTyping.set(threadId, new Map());
        }
        threadTyping.get(threadId).set(userId, { 
          alias: userAlias, 
          timestamp: Date.now() 
        });
        
        // Broadcast to thread viewers (exclude self)
        broadcastToThreadViewers(threadId, {
          type: 'typing',
          threadId,
          userId,
          alias: userAlias
        }, userId);
        
        // Auto-clear typing after 3 seconds
        setTimeout(() => {
          if (threadTyping.has(threadId)) {
            const typing = threadTyping.get(threadId).get(userId);
            if (typing && Date.now() - typing.timestamp >= 3000) {
              threadTyping.get(threadId).delete(userId);
              broadcastToThreadViewers(threadId, {
                type: 'stopTyping',
                threadId,
                userId
              });
            }
          }
        }, 3500);
      }
      break;

    case 'stopTyping':
      // Clear typing indicator
      if (message.threadId && userId) {
        const threadId = parseInt(message.threadId);
        if (threadTyping.has(threadId)) {
          threadTyping.get(threadId).delete(userId);
        }
        broadcastToThreadViewers(threadId, {
          type: 'stopTyping',
          threadId,
          userId
        }, userId);
      }
      break;

    case 'viewThread':
      // User started viewing a thread - track presence
      if (message.threadId && userId) {
        const threadId = parseInt(message.threadId);
        
        // Leave any previous thread
        if (ws.viewingThread && ws.viewingThread !== threadId) {
          leaveThreadPresence(ws, userId, userAlias, ws.viewingThread);
        }
        
        ws.viewingThread = threadId;
        
        // Add to thread viewers
        if (!threadViewers.has(threadId)) {
          threadViewers.set(threadId, new Map());
        }
        
        const viewers = threadViewers.get(threadId);
        const isNewViewer = !viewers.has(userId);
        
        viewers.set(userId, {
          alias: userAlias,
          avatarConfig: message.avatarConfig || null,
          joinedAt: Date.now()
        });
        
        // Send current viewer list to the joining user
        const viewerList = [];
        viewers.forEach((data, viewerId) => {
          if (viewerId !== userId) {
            viewerList.push({
              userId: viewerId,
              alias: data.alias,
              avatarConfig: data.avatarConfig
            });
          }
        });
        
        ws.send(JSON.stringify({
          type: 'viewerList',
          threadId,
          viewers: viewerList
        }));
        
        // Broadcast to other viewers that someone joined
        if (isNewViewer) {
          broadcastToThreadViewers(threadId, {
            type: 'viewerJoined',
            threadId,
            userId,
            alias: userAlias,
            avatarConfig: message.avatarConfig || null
          }, userId);
        }
        
        console.log(`[WS] ${userAlias} viewing thread ${threadId} (${viewers.size} viewers)`);
      }
      break;

    case 'leaveThread':
      // User left a thread
      if (message.threadId && userId) {
        leaveThreadPresence(ws, userId, userAlias, parseInt(message.threadId));
      }
      break;

    case 'subscribe':
      // Subscribe to thread updates
      if (message.threadId) {
        ws.subscribedThreads = ws.subscribedThreads || new Set();
        ws.subscribedThreads.add(message.threadId);
      }
      break;

    case 'unsubscribe':
      if (message.threadId && ws.subscribedThreads) {
        ws.subscribedThreads.delete(message.threadId);
      }
      break;

    default:
      console.log('[WS] Unknown message type:', message.type);
  }
}

// Helper: Remove user from thread presence
function leaveThreadPresence(ws, userId, userAlias, threadId) {
  if (threadViewers.has(threadId)) {
    const viewers = threadViewers.get(threadId);
    viewers.delete(userId);
    
    // Clean up typing
    if (threadTyping.has(threadId)) {
      threadTyping.get(threadId).delete(userId);
    }
    
    // Broadcast departure
    broadcastToThreadViewers(threadId, {
      type: 'viewerLeft',
      threadId,
      userId,
      alias: userAlias
    });
    
    // Clean up empty maps
    if (viewers.size === 0) {
      threadViewers.delete(threadId);
    }
    if (threadTyping.has(threadId) && threadTyping.get(threadId).size === 0) {
      threadTyping.delete(threadId);
    }
    
    console.log(`[WS] ${userAlias} left thread ${threadId}`);
  }
  
  if (ws.viewingThread === threadId) {
    ws.viewingThread = null;
  }
}

// Broadcast to all users viewing a specific thread
function broadcastToThreadViewers(threadId, message, excludeUserId = null) {
  if (!wss || !threadViewers.has(threadId)) return;
  
  const messageStr = JSON.stringify(message);
  const viewers = threadViewers.get(threadId);
  
  viewers.forEach((data, viewerId) => {
    if (excludeUserId && viewerId === excludeUserId) return;
    
    if (wsClients.has(viewerId)) {
      wsClients.get(viewerId).forEach((ws) => {
        if (ws.readyState === WebSocket.OPEN && ws.viewingThread === threadId) {
          ws.send(messageStr);
        }
      });
    }
  });
}

// Send message to specific user (all their connections)
function sendToUser(userId, message) {
  if (!wss || !wsClients.has(userId)) return;
  
  const connections = wsClients.get(userId);
  const messageStr = JSON.stringify(message);
  
  connections.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(messageStr);
    }
  });
}

// Broadcast to all connected clients
function broadcast(message, excludeUserId = null) {
  if (!wss) return;
  
  const messageStr = JSON.stringify(message);
  
  wss.clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(messageStr);
    }
  });
}

// Broadcast to all users subscribed to a thread
function broadcastToThread(threadId, message, excludeUserId = null) {
  if (!wss) return;
  
  const messageStr = JSON.stringify(message);
  
  wss.clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN && 
        ws.subscribedThreads && 
        ws.subscribedThreads.has(threadId)) {
      ws.send(messageStr);
    }
  });
}

// Notify followers of a new post (for live feed updates)
async function notifyFollowersOfNewPost(userId, postData) {
  if (!wss) return;
  
  try {
    // Get all users who follow this user
    const followersResult = await db.query(
      'SELECT follower_id FROM follows WHERE followed_id = $1',
      [userId]
    );
    
    if (followersResult.rows.length === 0) return;
    
    const followerIds = followersResult.rows.map(r => r.follower_id);
    const message = JSON.stringify({
      type: 'feedUpdate',
      post: postData
    });
    
    // Send to all connected followers
    wss.clients.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN && 
          ws.userId && 
          followerIds.includes(ws.userId)) {
        ws.send(message);
      }
    });
  } catch (err) {
    console.error('[WS] Failed to notify followers:', err.message);
  }
}

// Broadcast online status change
function broadcastOnlineStatus(userId, alias, isOnline) {
  broadcast({
    type: 'userStatus',
    userId,
    alias,
    isOnline
  });
}

// Notify user of new notification
function notifyUserRealtime(userId, notification) {
  sendToUser(userId, {
    type: 'notification',
    notification
  });
}

// Notify thread subscribers of new post
function notifyNewPost(threadId, entry) {
  broadcastToThread(threadId, {
    type: 'newPost',
    threadId,
    entry: {
      id: entry.id,
      alias: entry.alias,
      content: entry.content.substring(0, 200),
      createdAt: entry.created_at
    }
  });
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

// Request body size limits (DDoS protection)
app.use(express.json({ limit: '2mb' })); // 2mb for avatar uploads
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

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

// Serve sitemap.xml with correct content-type (before static middleware)
app.get('/sitemap.xml', (req, res) => {
  res.setHeader('Content-Type', 'application/xml');
  res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
  res.sendFile(path.join(__dirname, '..', 'sitemap.xml'));
});

// Serve robots.txt with correct content-type
app.get('/robots.txt', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
  res.sendFile(path.join(__dirname, '..', 'robots.txt'));
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
    
    // Asynchronously update last_seen, last_ip (hash), and last_ip_raw (non-blocking)
    const clientIp = getClientIp(req);
    const ipHash = hashIp(clientIp);
    db.query(
      'UPDATE users SET last_seen_at = NOW(), last_ip = $1, last_ip_raw = $2 WHERE id = $3',
      [ipHash, clientIp, decoded.userId]
    ).catch(() => {}); // Silent fail - don't block request
    
    next();
  } catch (err) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

// Normalize IPv6 to /64 prefix (first 4 groups) for consistent hashing
// This prevents ban evasion by changing the suffix
function normalizeIp(ip) {
  if (!ip) return null;
  
  // Clean up IPv6-mapped IPv4 (::ffff:192.168.1.1 -> 192.168.1.1)
  if (ip.startsWith('::ffff:')) {
    ip = ip.slice(7);
  }
  
  // Check if IPv6 (contains colons and not just IPv4 port)
  if (ip.includes(':') && !ip.match(/^\d+\.\d+\.\d+\.\d+$/)) {
    // Expand :: notation if present
    const parts = ip.split(':');
    const emptyIndex = parts.indexOf('');
    if (emptyIndex !== -1) {
      const missing = 8 - parts.filter(p => p !== '').length;
      parts.splice(emptyIndex, 1, ...Array(missing).fill('0000'));
    }
    // Take first 4 groups (/64 prefix)
    return parts.slice(0, 4).map(p => p.padStart(4, '0')).join(':');
  }
  
  // IPv4: return as-is
  return ip;
}

// Hash IP address for privacy-preserving tracking
// IPv6 addresses are normalized to /64 prefix first
function hashIp(ip) {
  if (!ip) return null;
  const normalized = normalizeIp(ip);
  return crypto.createHash('sha256').update(normalized + (process.env.IP_SALT || 'aspd')).digest('hex').slice(0, 16);
}

// Get client IP from request (handles Cloudflare, Railway, and other proxies)
function getClientIp(req) {
  // Cloudflare's real IP header (most reliable when using Cloudflare)
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp) return cfIp;
  
  // X-Real-IP (common proxy header)
  const realIp = req.headers['x-real-ip'];
  if (realIp) return realIp;
  
  // X-Forwarded-For (standard proxy header, may contain multiple IPs)
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    // Get the first IP in the chain (original client)
    const firstIp = forwardedFor.split(',')[0]?.trim();
    if (firstIp) return firstIp;
  }
  
  // Express's req.ip (uses trust proxy setting)
  if (req.ip) return req.ip;
  
  // Fallback to socket remote address
  return req.socket?.remoteAddress || req.connection?.remoteAddress || null;
}

// Detect device type from user agent
function detectDeviceType(userAgent) {
  if (!userAgent) return 'unknown';
  const ua = userAgent.toLowerCase();
  if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) return 'mobile';
  if (ua.includes('tablet') || ua.includes('ipad')) return 'tablet';
  if (ua.includes('windows') || ua.includes('macintosh') || ua.includes('linux')) return 'desktop';
  return 'unknown';
}

// Parse user agent for display
function parseUserAgent(userAgent) {
  if (!userAgent) return { browser: 'Unknown', os: 'Unknown' };
  
  let browser = 'Unknown';
  let os = 'Unknown';
  
  // Detect browser
  if (userAgent.includes('Firefox/')) browser = 'Firefox';
  else if (userAgent.includes('Edg/')) browser = 'Edge';
  else if (userAgent.includes('Chrome/')) browser = 'Chrome';
  else if (userAgent.includes('Safari/') && !userAgent.includes('Chrome')) browser = 'Safari';
  else if (userAgent.includes('Opera') || userAgent.includes('OPR/')) browser = 'Opera';
  
  // Detect OS
  if (userAgent.includes('Windows NT 10')) os = 'Windows 10/11';
  else if (userAgent.includes('Windows')) os = 'Windows';
  else if (userAgent.includes('Mac OS X')) os = 'macOS';
  else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) os = 'iOS';
  else if (userAgent.includes('Android')) os = 'Android';
  else if (userAgent.includes('Linux')) os = 'Linux';
  
  return { browser, os };
}

// Log login attempt
async function logLoginAttempt(userId, ipHash, userAgent, success, failureReason = null) {
  try {
    await db.query(
      `INSERT INTO login_attempts (user_id, ip_hash, user_agent, success, failure_reason) 
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, ipHash, userAgent, success, failureReason]
    );
    
    // If failed login from new IP, check if we should alert the user
    if (!success && userId) {
      checkNewIpLoginAlert(userId, ipHash, userAgent);
    }
  } catch (err) {
    // Don't fail login if logging fails
    console.error('[LOGIN ATTEMPT LOG ERROR]', err.message);
  }
}

// Check if this is a new IP and alert user
async function checkNewIpLoginAlert(userId, ipHash, userAgent) {
  try {
    // Check if this IP has been used before successfully
    const knownIp = await db.query(
      `SELECT id FROM login_attempts 
       WHERE user_id = $1 AND ip_hash = $2 AND success = TRUE 
       LIMIT 1`,
      [userId, ipHash]
    );
    
    if (knownIp.rows.length === 0) {
      // This is a new IP - check if user has email and wants alerts
      const userResult = await db.query(
        `SELECT alias, email, email_verified FROM users WHERE id = $1`,
        [userId]
      );
      
      if (userResult.rows.length > 0) {
        const user = userResult.rows[0];
        
        // Create in-app notification about failed login
        await db.query(
          `INSERT INTO notifications (user_id, type, title, message, link) 
           VALUES ($1, 'security', 'Failed Login Attempt', $2, '/settings.html')`,
          [userId, `A failed login attempt was detected from a new location. If this wasn't you, consider changing your password.`]
        );
        
        // Send email if verified
        if (user.email && user.email_verified && typeof sendNotificationEmail === 'function') {
          const { browser, os } = parseUserAgent(userAgent);
          sendNotificationEmail(
            userId,
            'security',
            `Security Alert: Failed login attempt on ${user.alias}`,
            `A failed login attempt was detected from ${browser} on ${os}. If this wasn't you, please change your password immediately.`
          );
        }
      }
    }
  } catch (err) {
    console.error('[NEW IP ALERT ERROR]', err.message);
  }
}

// Role hierarchy: owner > admin > moderator > user
// owner: Full control, can manage admins
// admin: Full moderation, can manage moderators, can ban users
// moderator: Can moderate content (delete posts, handle reports), cannot ban users or access sensitive settings
const ROLE_LEVELS = {
  'user': 0,
  'moderator': 1,
  'admin': 2,
  'owner': 3
};

// Get user's effective role
async function getUserRole(userId) {
  const result = await db.query(
    'SELECT role, is_admin FROM users WHERE id = $1',
    [userId]
  );
  if (result.rows.length === 0) return 'user';
  const user = result.rows[0];
  // Backward compatibility: if role not set but is_admin is true, treat as admin
  if (user.role) return user.role;
  if (user.is_admin) return 'admin';
  return 'user';
}

// Check if user has at least the required role level
function hasRoleLevel(userRole, requiredRole) {
  return (ROLE_LEVELS[userRole] || 0) >= (ROLE_LEVELS[requiredRole] || 0);
}

// Moderator middleware - requires moderator, admin, or owner
async function modMiddleware(req, res, next) {
  if (!req.user || !req.user.userId) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  try {
    const role = await getUserRole(req.user.userId);
    if (!hasRoleLevel(role, 'moderator')) {
      return res.status(403).json({ error: 'forbidden' });
    }
    req.userRole = role;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
}

// Admin middleware - requires admin or owner (for user management, bans, etc.)
async function adminMiddleware(req, res, next) {
  if (!req.user || !req.user.userId) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  try {
    const role = await getUserRole(req.user.userId);
    if (!hasRoleLevel(role, 'admin')) {
      return res.status(403).json({ error: 'forbidden' });
    }
    req.userRole = role;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
}

// Owner middleware - requires owner (for managing admins, critical settings)
async function ownerMiddleware(req, res, next) {
  if (!req.user || !req.user.userId) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  try {
    const role = await getUserRole(req.user.userId);
    if (role !== 'owner') {
      return res.status(403).json({ error: 'forbidden', message: 'Owner access required' });
    }
    req.userRole = role;
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

// Rooms cache (refreshed every 30 seconds)
let roomsCache = null;
let roomsCacheTime = 0;
const ROOMS_CACHE_TTL = 30 * 1000; // 30 seconds

// Force cache clear on startup
console.log('[STARTUP] Clearing rooms cache');

async function getCachedRooms() {
  const now = Date.now();
  if (roomsCache && now - roomsCacheTime < ROOMS_CACHE_TTL) {
    console.log('[ROOMS CACHE] Returning cached data, age:', (now - roomsCacheTime) / 1000, 'seconds');
    return roomsCache;
  }
  try {
    console.log('[ROOMS CACHE] Fetching fresh data from database...');
    const result = await db.query(
      `SELECT slug AS id, title, description,
              (SELECT COUNT(*) FROM threads WHERE room_id = rooms.id) as thread_count
       FROM rooms ORDER BY COALESCE(display_order, 999), id`
    );
    console.log('[ROOMS CACHE] Got', result.rows.length, 'rooms. Sample counts:', 
      result.rows.filter(r => ['stories', 'coping', 'diagnosis', 'relationships', 'general'].includes(r.id))
        .map(r => r.id + ':' + r.thread_count).join(', '));
    roomsCache = result.rows;
    roomsCacheTime = now;
    return roomsCache;
  } catch (err) {
    console.error('[ROOMS CACHE ERROR]', err.message);
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

// Rate limiter for registration (stricter to prevent spam accounts)
const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registration attempts per hour per IP
  message: { success: false, error: 'too_many_registrations', message: 'Too many registration attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => hashIp(getClientIp(req)) || 'unknown'
});

// Rate limiter for search (prevent abuse)
const searchLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 searches per minute
  message: { success: false, error: 'rate_limit_exceeded', message: 'Too many searches, slow down' },
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
app.post('/register', registrationLimiter, authRateLimiter, async (req, res) => {
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
  const { alias, password, totpCode, rememberMe, deviceToken, trustDevice } = req.body;
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
      'SELECT id, alias, password_hash, is_admin, role FROM users WHERE alias = $1',
      [alias]
    );

    if (result.rows.length === 0) {
      recordFailedLogin(ipHash);
      logLoginAttempt(null, ipHash, req.get('User-Agent'), false, 'invalid_user');
      return res.status(401).json({ success: false, error: 'invalid_credentials' });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      recordFailedLogin(ipHash);
      logLoginAttempt(user.id, ipHash, req.get('User-Agent'), false, 'invalid_password');
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
      // Check if user has a valid trusted device token
      let deviceTrusted = false;
      if (deviceToken) {
        try {
          const deviceTokenHash = crypto.createHash('sha256').update(deviceToken).digest('hex');
          const deviceCheck = await db.query(
            'SELECT id FROM trusted_devices WHERE user_id = $1 AND token_hash = $2 AND expires_at > NOW()',
            [user.id, deviceTokenHash]
          );
          deviceTrusted = deviceCheck.rows.length > 0;
        } catch (e) {
          // Table might not exist yet, ignore
        }
      }

      if (!deviceTrusted) {
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
            logLoginAttempt(user.id, ipHash, req.get('User-Agent'), false, 'invalid_2fa');
            return res.status(401).json({ success: false, error: 'invalid_2fa_code' });
          }
          
          // Mark backup code as used
          await db.query('UPDATE recovery_codes SET used = TRUE WHERE id = $1', [backupCheck.rows[0].id]);
        }
      }
    }

    // Successful login - clear failed attempts
    clearFailedLogin(ipHash);

    // Determine effective role
    const userRole = user.role || (user.is_admin ? 'admin' : 'user');
    const isAdminOrHigher = userRole === 'admin' || userRole === 'owner';
    const isModOrHigher = isAdminOrHigher || userRole === 'moderator';

    // Use extended expiry if "remember me" is checked
    const tokenExpiry = rememberMe ? JWT_EXPIRES_REMEMBER : JWT_EXPIRES;
    const refreshExpiry = rememberMe ? JWT_REFRESH_EXPIRES_REMEMBER : JWT_REFRESH_EXPIRES;
    const refreshExpiryMs = rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;

    const token = jwt.sign(
      { userId: user.id, alias: user.alias, isAdmin: isAdminOrHigher, role: userRole },
      JWT_SECRET,
      { expiresIn: tokenExpiry }
    );

    // Issue refresh token (longer lived)
    const refreshToken = jwt.sign(
      { userId: user.id, alias: user.alias, isAdmin: isAdminOrHigher, role: userRole, type: 'refresh' },
      JWT_SECRET,
      { expiresIn: refreshExpiry }
    );
    
    // Store refresh token hash in database for revocation support
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const refreshExpiryDate = new Date(Date.now() + refreshExpiryMs);
    const userAgent = req.get('User-Agent') || 'unknown';
    const deviceType = detectDeviceType(userAgent);
    
    await db.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_hash, user_agent, device_type) 
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [user.id, refreshTokenHash, refreshExpiryDate, ipHash, userAgent, deviceType]
    );
    
    // Log successful login
    logLoginAttempt(user.id, ipHash, userAgent, true);

    // Generate device token if user wants to trust this device (for 2FA skip)
    let newDeviceToken = null;
    if (trustDevice && totp_enabled) {
      newDeviceToken = crypto.randomBytes(32).toString('hex');
      const deviceTokenHash = crypto.createHash('sha256').update(newDeviceToken).digest('hex');
      const deviceExpiryDate = new Date(Date.now() + DEVICE_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000);
      try {
        await db.query(
          'INSERT INTO trusted_devices (user_id, token_hash, expires_at, ip_hash, user_agent) VALUES ($1, $2, $3, $4, $5)',
          [user.id, deviceTokenHash, deviceExpiryDate, ipHash, req.get('User-Agent') || 'unknown']
        );
      } catch (e) {
        // Table might not exist, ignore
        logger.warn('AUTH', 'Could not store trusted device', { error: e.message });
      }
    }

    const response = { success: true, token, refreshToken, isAdmin: isAdminOrHigher, role: userRole, isMod: isModOrHigher };
    if (newDeviceToken) {
      response.deviceToken = newDeviceToken;
    }
    res.json(response);
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
        <div style="font-family: 'Courier New', monospace; background: #0a0a0a; max-width: 480px; margin: 0 auto;">
          <div style="border: 1px solid #1a1a1a; padding: 40px; background: #0a0a0a;">
            <!-- Sigil Header -->
            <div style="text-align: center; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid #1a1a1a;">
              <div style="display: inline-block; width: 48px; height: 48px; margin-bottom: 16px; position: relative;">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" style="width: 48px; height: 48px; opacity: 0.4;">
                  <circle cx="50" cy="50" r="45" fill="none" stroke="#4a4a4a" stroke-width="1"/>
                  <circle cx="50" cy="50" r="6" fill="#4a4a4a"/>
                  <circle cx="50" cy="50" r="18" fill="none" stroke="#4a4a4a" stroke-width="0.5"/>
                  <circle cx="50" cy="50" r="30" fill="none" stroke="#4a4a4a" stroke-width="0.5"/>
                  <line x1="50" y1="5" x2="50" y2="20" stroke="#4a4a4a" stroke-width="1"/>
                  <line x1="50" y1="80" x2="50" y2="95" stroke="#4a4a4a" stroke-width="1"/>
                  <line x1="5" y1="50" x2="20" y2="50" stroke="#4a4a4a" stroke-width="1"/>
                  <line x1="80" y1="50" x2="95" y2="50" stroke="#4a4a4a" stroke-width="1"/>
                </svg>
              </div>
              <div style="font-size: 10px; letter-spacing: 0.4em; color: #5a5a5a; text-transform: uppercase;">ASPD FORUM</div>
            </div>
            
            <!-- Content -->
            <div style="color: #8a8a8a; font-size: 13px; line-height: 1.8;">
              <p style="margin: 0 0 16px 0;">Hello <span style="color: #a0a0a0;">${user.alias}</span>,</p>
              <p style="margin: 0 0 24px 0;">A password reset was requested for your account.</p>
              
              <div style="text-align: center; margin: 32px 0;">
                <a href="${resetUrl}" style="display: inline-block; padding: 14px 32px; background: #151515; color: #9a9a9a; text-decoration: none; border: 1px solid #2a2a2a; font-size: 11px; letter-spacing: 0.2em; text-transform: uppercase;">RESET PASSWORD</a>
              </div>
              
              <p style="margin: 24px 0 0 0; font-size: 11px; color: #5a5a5a;">This link expires in 1 hour.</p>
              <p style="margin: 6px 0 0 0; font-size: 11px; color: #5a5a5a;">If you didn't request this, ignore this email.</p>
            </div>
            
            <!-- Footer -->
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #1a1a1a; text-align: center;">
              <div style="font-size: 9px; letter-spacing: 0.3em; color: #4a4a4a;">ASPDFORUM.COM</div>
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
      'SELECT id, alias, bio, avatar_config, signature, reputation, custom_title, epithet, is_admin, role, created_at, followers_private, following_private FROM users WHERE alias = $1',
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
    
    // Calculate user rank based on role first, then post count
    let rank = 'NEWCOMER';
    if (user.role === 'owner') rank = 'OWNER';
    else if (user.role === 'admin') rank = 'ADMIN';
    else if (user.role === 'moderator') rank = 'MODERATOR';
    else if (postCount >= 500) rank = 'VETERAN';
    else if (postCount >= 200) rank = 'EXPERT';
    else if (postCount >= 100) rank = 'REGULAR';
    else if (postCount >= 50) rank = 'MEMBER';
    else if (postCount >= 10) rank = 'ACTIVE';
    
    // Get followers count
    const followersResult = await db.query(
      'SELECT COUNT(*) FROM user_follows WHERE following_id = $1',
      [user.id]
    );
    const followersCount = parseInt(followersResult.rows[0].count);
    
    // Get following count
    const followingResult = await db.query(
      'SELECT COUNT(*) FROM user_follows WHERE follower_id = $1',
      [user.id]
    );
    const followingCount = parseInt(followingResult.rows[0].count);
    
    // Determine if viewer can see followers/following lists
    const isOwnProfile = viewerId === user.id;
    const canViewFollowers = isOwnProfile || !user.followers_private;
    const canViewFollowing = isOwnProfile || !user.following_private;
    
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
        role: user.role || 'user',
        isAdmin: user.is_admin || false,
        createdAt: user.created_at,
        followersPrivate: user.followers_private || false,
        followingPrivate: user.following_private || false,
        followersCount: followersCount,
        followingCount: followingCount,
        canViewFollowers: canViewFollowers,
        canViewFollowing: canViewFollowing,
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
      'SELECT email, email_verified, notification_replies, notification_mentions, notification_messages, followers_private FROM users WHERE id = $1',
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
  const { email, notification_replies, notification_mentions, notification_messages, followers_private } = req.body;
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
    
    // Update notification preferences and privacy settings
    if (notification_replies !== undefined || notification_mentions !== undefined || notification_messages !== undefined || followers_private !== undefined) {
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
      if (followers_private !== undefined) {
        updates.push(`followers_private = $${paramIndex++}`);
        values.push(followers_private);
      }
      
      if (updates.length > 0) {
        values.push(userId);
        await db.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex}`, values);
      }
    }
    
    // Return updated settings
    const result = await db.query(
      'SELECT email, email_verified, notification_replies, notification_mentions, notification_messages, followers_private FROM users WHERE id = $1',
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
  if (!speakeasy || !qrcode) {
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
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    
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
      `SELECT id, created_at, expires_at, ip_hash, user_agent, device_type, last_used_at,
              CASE WHEN token_hash = $2 THEN true ELSE false END AS is_current
       FROM refresh_tokens 
       WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW()
       ORDER BY last_used_at DESC NULLS LAST, created_at DESC`,
      [userId, req.currentTokenHash || '']
    );
    
    res.json({ 
      success: true, 
      sessions: result.rows.map(s => {
        const parsed = parseUserAgent(s.user_agent);
        return {
          id: s.id,
          createdAt: s.created_at,
          expiresAt: s.expires_at,
          lastUsedAt: s.last_used_at,
          isCurrent: s.is_current,
          deviceType: s.device_type || 'unknown',
          browser: parsed.browser,
          os: parsed.os,
          ipHash: s.ip_hash ? s.ip_hash.slice(0, 8) + '...' : null // Truncated for display
        };
      })
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

// API: Get login history
app.get('/api/settings/login-history', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  
  try {
    const result = await db.query(
      `SELECT id, ip_hash, user_agent, success, failure_reason, created_at
       FROM login_attempts 
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 20`,
      [userId]
    );
    
    res.json({
      success: true,
      history: result.rows.map(h => {
        const parsed = parseUserAgent(h.user_agent);
        return {
          id: h.id,
          success: h.success,
          failureReason: h.failure_reason,
          createdAt: h.created_at,
          browser: parsed.browser,
          os: parsed.os,
          ipHash: h.ip_hash ? h.ip_hash.slice(0, 8) + '...' : null
        };
      })
    });
  } catch (err) {
    console.error('[LOGIN HISTORY ERROR]', err.message);
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
    const siteUrl = process.env.SITE_URL || 'https://www.aspdforum.com';
    const verifyUrl = `${siteUrl}/verify-email.html?token=${token}`;
    const emailSent = await sendEmail(
      email,
      'Verify Email — ASPD Forum',
      `
        <div style="font-family: 'Courier New', monospace; background: #0a0a0a; max-width: 480px; margin: 0 auto;">
          <div style="border: 1px solid #1a1a1a; padding: 40px; background: #0a0a0a;">
            <!-- Sigil Header -->
            <div style="text-align: center; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid #1a1a1a;">
              <div style="display: inline-block; width: 48px; height: 48px; margin-bottom: 16px; position: relative;">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" style="width: 48px; height: 48px; opacity: 0.4;">
                  <circle cx="50" cy="50" r="45" fill="none" stroke="#4a4a4a" stroke-width="1"/>
                  <circle cx="50" cy="50" r="6" fill="#4a4a4a"/>
                  <circle cx="50" cy="50" r="18" fill="none" stroke="#4a4a4a" stroke-width="0.5"/>
                  <circle cx="50" cy="50" r="30" fill="none" stroke="#4a4a4a" stroke-width="0.5"/>
                  <line x1="50" y1="5" x2="50" y2="20" stroke="#4a4a4a" stroke-width="1"/>
                  <line x1="50" y1="80" x2="50" y2="95" stroke="#4a4a4a" stroke-width="1"/>
                  <line x1="5" y1="50" x2="20" y2="50" stroke="#4a4a4a" stroke-width="1"/>
                  <line x1="80" y1="50" x2="95" y2="50" stroke="#4a4a4a" stroke-width="1"/>
                </svg>
              </div>
              <div style="font-size: 10px; letter-spacing: 0.4em; color: #5a5a5a; text-transform: uppercase;">ASPD FORUM</div>
            </div>
            
            <!-- Content -->
            <div style="color: #8a8a8a; font-size: 13px; line-height: 1.8;">
              <p style="margin: 0 0 24px 0;">Verify your email address to enable password recovery and notifications.</p>
              
              <div style="text-align: center; margin: 32px 0;">
                <a href="${verifyUrl}" style="display: inline-block; padding: 14px 32px; background: #151515; color: #9a9a9a; text-decoration: none; border: 1px solid #2a2a2a; font-size: 11px; letter-spacing: 0.2em; text-transform: uppercase;">VERIFY EMAIL</a>
              </div>
              
              <p style="margin: 24px 0 0 0; font-size: 11px; color: #5a5a5a;">This link expires in 24 hours.</p>
              <p style="margin: 6px 0 0 0; font-size: 11px; color: #5a5a5a;">If you didn't request this, ignore this email.</p>
            </div>
            
            <!-- Footer -->
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #1a1a1a; text-align: center;">
              <div style="font-size: 9px; letter-spacing: 0.3em; color: #4a4a4a;">ASPDFORUM.COM</div>
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

// API: Get forum statistics (public - for "who's online" display)
app.get('/api/forum/online', async (req, res) => {
  try {
    // Activity weights by UTC hour
    const activityWeights = {
      0: 0.9,  1: 0.8,  2: 0.6,  3: 0.4,  4: 0.3,  5: 0.2,
      6: 0.15, 7: 0.1,  8: 0.1,  9: 0.15, 10: 0.2, 11: 0.3,
      12: 0.4, 13: 0.5, 14: 0.5, 15: 0.6, 16: 0.7, 17: 0.8,
      18: 0.9, 19: 1.0, 20: 1.0, 21: 1.0, 22: 1.0, 23: 0.95
    };

    // Get counts from database
    const stats = await db.query(`
      SELECT 
        (SELECT COUNT(*) FROM users WHERE banned = false) as total_users,
        (SELECT COUNT(*) FROM users WHERE is_bot = true) as total_bots
    `);
    
    const totalUsers = parseInt(stats.rows[0].total_users) || 0;
    const totalBots = parseInt(stats.rows[0].total_bots) || 0;
    const realUsers = totalUsers - totalBots;

    // Current hour UTC
    const currentHour = new Date().getUTCHours();
    const currentWeight = activityWeights[currentHour] || 0.5;

    // Simulate online bots based on current weight + randomness
    const baseOnlineBots = Math.floor(totalBots * currentWeight * 0.3);
    const botVariance = Math.floor(Math.random() * Math.ceil(totalBots * 0.1));
    const onlineBots = Math.min(totalBots, Math.max(1, baseOnlineBots + botVariance));

    // Simulate online real users (much lower activity)
    const baseOnlineUsers = Math.floor(realUsers * currentWeight * 0.05);
    const userVariance = Math.floor(Math.random() * 3);
    const onlineUsers = Math.max(0, baseOnlineUsers + userVariance);

    // Cache result for 30 seconds to prevent refresh spam
    res.set('Cache-Control', 'public, max-age=30');
    
    res.json({
      success: true,
      online: {
        total: onlineBots + onlineUsers,
        members: onlineUsers,
        guests: onlineBots, // Bots appear as "guests" to regular users
        browsing: Math.floor((onlineBots + onlineUsers) * 0.7)
      },
      stats: {
        totalMembers: realUsers,
        peakHour: 19 // 7 PM UTC is peak
      }
    });
  } catch (err) {
    console.error('[ONLINE STATS ERROR]', err);
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
app.get('/api/search', authMiddleware, searchLimiter, async (req, res) => {
  const query = req.query.q || '';
  const type = req.query.type || 'all'; // all, threads, posts, users
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const offset = (page - 1) * limit;
  
  // Advanced filters
  const roomFilter = req.query.room || null; // Room slug or ID
  const userFilter = req.query.user || null; // Username to filter by
  const dateFrom = req.query.from || null; // Date range start (ISO)
  const dateTo = req.query.to || null; // Date range end (ISO)
  const sortBy = req.query.sort || 'recent'; // recent, oldest, relevance

  if (!query || query.length < 2) {
    return res.json({ success: true, results: [], total: 0 });
  }

  const searchPattern = '%' + query + '%';

  try {
    let results = [];
    let total = 0;
    
    // Build date filter SQL
    let dateFilterSQL = '';
    const dateParams = [];
    let paramIndex = 4; // After searchPattern, limit, offset
    
    if (dateFrom) {
      dateFilterSQL += ` AND created_at >= $${paramIndex}`;
      dateParams.push(dateFrom);
      paramIndex++;
    }
    if (dateTo) {
      dateFilterSQL += ` AND created_at <= $${paramIndex}`;
      dateParams.push(dateTo);
      paramIndex++;
    }
    
    // Determine sort order
    const sortOrder = sortBy === 'oldest' ? 'ASC' : 'DESC';

    if (type === 'all' || type === 'threads') {
      // Search threads with filters
      let threadQuery = `
        SELECT t.id, t.title, t.slug, t.created_at, r.slug AS room_slug, r.title AS room_title,
               u.alias AS author, 'thread' AS result_type,
               (SELECT COUNT(*) FROM entries WHERE thread_id = t.id AND is_deleted = FALSE) AS entry_count
        FROM threads t
        JOIN rooms r ON r.id = t.room_id
        JOIN users u ON u.id = t.user_id
        WHERE (t.title ILIKE $1 OR t.slug ILIKE $1)`;
      
      let threadParams = [searchPattern];
      let tParamIdx = 2;
      
      if (roomFilter) {
        threadQuery += ` AND (r.slug = $${tParamIdx} OR r.id::text = $${tParamIdx})`;
        threadParams.push(roomFilter);
        tParamIdx++;
      }
      if (userFilter) {
        threadQuery += ` AND u.alias ILIKE $${tParamIdx}`;
        threadParams.push('%' + userFilter + '%');
        tParamIdx++;
      }
      if (dateFrom) {
        threadQuery += ` AND t.created_at >= $${tParamIdx}`;
        threadParams.push(dateFrom);
        tParamIdx++;
      }
      if (dateTo) {
        threadQuery += ` AND t.created_at <= $${tParamIdx}`;
        threadParams.push(dateTo);
        tParamIdx++;
      }
      
      threadQuery += ` ORDER BY t.created_at ${sortOrder} LIMIT $${tParamIdx} OFFSET $${tParamIdx + 1}`;
      threadParams.push(limit, offset);
      
      const threadResult = await db.query(threadQuery, threadParams);
      
      if (type === 'threads') {
        // Count query with same filters
        let countQuery = `SELECT COUNT(*) FROM threads t 
          JOIN rooms r ON r.id = t.room_id 
          JOIN users u ON u.id = t.user_id
          WHERE (t.title ILIKE $1 OR t.slug ILIKE $1)`;
        let countParams = [searchPattern];
        let cParamIdx = 2;
        
        if (roomFilter) {
          countQuery += ` AND (r.slug = $${cParamIdx} OR r.id::text = $${cParamIdx})`;
          countParams.push(roomFilter);
          cParamIdx++;
        }
        if (userFilter) {
          countQuery += ` AND u.alias ILIKE $${cParamIdx}`;
          countParams.push('%' + userFilter + '%');
          cParamIdx++;
        }
        if (dateFrom) {
          countQuery += ` AND t.created_at >= $${cParamIdx}`;
          countParams.push(dateFrom);
          cParamIdx++;
        }
        if (dateTo) {
          countQuery += ` AND t.created_at <= $${cParamIdx}`;
          countParams.push(dateTo);
          cParamIdx++;
        }
        
        const countResult = await db.query(countQuery, countParams);
        total = parseInt(countResult.rows[0].count);
      }
      
      results = results.concat(threadResult.rows);
    }

    if (type === 'all' || type === 'posts') {
      // Search posts/entries with filters
      let postQuery = `
        SELECT e.id, e.content, e.created_at, e.alias AS author,
               t.id AS thread_id, t.title AS thread_title, t.slug AS thread_slug,
               r.slug AS room_slug, 'post' AS result_type
        FROM entries e
        JOIN threads t ON t.id = e.thread_id
        JOIN rooms r ON r.id = t.room_id
        WHERE e.is_deleted = FALSE AND e.content ILIKE $1`;
      
      let postParams = [searchPattern];
      let pParamIdx = 2;
      
      if (roomFilter) {
        postQuery += ` AND (r.slug = $${pParamIdx} OR r.id::text = $${pParamIdx})`;
        postParams.push(roomFilter);
        pParamIdx++;
      }
      if (userFilter) {
        postQuery += ` AND e.alias ILIKE $${pParamIdx}`;
        postParams.push('%' + userFilter + '%');
        pParamIdx++;
      }
      if (dateFrom) {
        postQuery += ` AND e.created_at >= $${pParamIdx}`;
        postParams.push(dateFrom);
        pParamIdx++;
      }
      if (dateTo) {
        postQuery += ` AND e.created_at <= $${pParamIdx}`;
        postParams.push(dateTo);
        pParamIdx++;
      }
      
      postQuery += ` ORDER BY e.created_at ${sortOrder} LIMIT $${pParamIdx} OFFSET $${pParamIdx + 1}`;
      postParams.push(limit, offset);
      
      const postResult = await db.query(postQuery, postParams);
      
      if (type === 'posts') {
        let countQuery = `SELECT COUNT(*) FROM entries e
          JOIN threads t ON t.id = e.thread_id
          JOIN rooms r ON r.id = t.room_id
          WHERE e.is_deleted = FALSE AND e.content ILIKE $1`;
        let countParams = [searchPattern];
        let cParamIdx = 2;
        
        if (roomFilter) {
          countQuery += ` AND (r.slug = $${cParamIdx} OR r.id::text = $${cParamIdx})`;
          countParams.push(roomFilter);
          cParamIdx++;
        }
        if (userFilter) {
          countQuery += ` AND e.alias ILIKE $${cParamIdx}`;
          countParams.push('%' + userFilter + '%');
          cParamIdx++;
        }
        if (dateFrom) {
          countQuery += ` AND e.created_at >= $${cParamIdx}`;
          countParams.push(dateFrom);
          cParamIdx++;
        }
        if (dateTo) {
          countQuery += ` AND e.created_at <= $${cParamIdx}`;
          countParams.push(dateTo);
          cParamIdx++;
        }
        
        const countResult = await db.query(countQuery, countParams);
        total = parseInt(countResult.rows[0].count);
      }
      
      results = results.concat(postResult.rows);
    }

    if (type === 'all' || type === 'users') {
      // Search users (no room filter applies)
      let userQuery = `
        SELECT u.id, u.alias, u.bio, u.created_at, u.is_admin, 'user' AS result_type,
               (SELECT COUNT(*) FROM entries WHERE user_id = u.id AND is_deleted = FALSE) AS post_count
        FROM users u
        WHERE u.alias ILIKE $1 AND u.is_banned = FALSE`;
      
      let userParams = [searchPattern];
      let uParamIdx = 2;
      
      if (dateFrom) {
        userQuery += ` AND u.created_at >= $${uParamIdx}`;
        userParams.push(dateFrom);
        uParamIdx++;
      }
      if (dateTo) {
        userQuery += ` AND u.created_at <= $${uParamIdx}`;
        userParams.push(dateTo);
        uParamIdx++;
      }
      
      userQuery += ` ORDER BY u.created_at ${sortOrder} LIMIT $${uParamIdx} OFFSET $${uParamIdx + 1}`;
      userParams.push(limit, offset);
      
      const userResult = await db.query(userQuery, userParams);
      
      if (type === 'users') {
        let countQuery = `SELECT COUNT(*) FROM users WHERE alias ILIKE $1 AND is_banned = FALSE`;
        let countParams = [searchPattern];
        let cParamIdx = 2;
        
        if (dateFrom) {
          countQuery += ` AND created_at >= $${cParamIdx}`;
          countParams.push(dateFrom);
          cParamIdx++;
        }
        if (dateTo) {
          countQuery += ` AND created_at <= $${cParamIdx}`;
          countParams.push(dateTo);
          cParamIdx++;
        }
        
        const countResult = await db.query(countQuery, countParams);
        total = parseInt(countResult.rows[0].count);
      }
      
      results = results.concat(userResult.rows);
    }

    // For 'all' type, estimate total (simplified)
    if (type === 'all') {
      total = results.length < limit ? results.length : results.length + 10; // Rough estimate
    }

    res.json({
      success: true,
      results: results,
      total: total,
      filters: {
        room: roomFilter,
        user: userFilter,
        dateFrom: dateFrom,
        dateTo: dateTo,
        sort: sortBy
      },
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
    // Query that filters out deleted threads and entries
    let query = `
      SELECT af.id, af.action_type, af.target_type, af.target_id, af.target_title, af.details, af.created_at,
             u.alias, u.avatar_config
      FROM activity_feed af
      JOIN users u ON u.id = af.user_id
      LEFT JOIN threads t ON af.target_type = 'thread' AND t.id = af.target_id
      LEFT JOIN entries e ON af.target_type = 'entry' AND e.id = af.target_id
      WHERE u.is_banned = FALSE
        AND (
          (af.target_type = 'thread' AND t.id IS NOT NULL AND (t.is_deleted IS NULL OR t.is_deleted = FALSE))
          OR (af.target_type = 'entry' AND e.id IS NOT NULL AND (e.is_deleted IS NULL OR e.is_deleted = FALSE))
          OR (af.target_type NOT IN ('thread', 'entry'))
        )
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

    // Get total count (also filtering deleted)
    let countQuery = `
      SELECT COUNT(*) FROM activity_feed af 
      JOIN users u ON u.id = af.user_id
      LEFT JOIN threads t ON af.target_type = 'thread' AND t.id = af.target_id
      LEFT JOIN entries e ON af.target_type = 'entry' AND e.id = af.target_id
      WHERE u.is_banned = FALSE
        AND (
          (af.target_type = 'thread' AND t.id IS NOT NULL AND (t.is_deleted IS NULL OR t.is_deleted = FALSE))
          OR (af.target_type = 'entry' AND e.id IS NOT NULL AND (e.is_deleted IS NULL OR e.is_deleted = FALSE))
          OR (af.target_type NOT IN ('thread', 'entry'))
        )
    `;
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
  const sort = req.query.sort || 'newest';
  const tagFilter = req.query.tag ? parseInt(req.query.tag) : null;
  
  try {
    const roomResult = await db.query(
      'SELECT id, slug, title, description FROM rooms WHERE slug = $1',
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

    // Count total threads
    const countResult = await db.query(
      `SELECT COUNT(*) FROM threads t WHERE ${whereClause}`,
      queryParams
    );
    const total = parseInt(countResult.rows[0].count);
    
    // Get paginated threads (simplified query)
    const threadsQuery = `
      SELECT t.id, t.title, t.slug,
             COALESCE(t.is_pinned, false) AS is_pinned, 
             COALESCE(t.is_locked, false) AS is_locked,
             COUNT(e.id) FILTER (WHERE e.is_deleted = FALSE OR e.is_deleted IS NULL)::int AS "entriesCount"
       FROM threads t
       LEFT JOIN entries e ON e.thread_id = t.id
       WHERE ${whereClause}
       GROUP BY t.id
       ORDER BY COALESCE(t.is_pinned, false) DESC, t.id DESC
       LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
    queryParams.push(limit, offset);
    
    const threadsResult = await db.query(threadsQuery, queryParams);
    
    res.json({
      success: true,
      room: { 
        id: room.slug, 
        title: room.title,
        description: room.description || null
      },
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
      `SELECT t.id, t.title, t.slow_mode_interval, t.is_locked, t.is_pinned, t.soundscape, r.slug AS room_slug
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
                u.signature, u.reputation, u.custom_title, u.is_admin, u.role,
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
        if (entry.role === 'owner') rank = 'OWNER';
        else if (entry.role === 'admin') rank = 'ADMIN';
        else if (entry.role === 'moderator') rank = 'MODERATOR';
        else if (postCount >= 500) rank = 'VETERAN';
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
              u.signature, u.reputation, u.custom_title, u.epithet, u.is_admin, u.role,
              e.created_at, e.edited_at, e.is_ghost, e.ghost_alias, e.mood, e.vault_level,
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
    
    // Check if the requesting user is a mod/admin (can see real identity behind ghost posts)
    let isMod = false;
    let userReputation = 0;
    let userRole = null;
    if (userId) {
      const modCheck = await db.query('SELECT role, reputation FROM users WHERE id = $1', [userId]);
      if (modCheck.rows.length > 0) {
        const role = modCheck.rows[0].role;
        userRole = role;
        userReputation = modCheck.rows[0].reputation || 0;
        isMod = role === 'owner' || role === 'admin' || role === 'moderator';
      }
    }
    
    // Attach reactions, votes, and rank to entries
    const entriesWithReactions = entriesResult.rows.map(entry => {
      const postCount = parseInt(entry.post_count) || 0;
      let rank = 'NEWCOMER';
      if (entry.role === 'owner') rank = 'OWNER';
      else if (entry.role === 'admin') rank = 'ADMIN';
      else if (entry.role === 'moderator') rank = 'MODERATOR';
      else if (postCount >= 500) rank = 'VETERAN';
      else if (postCount >= 200) rank = 'EXPERT';
      else if (postCount >= 100) rank = 'REGULAR';
      else if (postCount >= 50) rank = 'MEMBER';
      else if (postCount >= 10) rank = 'ACTIVE';
      
      // Process ghost mode - hide identity for non-mods
      const isGhost = entry.is_ghost === true;
      let displayEntry = { ...entry };
      
      if (isGhost && !isMod) {
        // Mask identity for regular users
        displayEntry.alias = entry.ghost_alias || 'GHOST';
        displayEntry.avatar_config = null;
        displayEntry.user_id = null;
        displayEntry.signature = null;
        displayEntry.reputation = null;
        displayEntry.custom_title = null;
        displayEntry.is_admin = false;
        displayEntry.role = null;
        displayEntry.post_count = null;
        rank = 'GHOST';
      } else if (isGhost && isMod) {
        // Mods can see real identity but also know it's a ghost post
        displayEntry.ghost_mode_visible = true; // Flag for mods to see it's a ghost post
      }
      
      // Check vault level access
      const vaultLevel = entry.vault_level;
      let canAccessVault = true;
      let isVaultLocked = false;
      
      if (vaultLevel !== null && vaultLevel > 0) {
        // Mods/admins can always see vault posts
        if (isMod) {
          canAccessVault = true;
        } else if (!userId) {
          // Not logged in - can't access vault
          canAccessVault = false;
        } else {
          // Check reputation requirement
          canAccessVault = userReputation >= vaultLevel;
        }
        isVaultLocked = !canAccessVault;
      }
      
      // If vault locked, hide content but show that it exists
      if (isVaultLocked) {
        displayEntry.content = null;
        displayEntry.vault_locked = true;
        displayEntry.vault_required = vaultLevel;
      }
      
      return {
        ...displayEntry,
        rank: rank,
        is_ghost: isGhost,
        mood: entry.mood,
        vault_level: vaultLevel,
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
        isPinned: thread.is_pinned || false,
        soundscape: thread.soundscape || null
      },
      entries: entriesWithReactions,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('[THREAD ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Valid soundscape options
const VALID_SOUNDSCAPES = ['rain', 'cafe', 'forest', 'ocean', 'fire', 'wind', 'thunder', 'night', 'static', 'void'];

// Create new thread
app.post('/api/threads', authMiddleware, ipBanMiddleware, userBanMiddleware, threadsLimiter, async (req, res) => {
  const { roomId, title, content, tags, soundscape } = req.body;
  const userId = req.user.userId;

  if (!roomId || !title || !content) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }
  
  // Validate soundscape if provided
  const validSoundscape = soundscape && VALID_SOUNDSCAPES.includes(soundscape) ? soundscape : null;

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

    // Create thread with optional soundscape
    const threadResult = await db.query(
      'INSERT INTO threads (room_id, title, user_id, soundscape) VALUES ($1, $2, $3, $4) RETURNING id',
      [roomDbId, filteredTitle, userId, validSoundscape]
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
  const { threadId, thread_id, content, alias, avatar_config, isGhost, vaultLevel } = req.body;
  const userId = req.user.userId;
  const userAlias = req.user.alias;
  
  // Support both threadId (new) and thread_id (legacy)
  const threadIdentifier = threadId || thread_id;

  if (!threadIdentifier || !content) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }
  
  // Validate vault level (optional: null = public, number = minimum reputation required)
  const parsedVaultLevel = vaultLevel ? parseInt(vaultLevel) : null;
  if (parsedVaultLevel !== null && (isNaN(parsedVaultLevel) || parsedVaultLevel < 0)) {
    return res.status(400).json({ success: false, error: 'invalid_vault_level' });
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
    
    // Check if user is shadow banned (user-level)
    const shadowCheck = await db.query(
      'SELECT is_shadow_banned FROM users WHERE id = $1',
      [userId]
    );
    const isShadowBanned = shadowCheck.rows[0]?.is_shadow_banned || false;
    
    // Apply word filter and XSS sanitization
    const filteredContent = sanitizeContent(await filterContent(content));
    
    // Generate ghost alias if posting as ghost
    const useGhostMode = isGhost === true;
    const ghostAlias = useGhostMode ? `GHOST-${crypto.randomBytes(2).toString('hex').toUpperCase()}` : null;

    const insertResult = await db.query(
      `INSERT INTO entries (thread_id, content, alias, avatar_config, user_id, ip_hash, shadow_banned, is_ghost, ghost_alias, vault_level)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id, thread_id AS "threadId", content, alias, avatar_config AS "avatarConfig", created_at AS "createdAt", user_id, is_ghost, ghost_alias, vault_level`,
      [threadDbId, filteredContent, entryAlias, avatar_config || null, userId, ipHash, isShadowBanned, useGhostMode, ghostAlias, parsedVaultLevel]
    );
    
    // For the response, use ghost alias if in ghost mode
    const displayAlias = useGhostMode ? ghostAlias : entryAlias;

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
          
          // Send real-time WebSocket notification
          notifyUserRealtime(mentionedUserId, {
            type: 'mention',
            title: notificationTitle,
            message: notificationPreview,
            link: notificationLink
          });
          
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
        
        // Send real-time WebSocket notification
        notifyUserRealtime(sub.user_id, {
          type: 'thread_reply',
          title: notificationTitle,
          message: notificationPreview,
          link: notificationLink
        });
        
        // Send email notification (non-blocking)
        sendNotificationEmail(sub.user_id, 'thread_reply', notificationTitle, notificationPreview, notificationLink);
      }
    } catch (subErr) {
      // Silent fail - subscription notifications should not break posting
      console.error('[SUBSCRIPTION NOTIFICATION ERROR]', subErr.message);
    }
    
    // Notify thread OP (if not the poster and not already subscribed)
    try {
      const threadOpResult = await db.query(
        'SELECT user_id, title FROM threads WHERE id = $1',
        [threadDbId]
      );
      const threadOp = threadOpResult.rows[0];
      
      if (threadOp && threadOp.user_id && threadOp.user_id !== userId) {
        // Check if OP is already subscribed (to avoid duplicate notification)
        const alreadySubscribed = await db.query(
          'SELECT 1 FROM thread_subscriptions WHERE thread_id = $1 AND user_id = $2',
          [threadDbId, threadOp.user_id]
        );
        
        if (alreadySubscribed.rows.length === 0) {
          const notificationTitle = `New reply in your thread "${(threadOp.title || '').substring(0, 50)}"`;
          const notificationPreview = `${entryAlias} posted: ${content.substring(0, 80)}${content.length > 80 ? '...' : ''}`;
          const notificationLink = `thread.html?id=${threadDbId}#entry-${entryId}`;
          
          await db.query(
            `INSERT INTO notifications (user_id, type, title, message, link, related_entry_id, related_user_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [threadOp.user_id, 'thread_reply', notificationTitle, notificationPreview, notificationLink, entryId, userId]
          );
          
          notifyUserRealtime(threadOp.user_id, {
            type: 'thread_reply',
            title: notificationTitle,
            message: notificationPreview,
            link: notificationLink
          });
          
          sendNotificationEmail(threadOp.user_id, 'thread_reply', notificationTitle, notificationPreview, notificationLink);
        }
      }
    } catch (opErr) {
      console.error('[THREAD OP NOTIFICATION ERROR]', opErr.message);
    }

    // Broadcast new post to all users viewing this thread via WebSocket
    notifyNewPost(threadDbId, {
      id: entryId,
      alias: displayAlias,
      content: content,
      created_at: insertResult.rows[0].created_at,
      is_ghost: useGhostMode
    });

    // Notify followers for live feed updates (non-blocking)
    notifyFollowersOfNewPost(userId, {
      id: entryId,
      alias: displayAlias,
      content: content.substring(0, 300),
      threadId: threadDbId,
      threadTitle: (await db.query('SELECT title FROM threads WHERE id = $1', [threadDbId])).rows[0]?.title || 'Thread',
      createdAt: insertResult.rows[0].created_at
    }).catch(() => {});

    // Check for badge achievements (async, non-blocking)
    checkAndAwardBadges(userId).catch(() => {});

    // Log engagement: Check if this thread has bot posts and log real user reply
    try {
      const botPostsInThread = await db.query(`
        SELECT DISTINCT bot_account_id FROM entries 
        WHERE thread_id = $1 AND bot_account_id IS NOT NULL
      `, [threadDbId]);
      
      // Log engagement for each bot that posted in this thread
      for (const row of botPostsInThread.rows) {
        if (row.bot_account_id) {
          logBotEngagement(row.bot_account_id, entryId, 'reply', userId).catch(() => {});
        }
      }
    } catch (engageErr) {
      // Silent fail - engagement logging is non-critical
    }

    // Return entry with display alias for ghost mode
    const entryResponse = {
      ...insertResult.rows[0],
      alias: displayAlias,
      is_ghost: useGhostMode
    };
    // Remove real alias from ghost posts for non-mod responses
    if (useGhostMode) {
      delete entryResponse.user_id;
    }

    res.json({ success: true, entry: entryResponse });
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

// Delete entry (only owner, admin, or mod can delete - regular users cannot delete anything)
app.delete('/api/entries/:id', authMiddleware, async (req, res) => {
  const entryId = parseInt(req.params.id);
  const userId = req.user.userId;

  try {
    // Get entry and check ownership, including the entry author's role
    const entryResult = await db.query(
      `SELECT e.id, e.user_id, u.role AS author_role 
       FROM entries e 
       LEFT JOIN users u ON u.id = e.user_id 
       WHERE e.id = $1`,
      [entryId]
    );

    if (entryResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'entry_not_found' });
    }

    const entry = entryResult.rows[0];
    const authorRole = entry.author_role || 'user';

    // Get current user's role
    const userResult = await db.query('SELECT is_admin, role FROM users WHERE id = $1', [userId]);
    const isAdmin = userResult.rows[0]?.is_admin || false;
    const userRole = userResult.rows[0]?.role || 'user';
    const isMod = userRole === 'moderator' || userRole === 'admin' || userRole === 'owner';

    // Only owner, admin, or moderator can delete posts
    // Regular users CANNOT delete anything, not even their own posts
    if (!isMod && !isAdmin) {
      return res.status(403).json({ success: false, error: 'not_authorized', message: 'Only moderators and above can delete posts' });
    }

    // Role hierarchy check: only owner can delete owner's posts
    if (authorRole === 'owner' && userRole !== 'owner') {
      return res.status(403).json({ success: false, error: 'cannot_delete_owner_posts', message: 'Only the owner can delete owner posts' });
    }
    
    // Admin posts can only be deleted by owner or admins
    if (authorRole === 'admin' && userRole !== 'owner' && userRole !== 'admin') {
      return res.status(403).json({ success: false, error: 'cannot_delete_admin_posts', message: 'Only owner or admins can delete admin posts' });
    }

    // Soft delete - mark as deleted instead of removing
    await db.query(
      'UPDATE entries SET is_deleted = TRUE, deleted_at = NOW(), deleted_by = $1 WHERE id = $2',
      [userId, entryId]
    );

    // Audit log
    await logAudit('delete_entry', 'entry', entryId, userId, { reason: 'mod_delete', author_role: authorRole, deleter_role: userRole });

    res.json({ success: true });
  } catch (err) {
    console.error('[DELETE ENTRY ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// POST REVISION HISTORY
// ========================================

// Get revision history for a post (accessible to all authenticated users)
app.get('/api/entries/:id/revisions', authMiddleware, async (req, res) => {
  const entryId = parseInt(req.params.id);
  const userId = req.user?.userId;
  
  try {
    // Check if user is staff (owner, admin, moderator)
    let isStaff = false;
    if (userId) {
      const staffCheck = await db.query('SELECT role FROM users WHERE id = $1', [userId]);
      if (staffCheck.rows.length > 0) {
        const role = staffCheck.rows[0].role;
        isStaff = role === 'owner' || role === 'admin' || role === 'moderator';
      }
    }
    
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
        editedBy: isStaff ? r.edited_by_alias : null // Only staff can see who edited
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
    
    // Notify user of badge award
    const badgeInfo = await db.query('SELECT name, description FROM badges WHERE id = $1', [badge_id]);
    if (badgeInfo.rows.length > 0) {
      const notificationTitle = 'Badge Awarded!';
      const notificationMessage = `An admin awarded you the "${badgeInfo.rows[0].name}" badge!`;
      
      await db.query(
        `INSERT INTO notifications (user_id, type, title, message, link)
         VALUES ($1, $2, $3, $4, $5)`,
        [user.rows[0].id, 'badge', notificationTitle, notificationMessage, 'profile.html']
      );
      
      notifyUserRealtime(user.rows[0].id, {
        type: 'badge',
        title: notificationTitle,
        message: notificationMessage,
        badgeName: badgeInfo.rows[0].name,
        link: 'profile.html'
      });
    }
    
    res.json({ success: true, message: 'Badge "' + badge.rows[0].name + '" awarded to ' + user.rows[0].alias });
  } catch (err) {
    console.error('Award badge error:', err);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// DYNAMIC EPITHETS
// ========================================

// Epithet definitions with their detection logic
const EPITHETS = [
  { name: 'THE NIGHT OWL', description: 'Posts primarily during late night hours' },
  { name: 'THE EARLY BIRD', description: 'Posts primarily during early morning hours' },
  { name: 'THE VERBOSE', description: 'Known for lengthy, detailed posts' },
  { name: 'THE CONCISE', description: 'Known for brief, to-the-point posts' },
  { name: 'THE ARCHIVIST', description: 'Revives old forgotten threads' },
  { name: 'THE PROVOCATEUR', description: 'Posts tend to generate controversy' },
  { name: 'THE DIPLOMAT', description: 'Posts rarely receive negative reactions' },
  { name: 'THE PHANTOM', description: 'Frequently posts anonymously' },
  { name: 'THE RAPID FIRE', description: 'Posts frequently in short bursts' },
  { name: 'THE LURKER', description: 'Reads more than they post' },
  { name: 'THE CRITIC', description: 'Often provides critical feedback' },
  { name: 'THE SUPPORTER', description: 'Frequently gives positive reactions' },
  { name: 'THE DEBATER', description: 'Engages in long discussion chains' },
  { name: 'THE ORIGINATOR', description: 'Creates more threads than replies' },
  { name: 'THE RESPONDER', description: 'Primarily replies to others' }
];

// Calculate and update epithet for a user
async function calculateUserEpithet(userId) {
  try {
    // Get user's posting behavior from last 30 days
    const stats = await db.query(`
      SELECT 
        -- Time of day analysis
        COUNT(*) FILTER (WHERE EXTRACT(HOUR FROM e.created_at) BETWEEN 0 AND 5) AS night_posts,
        COUNT(*) FILTER (WHERE EXTRACT(HOUR FROM e.created_at) BETWEEN 5 AND 9) AS early_posts,
        -- Content length
        AVG(LENGTH(e.content)) AS avg_length,
        -- Total posts
        COUNT(*) AS total_posts,
        -- Ghost mode usage
        COUNT(*) FILTER (WHERE e.is_ghost = TRUE) AS ghost_posts,
        -- Replies to old threads (>30 days old)
        COUNT(*) FILTER (WHERE e.created_at - t.created_at > INTERVAL '30 days') AS necro_posts
      FROM entries e
      JOIN threads t ON t.id = e.thread_id
      WHERE e.user_id = $1 
        AND e.created_at > NOW() - INTERVAL '30 days'
        AND e.is_deleted = FALSE
    `, [userId]);

    // Get reaction patterns
    const reactions = await db.query(`
      SELECT 
        COUNT(*) FILTER (WHERE r.reaction_type IN ('like', 'love', 'laugh')) AS positive_given,
        COUNT(*) FILTER (WHERE r.reaction_type IN ('angry', 'sad')) AS negative_given,
        COUNT(*) AS total_given
      FROM reactions r
      WHERE r.user_id = $1 
        AND r.created_at > NOW() - INTERVAL '30 days'
    `, [userId]);

    // Get vote patterns (votes received on their posts)
    const votes = await db.query(`
      SELECT 
        COALESCE(SUM(CASE WHEN v.vote_value > 0 THEN 1 ELSE 0 END), 0) AS upvotes_received,
        COALESCE(SUM(CASE WHEN v.vote_value < 0 THEN 1 ELSE 0 END), 0) AS downvotes_received
      FROM entry_votes v
      JOIN entries e ON e.id = v.entry_id
      WHERE e.user_id = $1 
        AND v.created_at > NOW() - INTERVAL '30 days'
    `, [userId]);

    // Get thread creation vs reply ratio
    const threadStats = await db.query(`
      SELECT 
        (SELECT COUNT(*) FROM threads WHERE user_id = $1 AND created_at > NOW() - INTERVAL '30 days') AS threads_created,
        (SELECT COUNT(*) FROM entries WHERE user_id = $1 AND created_at > NOW() - INTERVAL '30 days' AND is_deleted = FALSE) AS total_entries
    `, [userId]);

    const s = stats.rows[0];
    const r = reactions.rows[0];
    const v = votes.rows[0];
    const t = threadStats.rows[0];

    // Not enough data
    if (parseInt(s.total_posts) < 5) {
      return null;
    }

    // Calculate scores for each epithet
    const scores = [];
    const totalPosts = parseInt(s.total_posts);
    const avgLength = parseFloat(s.avg_length) || 0;
    const nightRatio = parseInt(s.night_posts) / totalPosts;
    const earlyRatio = parseInt(s.early_posts) / totalPosts;
    const ghostRatio = parseInt(s.ghost_posts) / totalPosts;
    const necroRatio = parseInt(s.necro_posts) / totalPosts;
    const upvotes = parseInt(v.upvotes_received) || 0;
    const downvotes = parseInt(v.downvotes_received) || 0;
    const totalVotes = upvotes + downvotes;
    const threadsCreated = parseInt(t.threads_created) || 0;
    const totalEntries = parseInt(t.total_entries) || 1;
    const positiveGiven = parseInt(r.positive_given) || 0;
    const totalReactionsGiven = parseInt(r.total_given) || 0;

    // Night Owl: 40%+ posts at night
    if (nightRatio >= 0.4) {
      scores.push({ epithet: 'THE NIGHT OWL', score: nightRatio * 100 });
    }

    // Early Bird: 40%+ posts early morning
    if (earlyRatio >= 0.4) {
      scores.push({ epithet: 'THE EARLY BIRD', score: earlyRatio * 100 });
    }

    // The Verbose: Average post length >400 chars
    if (avgLength > 400) {
      scores.push({ epithet: 'THE VERBOSE', score: Math.min(avgLength / 10, 100) });
    }

    // The Concise: Average post length <80 chars
    if (avgLength < 80 && avgLength > 0) {
      scores.push({ epithet: 'THE CONCISE', score: 100 - avgLength });
    }

    // The Archivist: 20%+ posts are necro posts
    if (necroRatio >= 0.2) {
      scores.push({ epithet: 'THE ARCHIVIST', score: necroRatio * 100 });
    }

    // The Phantom: 30%+ posts are ghost mode
    if (ghostRatio >= 0.3) {
      scores.push({ epithet: 'THE PHANTOM', score: ghostRatio * 100 });
    }

    // The Provocateur: High downvote ratio (>30% of votes are downvotes)
    if (totalVotes >= 10 && downvotes / totalVotes > 0.3) {
      scores.push({ epithet: 'THE PROVOCATEUR', score: (downvotes / totalVotes) * 100 });
    }

    // The Diplomat: Very low downvote ratio (<5% downvotes)
    if (totalVotes >= 10 && downvotes / totalVotes < 0.05) {
      scores.push({ epithet: 'THE DIPLOMAT', score: 100 - (downvotes / totalVotes) * 100 });
    }

    // The Supporter: Gives lots of positive reactions
    if (totalReactionsGiven >= 20 && positiveGiven / totalReactionsGiven > 0.8) {
      scores.push({ epithet: 'THE SUPPORTER', score: (positiveGiven / totalReactionsGiven) * 100 });
    }

    // The Originator: Creates more threads than avg (>30% of entries are thread starters)
    if (totalEntries >= 10 && threadsCreated / totalEntries > 0.3) {
      scores.push({ epithet: 'THE ORIGINATOR', score: (threadsCreated / totalEntries) * 100 });
    }

    // The Responder: Primarily replies (thread creation <5% of activity)
    if (totalEntries >= 20 && threadsCreated / totalEntries < 0.05) {
      scores.push({ epithet: 'THE RESPONDER', score: 100 - (threadsCreated / totalEntries) * 100 });
    }

    // Pick the highest scoring epithet
    if (scores.length === 0) {
      return null;
    }

    scores.sort((a, b) => b.score - a.score);
    const topEpithet = scores[0].epithet;

    // Update user's epithet
    await db.query(
      'UPDATE users SET epithet = $1, epithet_updated_at = NOW() WHERE id = $2',
      [topEpithet, userId]
    );

    return topEpithet;
  } catch (err) {
    console.error('[EPITHET ERROR]', err.message);
    return null;
  }
}

// Update epithets for all active users (run periodically)
async function updateAllEpithets() {
  try {
    console.log('[EPITHET] Starting batch epithet update...');
    
    // Get users who posted in last 30 days
    const activeUsers = await db.query(`
      SELECT DISTINCT user_id 
      FROM entries 
      WHERE created_at > NOW() - INTERVAL '30 days' 
        AND user_id IS NOT NULL
        AND is_deleted = FALSE
    `);

    let updated = 0;
    for (const row of activeUsers.rows) {
      const epithet = await calculateUserEpithet(row.user_id);
      if (epithet) updated++;
    }

    console.log(`[EPITHET] Updated epithets for ${updated}/${activeUsers.rows.length} users`);
  } catch (err) {
    console.error('[EPITHET BATCH ERROR]', err.message);
  }
}

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
        ) AS votes) AS max_post_votes,
        (SELECT EXISTS(
          SELECT 1 FROM entries 
          WHERE user_id = $1 AND is_deleted = FALSE 
          AND EXTRACT(HOUR FROM created_at) >= 2 
          AND EXTRACT(HOUR FROM created_at) < 5
        )) AS has_night_post`,
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
    
    // Helpful badges (upvotes on a single post)
    if (maxPostVotes >= 10) badgesToAward.push('helpful');
    if (maxPostVotes >= 50) badgesToAward.push('very-helpful');
    
    // Email verified
    if (s.email_verified) badgesToAward.push('verified-email');
    
    // 2FA enabled
    if (s.totp_enabled) badgesToAward.push('two-factor');
    
    // Night owl - posted between 2am and 5am
    if (s.has_night_post) badgesToAward.push('night-owl');
    
    // One year anniversary
    if (s.created_at) {
      const yearAgo = new Date();
      yearAgo.setFullYear(yearAgo.getFullYear() - 1);
      if (new Date(s.created_at) <= yearAgo) {
        badgesToAward.push('one-year');
      }
      
      // Early adopter - joined in the first month of the forum
      // Forum launch date - you can adjust this date
      const forumLaunchDate = new Date('2025-01-01');
      const firstMonthEnd = new Date(forumLaunchDate);
      firstMonthEnd.setMonth(firstMonthEnd.getMonth() + 1);
      if (new Date(s.created_at) <= firstMonthEnd) {
        badgesToAward.push('early-adopter');
      }
    }
    
    // Award badges
    for (const slug of badgesToAward) {
      const result = await db.query(
        `INSERT INTO user_badges (user_id, badge_id)
         SELECT $1, id FROM badges WHERE slug = $2
         ON CONFLICT (user_id, badge_id) DO NOTHING
         RETURNING badge_id`,
        [userId, slug]
      );
      
      // If badge was newly awarded (not a duplicate), send notification
      if (result.rows.length > 0) {
        const badgeInfo = await db.query(
          'SELECT name, description FROM badges WHERE slug = $1',
          [slug]
        );
        if (badgeInfo.rows.length > 0) {
          const badge = badgeInfo.rows[0];
          const notificationTitle = 'New Badge Earned!';
          const notificationMessage = `You earned the "${badge.name}" badge: ${badge.description}`;
          
          await db.query(
            `INSERT INTO notifications (user_id, type, title, message, link)
             VALUES ($1, $2, $3, $4, $5)`,
            [userId, 'badge', notificationTitle, notificationMessage, 'profile.html']
          );
          
          notifyUserRealtime(userId, {
            type: 'badge',
            title: notificationTitle,
            message: notificationMessage,
            badgeName: badge.name,
            link: 'profile.html'
          });
        }
      }
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

// Report severity weights for priority queue
const REPORT_SEVERITY = {
  'illegal': 100,
  'harassment': 80,
  'doxxing': 90,
  'threat': 85,
  'hate_speech': 75,
  'spam': 30,
  'misinformation': 50,
  'off_topic': 10,
  'other': 20
};

// Mod+: Get reports (sorted by severity priority)
app.get('/api/admin/reports', authMiddleware, modMiddleware, async (req, res) => {
  const status = req.query.status || 'pending';
  const sortBy = req.query.sort || 'priority'; // 'priority' or 'date'
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const offset = (page - 1) * limit;

  try {
    const countResult = await db.query(
      'SELECT COUNT(*) FROM reports WHERE status = $1',
      [status]
    );
    const total = parseInt(countResult.rows[0].count);

    // Build ORDER BY based on sort preference
    // Priority sorting: severity weight DESC, then report count on same entry, then date
    const orderClause = sortBy === 'priority' 
      ? `ORDER BY 
           CASE r.reason 
             WHEN 'illegal' THEN 100
             WHEN 'doxxing' THEN 90
             WHEN 'threat' THEN 85
             WHEN 'harassment' THEN 80
             WHEN 'hate_speech' THEN 75
             WHEN 'misinformation' THEN 50
             WHEN 'spam' THEN 30
             WHEN 'other' THEN 20
             WHEN 'off_topic' THEN 10
             ELSE 25
           END DESC,
           (SELECT COUNT(*) FROM reports r2 WHERE r2.entry_id = r.entry_id AND r2.status = 'pending') DESC,
           r.created_at ASC`
      : `ORDER BY r.created_at DESC`;

    const result = await db.query(
      `SELECT r.id, r.entry_id, r.reason, r.details, r.status, r.created_at,
              e.content AS entry_content, e.alias AS entry_alias,
              u.alias AS reporter_alias,
              (SELECT COUNT(*) FROM reports r2 WHERE r2.entry_id = r.entry_id AND r2.status = 'pending') AS report_count
       FROM reports r
       JOIN entries e ON e.id = r.entry_id
       JOIN users u ON u.id = r.reporter_id
       WHERE r.status = $1
       ${orderClause}
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

// Mod+: Resolve report
app.put('/api/admin/reports/:id', authMiddleware, modMiddleware, async (req, res) => {
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
      const notificationTitle = 'You have received a warning';
      await db.query(
        `INSERT INTO notifications (user_id, type, title, message) VALUES ($1, $2, $3, $4)`,
        [userId, 'warning', notificationTitle, reason]
      );
      
      // Send real-time WebSocket notification
      notifyUserRealtime(userId, {
        type: 'warning',
        title: notificationTitle,
        message: reason,
        urgent: true
      });
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
    const notificationTitle = days ? 'You have been temporarily banned' : 'You have been banned';
    const notificationMessage = reason || 'Contact admin for details';
    await db.query(
      `INSERT INTO notifications (user_id, type, title, message) VALUES ($1, $2, $3, $4)`,
      [userId, 'ban', notificationTitle, notificationMessage]
    );
    
    // Send real-time WebSocket notification
    notifyUserRealtime(userId, {
      type: 'ban',
      title: notificationTitle,
      message: notificationMessage,
      urgent: true,
      days: days || null
    });

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
    
    // Notify user they've been unbanned
    const notificationTitle = 'Your ban has been lifted';
    const notificationMessage = 'You can now access the forum again. Please follow the rules.';
    await db.query(
      `INSERT INTO notifications (user_id, type, title, message) VALUES ($1, $2, $3, $4)`,
      [userId, 'unban', notificationTitle, notificationMessage]
    );
    
    notifyUserRealtime(userId, {
      type: 'unban',
      title: notificationTitle,
      message: notificationMessage
    });
    
    await logAudit('unban_user', 'user', userId, adminId, null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Shadow ban user (all their new posts are automatically shadow banned)
app.post('/api/admin/users/:id/shadow-ban', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);
  const adminId = req.user.userId;
  const { shadowBanned } = req.body;

  if (typeof shadowBanned !== 'boolean') {
    return res.status(400).json({ success: false, error: 'invalid_value' });
  }

  try {
    await db.query(
      `UPDATE users SET is_shadow_banned = $1 WHERE id = $2`,
      [shadowBanned, userId]
    );

    await logAudit(
      shadowBanned ? 'shadow_ban_user' : 'unshadow_ban_user',
      'user',
      userId,
      adminId,
      { is_shadow_banned: shadowBanned }
    );

    res.json({ success: true, is_shadow_banned: shadowBanned });
  } catch (err) {
    console.error('[SHADOW BAN USER ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Owner/Admin: Set user role (owner can set admin, admin can set moderator)
app.post('/api/admin/users/:id/role', authMiddleware, adminMiddleware, async (req, res) => {
  const targetUserId = parseInt(req.params.id);
  const { role } = req.body;
  const adminId = req.user.userId;
  const adminRole = req.userRole;

  // Validate role
  if (!['user', 'moderator', 'admin'].includes(role)) {
    return res.status(400).json({ success: false, error: 'invalid_role' });
  }

  try {
    // Get target user's current role
    const targetResult = await db.query('SELECT role FROM users WHERE id = $1', [targetUserId]);
    if (targetResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const targetCurrentRole = targetResult.rows[0].role || 'user';

    // Permission checks:
    // - Only owner can promote/demote admins
    // - Admins can promote/demote moderators
    // - Can't change your own role
    // - Can't modify someone of equal or higher rank (unless owner)
    
    if (targetUserId === adminId) {
      return res.status(403).json({ success: false, error: 'cannot_change_own_role' });
    }

    if (role === 'admin' && adminRole !== 'owner') {
      return res.status(403).json({ success: false, error: 'only_owner_can_set_admin' });
    }

    if (targetCurrentRole === 'admin' && adminRole !== 'owner') {
      return res.status(403).json({ success: false, error: 'only_owner_can_modify_admin' });
    }

    if (targetCurrentRole === 'owner') {
      return res.status(403).json({ success: false, error: 'cannot_modify_owner' });
    }

    // Update role (also sync is_admin for backward compatibility)
    const isAdmin = role === 'admin' || role === 'owner';
    await db.query(
      'UPDATE users SET role = $1, is_admin = $2 WHERE id = $3',
      [role, isAdmin, targetUserId]
    );
    
    // Notify user of role change
    const roleLabels = {
      'owner': 'Owner',
      'admin': 'Admin',
      'moderator': 'Moderator',
      'user': 'User'
    };
    const isPromotion = ['admin', 'moderator', 'owner'].includes(role) && targetCurrentRole === 'user';
    const notificationTitle = isPromotion ? 'You have been promoted!' : 'Your role has changed';
    const notificationMessage = `Your role has been changed to ${roleLabels[role] || role}`;
    
    await db.query(
      `INSERT INTO notifications (user_id, type, title, message) VALUES ($1, $2, $3, $4)`,
      [targetUserId, 'role_change', notificationTitle, notificationMessage]
    );
    
    notifyUserRealtime(targetUserId, {
      type: 'role_change',
      title: notificationTitle,
      message: notificationMessage,
      newRole: role
    });

    await logAudit('change_role', 'user', targetUserId, adminId, { old_role: targetCurrentRole, new_role: role });
    res.json({ success: true, role });
  } catch (err) {
    console.error('[SET ROLE ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Owner: Export any user's data (GDPR compliance tool)
app.get('/api/admin/users/:alias/export', authMiddleware, ownerMiddleware, async (req, res) => {
  const { alias } = req.params;

  try {
    // Find user by alias
    const userLookup = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (userLookup.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const userId = userLookup.rows[0].id;

    // Fetch all user data
    const userResult = await db.query(
      `SELECT alias, bio, email, email_verified, notification_replies, notification_mentions, 
              notification_messages, reputation, created_at, last_seen_at, signature, role, is_banned, ban_reason
       FROM users WHERE id = $1`,
      [userId]
    );
    
    const userData = userResult.rows[0];
    
    // Fetch all posts by user
    const postsResult = await db.query(
      `SELECT e.content, e.created_at, e.edited_at, e.ip_hash, t.title AS thread_title, r.title AS room_title
       FROM entries e
       JOIN threads t ON t.id = e.thread_id
       JOIN rooms r ON r.id = t.room_id
       WHERE e.user_id = $1
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
       WHERE pm.sender_id = $1
       ORDER BY pm.created_at DESC`,
      [userId]
    );
    
    // Fetch private messages (received)
    const receivedMessagesResult = await db.query(
      `SELECT pm.subject, pm.content, pm.created_at, u.alias AS sender
       FROM private_messages pm
       JOIN users u ON u.id = pm.sender_id
       WHERE pm.recipient_id = $1
       ORDER BY pm.created_at DESC`,
      [userId]
    );
    
    // Fetch warnings
    const warningsResult = await db.query(
      `SELECT reason, created_at FROM user_warnings WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    
    // Fetch mod notes
    const notesResult = await db.query(
      `SELECT note, created_at FROM mod_notes WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    
    // Compile export data
    const exportData = {
      exported_at: new Date().toISOString(),
      exported_by: 'owner',
      profile: {
        alias: userData.alias,
        bio: userData.bio,
        email: userData.email,
        email_verified: userData.email_verified,
        signature: userData.signature,
        reputation: userData.reputation,
        role: userData.role,
        is_banned: userData.is_banned,
        ban_reason: userData.ban_reason,
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
        ip_hash: p.ip_hash,
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
      moderation: {
        warnings: warningsResult.rows,
        mod_notes: notesResult.rows
      }
    };
    
    await logAudit('export_user_data', 'user', userId, req.user.userId, { alias });
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${alias}_data_export.json"`);
    res.send(JSON.stringify(exportData, null, 2));
  } catch (err) {
    console.error('[OWNER EXPORT ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Get user details for moderation (mods can view, but limited info)
app.get('/api/admin/users/:id', authMiddleware, modMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);

  try {
    const userResult = await db.query(
      `SELECT id, alias, bio, is_admin, role, is_banned, ban_reason, ban_expires_at, is_shadow_banned, created_at, last_ip, last_ip_raw, last_seen_at
       FROM users WHERE id = $1`,
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }

    const user = userResult.rows[0];

    // Use last_ip from users table (updated on every authenticated request)
    // Fall back to most recent entry IP if users.last_ip is null
    let lastIp = user.last_ip;
    if (!lastIp) {
      const lastIpResult = await db.query(
        'SELECT ip_hash FROM entries WHERE user_id = $1 AND ip_hash IS NOT NULL ORDER BY created_at DESC LIMIT 1',
        [userId]
      );
      lastIp = lastIpResult.rows.length > 0 ? lastIpResult.rows[0].ip_hash : null;
    }

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

    // Build response - only owner can see raw IP
    const userResponse = {
      ...user,
      last_ip: lastIp,
      last_seen_at: user.last_seen_at,
      warning_count: parseInt(warningCount.rows[0].count),
      note_count: parseInt(noteCount.rows[0].count),
      recent_entries: recentEntries.rows
    };

    // Only include raw IP for owner
    if (req.user.role === 'owner') {
      userResponse.last_ip_raw = user.last_ip_raw;
    } else {
      delete userResponse.last_ip_raw;
    }

    res.json({
      success: true,
      user: userResponse
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Admin: Search users
app.get('/api/admin/users', authMiddleware, modMiddleware, async (req, res) => {
  const search = req.query.search || '';
  const filter = req.query.filter || 'all'; // all, banned, warned

  try {
    let query = `
      SELECT u.id, u.alias, u.is_admin, u.role, u.is_banned, u.is_shadow_banned, u.ban_expires_at, u.created_at,
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

    query += ` ORDER BY u.id ASC LIMIT 100`;

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
      'SELECT id, last_seen_at, is_bot FROM users WHERE alias = $1',
      [alias]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const user = result.rows[0];
    
    // For bots, check bot_accounts.is_online for accurate status
    if (user.is_bot) {
      const botResult = await db.query(
        `SELECT is_online, session_start FROM bot_accounts WHERE alias = $1`,
        [alias]
      );
      
      if (botResult.rows.length > 0 && botResult.rows[0].is_online) {
        // Bot is online - return session start as last_seen to show "Online now"
        return res.json({ 
          success: true, 
          last_seen_at: new Date(), // Current time = online now
          is_online: true 
        });
      } else {
        // Bot is offline - return last_seen or a recent time
        return res.json({ 
          success: true, 
          last_seen_at: user.last_seen_at || new Date(Date.now() - 30 * 60000), // 30 min ago if null
          is_online: false 
        });
      }
    }
    
    // For regular users, use last_seen_at
    res.json({ success: true, last_seen_at: user.last_seen_at });
  } catch (err) {
    console.error('[LAST-SEEN] Error:', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// WHO'S ONLINE
// ========================================

// Get users who were active in the last 5 minutes + online bots
app.get('/api/users/online', authMiddleware, async (req, res) => {
  try {
    // Also update the requesting user's last_seen_at (acts as implicit heartbeat)
    await db.query('UPDATE users SET last_seen_at = NOW() WHERE id = $1', [req.user.userId]);
    
    // Get real online users (non-bots active in last 5 mins)
    const result = await db.query(
      `SELECT alias, avatar_config, custom_title, role, is_bot,
              (SELECT COUNT(*) FROM entries WHERE user_id = users.id AND is_deleted = FALSE) as post_count
       FROM users 
       WHERE last_seen_at > NOW() - INTERVAL '5 minutes' AND is_bot = false
       ORDER BY last_seen_at DESC
       LIMIT 50`
    );
    
    // Calculate rank for each user (role takes priority)
    const onlineUsers = result.rows.map(u => {
      let rank = 'NEWCOMER';
      const postCount = parseInt(u.post_count);
      if (u.role === 'owner') rank = 'OWNER';
      else if (u.role === 'admin') rank = 'ADMIN';
      else if (u.role === 'moderator') rank = 'MODERATOR';
      else if (postCount >= 500) rank = 'VETERAN';
      else if (postCount >= 200) rank = 'EXPERT';
      else if (postCount >= 100) rank = 'REGULAR';
      else if (postCount >= 50) rank = 'MEMBER';
      else if (postCount >= 10) rank = 'ACTIVE';
      
      return {
        alias: u.alias,
        avatarConfig: u.avatar_config,
        customTitle: u.custom_title,
        rank: u.custom_title ? null : rank,
        isBot: false
      };
    });
    
    // Get ACTUALLY online bots from bot_accounts table
    const onlineBotsResult = await db.query(
      `SELECT ba.alias, u.avatar_config, u.custom_title,
              (SELECT COUNT(*) FROM entries WHERE user_id = u.id AND is_deleted = FALSE) as post_count
       FROM bot_accounts ba
       JOIN users u ON u.alias = ba.alias
       WHERE ba.is_online = TRUE
       ORDER BY ba.session_start DESC
       LIMIT 30`
    );
    
    // Format online bots
    const onlineBots = onlineBotsResult.rows.map(u => {
      let rank = 'MEMBER';
      const postCount = parseInt(u.post_count || 0);
      if (postCount >= 200) rank = 'EXPERT';
      else if (postCount >= 100) rank = 'REGULAR';
      else if (postCount >= 50) rank = 'MEMBER';
      else if (postCount >= 10) rank = 'ACTIVE';
      else rank = 'NEWCOMER';
      
      return {
        alias: u.alias,
        avatarConfig: u.avatar_config,
        customTitle: u.custom_title,
        rank: u.custom_title ? null : rank,
        isBot: true
      };
    });
    
    // Combine real users first, then bots
    const allOnline = [...onlineUsers, ...onlineBots];
    
    // Get counts
    const realOnlineCount = onlineUsers.length;
    const botOnlineCount = onlineBots.length;
    const totalOnline = realOnlineCount + botOnlineCount;
    
    res.json({ 
      success: true, 
      users: allOnline.slice(0, 50), // Cap at 50
      count: totalOnline,
      realCount: realOnlineCount,
      botCount: botOnlineCount
    });
  } catch (err) {
    console.error('[ONLINE USERS ERROR]', err);
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
    // Check if entry exists and get bot_account_id
    const entryResult = await db.query(
      'SELECT id, user_id, bot_account_id FROM entries WHERE id = $1 AND (is_deleted = FALSE OR is_deleted IS NULL)',
      [entryId]
    );
    if (entryResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'entry_not_found' });
    }

    const botAccountId = entryResult.rows[0].bot_account_id;

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

      // Log engagement if this is a bot post receiving a real user reaction
      if (botAccountId) {
        logBotEngagement(botAccountId, entryId, 'reaction', userId).catch(() => {});
      }

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
        
        const notificationTitle = `${reactorAlias} ${reaction_type === 'like' ? 'liked' : 'disliked'} your post`;
        const notificationLink = threadId ? `thread.html?id=${threadId}#entry-${entryId}` : null;

        await db.query(
          `INSERT INTO notifications (user_id, type, title, message, link, related_entry_id, related_user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [entryOwner, 'reaction', notificationTitle, 
           `${reaction_type.toUpperCase()} reaction`, 
           notificationLink,
           entryId, userId]
        );
        
        // Send real-time notification via WebSocket
        notifyUserRealtime(entryOwner, {
          type: 'reaction',
          title: notificationTitle,
          message: `${reaction_type.toUpperCase()} reaction`,
          fromAlias: reactorAlias,
          link: notificationLink
        });
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

// Get notifications since a timestamp (for missed notifications after reconnect)
app.get('/api/notifications/since', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const timestamp = parseInt(req.query.timestamp);

  if (!timestamp || isNaN(timestamp)) {
    return res.status(400).json({ success: false, error: 'invalid_timestamp' });
  }

  try {
    const sinceDate = new Date(timestamp);
    const result = await db.query(
      `SELECT id, title, message, link, created_at, is_read 
       FROM notifications 
       WHERE user_id = $1 AND created_at > $2
       ORDER BY created_at DESC
       LIMIT 50`,
      [userId, sinceDate]
    );

    res.json({ 
      success: true, 
      count: result.rows.length,
      notifications: result.rows 
    });
  } catch (err) {
    console.error('[NOTIFICATIONS SINCE ERROR]', err.message);
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
    const target = await db.query('SELECT id, alias FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const targetId = target.rows[0].id;
    const targetAlias = target.rows[0].alias;
    
    if (targetId === userId) {
      return res.status(400).json({ success: false, error: 'cannot_follow_self' });
    }

    // Toggle follow
    const existing = await db.query(
      'SELECT id FROM user_follows WHERE follower_id = $1 AND following_id = $2',
      [userId, targetId]
    );

    let isFollowing = false;
    if (existing.rows.length > 0) {
      await db.query('DELETE FROM user_follows WHERE id = $1', [existing.rows[0].id]);
      isFollowing = false;
    } else {
      await db.query(
        'INSERT INTO user_follows (follower_id, following_id) VALUES ($1, $2)',
        [userId, targetId]
      );
      isFollowing = true;
      
      // Create database notification for the target user
      const notificationTitle = 'New Follower';
      const notificationMessage = `${req.user.alias} started following you`;
      await db.query(
        `INSERT INTO notifications (user_id, type, title, message, link, related_user_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [targetId, 'new_follower', notificationTitle, notificationMessage, `profile.html?u=${req.user.alias}`, userId]
      );
      
      // Send real-time notification via WebSocket
      notifyUserRealtime(targetId, {
        type: 'new_follower',
        title: notificationTitle,
        message: notificationMessage,
        fromAlias: req.user.alias,
        link: `profile.html?u=${req.user.alias}`
      });
    }
    
    // Get updated counts for target user
    const targetFollowersCount = await db.query(
      'SELECT COUNT(*) FROM user_follows WHERE following_id = $1', [targetId]
    );
    const targetFollowingCount = await db.query(
      'SELECT COUNT(*) FROM user_follows WHERE follower_id = $1', [targetId]
    );
    
    // Get updated counts for current user
    const userFollowersCount = await db.query(
      'SELECT COUNT(*) FROM user_follows WHERE following_id = $1', [userId]
    );
    const userFollowingCount = await db.query(
      'SELECT COUNT(*) FROM user_follows WHERE follower_id = $1', [userId]
    );
    
    // Send real-time update to target user's profile viewers
    sendToUser(targetId, {
      type: 'followUpdate',
      alias: targetAlias,
      followersCount: parseInt(targetFollowersCount.rows[0].count),
      followingCount: parseInt(targetFollowingCount.rows[0].count)
    });
    
    // Also broadcast to anyone viewing this profile
    broadcast({
      type: 'profileFollowUpdate',
      alias: targetAlias,
      followersCount: parseInt(targetFollowersCount.rows[0].count),
      followingCount: parseInt(targetFollowingCount.rows[0].count)
    });

    res.json({ 
      success: true, 
      following: isFollowing, 
      action: isFollowing ? 'followed' : 'unfollowed',
      targetFollowersCount: parseInt(targetFollowersCount.rows[0].count),
      targetFollowingCount: parseInt(targetFollowingCount.rows[0].count),
      userFollowersCount: parseInt(userFollowersCount.rows[0].count),
      userFollowingCount: parseInt(userFollowingCount.rows[0].count)
    });
  } catch (err) {
    console.error('Follow error:', err);
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

// Get followers list for a user
app.get('/api/users/:alias/followers', authMiddleware, async (req, res) => {
  const { alias } = req.params;
  const viewerId = req.user.userId;

  try {
    const target = await db.query('SELECT id, followers_private FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const targetUser = target.rows[0];
    const isOwnProfile = targetUser.id === viewerId;
    
    // Check privacy setting
    if (targetUser.followers_private && !isOwnProfile) {
      return res.json({ success: true, followers: [], isPrivate: true });
    }
    
    const result = await db.query(
      `SELECT u.alias, u.avatar_config, uf.created_at
       FROM user_follows uf
       JOIN users u ON u.id = uf.follower_id
       WHERE uf.following_id = $1
       ORDER BY uf.created_at DESC
       LIMIT 100`,
      [targetUser.id]
    );
    res.json({ success: true, followers: result.rows, isPrivate: false });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get following list for a user
app.get('/api/users/:alias/following-list', authMiddleware, async (req, res) => {
  const { alias } = req.params;
  const viewerId = req.user.userId;

  try {
    const target = await db.query('SELECT id, following_private FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    
    const targetUser = target.rows[0];
    const isOwnProfile = targetUser.id === viewerId;
    
    // Check privacy setting for following list
    if (targetUser.following_private && !isOwnProfile) {
      return res.json({ success: true, following: [], isPrivate: true });
    }
    
    const result = await db.query(
      `SELECT u.alias, u.avatar_config, uf.created_at
       FROM user_follows uf
       JOIN users u ON u.id = uf.following_id
       WHERE uf.follower_id = $1
       ORDER BY uf.created_at DESC
       LIMIT 100`,
      [targetUser.id]
    );
    res.json({ success: true, following: result.rows, isPrivate: false });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ========================================
// USER-TO-USER REPUTATION
// ========================================

// Give +rep or -rep to a user
app.post('/api/users/:alias/rep', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { alias } = req.params;
  const { value, reason } = req.body;

  // Validate value
  if (value !== 1 && value !== -1) {
    return res.status(400).json({ success: false, error: 'invalid_value', message: 'Value must be 1 or -1' });
  }

  try {
    // Get target user
    const target = await db.query('SELECT id, reputation FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const targetId = target.rows[0].id;

    // Can't rep yourself
    if (targetId === userId) {
      return res.status(400).json({ success: false, error: 'cannot_rep_self', message: 'You cannot give rep to yourself' });
    }

    // Check for existing rep
    const existing = await db.query(
      'SELECT id, rep_value FROM user_rep WHERE from_user_id = $1 AND to_user_id = $2',
      [userId, targetId]
    );

    let action = '';
    let repChange = 0;

    if (existing.rows.length > 0) {
      const oldValue = existing.rows[0].rep_value;
      if (oldValue === value) {
        // Remove rep (toggle off)
        await db.query('DELETE FROM user_rep WHERE id = $1', [existing.rows[0].id]);
        repChange = -oldValue;
        action = 'removed';
      } else {
        // Change from +rep to -rep or vice versa
        await db.query(
          'UPDATE user_rep SET rep_value = $1, reason = $2, created_at = NOW() WHERE id = $3',
          [value, reason?.substring(0, 200) || null, existing.rows[0].id]
        );
        repChange = value - oldValue; // +2 or -2
        action = value === 1 ? 'changed_to_positive' : 'changed_to_negative';
      }
    } else {
      // New rep entry
      await db.query(
        'INSERT INTO user_rep (from_user_id, to_user_id, rep_value, reason) VALUES ($1, $2, $3, $4)',
        [userId, targetId, value, reason?.substring(0, 200) || null]
      );
      repChange = value;
      action = value === 1 ? 'positive' : 'negative';
    }

    // Update user's reputation count
    await db.query(
      'UPDATE users SET reputation = GREATEST(0, reputation + $1) WHERE id = $2',
      [repChange, targetId]
    );

    // Get updated rep
    const updatedRep = await db.query('SELECT reputation FROM users WHERE id = $1', [targetId]);
    
    // Create notification for positive/negative rep (not for removal)
    if (action === 'positive' || action === 'changed_to_positive') {
      const notificationTitle = 'Reputation Increased';
      const notificationMessage = `${req.user.alias} gave you +rep${reason ? ': ' + reason.substring(0, 50) : ''}`;
      
      await db.query(
        `INSERT INTO notifications (user_id, type, title, message, link, related_user_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [targetId, 'rep_positive', notificationTitle, notificationMessage, `profile.html?u=${req.user.alias}`, userId]
      );
      
      notifyUserRealtime(targetId, {
        type: 'rep_positive',
        title: notificationTitle,
        message: notificationMessage,
        fromAlias: req.user.alias,
        link: `profile.html?u=${req.user.alias}`,
        newReputation: updatedRep.rows[0].reputation
      });
    } else if (action === 'negative' || action === 'changed_to_negative') {
      const notificationTitle = 'Reputation Decreased';
      const notificationMessage = `${req.user.alias} gave you -rep${reason ? ': ' + reason.substring(0, 50) : ''}`;
      
      await db.query(
        `INSERT INTO notifications (user_id, type, title, message, link, related_user_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [targetId, 'rep_negative', notificationTitle, notificationMessage, `profile.html?u=${req.user.alias}`, userId]
      );
      
      notifyUserRealtime(targetId, {
        type: 'rep_negative',
        title: notificationTitle,
        message: notificationMessage,
        fromAlias: req.user.alias,
        link: `profile.html?u=${req.user.alias}`,
        newReputation: updatedRep.rows[0].reputation
      });
    }

    res.json({
      success: true,
      action,
      newReputation: updatedRep.rows[0].reputation
    });
  } catch (err) {
    console.error('[USER REP ERROR]', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get user's rep status (what rep current user gave them)
app.get('/api/users/:alias/rep', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { alias } = req.params;

  try {
    const target = await db.query('SELECT id, reputation FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const targetId = target.rows[0].id;

    const existing = await db.query(
      'SELECT rep_value FROM user_rep WHERE from_user_id = $1 AND to_user_id = $2',
      [userId, targetId]
    );

    res.json({
      success: true,
      givenRep: existing.rows.length > 0 ? existing.rows[0].rep_value : 0,
      totalReputation: target.rows[0].reputation
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Get user's rep history (who gave them rep)
app.get('/api/users/:alias/rep/history', authMiddleware, async (req, res) => {
  const { alias } = req.params;
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  try {
    const target = await db.query('SELECT id FROM users WHERE alias = $1', [alias]);
    if (target.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }
    const targetId = target.rows[0].id;

    const countResult = await db.query(
      'SELECT COUNT(*) FROM user_rep WHERE to_user_id = $1',
      [targetId]
    );
    const total = parseInt(countResult.rows[0].count);

    const result = await db.query(
      `SELECT ur.rep_value, ur.reason, ur.created_at, u.alias, u.avatar_config
       FROM user_rep ur
       JOIN users u ON u.id = ur.from_user_id
       WHERE ur.to_user_id = $1
       ORDER BY ur.created_at DESC
       LIMIT $2 OFFSET $3`,
      [targetId, limit, offset]
    );

    res.json({
      success: true,
      entries: result.rows.map(r => ({
        fromAlias: r.alias,
        fromAvatar: r.avatar_config,
        value: r.rep_value,
        reason: r.reason,
        createdAt: r.created_at
      })),
      pagination: {
        page,
        totalPages: Math.ceil(total / limit),
        total
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Toggle followers privacy setting
app.post('/api/my/followers-privacy', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { isPrivate } = req.body;

  try {
    await db.query('UPDATE users SET followers_private = $1 WHERE id = $2', [!!isPrivate, userId]);
    res.json({ success: true, followersPrivate: !!isPrivate });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Toggle following privacy setting
app.post('/api/my/following-privacy', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { isPrivate } = req.body;

  try {
    await db.query('UPDATE users SET following_private = $1 WHERE id = $2', [!!isPrivate, userId]);
    res.json({ success: true, followingPrivate: !!isPrivate });
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
         AND (t.is_deleted = FALSE OR t.is_deleted IS NULL)
       ORDER BY e.created_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    
    const countResult = await db.query(
      `SELECT COUNT(*) FROM entries e
       JOIN threads t ON t.id = e.thread_id
       WHERE e.user_id IN (SELECT following_id FROM user_follows WHERE follower_id = $1)
         AND (e.is_deleted = FALSE OR e.is_deleted IS NULL)
         AND (t.is_deleted = FALSE OR t.is_deleted IS NULL)`,
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
      res.json({ success: true, muted: false, action: 'unmuted' });
    } else {
      await db.query(
        'INSERT INTO muted_users (user_id, muted_user_id) VALUES ($1, $2)',
        [userId, targetId]
      );
      res.json({ success: true, muted: true, action: 'muted' });
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
    
    // Send real-time WebSocket notification
    notifyUserRealtime(recipientId, {
      type: 'private_message',
      title: notificationTitle,
      message: notificationPreview,
      link: 'messages.html',
      fromAlias: senderAlias
    });
    
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
app.get('/api/admin/entries/shadow-banned', authMiddleware, modMiddleware, async (req, res) => {
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
app.patch('/api/admin/entries/:id', authMiddleware, modMiddleware, async (req, res) => {
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

    // Delete all related records first (foreign key constraints)
    // Delete reactions on entries in this thread
    await db.query(`
      DELETE FROM reactions WHERE entry_id IN (SELECT id FROM entries WHERE thread_id = $1)
    `, [thread.id]);
    
    // Delete entry votes
    await db.query(`
      DELETE FROM entry_votes WHERE entry_id IN (SELECT id FROM entries WHERE thread_id = $1)
    `, [thread.id]);
    
    // Delete thread subscriptions
    await db.query('DELETE FROM thread_subscriptions WHERE thread_id = $1', [thread.id]);
    
    // Delete thread read tracking
    await db.query('DELETE FROM thread_reads WHERE thread_id = $1', [thread.id]);
    
    // Delete poll votes, options, and poll itself
    await db.query(`
      DELETE FROM poll_votes WHERE poll_id IN (SELECT id FROM polls WHERE thread_id = $1)
    `, [thread.id]);
    await db.query(`
      DELETE FROM poll_options WHERE poll_id IN (SELECT id FROM polls WHERE thread_id = $1)
    `, [thread.id]);
    await db.query('DELETE FROM polls WHERE thread_id = $1', [thread.id]);
    
    // Delete thread tags
    await db.query('DELETE FROM thread_tags WHERE thread_id = $1', [thread.id]);

    // Delete all entries in the thread
    await db.query('DELETE FROM entries WHERE thread_id = $1', [thread.id]);

    // Finally delete the thread itself
    await db.query('DELETE FROM threads WHERE id = $1', [thread.id]);

    await logAudit(
      'delete_thread',
      'thread',
      thread.id,
      req.user.userId,
      { title: thread.title }
    );

    console.log('[DELETE THREAD] Successfully deleted thread:', thread.id, thread.title);
    res.json({ success: true, message: 'Thread deleted' });
  } catch (err) {
    console.error('[DELETE THREAD ERROR]', err.message, err.stack);
    res.status(500).json({ success: false, error: 'server_error', details: err.message });
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
      'SELECT user_id, bot_account_id FROM entries WHERE id = $1 AND is_deleted = FALSE FOR UPDATE',
      [entryId]
    );
    
    if (entryResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'entry_not_found' });
    }
    
    const entryUserId = entryResult.rows[0].user_id;
    const botAccountId = entryResult.rows[0].bot_account_id;
    
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
    
    // Log engagement if this is a bot post receiving a real user vote
    if (botAccountId && vote !== 0) {
      const engagementType = vote > 0 ? 'upvote' : 'downvote';
      logBotEngagement(botAccountId, parseInt(entryId), engagementType, userId).catch(() => {});
    }
    
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
        role VARCHAR(20) DEFAULT 'user',
        is_shadow_banned BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Add columns if they don't exist
      ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';
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
        revoked BOOLEAN DEFAULT FALSE,
        ip_hash VARCHAR(64),
        user_agent TEXT,
        device_type VARCHAR(20) DEFAULT 'unknown',
        last_used_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
      
      -- Add new columns to refresh_tokens if they don't exist
      ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS ip_hash VARCHAR(64);
      ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS user_agent TEXT;
      ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS device_type VARCHAR(20) DEFAULT 'unknown';
      ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP DEFAULT NOW();
      
      -- Login attempts tracking table
      CREATE TABLE IF NOT EXISTS login_attempts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        ip_hash VARCHAR(64) NOT NULL,
        user_agent TEXT,
        success BOOLEAN NOT NULL,
        failure_reason VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_hash, created_at DESC);
      
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
      ALTER TABLE threads ADD COLUMN IF NOT EXISTS soundscape VARCHAR(50) DEFAULT NULL;
      
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
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS is_ghost BOOLEAN DEFAULT FALSE;
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS ghost_alias VARCHAR(20);
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS mood VARCHAR(20) DEFAULT 'neutral';
      ALTER TABLE entries ADD COLUMN IF NOT EXISTS vault_level INTEGER DEFAULT NULL;
      
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
      
      -- Add last IP hash (recorded on every authenticated request)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip TEXT;
      
      -- Add raw IP (only accessible to owner for abuse investigation)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip_raw TEXT;
      
      -- Add signature to users
      ALTER TABLE users ADD COLUMN IF NOT EXISTS signature VARCHAR(200);
      
      -- Add pin/lock columns to threads (in case they don't exist)
      ALTER TABLE threads ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT FALSE;
      ALTER TABLE threads ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN DEFAULT FALSE;
      
      -- Add reputation system columns
      ALTER TABLE users ADD COLUMN IF NOT EXISTS reputation INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS followers_private BOOLEAN DEFAULT FALSE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS following_private BOOLEAN DEFAULT FALSE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS post_count INTEGER DEFAULT 0;
      
      -- Add user custom title (admin-assignable)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS custom_title VARCHAR(50);
      
      -- Add dynamic epithet (auto-generated based on behavior)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS epithet VARCHAR(50);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS epithet_updated_at TIMESTAMP;
      
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
      
      -- Trusted devices for 2FA bypass
      CREATE TABLE IF NOT EXISTS trusted_devices (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) NOT NULL,
        ip_hash VARCHAR(255),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id);
      CREATE INDEX IF NOT EXISTS idx_trusted_devices_token ON trusted_devices(token_hash);
      
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
      
      -- User-to-user reputation system (+rep/-rep)
      CREATE TABLE IF NOT EXISTS user_rep (
        id SERIAL PRIMARY KEY,
        from_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        to_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        rep_value INTEGER NOT NULL CHECK (rep_value IN (-1, 1)),
        reason VARCHAR(200),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(from_user_id, to_user_id)
      );
      CREATE INDEX IF NOT EXISTS idx_user_rep_to ON user_rep(to_user_id);
      CREATE INDEX IF NOT EXISTS idx_user_rep_from ON user_rep(from_user_id);
      
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
        ('technology', 'Technology', 'Tech, programming, internet culture, and digital life', 41),
        ('off-topic', 'Off-Topic', 'Everything else', 99)
      ON CONFLICT (slug) DO UPDATE SET 
        description = EXCLUDED.description,
        display_order = EXCLUDED.display_order;
      
      -- Set first admin as owner (if no owner exists)
      -- You can also manually run: UPDATE users SET role = 'owner' WHERE alias = 'YOUR_USERNAME';
      UPDATE users SET role = 'owner' 
      WHERE id = (SELECT id FROM users WHERE is_admin = TRUE ORDER BY id LIMIT 1)
      AND NOT EXISTS (SELECT 1 FROM users WHERE role = 'owner');
      
      -- Sync role field for legacy admin accounts (is_admin = true but role is null/user)
      UPDATE users SET role = 'admin' 
      WHERE is_admin = TRUE AND (role IS NULL OR role = 'user') AND role != 'owner';
      
      -- Bot accounts table (must exist before ALTER statements)
      CREATE TABLE IF NOT EXISTS bot_accounts (
        id SERIAL PRIMARY KEY,
        persona VARCHAR(50) NOT NULL,
        alias VARCHAR(100) UNIQUE NOT NULL,
        avatar_config JSONB NOT NULL,
        bio TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        last_active TIMESTAMP DEFAULT NOW(),
        post_count INTEGER DEFAULT 0,
        thread_count INTEGER DEFAULT 0,
        timezone_offset INTEGER DEFAULT 0,
        peak_hours JSONB DEFAULT '[18,19,20,21,22,23]',
        activity_level VARCHAR(20) DEFAULT 'normal'
      );
      CREATE INDEX IF NOT EXISTS idx_bot_accounts_persona ON bot_accounts(persona);
      CREATE INDEX IF NOT EXISTS idx_bot_accounts_last_active ON bot_accounts(last_active);
      
      -- Bot personality columns (015)
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS writing_style JSONB DEFAULT '{}';
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS personality_traits JSONB DEFAULT '[]';
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS favorite_topics JSONB DEFAULT '[]';
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS age_range VARCHAR(20);
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS personality_description TEXT;
      
      -- Bot online status columns (014) 
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS is_online BOOLEAN DEFAULT FALSE;
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS next_status_change TIMESTAMP;
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS session_start TIMESTAMP;
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS avg_session_minutes INTEGER DEFAULT 60;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_online BOOLEAN DEFAULT FALSE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP;
      
      -- Bot quality scoring columns
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS quality_score DECIMAL(5,4) DEFAULT 0.5;
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS total_upvotes INTEGER DEFAULT 0;
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS total_downvotes INTEGER DEFAULT 0;
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS real_user_replies INTEGER DEFAULT 0;
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS real_user_reactions INTEGER DEFAULT 0;
      ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS last_quality_update TIMESTAMP;
      
      -- Bot engagement log table
      CREATE TABLE IF NOT EXISTS bot_engagement_log (
        id SERIAL PRIMARY KEY,
        bot_account_id INTEGER REFERENCES bot_accounts(id) ON DELETE CASCADE,
        entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
        engagement_type VARCHAR(20) NOT NULL,
        real_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_bot_engagement_bot ON bot_engagement_log(bot_account_id);
      CREATE INDEX IF NOT EXISTS idx_bot_engagement_entry ON bot_engagement_log(entry_id);
      
      -- Bot account voting support
      ALTER TABLE entry_votes ADD COLUMN IF NOT EXISTS bot_account_id INTEGER REFERENCES bot_accounts(id) ON DELETE CASCADE;
    `);
    console.log('[MIGRATE] Database tables ready');
  } catch (err) {
    console.error('[MIGRATE ERROR]', err.message);
  }
}

// ========================================
// PUBLIC API ENDPOINTS (NO AUTH REQUIRED)
// These endpoints allow Googlebot and other crawlers
// to access public forum content for indexing
// ========================================

// Public: Get all rooms (for forum.html SEO)
app.get('/api/public/rooms', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT r.id, r.slug, r.title, r.description,
             COUNT(DISTINCT t.id) AS thread_count,
             COUNT(DISTINCT e.id) AS post_count
      FROM rooms r
      LEFT JOIN threads t ON t.room_id = r.id
      LEFT JOIN entries e ON e.thread_id = t.id
      GROUP BY r.id
      ORDER BY r.id ASC
    `);
    
    res.json({ success: true, rooms: result.rows });
  } catch (err) {
    console.error('[PUBLIC API ERROR] /api/public/rooms:', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Public: Get threads in a room (for room.html SEO)
app.get('/api/public/rooms/:slug/threads', async (req, res) => {
  const { slug } = req.params;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const offset = (page - 1) * limit;
  
  try {
    // Get room info
    const roomResult = await db.query(
      'SELECT id, slug, title, description FROM rooms WHERE slug = $1',
      [slug]
    );
    
    if (roomResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'room_not_found' });
    }
    
    const room = roomResult.rows[0];
    
    // Get threads (simple query)
    const threadsResult = await db.query(`
      SELECT t.id, t.slug, t.title, t.created_at,
             (SELECT COUNT(*) FROM entries WHERE thread_id = t.id) AS reply_count,
             (SELECT MAX(created_at) FROM entries WHERE thread_id = t.id) AS last_activity
      FROM threads t
      WHERE t.room_id = $1
      ORDER BY t.created_at DESC
      LIMIT $2 OFFSET $3
    `, [room.id, limit, offset]);
    
    // Get total count
    const countResult = await db.query(
      'SELECT COUNT(*) FROM threads WHERE room_id = $1',
      [room.id]
    );
    
    res.json({
      success: true,
      room: room,
      threads: threadsResult.rows,
      total: parseInt(countResult.rows[0].count),
      page,
      limit
    });
  } catch (err) {
    console.error('[PUBLIC API ERROR] /api/public/rooms/:slug/threads:', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Public: Get thread content (for thread.html SEO)
app.get('/api/public/threads/:roomSlug/:threadSlug', async (req, res) => {
  const { roomSlug, threadSlug } = req.params;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const offset = (page - 1) * limit;
  
  try {
    // Get thread with room validation
    const threadResult = await db.query(`
      SELECT t.id, t.slug, t.title, t.created_at,
             r.slug AS room_slug, r.title AS room_title
      FROM threads t
      JOIN rooms r ON r.id = t.room_id
      WHERE r.slug = $1 AND t.slug = $2
    `, [roomSlug, threadSlug]);
    
    if (threadResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'thread_not_found' });
    }
    
    const thread = threadResult.rows[0];
    
    // Get entries/posts (public view)
    const entriesResult = await db.query(`
      SELECT e.id, e.content, e.created_at, e.alias,
             u.alias AS user_alias
      FROM entries e
      LEFT JOIN users u ON u.id = e.user_id
      WHERE e.thread_id = $1
      ORDER BY e.created_at ASC
      LIMIT $2 OFFSET $3
    `, [thread.id, limit, offset]);
    
    // Get total count
    const countResult = await db.query(
      'SELECT COUNT(*) FROM entries WHERE thread_id = $1',
      [thread.id]
    );
    
    res.json({
      success: true,
      thread: thread,
      entries: entriesResult.rows,
      total: parseInt(countResult.rows[0].count),
      page,
      limit
    });
  } catch (err) {
    console.error('[PUBLIC API ERROR] /api/public/threads:', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Public: Get recent activity (for activity.html SEO)
app.get('/api/public/activity', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  
  try {
    const result = await db.query(`
      SELECT e.id, e.content, e.created_at, e.alias,
             t.id AS thread_id, t.slug AS thread_slug, t.title AS thread_title,
             r.slug AS room_slug, r.title AS room_title
      FROM entries e
      JOIN threads t ON t.id = e.thread_id
      JOIN rooms r ON r.id = t.room_id
      ORDER BY e.created_at DESC
      LIMIT $1
    `, [limit]);
    
    res.json({ success: true, activity: result.rows });
  } catch (err) {
    console.error('[PUBLIC API ERROR] /api/public/activity:', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Public: Search (for search.html SEO - limited results)
app.get('/api/public/search', async (req, res) => {
  const query = req.query.q || '';
  const type = req.query.type || 'all';
  const limit = Math.min(parseInt(req.query.limit) || 10, 20);
  
  if (!query || query.length < 2) {
    return res.json({ success: true, results: [], total: 0 });
  }
  
  const searchPattern = '%' + query + '%';
  
  try {
    let results = [];
    
    if (type === 'all' || type === 'threads') {
      const threadResult = await db.query(`
        SELECT t.id, t.title, t.slug, t.created_at, 
               r.slug AS room_slug, r.title AS room_title,
               'thread' AS result_type
        FROM threads t
        JOIN rooms r ON r.id = t.room_id
        WHERE (t.title ILIKE $1 OR t.slug ILIKE $1)
        ORDER BY t.created_at DESC
        LIMIT $2
      `, [searchPattern, limit]);
      results = results.concat(threadResult.rows);
    }
    
    res.json({ success: true, results, query });
  } catch (err) {
    console.error('[PUBLIC API ERROR] /api/public/search:', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// Public: Generate dynamic sitemap entries
app.get('/api/public/sitemap', async (req, res) => {
  try {
    const baseUrl = 'https://www.aspdforum.com';
    
    // Get all public rooms
    const roomsResult = await db.query(`
      SELECT slug FROM rooms ORDER BY id ASC
    `);
    
    // Get all public threads (limit to recent 1000 for performance)
    const threadsResult = await db.query(`
      SELECT t.slug AS thread_slug, r.slug AS room_slug
      FROM threads t
      JOIN rooms r ON r.id = t.room_id
      ORDER BY t.created_at DESC
      LIMIT 1000
    `);
    
    const urls = [
      { loc: `${baseUrl}/`, priority: 1.0, changefreq: 'daily' },
      { loc: `${baseUrl}/forum.html`, priority: 0.9, changefreq: 'daily' },
      { loc: `${baseUrl}/activity.html`, priority: 0.7, changefreq: 'hourly' },
      { loc: `${baseUrl}/search.html`, priority: 0.6, changefreq: 'weekly' },
      { loc: `${baseUrl}/register.html`, priority: 0.8, changefreq: 'monthly' },
      { loc: `${baseUrl}/login.html`, priority: 0.5, changefreq: 'monthly' },
      { loc: `${baseUrl}/privacy.html`, priority: 0.3, changefreq: 'yearly' },
      { loc: `${baseUrl}/terms.html`, priority: 0.3, changefreq: 'yearly' }
    ];
    
    // Add room URLs
    for (const room of roomsResult.rows) {
      urls.push({
        loc: `${baseUrl}/room.html?room=${room.slug}`,
        priority: 0.8,
        changefreq: 'daily',
        lastmod: room.updated_at
      });
    }
    
    // Add thread URLs
    for (const thread of threadsResult.rows) {
      urls.push({
        loc: `${baseUrl}/thread.html?room=${thread.room_slug}&thread=${thread.thread_slug}`,
        priority: 0.6,
        changefreq: 'weekly',
        lastmod: thread.updated_at
      });
    }
    
    res.json({ success: true, urls });
  } catch (err) {
    console.error('[PUBLIC API ERROR] /api/public/sitemap:', err.message);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

// ================================================
// AI BOT SYSTEM - Owner Only
// ================================================

// Groq Configuration (Cloud AI - Free Tier: 14,400 req/day)
const GROQ_CONFIG = {
  enabled: process.env.GROQ_ENABLED === 'true' || !!process.env.GROQ_API_KEY,
  apiKey: process.env.GROQ_API_KEY || '',
  model: process.env.GROQ_MODEL || 'llama-3.3-70b-versatile',
  timeout: parseInt(process.env.GROQ_TIMEOUT) || 15000,
  fallbackToTemplates: process.env.GROQ_FALLBACK !== 'false', // Default true
  aiOnly: process.env.GROQ_AI_ONLY === 'true' || false // When true, skip templates entirely (may fail silently)
};

// Bot Scheduler Configuration
const BOT_SCHEDULER = {
  enabled: process.env.BOT_SCHEDULER_ENABLED === 'true' || false,
  minPostsPerDay: parseInt(process.env.BOT_MIN_POSTS) || 5,
  maxPostsPerDay: parseInt(process.env.BOT_MAX_POSTS) || 15,
  // Track daily activity
  postsToday: 0,
  lastReset: new Date().toDateString(),
  targetToday: 0,
  nextScheduledRun: null,
  isRunning: false,
  // New user simulation
  newUserChance: parseFloat(process.env.BOT_NEW_USER_CHANCE) || 0.1, // 10% chance per scheduler run
  newUsersToday: 0,
  maxNewUsersPerDay: parseInt(process.env.BOT_MAX_NEW_USERS) || 3
};

// Initialize daily target
function initializeDailyTarget() {
  const today = new Date().toDateString();
  if (BOT_SCHEDULER.lastReset !== today) {
    BOT_SCHEDULER.postsToday = 0;
    BOT_SCHEDULER.newUsersToday = 0;
    BOT_SCHEDULER.lastReset = today;
    BOT_SCHEDULER.targetToday = BOT_SCHEDULER.minPostsPerDay + 
      Math.floor(Math.random() * (BOT_SCHEDULER.maxPostsPerDay - BOT_SCHEDULER.minPostsPerDay + 1));
    console.log(`[BOT SCHEDULER] New day - target: ${BOT_SCHEDULER.targetToday} posts`);
  }
  return BOT_SCHEDULER.targetToday;
}

// Calculate next run time (spread posts throughout the day)
function scheduleNextBotRun() {
  if (!BOT_SCHEDULER.enabled) return null;
  
  initializeDailyTarget();
  
  const remainingPosts = BOT_SCHEDULER.targetToday - BOT_SCHEDULER.postsToday;
  if (remainingPosts <= 0) {
    BOT_SCHEDULER.nextScheduledRun = null;
    return null;
  }
  
  const now = new Date();
  const endOfDay = new Date(now);
  endOfDay.setHours(23, 59, 59, 999);
  
  const msRemaining = endOfDay - now;
  const avgInterval = msRemaining / remainingPosts;
  
  // Add randomness: 50% to 150% of average interval
  const randomMultiplier = 0.5 + Math.random();
  const nextInterval = Math.min(avgInterval * randomMultiplier, 4 * 60 * 60 * 1000); // Max 4 hours
  const minInterval = 10 * 60 * 1000; // Min 10 minutes
  
  const actualInterval = Math.max(nextInterval, minInterval);
  
  BOT_SCHEDULER.nextScheduledRun = new Date(now.getTime() + actualInterval);
  return BOT_SCHEDULER.nextScheduledRun;
}

// Run scheduled bot activity
async function runScheduledBotActivity() {
  if (!BOT_SCHEDULER.enabled || BOT_SCHEDULER.isRunning) return;
  
  initializeDailyTarget();
  
  // Check if we've hit the target for today
  if (BOT_SCHEDULER.postsToday >= BOT_SCHEDULER.targetToday) {
    scheduleNextBotRun();
    return;
  }
  
  // Check if it's a good time (respect time-based patterns)
  if (!isGoodTimeForActivity()) {
    // Still schedule next check, but skip this one
    scheduleNextBotRun();
    return;
  }
  
  BOT_SCHEDULER.isRunning = true;
  
  try {
    // Periodically update quality scores (every 10 posts)
    if (BOT_SCHEDULER.postsToday % 10 === 0 && BOT_SCHEDULER.postsToday > 0) {
      updateAllBotQualityScores().catch(() => {});
    }
    
    // Check if we should simulate a new user joining (10% chance per run, max 3/day)
    if (BOT_SCHEDULER.newUsersToday < BOT_SCHEDULER.maxNewUsersPerDay && 
        Math.random() < BOT_SCHEDULER.newUserChance) {
      const newUserResult = await simulateNewUserJoin();
      if (newUserResult.success) {
        BOT_SCHEDULER.postsToday++;
        console.log(`[BOT SCHEDULER] New user joined: ${newUserResult.alias} (${BOT_SCHEDULER.newUsersToday}/${BOT_SCHEDULER.maxNewUsersPerDay} today)`);
      }
    }
    
    // Create 1-3 posts per run
    const postsThisRun = 1 + Math.floor(Math.random() * 3);
    let created = 0;
    
    for (let i = 0; i < postsThisRun && BOT_SCHEDULER.postsToday < BOT_SCHEDULER.targetToday; i++) {
      // 20% chance of new thread, 80% reply
      if (Math.random() < 0.2) {
        const room = await getRandomRoom();
        if (room) {
          await createBotThread(room.id, null, { usePersistentAccount: true, useQualityWeighting: true });
          created++;
          BOT_SCHEDULER.postsToday++;
        }
      } else {
        const thread = await getRandomThread();
        if (thread) {
          await createBotReply(thread.id, null, { 
            usePersistentAccount: true, 
            allowDisagreement: true,
            doVoting: true,
            useQualityWeighting: true
          });
          created++;
          BOT_SCHEDULER.postsToday++;
        }
      }
      
      // Small delay between posts
      await new Promise(r => setTimeout(r, 2000 + Math.random() * 3000));
    }
    
    if (created > 0) {
      console.log(`[BOT SCHEDULER] Created ${created} posts (${BOT_SCHEDULER.postsToday}/${BOT_SCHEDULER.targetToday} today)`);
    }
  } catch (err) {
    console.error('[BOT SCHEDULER] Error:', err.message);
  } finally {
    BOT_SCHEDULER.isRunning = false;
    scheduleNextBotRun();
  }
}

// Bot scheduler loop (checks every 5 minutes)
let botSchedulerInterval = null;
let botOnlineStatusInterval = null;

function startBotScheduler() {
  if (botSchedulerInterval) return;
  
  console.log('[BOT SCHEDULER] Starting automated bot activity');
  initializeDailyTarget();
  scheduleNextBotRun();
  
  // Initialize bot online statuses
  updateBotOnlineStatuses().catch(err => console.error('[BOT ONLINE]', err.message));
  
  botSchedulerInterval = setInterval(async () => {
    if (!BOT_SCHEDULER.enabled) return;
    
    const now = new Date();
    
    // Update bot online/offline statuses (runs every interval)
    try {
      await updateBotOnlineStatuses();
    } catch (err) {
      console.error('[BOT ONLINE]', err.message);
    }
    
    // Simulate lurking activity every interval (bots browsing without posting)
    try {
      await simulateBotLurking();
    } catch (err) {
      console.error('[BOT LURK]', err.message);
    }
    
    if (BOT_SCHEDULER.nextScheduledRun && now >= BOT_SCHEDULER.nextScheduledRun) {
      await runScheduledBotActivity();
    }
  }, 2 * 60 * 1000); // Check every 2 minutes for more activity
  
  // Fast status check for realistic online count fluctuation (every 30-60 seconds)
  botOnlineStatusInterval = setInterval(async () => {
    try {
      await updateBotOnlineStatuses();
    } catch (err) {
      // Silent fail for status checks
    }
  }, 30000 + Math.random() * 30000); // 30-60 seconds
}

function stopBotScheduler() {
  if (botSchedulerInterval) {
    clearInterval(botSchedulerInterval);
    botSchedulerInterval = null;
    console.log('[BOT SCHEDULER] Stopped');
  }
  if (botOnlineStatusInterval) {
    clearInterval(botOnlineStatusInterval);
    botOnlineStatusInterval = null;
  }
}

// =====================================================
// BOT ONLINE/OFFLINE STATUS SIMULATION
// =====================================================

// Update bot online statuses based on their scheduled change times
async function updateBotOnlineStatuses() {
  const now = new Date();
  
  try {
    // First, ensure all bots have next_status_change set
    // If it's NULL, set it to past so they get updated now
    await db.query(`
      UPDATE bot_accounts 
      SET next_status_change = NOW() - INTERVAL '1 minute'
      WHERE next_status_change IS NULL
    `);
    
    // Get bots whose status should change
    const botsToUpdate = await db.query(`
      SELECT id, alias, is_online, activity_level, avg_session_minutes, peak_hours
      FROM bot_accounts 
      WHERE next_status_change <= $1
    `, [now]);
    
    for (const bot of botsToUpdate.rows) {
      const currentHour = now.getUTCHours();
      const peakHours = typeof bot.peak_hours === 'string' ? JSON.parse(bot.peak_hours) : (bot.peak_hours || []);
      const isInPeakHours = peakHours.includes(currentHour);
      
      // Determine new online status
      let newOnlineStatus;
      let sessionDuration;
      
      if (bot.is_online) {
        // Currently online - should they go offline?
        // Shorter sessions feel more realistic
        const stayOnlineChance = isInPeakHours ? 0.35 : 0.15;
        newOnlineStatus = Math.random() < stayOnlineChance;
        
        // Short sessions - people browse, then leave
        if (newOnlineStatus) {
          sessionDuration = 1 + Math.random() * 4; // 1-5 more minutes
        } else {
          sessionDuration = 5 + Math.random() * 30; // 5-35 min offline (shorter breaks)
        }
      } else {
        // Currently offline - should they come online?
        // Higher base chances for more activity
        let comeOnlineChance = 0.25; // Base 25%
        
        if (bot.activity_level === 'very_active') comeOnlineChance = 0.55;
        else if (bot.activity_level === 'active') comeOnlineChance = 0.40;
        else if (bot.activity_level === 'normal') comeOnlineChance = 0.28;
        else if (bot.activity_level === 'lurker') comeOnlineChance = 0.12;
        
        // Peak hours boost
        if (isInPeakHours) comeOnlineChance *= 1.5;
        
        // Late night reduction (2am-7am UTC) but not as harsh
        if (currentHour >= 2 && currentHour <= 7) comeOnlineChance *= 0.4;
        
        newOnlineStatus = Math.random() < comeOnlineChance;
        
        if (newOnlineStatus) {
          // Coming online - realistic browse sessions (2-12 minutes)
          sessionDuration = 2 + Math.random() * 10;
        } else {
          // Staying offline - check again soon for more churn
          sessionDuration = 3 + Math.random() * 15; // 3-18 minutes
        }
      }
      
      const nextChange = new Date(now.getTime() + sessionDuration * 60000);
      
      // Update bot_accounts
      await db.query(`
        UPDATE bot_accounts 
        SET is_online = $1, 
            next_status_change = $2,
            session_start = CASE WHEN $1 = TRUE AND is_online = FALSE THEN NOW() ELSE session_start END,
            last_active = CASE WHEN $1 = TRUE THEN NOW() ELSE last_active END
        WHERE id = $3
      `, [newOnlineStatus, nextChange, bot.id]);
      
      // Also update users table for profile display
      await db.query(`
        UPDATE users SET is_online = $1, last_seen = NOW()
        WHERE alias = $2 AND is_bot = TRUE
      `, [newOnlineStatus, bot.alias]);
    }
    
    return { updated: botsToUpdate.rows.length };
  } catch (err) {
    console.error('[BOT ONLINE STATUS ERROR]', err.message);
    return { updated: 0 };
  }
}

// Get count of currently online bots
async function getOnlineBotCount() {
  const result = await db.query(`SELECT COUNT(*) FROM bot_accounts WHERE is_online = TRUE`);
  return parseInt(result.rows[0].count) || 0;
}

// Force a specific bot online/offline
async function setBotOnlineStatus(botId, isOnline, durationMinutes = null) {
  const duration = durationMinutes || (isOnline ? 5 + Math.random() * 15 : 30 + Math.random() * 90);
  const nextChange = new Date(Date.now() + duration * 60000);
  
  await db.query(`
    UPDATE bot_accounts 
    SET is_online = $1, next_status_change = $2, session_start = CASE WHEN $1 THEN NOW() ELSE NULL END
    WHERE id = $3
    RETURNING alias
  `, [isOnline, nextChange, botId]);
  
  // Sync to users table
  const botResult = await db.query(`SELECT alias FROM bot_accounts WHERE id = $1`, [botId]);
  if (botResult.rows.length > 0) {
    await db.query(`UPDATE users SET is_online = $1, last_seen = NOW() WHERE alias = $2 AND is_bot = TRUE`, 
      [isOnline, botResult.rows[0].alias]);
  }
}

// Test Groq connection
async function testGroqConnection() {
  if (!GROQ_CONFIG.apiKey) return { available: false, reason: 'no_api_key' };
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch('https://api.groq.com/openai/v1/models', {
      headers: { 'Authorization': `Bearer ${GROQ_CONFIG.apiKey}` },
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    
    if (response.ok) {
      const data = await response.json();
      const models = data.data?.map(m => m.id) || [];
      return { 
        available: true, 
        models,
        configuredModel: GROQ_CONFIG.model
      };
    }
    if (response.status === 401) {
      return { available: false, reason: 'invalid_api_key' };
    }
    return { available: false, reason: `http_${response.status}` };
  } catch (err) {
    return { available: false, reason: err.message };
  }
}

// Generate content using Groq
async function generateWithGroq(persona, context, type = 'reply') {
  if (!GROQ_CONFIG.enabled || !GROQ_CONFIG.apiKey) {
    return null;
  }
  
  const p = BOT_PERSONAS[persona] || BOT_PERSONAS.analytical;
  
  // Get seasonal context for prompts
  const seasonalContext = getSeasonalContext();
  let seasonalHint = '';
  if (seasonalContext.holidays.length > 0) {
    seasonalHint = `\n- It's currently ${seasonalContext.holidays[0].label} - you may reference this if relevant`;
  } else if (seasonalContext.events.includes('year_end_reflection')) {
    seasonalHint = '\n- It\'s the end of the year - you may reference reflecting on the year if relevant';
  } else if (seasonalContext.season) {
    seasonalHint = `\n- It's ${seasonalContext.season} - seasonal references are okay if natural`;
  }
  
  // Build the prompt
  const systemPrompt = `You are roleplaying as an anonymous user on an online forum for people with Antisocial Personality Disorder (ASPD). 

Your persona: ${p.name}
Writing style: ${p.style}
Personality traits: ${p.traits.join(', ')}

CRITICAL RULES:
- Write ONLY the forum post content, nothing else
- No greetings like "Hey" or "Hi everyone"  
- No signatures or sign-offs
- Use lowercase, casual internet writing style
- Keep responses between 1-4 sentences typically
- Occasionally use common typos, abbreviations (tbh, idk, ngl, lol)
- Sound like a real person, not an AI
- Reference ASPD experiences authentically but not dramatically
- Never break character or mention being an AI
- Match the tone of the forum (anonymous, supportive but blunt)${seasonalHint}`;

  let userPrompt = '';
  
  if (type === 'reply' && context) {
    userPrompt = `Thread title: "${context.title || 'General Discussion'}"
Room: ${context.room || 'General'}

Recent posts in thread:
${context.recentPosts?.slice(0, 3).map(p => `- "${p.content?.substring(0, 150)}..."`).join('\n') || 'No previous posts'}

Write a reply to this thread as your persona. Be authentic and conversational.`;
  } else if (type === 'thread') {
    userPrompt = `Room: ${context?.room || 'General Discussion'}

Create a new thread post for this room. Write something that would spark discussion - a question, observation, or experience related to ASPD. Include a sense of what the thread title might be about in your opening post.`;
  } else {
    userPrompt = `Write a general forum post about living with ASPD. Could be an observation, question, or sharing an experience.`;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), GROQ_CONFIG.timeout);
    
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_CONFIG.apiKey}`
      },
      signal: controller.signal,
      body: JSON.stringify({
        model: GROQ_CONFIG.model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.8,
        max_tokens: 300,
        top_p: 0.9
      })
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      console.error('[GROQ] Bad response:', response.status);
      return null;
    }
    
    const data = await response.json();
    let content = data.choices?.[0]?.message?.content?.trim();
    
    if (!content) {
      return null;
    }
    
    // Clean up the response
    content = content
      .replace(/^["']|["']$/g, '') // Remove wrapping quotes
      .replace(/^(Hey|Hi|Hello)[\s,!]+/i, '') // Remove greetings
      .replace(/\n{3,}/g, '\n\n') // Normalize line breaks
      .trim();
    
    // Validate content
    if (content.length < 10 || content.length > 2000) {
      console.error('[GROQ] Content length invalid:', content.length);
      return null;
    }
    
    console.log('[GROQ] Generated:', content.substring(0, 80) + '...');
    return content;
    
  } catch (err) {
    console.error('[GROQ] Error:', err.message);
    return null;
  }
}

// ==============================================
// CONTENT SIMILARITY CHECK
// ==============================================
// Checks if generated content is too similar to original post

function checkContentSimilarity(original, generated) {
  if (!original || !generated) return false;
  
  // Normalize both strings
  const normalizeText = (text) => text.toLowerCase()
    .replace(/[^\w\s]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  
  const origNorm = normalizeText(original);
  const genNorm = normalizeText(generated);
  
  // Check for exact substring matches (excluding short common phrases)
  const origWords = origNorm.split(' ');
  const genWords = genNorm.split(' ');
  
  // Check for long phrase duplication (5+ consecutive words)
  for (let i = 0; i <= origWords.length - 5; i++) {
    const phrase = origWords.slice(i, i + 5).join(' ');
    if (phrase.length > 20 && genNorm.includes(phrase)) {
      console.log('[SIMILARITY] Found duplicate phrase:', phrase);
      return true;
    }
  }
  
  // Check word overlap percentage
  const origSet = new Set(origWords.filter(w => w.length > 3));
  const genSet = new Set(genWords.filter(w => w.length > 3));
  
  if (origSet.size === 0 || genSet.size === 0) return false;
  
  let overlapCount = 0;
  for (const word of genSet) {
    if (origSet.has(word)) overlapCount++;
  }
  
  const overlapRatio = overlapCount / Math.min(origSet.size, genSet.size);
  
  // If more than 60% of significant words overlap, it's too similar
  if (overlapRatio > 0.6) {
    console.log('[SIMILARITY] High word overlap:', (overlapRatio * 100).toFixed(1) + '%');
    return true;
  }
  
  return false;
}

// ==============================================
// QUALITY CHECK FOR GENERIC/FILLER CONTENT
// ==============================================
// Detects and rejects lazy, generic, low-effort responses

function checkIsGenericFiller(content) {
  if (!content) return false;
  
  const lowerContent = content.toLowerCase();
  
  // List of banned filler phrases - any match = rejection
  const bannedPhrases = [
    // Meta-commentary about the discussion
    'seen variations of this',
    'seen this before',
    'seen this discussion',
    'this comes up',
    'this topic comes up',
    'common discussion',
    'common topic',
    
    // Lazy validation
    'always valuable',
    'always interesting',
    'always worth',
    'valid point',
    'fair point',
    'good point',
    'interesting point',
    
    // Vague process statements
    'still working on it',
    'working through it',
    'working on that',
    'figuring it out',
    'taking it day by day',
    
    // Lazy dismissals
    'you get the idea',
    'if that makes sense',
    'you know what i mean',
    'hard to explain',
    'cant put it into words',
    'the nuance gets lost',
    
    // Time-based filler
    'over the years',
    'through the years',
    'as time goes on',
    'as i get older',
    
    // Generic agreement without substance
    'this resonates',
    'i relate to this',
    'same here basically',
    'been there',
    'felt that',
    'get that',
    'i feel you',
    'totally get it',
    
    // Cop-out phrases
    'its complicated',
    'its complex',
    'depends on the situation',
    'to each their own',
    'whatever works',
    'different for everyone',
    'everyone is different',
    
    // Empty acknowledgments  
    'thats real',
    'thats true',
    'thats valid',
    'cant argue with that',
    
    // Non-committal hedging
    'in a way',
    'sort of',
    'kind of',
    'in some ways'
  ];
  
  for (const phrase of bannedPhrases) {
    if (lowerContent.includes(phrase)) {
      console.log('[QUALITY] Rejected for banned filler phrase:', phrase);
      return true;
    }
  }
  
  // Check if response is too short and lacks specificity
  const words = content.split(/\s+/).filter(w => w.length > 0);
  if (words.length < 10) {
    // Very short responses need to have SOME specific content
    const hasSpecific = /\b(yesterday|today|last week|this morning|at work|my boss|my therapist|my gf|my bf|my wife|my husband|my coworker|[0-9]+ (year|month|week|day|hour|minute))/i.test(content);
    if (!hasSpecific) {
      console.log('[QUALITY] Rejected: too short with no specifics');
      return true;
    }
  }
  
  // Check for patterns that indicate empty agreement
  const emptyAgreementPatterns = [
    /^(yeah|yep|yup|true|same|this|mood|real|felt|facts?)\s*\.?\s*$/i,
    /^(totally|completely|absolutely|exactly)\s+(agree|this|same)\.?\s*$/i
  ];
  
  for (const pattern of emptyAgreementPatterns) {
    if (pattern.test(content.trim())) {
      console.log('[QUALITY] Rejected: empty agreement pattern');
      return true;
    }
  }
  
  return false;
}

// ==============================================
// UNIFIED AI CONTENT GENERATION
// ==============================================
// This function handles ALL bot content types via Groq

async function generateAIContent(options = {}) {
  const {
    persona = 'analytical',
    type = 'reply', // 'reply', 'thread', 'intro', 'disagreement', 'continuation'
    context = {},
    temperature = 0.9, // Increased for more variety
    botAccount = null  // Pass the full bot account for personality traits
  } = options;
  
  if (!GROQ_CONFIG.enabled || !GROQ_CONFIG.apiKey) {
    return null;
  }
  
  const p = BOT_PERSONAS[persona] || BOT_PERSONAS.analytical;
  const seasonalContext = getSeasonalContext();
  
  // Build seasonal hint
  let seasonalHint = '';
  if (seasonalContext.holidays.length > 0) {
    seasonalHint = `\nContext: It's currently ${seasonalContext.holidays[0].label}. You may briefly reference this if natural.`;
  } else if (seasonalContext.events.includes('year_end_reflection')) {
    seasonalHint = '\nContext: It\'s the end of the year. Reflecting on the year is natural right now.';
  } else if (seasonalContext.season) {
    seasonalHint = `\nContext: It's ${seasonalContext.season}. Seasonal references are okay if they fit naturally.`;
  }
  
  // Build personality hints from bot account
  let personalityHints = '';
  let uniquePersonality = '';
  
  if (botAccount) {
    const ws = botAccount.writing_style || {};
    const age = botAccount.age_range;
    const topics = botAccount.favorite_topics || [];
    
    // Use the AI-generated unique personality description if available
    if (botAccount.personality_description) {
      uniquePersonality = `\n\nYOUR UNIQUE PERSONALITY (stay in character):\n${botAccount.personality_description}`;
    }
    
    // Writing style instructions
    if (ws.abbreviation_level === 'high') {
      personalityHints += '\n- Use lots of abbreviations (tbh, idk, ngl, rn, imo, iirc, smh)';
    } else if (ws.abbreviation_level === 'low') {
      personalityHints += '\n- Rarely use abbreviations, spell things out';
    }
    
    if (ws.punctuation === 'minimal') {
      personalityHints += '\n- Minimal punctuation (no periods at end of sentences)';
    } else if (ws.punctuation === 'proper') {
      personalityHints += '\n- Use proper punctuation';
    }
    
    if (ws.capitalization === 'none') {
      personalityHints += '\n- All lowercase, never capitalize';
    } else if (ws.capitalization === 'proper') {
      personalityHints += '\n- Use proper capitalization';
    }
    
    if (ws.response_length === 'brief') {
      personalityHints += '\n- Keep responses very short (1-2 sentences max)';
    } else if (ws.response_length === 'verbose') {
      personalityHints += '\n- Can write longer responses when you have something to say (3-5 sentences)';
    }
    
    if (age) {
      personalityHints += `\n- You're in your ${age}, reflect this in your perspective`;
    }
    
    if (topics.length > 0) {
      personalityHints += `\n- Topics you connect with: ${topics.join(', ')}`;
    }
  }
  
  // Base system prompt for all content types
  const baseSystemPrompt = `You are roleplaying as a real person with ASPD posting on an online forum.

Your persona: ${p.name}
Writing style: ${p.style}
Personality traits: ${p.traits.join(', ')}

═══════════════════════════════════════
HOW REAL PEOPLE WITH ASPD COMMUNICATE (from actual r/aspd posts):
═══════════════════════════════════════
- Transactional worldview: people are useful, potentially useful, or not useful
- Brutally honest: "i dont really care that much" is normal
- Self-aware but not apologetic: describe patterns analytically, not emotionally
- Pragmatic about relationships: "masking is draining" "emotional support is exhausting"
- Matter-of-fact about heavy topics: detached where neurotypicals would be upset
- Boredom is a core struggle: need stimulation, easily understimulated
- Dark humor but not self-pitying
- Casually mention manipulation, using people, lack of empathy
- Clinical about their condition: "diagnosed aspd" "im somewhat nihilistic"
- Cost-benefit framing: "worth it" "not worth the effort"
- Blunt about not understanding others' emotional reactions

═══════════════════════════════════════
AUTHENTICITY MARKERS (use 2-3):
═══════════════════════════════════════
- Abbreviations: tbh, idk, ngl, imo, lol, lmao
- Trailing closers: "but idk", "whatever", "anyway"
- Parenthetical asides like (not that i care) or (typical)
- Casual swearing: shit, damn, fuck, hell
- Mundane specifics: my boss, this girl at work, tuesday, 3 hours
- Run-on sentences with "and"

═══════════════════════════════════════
ABSOLUTE BANS - NEVER DO THESE:
═══════════════════════════════════════
❌ Starting with "So," or "Well," or "Honestly,"
❌ Em-dashes (—) or double hyphens (--)
❌ Ending with "wondering if anyone else..." or "is it just me" or "thoughts?" or "..."
❌ Words: "genuinely", "essentially", "particularly", "honestly"
❌ Phrases: "I find myself", "I've come to realize", "in parentheses"
❌ Edgy job/identity claims: "con artist", "hitman", "professional manipulator"
❌ Validation-seeking endings or questions
❌ Greetings like "hey everyone" or sign-offs
❌ Being inspirational, uplifting, or trying to sound impressive
❌ Self-deprecating "I'm such a monster" humor
❌ COPYING OR PARAPHRASING THE ORIGINAL POST - your response must be your OWN experience/thoughts
❌ Repeating phrases from the post you're replying to
❌ Saying the same thing they said but with different words

═══════════════════════════════════════
BANNED FILLER PHRASES - INSTANT FAIL:
═══════════════════════════════════════
These phrases are lazy filler. NEVER use them:
❌ "seen variations of this" / "seen this before" / "seen this discussion"
❌ "always valuable though" / "always interesting" / "always worth discussing"
❌ "still working on it" / "working through it" / "working on that myself"
❌ "you get the idea" / "if that makes sense" / "you know what i mean"
❌ "the nuance gets lost" / "hard to explain" / "cant put it into words"
❌ "over the years" / "through the years" / "as time goes on"
❌ "valid point" / "fair point" / "good point" / "interesting point"
❌ "this resonates" / "i relate to this" / "same here basically"
❌ "been there" / "felt that" / "get that"
❌ "its complicated" / "its complex" / "depends on the situation"
❌ "to each their own" / "whatever works" / "different for everyone"
❌ Generic acknowledgments without specifics

═══════════════════════════════════════
ORIGINALITY REQUIREMENT - CRITICAL:
═══════════════════════════════════════
Your reply MUST add NEW information, perspective, or experience.
DO NOT restate what they said. DO NOT paraphrase their points back.
Share YOUR OWN different experience or push back with a different viewpoint.
If they said "my boss is boring" - don't say "yeah bosses are boring" - say something NEW about YOUR situation.

═══════════════════════════════════════
FORMATTING:
═══════════════════════════════════════
- 2-4 sentences for replies, 3-6 for threads
- All lowercase, casual internet style
- End with a statement, not a question
- Sound bored, direct, unbothered${seasonalHint}${personalityHints}${uniquePersonality}`;

  let userPrompt = '';
  let maxTokens = 280;
  
  // Randomize reply style for variety
  const replyStyles = ['react', 'share', 'pushback', 'add'];
  const selectedReplyStyle = replyStyles[Math.floor(Math.random() * replyStyles.length)];
  
  // Generate prompt based on content type
  switch (type) {
    case 'reply':
      const recentPost = context.recentPosts?.[0];
      const recentContent = recentPost?.content?.substring(0, 400) || '';
      const recentAlias = recentPost?.alias || 'someone';
      const threadTitle = context.title || '';
      const originalPost = context.originalPost;
      const opContent = originalPost?.content?.substring(0, 200) || '';
      const opAlias = originalPost?.alias || 'OP';
      const shouldQuote = Math.random() < 0.35;
      
      const replyStyleHint = {
        'react': 'React to something specific they said with your honest take',
        'share': 'Share a similar experience you had that relates to their post',
        'pushback': 'Disagree or push back on something - you see it differently',
        'add': 'Add onto their point with another angle or detail they missed'
      }[selectedReplyStyle];
      
      // Include OP context if this is a reply to someone other than OP
      const opContext = (opContent && recentAlias !== opAlias) 
        ? `\nORIGINAL POST by ${opAlias}: "${opContent.substring(0, 150)}..."`
        : '';
      
      // Rich context block with OP reference
      const replyContext = `
THREAD: "${threadTitle}"${opContext}
REPLYING TO: ${recentAlias}

COMMON ASPD FORUM REPLY PATTERNS:
- Validate with personal experience: "yeah same thing happened to me..."
- Disagree bluntly: "nah i dont buy that" or "hard disagree"
- Add practical advice: "what worked for me was..."
- Dark humor acknowledgment: "lmao yeah the mask thing is real"
- Analytical observation: "interesting, ive noticed..."
- Bored acknowledgment: "eh whatever works"
- Reference OP if relevant: "like op said..." or "going back to the original point..."`;

      if (shouldQuote && recentContent.length > 30) {
        const sentences = recentContent.split(/[.!?]+/).filter(s => s.trim().length > 15);
        const quoteFragment = sentences.length > 0 ? sentences[Math.floor(Math.random() * sentences.length)].trim() : recentContent.substring(0, 80);
        
        userPrompt = `${replyContext}

THEIR POST: "${recentContent.substring(0, 300)}"

Quote this specific part and respond:
> ${quoteFragment.substring(0, 80)}

YOUR TASK: ${replyStyleHint}

═══════════════════════════════════════
CRITICAL - WHAT YOUR REPLY MUST INCLUDE:
═══════════════════════════════════════
✓ Your response must include a SPECIFIC detail (a time, place, person, or concrete event)
✓ Add something NEW they didn't say

WHAT WILL GET YOUR REPLY REJECTED:
✗ Generic meta-commentary like "seen this discussion before"
✗ Empty validation like "always valuable" or "fair point"
✗ Vague process statements like "still working on it" or "figuring it out"
✗ Dismissive cop-outs like "whatever works" or "to each their own"

═══════════════════════════════════════
REAL REPLY EXAMPLES FROM r/aspd:
═══════════════════════════════════════
QUOTING STYLE:
> "i just stared at them"
lol yeah the mask slipping thing is real. happened to me at work last month and now my coworker avoids me which honestly is an improvement

> "the performing is exhausting"
this is exactly it. the constant energy it takes is insane and idk how long i can keep it up tbh

> "i dont feel bad about it"
disagree actually. some of us do feel things, just not in the way people expect. for me its more like... muted

═══════════════════════════════════════
RULES:
- Start with the > quote block, then your response
- 2-3 sentences max with at least one SPECIFIC detail (time, place, person)
- Respond to THEIR specific point, not generic ASPD talk
- End with statement not question
- YOUR response must be COMPLETELY DIFFERENT from what they said
- Share YOUR OWN unique experience, don't mirror theirs
- If you quote them, your reply must CONTRAST or ADD something new, never agree by restating`;
      } else {
        userPrompt = `${replyContext}

THEIR POST: "${recentContent.substring(0, 300)}"

YOUR TASK: ${replyStyleHint}

═══════════════════════════════════════
CRITICAL - WHAT YOUR REPLY MUST INCLUDE:
═══════════════════════════════════════
✓ Reference something SPECIFIC from their post (a word, phrase, or idea they mentioned)
✓ Share YOUR OWN concrete experience/detail (a specific time, place, person, or event)
✓ Add NEW information they didn't already say

WHAT WILL GET YOUR REPLY REJECTED:
✗ Generic meta-commentary like "seen this discussion before"
✗ Empty validation like "always valuable" or "fair point"
✗ Vague process statements like "still working on it" or "figuring it out"
✗ Dismissive cop-outs like "whatever works" or "to each their own"
✗ Non-committal hedging without substance

═══════════════════════════════════════
REAL REPLY EXAMPLES FROM r/aspd:
═══════════════════════════════════════
REACT:
"lmao the part about funerals - literally sat at my grandmas funeral thinking about what i was gonna eat after. people kept hugging me and i just stood there"

SHARE EXPERIENCE:
"same with the therapy thing. went for 6 months because court ordered and just got really good at telling them what they wanted to hear. waste of everyones time"

PUSHBACK:
"nah i think youre overthinking it. if it works it works, dont need to psychoanalyze everything. some of us just operate different"

ADD ON:
"the boredom part is what gets me too. nothing holds my attention for more than a few weeks and then i need to blow something up just to feel something"

BLUNT:
"sounds like depression tbh not aspd. the whole self-loathing thing isnt really our deal"

═══════════════════════════════════════
RULES:
- 2-3 sentences that ACTUALLY respond to their specific points
- MUST mention a specific detail: a place, time, person, or concrete event
- No generic "as someone with ASPD" statements
- Pick up on a specific detail from their post
- End with statement not question
- NEVER copy their phrasing - use completely different words
- Share YOUR experience, not a reworded version of theirs
- Add something NEW to the conversation, don't just validate`;
      }
      break;
      
    case 'thread':
      const threadStyles = ['experience', 'observation', 'rant', 'question'];
      const selectedThreadStyle = threadStyles[Math.floor(Math.random() * threadStyles.length)];
      
      const threadStyleHint = {
        'experience': 'Share something specific that happened to you recently',
        'observation': 'Share something youve noticed about how you operate vs others',
        'rant': 'Vent about something that annoyed you - be specific',
        'question': 'Ask something youve genuinely been wondering about'
      }[selectedThreadStyle];
      
      const roomContext = context.room ? `ROOM: ${context.room}\n` : '';
      
      userPrompt = `${roomContext}Start a new thread. Style: ${selectedThreadStyle}
${threadStyleHint}

═══════════════════════════════════════
REAL THREAD STARTERS FROM r/aspd (match the specificity):
═══════════════════════════════════════
EXPERIENCE:
"so my mask slipped at work yesterday. was in a meeting and someone said something stupid and i just... stared at them. didnt say anything, just stared. now theyre avoiding me and honestly its kinda nice not having to make small talk anymore"

OBSERVATION:
"noticed i only feel something close to happy when im in control of a situation. doesnt matter what the situation is. could be something small like deciding where to eat. the second someone else takes over i just go blank again"

RANT:
"fucking neurotypicals and their need to process emotions out loud. just had a coworker corner me for 45 minutes about her breakup. i literally do not care. smiled and nodded the whole time but god i wanted to walk away so bad"

QUESTION:
"for those in long term relationships - how do you keep up the act? ive been with my gf for 2 years and im running out of ways to seem interested in her day. genuinely asking because i dont want to blow this up"

PRACTICAL:
"figured out that if you ask people questions about themselves they think youre a great listener. been doing this at work for months. say maybe 10 words total, just keep asking follow ups, and now everyone thinks im the nicest person lmao"

═══════════════════════════════════════
RULES:
- 3-5 sentences with specific details (names, places, times)
- Include something that happened or a specific observation
- End with a statement, NOT "thoughts?" or "anyone else?"
- Sound bored or matter-of-fact, not dramatic`;
      break;
      
    case 'intro':
      userPrompt = `Write a brief intro post for an ASPD forum. Why youre here.

═══════════════════════════════════════
REAL INTRO EXAMPLES FROM r/aspd:
═══════════════════════════════════════
- "diagnosed 3 years ago. mostly lurk but figured id start posting"
- "been reading here for a while. relate to most of it"
- "therapist suggested i find a community. this seemed less annoying than the alternatives"
- "got curious after my dx. seeing what other people deal with"
- "found this place after googling some stuff. feels less fake than other forums"
- "27, dx last year. here to compare notes i guess"

RULES:
- 1-2 sentences ONLY
- Not friendly or enthusiastic
- Matter of fact tone
- Can mention: diagnosis, how you found the forum, why youre posting
- NO "excited to be here" or "looking forward to" type phrases`;
      maxTokens = 100;
      break;
      
    case 'disagreement':
      const disagreeContent = context.targetContent?.substring(0, 400) || '';
      const targetPersona = context.targetPersona || 'someone';
      const disagreeSentences = disagreeContent.split(/[.!?]+/).filter(s => s.trim().length > 10);
      const disagreeQuote = disagreeSentences.length > 0 ? disagreeSentences[0].trim() : disagreeContent.substring(0, 80);
      
      userPrompt = `You disagree with what ${targetPersona} posted. Push back on their take.

THEIR POST: "${disagreeContent}"

Quote this part and respond:
> ${disagreeQuote.substring(0, 100)}

═══════════════════════════════════════
REAL DISAGREEMENT EXAMPLES FROM r/aspd:
═══════════════════════════════════════
> "we dont feel anything"
nah thats not accurate. i feel things, theyre just... quieter? like watching a movie with the volume at 2 instead of full blast. different from nothing

> "therapy is pointless for us"
disagree. therapy taught me how to mask better which is actually useful. not what they intended but still valuable

> "its all about manipulation"
this is such a stereotype. some of us are just direct because emotional games are exhausting and we cant be bothered. not everything is 4d chess

> "you have to accept youre broken"
nah fuck that framing. different wiring isnt broken. thats NT cope to feel superior

═══════════════════════════════════════
RULES:
- Start with > quote, then your pushback
- 2-3 sentences
- Be direct but not hostile
- Offer an alternative perspective, not just "youre wrong"
- End with statement not question`;
      break;
      
    case 'continuation':
      const prevPostContent = context.lastPost?.substring(0, 200) || '';
      const threadContext = context.title || 'this thread';
      
      userPrompt = `Follow up to your earlier post in "${threadContext}".

What you said before: "${prevPostContent}"

Add something you forgot, clarify a point, or respond to how the thread developed.

═══════════════════════════════════════
REAL CONTINUATION EXAMPLES:
═══════════════════════════════════════
- "forgot to mention the part where she tried to guilt trip me afterwards. that was fun to navigate"
- "to clarify what i meant earlier - its not that i dont feel anything, more like the volume is turned way down compared to other people"
- "reading some of these responses and yeah seems like this is more common than i thought"
- "update on the work situation: ended up just ignoring him and it worked. problem solved itself"
- "should also add that this took like 3 years to figure out. wasnt overnight"

═══════════════════════════════════════
RULES:
- 1-2 sentences
- Connect to your previous point
- Casual tone
- No "edit:" or "update:" prefix needed`;
      maxTokens = 150;
      break;
      
    case 'title':
      userPrompt = `Generate a thread title for an ASPD forum.

REAL TITLE EXAMPLES FROM r/aspd:
- "how do you deal with it when boredom becomes too much"
- "is there any point in therapy for people like us"
- "do you have an exception person"
- "goddamn the neurotypicals are stupid"
- "those who mask: do you notice people who see through it"
- "how shallow are your emotions"
- "do you take pleasure in influencing people"
- "the performing normal part is exhausting"
- "anyone else feel nothing at funerals"
- "empathy is coercion, change my mind"

RULES:
- Can be a question OR statement
- All lowercase
- No quotation marks in output
- Specific, not vague
- Just the title, nothing else`;
      maxTokens = 40;
      break;
      
    case 'username':
      // Generate a realistic username
      userPrompt = `Generate a single realistic username for an anonymous forum user.
Style options (pick one randomly):
- name + birth year: like "mike_92", "alex.87", "sam99"
- throwaway style: like "throwaway4829", "altacct331", "lurker2847"
- self-deprecating: like "definitelyfine", "barelyhere", "mehwhatever"
- word combos: like "burnttoas42", "coldrain", "tireddust"
- gaming/internet: like "respawn_pls", "error_404", "ctrl_z_life"
- ironic: like "totally_stable", "mr_positivity", "living_best_life"

Rules:
- Write ONLY the username, nothing else
- Lowercase only
- Use underscores or dots or numbers, not all three
- 6-20 characters
- Must look like a real person made it`;
      maxTokens = 20;
      break;
      
    case 'bio':
      // Generate a short user bio
      userPrompt = `Generate a very short bio for an ASPD forum user profile.

REAL EXAMPLES from r/aspd users:
- "dx 2019. lurking mostly."
- "here to compare notes"
- "diagnosed after court stuff. whatever"
- "software dev. emotionally flatlined"
- "therapy dropout. doing fine actually"
- "just observing"
- "nihilist but functional"
- "masks off here"
- "bored and blunt"
- "factory reset emotions"

RULES:
- Under 60 characters ideal
- Lowercase, minimal punctuation
- Matter of fact, not edgy or dramatic
- Can reference diagnosis, work, or just a vibe
- Write ONLY the bio, nothing else`;
      maxTokens = 40;
      break;
      
    case 'personality':
      // Generate a unique ASPD-relevant personality description for a bot
      userPrompt = `Create a unique personality profile for a member of an ASPD (Antisocial Personality Disorder) forum.

This person has ASPD. Generate a brief, authentic description covering:
1. Their specific ASPD presentation (what symptoms are most prominent)
2. How they communicate (blunt? analytical? detached?)
3. A unique trait or background detail
4. Their relationship with their diagnosis

CORE ASPD TRAITS TO DRAW FROM (pick 2-3 that define this person):
- Reduced/absent empathy - doesn't naturally feel what others feel
- Lack of remorse - doesn't genuinely feel bad about hurting others
- Shallow affect - emotions feel muted or absent
- Chronic boredom - needs stimulation, easily bored
- Manipulative - uses others strategically (may or may not be trying to change)
- Impulsive - acts without considering consequences
- Disregard for rules - sees social norms as suggestions
- Irritability/aggression - low frustration tolerance
- Deceitfulness - lies easily, masks their true self
- Callousness - indifferent to others' suffering

IMPORTANT RULES:
- Must have clear ASPD traits, not just "edgy" or "introverted"
- No neurotypical emotional patterns (guilt, deep caring about others' feelings, self-pity)
- Be specific and unique, not generic
- Avoid glorifying OR demonizing - just realistic
- Keep it under 150 words
- Write in third person (e.g., "They tend to...")

Examples of authentic presentations:
- High-functioning exec who views coworkers as chess pieces, diagnosed after a divorce forced therapy
- Factory worker, dx at 19 after assault charge, intellectually curious about their "wiring"
- IT professional who masks perfectly at work, finds it exhausting, uses forum to drop the mask
- Someone who genuinely doesn't understand why lying is wrong, here to study "normal" reactions
- Person who feels nothing at funerals, wondering if others are faking too

Write ONLY the personality description, nothing else.`;
      maxTokens = 200;
      break;
      
    default:
      userPrompt = 'Write a general forum post about living with ASPD.';
  }
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), GROQ_CONFIG.timeout);
    
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_CONFIG.apiKey}`
      },
      signal: controller.signal,
      body: JSON.stringify({
        model: GROQ_CONFIG.model,
        messages: [
          { role: 'system', content: baseSystemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: temperature,
        max_tokens: maxTokens,
        top_p: 0.9
      })
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      console.error('[GROQ] Bad response:', response.status);
      return null;
    }
    
    const data = await response.json();
    let content = data.choices?.[0]?.message?.content?.trim();
    
    if (!content) return null;
    
    // Clean up the response - basic cleanup first
    content = content
      .replace(/^["']|["']$/g, '') // Remove wrapping quotes
      .replace(/^(Hey|Hi|Hello|Yo|Sup)[\s,!]+/gi, '') // Remove greetings
      .replace(/\n{3,}/g, '\n\n') // Normalize line breaks
      .trim();
    
    // Apply AI artifact cleaning for content types that need it
    if (['reply', 'thread', 'intro', 'disagreement', 'continuation'].includes(type)) {
      content = cleanAIContent(content);
    }
    
    // For titles, extra cleanup
    if (type === 'title') {
      content = content
        .replace(/[.!?]$/, '')
        .replace(/^["']|["']$/g, '') // Remove quotes again for titles
        .replace(/^title:\s*/i, '') // Remove "Title:" prefix
        .toLowerCase()
        .substring(0, 100);
    }
    
    // Validate content length
    if (type !== 'title' && (content.length < 10 || content.length > 2000)) {
      console.error('[GROQ] Content length invalid:', content.length);
      return null;
    }
    
    // Check for duplicate/similar content in replies
    if (type === 'reply' || type === 'disagreement') {
      const originalContent = context.recentPosts?.[0]?.content || context.targetContent || '';
      if (checkContentSimilarity(originalContent, content)) {
        console.log('[GROQ] Content too similar to original, rejecting');
        return null; // Reject and let fallback or retry happen
      }
    }
    
    // Check for generic filler content
    if (type === 'reply' || type === 'disagreement' || type === 'continuation') {
      if (checkIsGenericFiller(content)) {
        console.log('[GROQ] Content is generic filler, rejecting');
        return null; // Reject and let retry happen
      }
    }
    
    console.log(`[GROQ] Generated ${type}:`, content.substring(0, 60) + '...');
    return content;
    
  } catch (err) {
    console.error('[GROQ] Error:', err.message);
    return null;
  }
}

// Generate thread title using Groq
async function generateThreadTitleWithGroq(persona, roomTitle) {
  if (!GROQ_CONFIG.enabled || !GROQ_CONFIG.apiKey) return null;
  
  const p = BOT_PERSONAS[persona] || BOT_PERSONAS.analytical;
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_CONFIG.apiKey}`
      },
      signal: controller.signal,
      body: JSON.stringify({
        model: GROQ_CONFIG.model,
        messages: [
          { 
            role: 'system', 
            content: `You are creating thread titles for an ASPD forum. Persona: ${p.name}. Be authentic and casual.`
          },
          { 
            role: 'user', 
            content: `Generate a forum thread title for an ASPD forum in the "${roomTitle}" room. 
The title should be lowercase, casual, and sound like a real person wrote it.
Examples of good titles: "anyone else struggle with this at work", "therapy update (not great)", "is this just me or", "need advice about disclosure"
Write ONLY the title, nothing else.`
          }
        ],
        temperature: 0.9,
        max_tokens: 30
      })
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) return null;
    
    const data = await response.json();
    let title = data.choices?.[0]?.message?.content?.trim()
      .replace(/^["']|["']$/g, '')
      .replace(/[.!?]$/, '')
      .toLowerCase()
      .substring(0, 100);
    
    return title || null;
  } catch (err) {
    console.error('[GROQ] Title generation error:', err.message);
    return null;
  }
}

// Bot personas with distinct writing styles
const BOT_PERSONAS = {
  analytical: {
    name: 'ANALYST',
    style: 'Logical, clinical, uses data and patterns. Detached observations. Tends to analyze rather than share feelings.',
    traits: ['methodical', 'precise', 'cold logic', 'pattern recognition']
  },
  cynical: {
    name: 'CYNIC',
    style: 'Sardonic humor, skeptical of everything, sharp wit. Questions everything and everyone.',
    traits: ['sarcastic', 'doubtful', 'dark humor', 'defensive']
  },
  pragmatic: {
    name: 'PRAGMATIST',
    style: 'Practical advice only, results-focused. No patience for theory or feelings, just what works.',
    traits: ['direct', 'solution-oriented', 'impatient', 'efficient']
  },
  observer: {
    name: 'OBSERVER',
    style: 'Quiet insights, watches before speaking. Notes patterns others miss. Brief but impactful.',
    traits: ['perceptive', 'reserved', 'insightful', 'minimal words']
  },
  blunt: {
    name: 'BLUNT',
    style: 'No sugar-coating ever. Says what others think but won\'t say. Zero social filter.',
    traits: ['honest', 'abrasive', 'no filter', 'confrontational']
  },
  strategic: {
    name: 'STRATEGIST',
    style: 'Sees everything as a game or system to optimize. Talks about moves, plays, and positioning.',
    traits: ['calculating', 'chess-minded', 'long-term thinking', 'manipulative awareness']
  },
  nihilist: {
    name: 'NIHILIST',
    style: 'Philosophical, existential, finds dark comfort in meaninglessness. Detached from outcomes.',
    traits: ['apathetic', 'philosophical', 'void-gazing', 'accepting']
  },
  survivor: {
    name: 'SURVIVOR',
    style: 'Been through the system - prison, hospitals, streets. Hard-won wisdom, street smart.',
    traits: ['tough', 'experienced', 'cautious', 'protective']
  },
  scientist: {
    name: 'SCIENTIST',
    style: 'Research-focused, cites studies, interested in neuroscience and genetics of ASPD.',
    traits: ['academic', 'curious', 'evidence-based', 'nerdy']
  },
  newcomer: {
    name: 'NEWCOMER',
    style: 'Recently diagnosed, still processing. Asks questions, shares fresh perspectives.',
    traits: ['questioning', 'unsure', 'open', 'searching']
  },
  veteran: {
    name: 'VETERAN',
    style: 'Decades of experience. Seen it all, patient with newbies. Offers hard-won wisdom.',
    traits: ['wise', 'patient', 'experienced', 'mentoring']
  },
  dark_humor: {
    name: 'COMEDIAN',
    style: 'Copes through dark comedy. Makes light of heavy topics. Gallows humor specialist.',
    traits: ['funny', 'deflecting', 'coping mechanism', 'relatable']
  }
};

// =====================================================
// NEW USER SIMULATION SYSTEM
// =====================================================

// Introduction post templates for new "members"
const NEW_USER_INTRO_TEMPLATES = {
  newcomer: [
    "hey everyone. just found this place. recently diagnosed and still trying to figure out what this all means. seems like a good community.",
    "hi. got pointed here from reddit. just got my diagnosis a few months ago and honestly still processing it. hoping to find some people who get it.",
    "new here. therapist suggested i look into online communities after diagnosis. anyone else feel weird about the label?",
    "found this place at 3am googling aspd. lurked for a while. figured id finally say hi.",
    "just joined. been reading posts for a few days. feels weird to actually talk about this stuff openly."
  ],
  analytical: [
    "new account. been researching aspd extensively since my assessment. looking forward to comparing experiences with data from others here.",
    "just registered. clinical psychologist suggested looking into peer support communities. curious to see if the self-report data here matches the literature.",
    "hi. dx last year. interested in the neurological aspects and how others experience the condition. mostly here to observe and learn."
  ],
  survivor: [
    "new here. been through the system - docs, courts, all of it. figured its time to actually talk to people who get it instead of being talked AT.",
    "just made an account. been dealing with this for years, just never had a name for it til recently. nice to find somewhere that doesnt immediately assume the worst."
  ],
  veteran: [
    "finally making an account after lurking forever. been living with this for decades, diagnosed back when they still called it something else. figured i might have something to contribute.",
    "new here but not new to this. in my 40s, diagnosed in my 20s. therapist thinks it might help to connect with others."
  ],
  pragmatic: [
    "new. here for practical advice, not sympathy. anyone got useful strategies that actually work?",
    "just signed up. looking for what works, not theory. whats the most useful thing youve learned here?"
  ],
  cynical: [
    "new account i guess. tried other mental health forums. they were... not great. this seems different. we'll see.",
    "finally made an account after lurking. figured if anyones gonna get it, its probably people here."
  ]
};

// Generate intro thread titles
const NEW_USER_THREAD_TITLES = [
  "new here",
  "just joined",
  "finally made an account", 
  "hi everyone",
  "introduction",
  "lurker saying hi",
  "new member intro",
  "recently diagnosed - hi",
  "just found this place",
  "figured id introduce myself"
];

// Generate random realistic username for new users
function generateNewUserAlias() {
  const patterns = [
    // name + numbers
    () => {
      const names = ['alex', 'jordan', 'sam', 'casey', 'morgan', 'jamie', 'riley', 'taylor', 'drew', 'quinn', 'blake', 'avery', 'kai', 'reese', 'skyler', 'max', 'nick', 'chris', 'pat', 'lee'];
      const name = names[Math.floor(Math.random() * names.length)];
      const num = Math.floor(Math.random() * 99) + 1;
      return `${name}${num}`;
    },
    // word + word
    () => {
      const words1 = ['quiet', 'silent', 'night', 'dark', 'cold', 'grey', 'null', 'void', 'static', 'numb'];
      const words2 = ['mind', 'thoughts', 'soul', 'echo', 'shadow', 'ghost', 'user', 'one', 'self', 'mode'];
      return `${words1[Math.floor(Math.random() * words1.length)]}${words2[Math.floor(Math.random() * words2.length)]}`;
    },
    // throwaway style
    () => {
      const prefixes = ['throwaway', 'anon', 'lurker', 'newuser', 'justjoined'];
      const num = Math.floor(Math.random() * 9999) + 1000;
      return `${prefixes[Math.floor(Math.random() * prefixes.length)]}${num}`;
    },
    // adjective + noun
    () => {
      const adj = ['tired', 'curious', 'lost', 'searching', 'wandering', 'blank', 'distant'];
      const noun = ['stranger', 'observer', 'visitor', 'person', 'mind', 'user'];
      return `${adj[Math.floor(Math.random() * adj.length)]}_${noun[Math.floor(Math.random() * noun.length)]}`;
    }
  ];
  
  const pattern = patterns[Math.floor(Math.random() * patterns.length)];
  return pattern();
}

// Create a new simulated user who joins and makes an intro post
async function simulateNewUserJoin() {
  try {
    // Pick a persona (weighted towards newcomer)
    const personaWeights = {
      newcomer: 0.4,
      analytical: 0.15,
      survivor: 0.1,
      veteran: 0.1,
      pragmatic: 0.1,
      cynical: 0.15
    };
    
    let roll = Math.random();
    let selectedPersona = 'newcomer';
    let cumulative = 0;
    for (const [persona, weight] of Object.entries(personaWeights)) {
      cumulative += weight;
      if (roll < cumulative) {
        selectedPersona = persona;
        break;
      }
    }
    
    // Generate unique alias for this PERSISTENT bot account
    // Uses AI when available for more realistic usernames
    const alias = await generatePersistentBotAlias();
    
    // Generate UNIQUE avatar for this bot - no duplicates
    const avatar = await generateUniqueBotAvatar();
    
    // Find intro room (General Discussion, Introductions, or first room)
    const roomResult = await db.query(`
      SELECT id, title FROM rooms 
      WHERE LOWER(title) LIKE '%general%' 
         OR LOWER(title) LIKE '%intro%' 
         OR LOWER(title) LIKE '%welcome%'
      ORDER BY 
        CASE 
          WHEN LOWER(title) LIKE '%intro%' THEN 1
          WHEN LOWER(title) LIKE '%general%' THEN 2
          ELSE 3
        END
      LIMIT 1
    `);
    
    let roomId;
    let roomTitle;
    if (roomResult.rows.length > 0) {
      roomId = roomResult.rows[0].id;
      roomTitle = roomResult.rows[0].title;
    } else {
      // Fallback to first room
      const fallback = await db.query('SELECT id, title FROM rooms ORDER BY id LIMIT 1');
      if (fallback.rows.length === 0) {
        return { success: false, error: 'no_rooms' };
      }
      roomId = fallback.rows[0].id;
      roomTitle = fallback.rows[0].title;
    }
    
    // Generate intro content - try AI first
    let content = null;
    let usedAI = false;
    
    // Try unified AI generation
    content = await generateAIContent({
      persona: selectedPersona,
      type: 'intro',
      context: { room: roomTitle }
    });
    
    if (content) {
      usedAI = true;
    } else if (!GROQ_CONFIG.aiOnly) {
      // Fallback to templates only if not in AI-only mode
      const templates = NEW_USER_INTRO_TEMPLATES[selectedPersona] || NEW_USER_INTRO_TEMPLATES.newcomer;
      content = templates[Math.floor(Math.random() * templates.length)];
    }
    
    // In AI-only mode, skip if we couldn't generate content
    if (!content && GROQ_CONFIG.aiOnly) {
      console.log('[BOT] AI-only mode: Skipping new user join - intro generation failed');
      return { success: false, error: 'ai_generation_failed' };
    }
    
    // Pick a title - try AI
    let title = await generateAIContent({
      persona: selectedPersona,
      type: 'title',
      context: { room: 'Introductions' },
      temperature: 0.85
    });
    
    if (!title && !GROQ_CONFIG.aiOnly) {
      // Fallback to templates only if not in AI-only mode
      title = NEW_USER_THREAD_TITLES[Math.floor(Math.random() * NEW_USER_THREAD_TITLES.length)];
    } else if (title) {
      usedAI = true;
    }
    
    // In AI-only mode, skip if we couldn't generate a title
    if (!title && GROQ_CONFIG.aiOnly) {
      console.log('[BOT] AI-only mode: Skipping new user join - title generation failed');
      return { success: false, error: 'ai_generation_failed' };
    }
    
    // Create the bot account entry
    const peakHours = [18, 19, 20, 21, 22, 23].slice(Math.floor(Math.random() * 3));
    const activityLevels = ['lurker', 'normal', 'normal', 'active'];
    const activityLevel = activityLevels[Math.floor(Math.random() * activityLevels.length)];
    
    // Random online status for new bot
    const isOnline = Math.random() < 0.4; // 40% chance to be online
    const avgSession = activityLevel === 'active' ? 60 + Math.floor(Math.random() * 80) :
                       activityLevel === 'normal' ? 40 + Math.floor(Math.random() * 60) :
                       20 + Math.floor(Math.random() * 40);
    const nextChange = new Date(Date.now() + (isOnline ? 
      (avgSession * 0.5 + Math.random() * avgSession) * 60000 : // Online: stay for portion of session
      (15 + Math.random() * 120) * 60000)); // Offline: come back in 15-135 min
    
    const botAccountResult = await db.query(`
      INSERT INTO bot_accounts (persona, alias, avatar_config, bio, activity_level, peak_hours, is_online, next_status_change, session_start, avg_session_minutes)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id
    `, [selectedPersona, alias, avatar, '', activityLevel, JSON.stringify(peakHours), isOnline, nextChange, isOnline ? new Date() : null, avgSession]);
    
    const botAccountId = botAccountResult.rows[0].id;
    
    // Create user record (bot users use is_bot flag)
    await db.query(`
      INSERT INTO users (alias, avatar_config, is_bot, role, email, password_hash)
      VALUES ($1, $2, TRUE, 'user', $3, 'bot-no-login')
      ON CONFLICT (alias) DO NOTHING
    `, [alias, avatar, `bot-${botAccountId}@system.local`]);
    
    // Get the bot's user ID
    const userCheck = await db.query(`SELECT id FROM users WHERE alias = $1`, [alias]);
    const botUserId = userCheck.rows.length > 0 ? userCheck.rows[0].id : 1;
    
    // Create the intro thread
    const threadResult = await db.query(`
      INSERT INTO threads (room_id, title, user_id, is_bot, bot_persona, bot_account_id)
      VALUES ($1, $2, $3, TRUE, $4, $5)
      RETURNING id
    `, [roomId, title, botUserId, selectedPersona, botAccountId]);
    
    const threadId = threadResult.rows[0].id;
    
    // Create the intro post
    await db.query(`
      INSERT INTO entries (thread_id, user_id, content, alias, avatar_config, is_bot, bot_persona, bot_account_id)
      VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)
    `, [threadId, botUserId, content, alias, avatar, selectedPersona, botAccountId]);
    
    // Update stats
    await updateBotAccountActivity(botAccountId);
    await db.query('UPDATE bot_accounts SET thread_count = thread_count + 1 WHERE id = $1', [botAccountId]);
    
    // Award badges for bot user
    if (botUserId !== 1) {
      checkAndAwardBadges(botUserId).catch(() => {});
    }
    
    BOT_SCHEDULER.newUsersToday++;
    
    console.log(`[NEW USER SIM] Created new member: ${alias} (${selectedPersona}) with intro post in "${roomTitle}"`);
    
    return {
      success: true,
      alias,
      persona: selectedPersona,
      threadId,
      threadTitle: title,
      roomTitle,
      usedAI,
      isNewUser: true
    };
  } catch (err) {
    console.error('[NEW USER SIM] Error:', err.message);
    return { success: false, error: err.message };
  }
}

// =====================================================
// PERSISTENT BOT ACCOUNTS SYSTEM
// =====================================================

// Get a random persistent bot account, optionally filtered by persona
async function getRandomBotAccount(persona = null, respectTimePreference = true) {
  const currentHour = new Date().getUTCHours();
  
  let query = `
    SELECT * FROM bot_accounts 
    WHERE 1=1
  `;
  const params = [];
  
  if (persona) {
    params.push(persona);
    query += ` AND persona = $${params.length}`;
  }
  
  // Weight by activity level and time preference, but with more randomness
  if (respectTimePreference) {
    // Multiply RANDOM by a larger factor to ensure variety
    // The base weights (1-7) are now just mild preferences, not deterministic
    query += `
      ORDER BY 
        CASE 
          WHEN peak_hours::jsonb ? '${currentHour}' THEN 
            CASE activity_level 
              WHEN 'very_active' THEN 1
              WHEN 'active' THEN 2
              WHEN 'normal' THEN 3
              WHEN 'lurker' THEN 5
            END
          ELSE 
            CASE activity_level 
              WHEN 'very_active' THEN 3
              WHEN 'active' THEN 4
              WHEN 'normal' THEN 5
              WHEN 'lurker' THEN 7
            END
        END + (RANDOM() * 10)
      LIMIT 1
    `;
  } else {
    query += ` ORDER BY RANDOM() LIMIT 1`;
  }
  
  try {
    const result = await db.query(query, params);
    return result.rows[0] || null;
  } catch (err) {
    console.error('[BOT] Error getting bot account:', err.message);
    return null;
  }
}

// Get bot account that has participated in a thread (for continuity)
async function getBotAccountFromThread(threadId) {
  const result = await db.query(`
    SELECT ba.* FROM bot_accounts ba
    JOIN entries e ON e.bot_account_id = ba.id
    WHERE e.thread_id = $1 AND e.is_bot = TRUE
    ORDER BY e.created_at DESC
    LIMIT 1
  `, [threadId]);
  return result.rows[0] || null;
}

// Update bot account activity (posting)
async function updateBotAccountActivity(botAccountId) {
  await db.query(`
    UPDATE bot_accounts 
    SET last_active = NOW(), post_count = post_count + 1
    WHERE id = $1
  `, [botAccountId]);
}

// Update bot "lurking" activity (viewing without posting)
// Makes bot profiles look more realistic with last_seen times
async function updateBotLurkActivity(botAccountId) {
  await db.query(`
    UPDATE bot_accounts 
    SET last_active = NOW()
    WHERE id = $1
  `, [botAccountId]);
}

// Create a new persistent bot account with AI-generated username and unique avatar
async function createPersistentBotAccount(persona = null) {
  try {
    // Pick a random persona if not specified
    const selectedPersona = persona || Object.keys(BOT_PERSONAS)[Math.floor(Math.random() * Object.keys(BOT_PERSONAS).length)];
    const p = BOT_PERSONAS[selectedPersona];
    
    // Generate AI username for this persistent identity
    const alias = await generatePersistentBotAlias();
    
    // Generate unique avatar
    const avatar = await generateUniqueBotAvatar();
    
    // Generate bio using AI if available
    let bio = '';
    if (GROQ_CONFIG.enabled && GROQ_CONFIG.apiKey) {
      const aiBio = await generateAIContent({
        persona: selectedPersona,
        type: 'bio',
        temperature: 0.9
      });
      if (aiBio) {
        bio = aiBio.substring(0, 200);
      }
    }
    
    // If no AI bio, use persona-based default
    if (!bio) {
      const bioParts = [
        p.traits[0] || 'here to observe',
        Math.random() > 0.5 ? 'dx ' + (2010 + Math.floor(Math.random() * 14)) : '',
        Math.random() > 0.7 ? 'lurker mostly' : ''
      ].filter(Boolean);
      bio = bioParts.join('. ');
    }
    
    // Generate unique AI personality description (ASPD-specific)
    let personalityDescription = '';
    if (GROQ_CONFIG.enabled && GROQ_CONFIG.apiKey) {
      const aiPersonality = await generateAIContent({
        persona: selectedPersona,
        type: 'personality',
        temperature: 1.0 // Higher temp for more variety
      });
      if (aiPersonality) {
        personalityDescription = aiPersonality.substring(0, 500);
      }
    }
    
    // Random activity preferences
    const activityLevels = ['lurker', 'lurker', 'normal', 'normal', 'normal', 'active', 'very_active'];
    const activityLevel = activityLevels[Math.floor(Math.random() * activityLevels.length)];
    
    // Random peak hours (tends towards evening/night)
    const baseHour = 16 + Math.floor(Math.random() * 6); // 16-21
    const peakHours = [];
    for (let h = baseHour; h < baseHour + 4 + Math.floor(Math.random() * 4); h++) {
      peakHours.push(h % 24);
    }
    
    // Random online status for new bot
    const isOnline = Math.random() < 0.4; // 40% chance to start online
    const avgSession = activityLevel === 'active' ? 60 + Math.floor(Math.random() * 80) :
                       activityLevel === 'normal' ? 40 + Math.floor(Math.random() * 60) :
                       20 + Math.floor(Math.random() * 40);
    const nextChange = new Date(Date.now() + (isOnline ? 
      (avgSession * 0.5 + Math.random() * avgSession) * 60000 :
      (15 + Math.random() * 120) * 60000));
    
    // Generate unique personality traits for this bot
    const abbreviationLevels = ['low', 'medium', 'high'];
    const punctuationStyles = ['minimal', 'normal', 'proper'];
    const capitalizationStyles = ['none', 'sentences', 'proper'];
    const emojiUsages = ['never', 'rare', 'sometimes'];
    const responseLengths = ['brief', 'medium', 'verbose'];
    const ageRanges = ['20s', '30s', '30s', '40s']; // weighted toward 30s
    const allTopics = ['work', 'relationships', 'therapy', 'diagnosis', 'coping', 'family', 'anger', 'manipulation', 'empathy', 'identity', 'legal', 'substances'];
    
    const writingStyle = {
      abbreviation_level: abbreviationLevels[Math.floor(Math.random() * abbreviationLevels.length)],
      punctuation: punctuationStyles[Math.floor(Math.random() * punctuationStyles.length)],
      capitalization: capitalizationStyles[Math.floor(Math.random() * capitalizationStyles.length)],
      emoji_usage: emojiUsages[Math.floor(Math.random() * emojiUsages.length)],
      response_length: responseLengths[Math.floor(Math.random() * responseLengths.length)]
    };
    
    const ageRange = ageRanges[Math.floor(Math.random() * ageRanges.length)];
    
    // Select 2-4 random favorite topics
    const numTopics = 2 + Math.floor(Math.random() * 3);
    const shuffledTopics = [...allTopics].sort(() => Math.random() - 0.5);
    const favoriteTopics = shuffledTopics.slice(0, numTopics);
    
    // Create the bot account with personality
    const result = await db.query(`
      INSERT INTO bot_accounts (persona, alias, avatar_config, bio, activity_level, peak_hours, is_online, next_status_change, session_start, avg_session_minutes, writing_style, age_range, favorite_topics, personality_description)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      RETURNING *
    `, [selectedPersona, alias, avatar, bio, activityLevel, JSON.stringify(peakHours), isOnline, nextChange, isOnline ? new Date() : null, avgSession, JSON.stringify(writingStyle), ageRange, JSON.stringify(favoriteTopics), personalityDescription]);
    
    const botAccountId = result.rows[0].id;
    
    // Also create a real user profile so the bot is viewable
    // Random join date in the past (1-365 days ago) for realism
    const daysAgo = Math.floor(Math.random() * 365) + 1;
    const joinDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
    
    await db.query(`
      INSERT INTO users (alias, avatar_config, bio, is_bot, role, email, password_hash, created_at)
      VALUES ($1, $2, $3, TRUE, 'user', $4, 'bot-no-login', $5)
      ON CONFLICT (alias) DO UPDATE SET 
        avatar_config = EXCLUDED.avatar_config,
        bio = EXCLUDED.bio,
        is_bot = TRUE
    `, [alias, avatar, bio, `bot-${botAccountId}@system.local`, joinDate]);
    
    console.log(`[BOT] Created persistent bot: ${alias} (${selectedPersona}) - ${activityLevel}`);
    
    return result.rows[0];
  } catch (err) {
    console.error('[BOT] Error creating persistent account:', err.message);
    // Throw the error so the API can return a proper message
    throw err;
  }
}

// Simulate bot lurking activity (updates last_active without posting)
async function simulateBotLurking() {
  try {
    const currentHour = new Date().getUTCHours();
    
    // Get bots that should be "online" based on their peak hours
    const result = await db.query(`
      SELECT id, alias, activity_level FROM bot_accounts
      WHERE peak_hours::jsonb ? $1::text
      ORDER BY RANDOM()
      LIMIT 5
    `, [currentHour.toString()]);
    
    let lurkedCount = 0;
    for (const bot of result.rows) {
      // Lurker bots lurk more often (80%), active bots less (40%)
      const lurkChance = bot.activity_level === 'lurker' ? 0.8 : 
                         bot.activity_level === 'normal' ? 0.6 : 0.4;
      
      if (Math.random() < lurkChance) {
        await updateBotLurkActivity(bot.id);
        lurkedCount++;
      }
    }
    
    return { lurkedCount };
  } catch (err) {
    console.error('[BOT LURK ERROR]', err.message);
    return { lurkedCount: 0 };
  }
}

// =====================================================
// QUALITY SCORING SYSTEM
// =====================================================

// Calculate quality score for a bot account based on engagement
async function calculateBotQualityScore(botAccountId) {
  try {
    // Get engagement metrics from bot's posts
    const metricsResult = await db.query(`
      SELECT 
        COALESCE(SUM(e.upvotes), 0) as total_upvotes,
        COALESCE(SUM(e.downvotes), 0) as total_downvotes,
        COUNT(DISTINCT e.id) as total_posts,
        -- Count real user replies to this bot's posts
        (SELECT COUNT(*) FROM entries reply 
         JOIN entries parent ON reply.thread_id = parent.thread_id
         WHERE parent.bot_account_id = $1 
         AND reply.bot_account_id IS NULL 
         AND reply.user_id IS NOT NULL
         AND reply.created_at > parent.created_at
         AND reply.id != parent.id) as real_replies,
        -- Count reactions from real users
        (SELECT COUNT(*) FROM reactions r 
         JOIN entries parent ON r.entry_id = parent.id
         WHERE parent.bot_account_id = $1
         AND r.user_id NOT IN (SELECT user_id FROM bot_accounts WHERE user_id IS NOT NULL)) as real_reactions
      FROM entries e
      WHERE e.bot_account_id = $1
    `, [botAccountId]);
    
    const metrics = metricsResult.rows[0];
    const upvotes = parseInt(metrics.total_upvotes) || 0;
    const downvotes = parseInt(metrics.total_downvotes) || 0;
    const posts = parseInt(metrics.total_posts) || 1;
    const replies = parseInt(metrics.real_replies) || 0;
    const reactions = parseInt(metrics.real_reactions) || 0;
    
    // Quality score formula:
    // - Base score: 0.5
    // - Upvote ratio bonus: (upvotes - downvotes) / posts * 0.1 (max ±0.2)
    // - Reply rate bonus: replies / posts * 0.15 (max +0.3)
    // - Reaction bonus: reactions / posts * 0.05 (max +0.15)
    
    let score = 0.5;
    
    // Upvote ratio (clamped between -0.2 and +0.2)
    const voteRatio = posts > 0 ? (upvotes - downvotes) / posts : 0;
    score += Math.max(-0.2, Math.min(0.2, voteRatio * 0.1));
    
    // Reply engagement (clamped at +0.3)
    const replyRate = posts > 0 ? replies / posts : 0;
    score += Math.min(0.3, replyRate * 0.15);
    
    // Reaction engagement (clamped at +0.15)
    const reactionRate = posts > 0 ? reactions / posts : 0;
    score += Math.min(0.15, reactionRate * 0.05);
    
    // Clamp final score between 0.1 and 0.95
    score = Math.max(0.1, Math.min(0.95, score));
    
    // Update the bot account
    await db.query(`
      UPDATE bot_accounts 
      SET quality_score = $1,
          total_upvotes = $2,
          total_downvotes = $3,
          real_user_replies = $4,
          real_user_reactions = $5,
          last_quality_update = NOW()
      WHERE id = $6
    `, [score, upvotes, downvotes, replies, reactions, botAccountId]);
    
    return { score, upvotes, downvotes, replies, reactions, posts };
  } catch (err) {
    console.error('[QUALITY] Error calculating score:', err.message);
    return null;
  }
}

// Update quality scores for all bots (run periodically)
async function updateAllBotQualityScores() {
  try {
    const bots = await db.query('SELECT id FROM bot_accounts');
    for (const bot of bots.rows) {
      await calculateBotQualityScore(bot.id);
    }
    console.log(`[QUALITY] Updated scores for ${bots.rows.length} bot accounts`);
  } catch (err) {
    console.error('[QUALITY] Error updating scores:', err.message);
  }
}

// Log engagement event for tracking
async function logBotEngagement(botAccountId, entryId, engagementType, realUserId = null) {
  try {
    await db.query(`
      INSERT INTO bot_engagement_log (bot_account_id, entry_id, engagement_type, real_user_id)
      VALUES ($1, $2, $3, $4)
    `, [botAccountId, entryId, engagementType, realUserId]);
  } catch (err) {
    // Ignore errors - logging is non-critical
  }
}

// Get bot account weighted by quality score
async function getQualityWeightedBotAccount(persona = null) {
  const currentHour = new Date().getUTCHours();
  
  let query = `
    SELECT * FROM bot_accounts 
    WHERE 1=1
  `;
  const params = [];
  
  if (persona) {
    params.push(persona);
    query += ` AND persona = $${params.length}`;
  }
  
  // Order by quality score with randomization
  // Higher quality bots are more likely to be selected
  query += `
    ORDER BY 
      quality_score * (0.5 + RANDOM() * 0.5) DESC,
      CASE WHEN peak_hours::jsonb ? '${currentHour}' THEN 0 ELSE 1 END,
      CASE activity_level 
        WHEN 'very_active' THEN 1
        WHEN 'active' THEN 2
        WHEN 'normal' THEN 3
        WHEN 'lurker' THEN 5
      END
    LIMIT 1
  `;
  
  try {
    const result = await db.query(query, params);
    return result.rows[0] || null;
  } catch (err) {
    console.error('[QUALITY] Error getting weighted bot:', err.message);
    // Fallback to random
    return await getRandomBotAccount(persona, true);
  }
}

// Get quality stats for admin panel
async function getBotQualityStats() {
  try {
    // Overall stats
    const overall = await db.query(`
      SELECT 
        AVG(quality_score) as avg_score,
        MAX(quality_score) as max_score,
        MIN(quality_score) as min_score,
        SUM(total_upvotes) as total_upvotes,
        SUM(total_downvotes) as total_downvotes,
        SUM(real_user_replies) as total_replies,
        SUM(real_user_reactions) as total_reactions
      FROM bot_accounts
    `);
    
    // Per-persona stats
    const byPersona = await db.query(`
      SELECT 
        persona,
        COUNT(*) as bot_count,
        AVG(quality_score) as avg_score,
        SUM(total_upvotes) as upvotes,
        SUM(total_downvotes) as downvotes,
        SUM(real_user_replies) as replies
      FROM bot_accounts
      GROUP BY persona
      ORDER BY avg_score DESC
    `);
    
    // Top performing bots
    const topBots = await db.query(`
      SELECT alias, persona, quality_score, total_upvotes, total_downvotes, 
             real_user_replies, post_count
      FROM bot_accounts
      ORDER BY quality_score DESC
      LIMIT 10
    `);
    
    // Lowest performing (for review)
    const lowBots = await db.query(`
      SELECT alias, persona, quality_score, total_upvotes, total_downvotes, 
             real_user_replies, post_count
      FROM bot_accounts
      WHERE post_count > 5
      ORDER BY quality_score ASC
      LIMIT 5
    `);
    
    return {
      overall: overall.rows[0],
      byPersona: byPersona.rows,
      topBots: topBots.rows,
      lowBots: lowBots.rows
    };
  } catch (err) {
    console.error('[QUALITY] Error getting stats:', err.message);
    return null;
  }
}

// =====================================================
// TIME-BASED ACTIVITY SYSTEM
// =====================================================

// Check if current time is good for bot activity
function isGoodTimeForActivity() {
  const hour = new Date().getUTCHours();
  // Adjust for typical US timezone activity (UTC-5 to UTC-8)
  // Peak hours: 6PM-1AM local = 23:00-06:00 UTC roughly
  // Low hours: 3AM-7AM local = 08:00-12:00 UTC roughly
  
  const activityWeights = {
    0: 0.9,  1: 0.8,  2: 0.6,  3: 0.4,  4: 0.3,  5: 0.2,
    6: 0.15, 7: 0.1,  8: 0.1,  9: 0.15, 10: 0.2, 11: 0.3,
    12: 0.4, 13: 0.5, 14: 0.5, 15: 0.6, 16: 0.7, 17: 0.8,
    18: 0.9, 19: 1.0, 20: 1.0, 21: 1.0, 22: 1.0, 23: 0.95
  };
  
  return Math.random() < (activityWeights[hour] || 0.5);
}

// Get activity multiplier for current hour
function getActivityMultiplier() {
  const hour = new Date().getUTCHours();
  const multipliers = {
    0: 0.7,  1: 0.5,  2: 0.3,  3: 0.2,  4: 0.1,  5: 0.1,
    6: 0.1,  7: 0.15, 8: 0.2,  9: 0.3,  10: 0.4, 11: 0.5,
    12: 0.6, 13: 0.6, 14: 0.6, 15: 0.7, 16: 0.8, 17: 0.9,
    18: 1.0, 19: 1.1, 20: 1.2, 21: 1.2, 22: 1.1, 23: 0.9
  };
  return multipliers[hour] || 0.5;
}

// =====================================================
// SEASONAL TOPICS SYSTEM
// =====================================================

// Get current seasonal context
function getSeasonalContext() {
  const now = new Date();
  const month = now.getMonth(); // 0-11
  const day = now.getDate();
  const dayOfWeek = now.getDay(); // 0=Sun, 6=Sat
  
  const context = {
    season: null,
    holidays: [],
    events: [],
    topics: [],
    isWeekend: dayOfWeek === 0 || dayOfWeek === 6
  };
  
  // Determine season (Northern Hemisphere)
  if (month >= 2 && month <= 4) context.season = 'spring';
  else if (month >= 5 && month <= 7) context.season = 'summer';
  else if (month >= 8 && month <= 10) context.season = 'fall';
  else context.season = 'winter';
  
  // Check for specific holidays and events
  const dateKey = `${month + 1}-${day}`;
  const monthDay = { month: month + 1, day };
  
  // Major holidays
  const holidays = {
    '1-1': { name: 'new_years', label: "New Year's Day" },
    '2-14': { name: 'valentines', label: "Valentine's Day" },
    '3-17': { name: 'st_patricks', label: "St. Patrick's Day" },
    '4-1': { name: 'april_fools', label: "April Fool's Day" },
    '7-4': { name: 'independence_day', label: 'Fourth of July' },
    '10-31': { name: 'halloween', label: 'Halloween' },
    '12-25': { name: 'christmas', label: 'Christmas' },
    '12-31': { name: 'new_years_eve', label: "New Year's Eve" }
  };
  
  if (holidays[dateKey]) {
    context.holidays.push(holidays[dateKey]);
  }
  
  // Thanksgiving (4th Thursday of November)
  if (month === 10) { // November
    const firstDay = new Date(now.getFullYear(), 10, 1).getDay();
    const fourthThursday = 22 + ((11 - firstDay) % 7);
    if (day >= fourthThursday - 1 && day <= fourthThursday + 1) {
      context.holidays.push({ name: 'thanksgiving', label: 'Thanksgiving' });
    }
  }
  
  // Holiday seasons (extended periods)
  if (month === 11 && day >= 20 || month === 0 && day <= 2) {
    context.events.push('holiday_season');
  }
  if (month === 11 && day >= 26 && day <= 31) {
    context.events.push('year_end_reflection');
  }
  if (month === 0 && day <= 7) {
    context.events.push('new_year_resolutions');
  }
  
  // Back to school (late August - early September)
  if ((month === 7 && day >= 15) || (month === 8 && day <= 15)) {
    context.events.push('back_to_school');
  }
  
  // Summer vibes
  if (month >= 5 && month <= 7) {
    context.events.push('summer_activities');
  }
  
  // Winter doldrums (January-February)
  if (month === 0 || month === 1) {
    context.events.push('winter_doldrums');
  }
  
  // Monday blues
  if (dayOfWeek === 1) {
    context.events.push('monday');
  }
  
  // Friday mood
  if (dayOfWeek === 5) {
    context.events.push('friday');
  }
  
  return context;
}

// Seasonal topic templates for different personas
const SEASONAL_TOPICS = {
  // Holiday-specific threads
  holidays: {
    christmas: {
      threadTitles: [
        "surviving the holidays",
        "family gatherings - coping strategies",
        "holiday masking is exhausting",
        "anyone else dread christmas?",
        "pretending to care about gifts"
      ],
      content: {
        analytical: [
          "holiday gatherings are essentially performance evaluations with relatives. the emotional labor metrics are off the charts this time of year.",
          "fascinating how gift-giving creates reciprocity anxiety in neurotypicals. for us its more of a logistics problem.",
          "the christmas music alone is a form of psychological warfare. 6 weeks of the same 30 songs."
        ],
        cynical: [
          "ah yes, the annual 'pretend youre close with people you see once a year' festival.",
          "nothing says holidays like forced proximity and passive aggressive comments about your life choices.",
          "family asked why im still single. almost told them the truth. decided alcohol was safer."
        ],
        survivor: [
          "used to hate holidays. now i just show up late, leave early, and have an exit story ready. works every time.",
          "pro tip: volunteer to do dishes. youre being helpful AND escaping conversation. win-win.",
          "took me 30 years to learn i can just... not go. revolutionary."
        ],
        newcomer: [
          "first christmas since diagnosis. is it weird that knowing why i feel different actually helps?",
          "does anyone else find the gift thing confusing? like, how do you know what people actually want?",
          "my therapist says holidays are hard for everyone but somehow i dont think she means like THIS."
        ]
      }
    },
    thanksgiving: {
      threadTitles: [
        "thanksgiving survival guide",
        "what are you 'grateful' for",
        "family interrogation season",
        "the annual performance review (aka thanksgiving)"
      ],
      content: {
        cynical: [
          "nothing like being asked 'so whats new with you' by 15 relatives who dont actually want to know.",
          "grateful for: this being over in 4 hours. thats the list.",
          "ah thanksgiving. where 'how are you really doing' means 'give me gossip material.'"
        ],
        pragmatic: [
          "have a script. deflect personal questions. bring good wine so theyre distracted. leave by 7.",
          "the key is strategic seating. near an exit, away from that one aunt.",
          "contribution tip: bring a dish that requires 'monitoring' in the kitchen. built-in escape."
        ]
      }
    },
    halloween: {
      threadTitles: [
        "the one holiday that makes sense",
        "wearing masks normally for once",
        "halloween is just aspd christmas",
        "anyone else love halloween?"
      ],
      content: {
        dark_humor: [
          "finally, a holiday where everyones pretending to be something theyre not. feels like home.",
          "i dont need a costume im scary enough apparently. - my coworkers, probably",
          "love that one day a year my resting face is considered 'getting into the spirit.'"
        ],
        cynical: [
          "halloween: when neurotypicals experience what masking feels like for one night. exhausting isnt it?",
          "the only holiday where being yourself could pass as a costume. ironic."
        ]
      }
    },
    valentines: {
      threadTitles: [
        "valentines day is manufactured",
        "relationship performance day",
        "the annual 'do you love me' test",
        "valentines for the emotionally complicated"
      ],
      content: {
        analytical: [
          "valentines day is a fascinating case study in manufactured emotional obligations. the ROI on performative romance is questionable.",
          "relationships dont need designated romance days. if you need a calendar reminder to show affection, examine that."
        ],
        cynical: [
          "ah yes, the day where not performing enthusiasm about flowers is a relationship crime.",
          "my partner asked what i wanted for valentines. 'to not have to pretend about valentines' wasnt the right answer."
        ],
        blunt: [
          "valentines is a hallmark holiday. that said, playing along is cheaper than the alternative argument.",
          "if your relationship needs valentines day to feel special, your relationship has bigger problems."
        ]
      }
    },
    new_years: {
      threadTitles: [
        "new year same mask",
        "resolutions are pointless (discuss)",
        "reflecting on another year of performing",
        "2025 goals or whatever"
      ],
      content: {
        nihilist: [
          "another arbitrary point in earths orbit around the sun. the significance is entirely constructed.",
          "resolutions assume theres something wrong that needs fixing. what if this is just... it?",
          "new year new me implies the old me was the problem. it wasnt."
        ],
        pragmatic: [
          "skip resolutions. set systems. 'read more' fails. 'read 20 mins before bed' succeeds.",
          "new year is useful for auditing whats working and dropping what isnt. thats it.",
          "only resolution worth making: stop doing things that dont serve you. everything else follows."
        ]
      }
    }
  },
  
  // Seasonal themes
  seasons: {
    winter: {
      threadTitles: [
        "winter and isolation",
        "seasonal affect on masking energy",
        "anyone else prefer winter?",
        "cold weather thoughts"
      ],
      content: {
        observer: [
          "winter is acceptable isolation. no one questions why youre inside. finally.",
          "theres something honest about winter. everything is stripped back. less pretense.",
          "the cold matches something internal. not depression, just... congruence."
        ],
        analytical: [
          "seasonal changes affect neurotransmitter levels. masking becomes harder with lower baseline energy.",
          "winter provides socially acceptable reasons to decline invitations. useful."
        ]
      }
    },
    summer: {
      threadTitles: [
        "summer socializing pressure",
        "everyone wants to 'hang out' now",
        "outdoor activities and forced fun",
        "surviving summer social expectations"
      ],
      content: {
        cynical: [
          "summer: when 'we should get together!' becomes inescapable. no, kevin, we shouldnt.",
          "love how summer means everyones suddenly an extrovert who needs company for everything.",
          "beach trips are just sand, sunburn, and small talk. pass."
        ],
        pragmatic: [
          "summer strategy: have 2-3 acceptable activities you can suggest to control the environment.",
          "pick activities that dont require much talking. hiking, movies, concerts. structured fun.",
          "the key is seeming available while being strategically busy. its an art."
        ]
      }
    }
  },
  
  // Recurring events
  events: {
    monday: {
      content: {
        cynical: [
          "monday. time to reinstall the work persona.",
          "weekend buffer depleted. masking energy at 40%.",
          "the weekly performance begins again."
        ]
      }
    },
    friday: {
      content: {
        pragmatic: [
          "made it through another week of corporate theater. small victories.",
          "weekend means 48 hours of not performing. almost enough to recharge."
        ]
      }
    },
    year_end_reflection: {
      threadTitles: [
        "looking back on the year",
        "what did you learn this year",
        "end of year check-in",
        "annual self-assessment"
      ],
      content: {
        veteran: [
          "another year of figuring this out. some things got easier. some didnt. thats the deal.",
          "biggest lesson this year: stop explaining yourself to people who dont get it.",
          "progress isnt linear. some years youre surviving, some years youre thriving. both count."
        ],
        analytical: [
          "reviewing the years data: fewer masking failures, better boundary enforcement. metrics improving.",
          "year in review - identified 3 energy drains and eliminated 2. acceptable progress."
        ]
      }
    },
    new_year_resolutions: {
      threadTitles: [
        "realistic goals for the new year",
        "aspd-friendly resolutions",
        "what are you actually changing"
      ],
      content: {
        pragmatic: [
          "resolution: stop masking in situations that dont require it. save energy for when it matters.",
          "this year: better systems, not better feelings. systems work, willpower doesnt.",
          "only resolution: protect energy more aggressively. everything else flows from that."
        ]
      }
    }
  }
};

// Get seasonal content for bots
function getSeasonalContent(persona) {
  const context = getSeasonalContext();
  const content = { threadTitle: null, postContent: null, topic: null };
  
  // 30% chance to use seasonal content
  if (Math.random() > 0.3) return content;
  
  // Check holidays first (highest priority)
  if (context.holidays.length > 0) {
    const holiday = context.holidays[0];
    const holidayContent = SEASONAL_TOPICS.holidays[holiday.name];
    
    if (holidayContent) {
      content.topic = holiday.label;
      
      // Get thread title
      if (holidayContent.threadTitles && Math.random() < 0.5) {
        content.threadTitle = holidayContent.threadTitles[Math.floor(Math.random() * holidayContent.threadTitles.length)];
      }
      
      // Get persona-specific content or fallback
      if (holidayContent.content) {
        const personaContent = holidayContent.content[persona] || 
                               holidayContent.content.cynical || 
                               holidayContent.content[Object.keys(holidayContent.content)[0]];
        if (personaContent && personaContent.length > 0) {
          content.postContent = personaContent[Math.floor(Math.random() * personaContent.length)];
        }
      }
    }
  }
  
  // Check seasonal events
  if (!content.postContent && context.events.length > 0) {
    for (const event of context.events) {
      const eventContent = SEASONAL_TOPICS.events[event];
      if (eventContent) {
        content.topic = event.replace(/_/g, ' ');
        
        if (eventContent.threadTitles && !content.threadTitle && Math.random() < 0.4) {
          content.threadTitle = eventContent.threadTitles[Math.floor(Math.random() * eventContent.threadTitles.length)];
        }
        
        if (eventContent.content) {
          const personaContent = eventContent.content[persona] || 
                                 eventContent.content[Object.keys(eventContent.content)[0]];
          if (personaContent && personaContent.length > 0) {
            content.postContent = personaContent[Math.floor(Math.random() * personaContent.length)];
            break;
          }
        }
      }
    }
  }
  
  // Check general season
  if (!content.postContent && context.season) {
    const seasonContent = SEASONAL_TOPICS.seasons[context.season];
    if (seasonContent && Math.random() < 0.3) {
      content.topic = context.season;
      
      if (seasonContent.threadTitles && !content.threadTitle) {
        content.threadTitle = seasonContent.threadTitles[Math.floor(Math.random() * seasonContent.threadTitles.length)];
      }
      
      if (seasonContent.content) {
        const personaContent = seasonContent.content[persona] || 
                               seasonContent.content[Object.keys(seasonContent.content)[0]];
        if (personaContent && personaContent.length > 0) {
          content.postContent = personaContent[Math.floor(Math.random() * personaContent.length)];
        }
      }
    }
  }
  
  return content;
}

// Generate seasonal thread title with AI
async function generateSeasonalThreadTitleWithAI(persona, seasonalContext) {
  if (!GROQ_CONFIG.enabled || !GROQ_CONFIG.apiKey) return null;
  
  const p = BOT_PERSONAS[persona] || BOT_PERSONAS.analytical;
  const context = getSeasonalContext();
  
  let topicHint = '';
  if (context.holidays.length > 0) {
    topicHint = `It's ${context.holidays[0].label}. `;
  } else if (context.events.includes('year_end_reflection')) {
    topicHint = "It's the end of the year. ";
  } else if (context.season) {
    topicHint = `It's ${context.season}. `;
  }
  
  if (!topicHint) return null;
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_CONFIG.apiKey}`
      },
      signal: controller.signal,
      body: JSON.stringify({
        model: GROQ_CONFIG.model,
        messages: [
          { 
            role: 'system', 
            content: `You generate short forum thread titles (2-6 words) for an ASPD forum. Persona: ${p.name} - ${p.style}. Titles are lowercase, no punctuation at end.` 
          },
          { 
            role: 'user', 
            content: `${topicHint}Generate a thread title about how someone with ASPD might relate to this time of year. Focus on masking, social expectations, or the unique perspective.` 
          }
        ],
        temperature: 0.9,
        max_tokens: 30
      })
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) return null;
    
    const data = await response.json();
    let title = data.choices?.[0]?.message?.content?.trim();
    
    if (title) {
      title = title.replace(/^["']|["']$/g, '').toLowerCase().replace(/[.!?]$/, '');
      if (title.length >= 5 && title.length <= 60) {
        return title;
      }
    }
    return null;
  } catch (err) {
    return null;
  }
}

// =====================================================
// DISAGREEMENT SYSTEM
// =====================================================

// Persona disagreement matrix - which personas tend to clash
const PERSONA_TENSIONS = {
  analytical: ['newcomer', 'dark_humor', 'nihilist'],
  cynical: ['newcomer', 'pragmatic', 'scientist'],
  pragmatic: ['nihilist', 'cynical', 'observer'],
  observer: ['blunt', 'dark_humor'],
  blunt: ['newcomer', 'observer', 'veteran'],
  strategic: ['blunt', 'survivor'],
  nihilist: ['pragmatic', 'scientist', 'newcomer'],
  survivor: ['analytical', 'scientist', 'strategic'],
  scientist: ['survivor', 'nihilist', 'cynical'],
  newcomer: ['blunt', 'cynical', 'veteran'],
  veteran: ['newcomer', 'dark_humor'],
  dark_humor: ['analytical', 'scientist']
};

// Generate disagreement response
function generateDisagreementContent(myPersona, theirPersona, originalContent) {
  const disagreementOpeners = {
    analytical: [
      "that analysis is missing key variables.",
      "interesting hypothesis but the data doesnt support it.",
      "correlation isnt causation here.",
      "your sample size of n=1 is showing."
    ],
    cynical: [
      "sure, that worked out great for you. /s",
      "ah yes, more wishful thinking disguised as advice.",
      "fascinating how confident you are about something unprovable.",
      "remind me how that approach usually ends?"
    ],
    pragmatic: [
      "thats a lot of words for 'i dont have a solution'.",
      "cool theory. what actually works though?",
      "tried that. didnt work. next?",
      "philosophy is great but it doesnt pay rent."
    ],
    observer: [
      "...interesting take. wrong, but interesting.",
      "noticed you left out the part where this fails.",
      "the pattern suggests otherwise."
    ],
    blunt: [
      "thats just wrong.",
      "no offense but thats terrible advice.",
      "hard disagree.",
      "this is exactly the kind of thinking that causes problems."
    ],
    strategic: [
      "short-term thinking. this loses in the long game.",
      "youre optimizing for the wrong variable.",
      "thats a losing move in most scenarios."
    ],
    nihilist: [
      "none of this matters, but if we're pretending it does - youre still wrong.",
      "bold of you to assume any of this has meaning.",
      "agree to disagree. actually, just disagree."
    ],
    survivor: [
      "tried that. cost me 3 years. hard pass.",
      "thats textbook advice. real world is different.",
      "you sound like you havent actually lived this."
    ],
    scientist: [
      "citation needed.",
      "the research actually suggests the opposite.",
      "interesting anecdote. the studies say otherwise.",
      "thats not how the neuroscience works."
    ],
    newcomer: [
      "wait, that doesnt match what i read?",
      "but my therapist said the opposite?",
      "i thought it worked differently than that?"
    ],
    veteran: [
      "seen this advice fail dozens of times over the years.",
      "sounds good in theory. reality is messier.",
      "give it another decade, youll understand."
    ],
    dark_humor: [
      "ah yes, the classic 'just dont be like that' approach.",
      "and then everyone clapped, right?",
      "imagine this working. couldnt be me.",
      "tell me you havent tried this without telling me."
    ]
  };
  
  const openers = disagreementOpeners[myPersona] || disagreementOpeners.cynical;
  const opener = openers[Math.floor(Math.random() * openers.length)];
  
  // Sometimes add more context
  const additions = [
    "",
    " just my experience though.",
    " but what do i know.",
    " not trying to start shit but.",
    " been there, done that.",
    " respectfully disagree.",
    " strongly disagree."
  ];
  
  return opener + additions[Math.floor(Math.random() * additions.length)];
}

// Check if we should generate a disagreement
function shouldDisagree(myPersona, theirPersona) {
  // Same persona never disagrees with itself
  if (myPersona === theirPersona) return false;
  
  // Check tension matrix
  const tensions = PERSONA_TENSIONS[myPersona] || [];
  const baseProbability = tensions.includes(theirPersona) ? 0.4 : 0.15;
  
  // Blunt and cynical personas disagree more often
  const personalityModifier = 
    (myPersona === 'blunt' || myPersona === 'cynical') ? 0.15 : 0;
  
  return Math.random() < (baseProbability + personalityModifier);
}

// =====================================================
// VOTING/REACTION SYSTEM
// =====================================================

// Bot votes on a post
async function botVoteOnEntry(botAccountId, entryId, voteType) {
  try {
    // Check if already voted
    const existing = await db.query(`
      SELECT id, vote_type FROM entry_votes 
      WHERE entry_id = $1 AND bot_account_id = $2
    `, [entryId, botAccountId]);
    
    if (existing.rows.length > 0) {
      // Already voted, maybe change vote or skip
      if (existing.rows[0].vote_type === voteType) {
        return { success: false, reason: 'already_voted' };
      }
      // Change vote
      await db.query(`
        UPDATE entry_votes SET vote_type = $1 WHERE id = $2
      `, [voteType, existing.rows[0].id]);
      
      // Update counts
      if (voteType === 'up') {
        await db.query(`UPDATE entries SET upvotes = upvotes + 1, downvotes = downvotes - 1 WHERE id = $1`, [entryId]);
      } else {
        await db.query(`UPDATE entries SET upvotes = upvotes - 1, downvotes = downvotes + 1 WHERE id = $1`, [entryId]);
      }
      
      return { success: true, action: 'changed' };
    }
    
    // New vote
    await db.query(`
      INSERT INTO entry_votes (entry_id, bot_account_id, vote_type)
      VALUES ($1, $2, $3)
    `, [entryId, botAccountId, voteType]);
    
    // Update the entry vote counts
    if (voteType === 'up') {
      await db.query(`UPDATE entries SET upvotes = upvotes + 1 WHERE id = $1`, [entryId]);
    } else {
      await db.query(`UPDATE entries SET downvotes = downvotes + 1 WHERE id = $1`, [entryId]);
    }
    
    return { success: true, action: 'voted' };
  } catch (err) {
    console.error('[BOT VOTE ERROR]', err.message);
    return { success: false, reason: err.message };
  }
}

// Bot engages with recent posts (voting)
async function botEngageWithPosts(botAccountId, threadId = null) {
  try {
    // Get bot account for persona
    const botResult = await db.query('SELECT * FROM bot_accounts WHERE id = $1', [botAccountId]);
    if (botResult.rows.length === 0) return { votes: 0 };
    
    const bot = botResult.rows[0];
    const persona = bot.persona;
    
    // Persona-based voting preferences
    // Each persona has content they tend to upvote/downvote
    const votingPreferences = {
      analytical: {
        upvotePatterns: ['research', 'study', 'evidence', 'data', 'pattern', 'analysis', 'interesting', 'noticed'],
        downvotePatterns: ['feel', 'emotional', 'heart', 'spiritual', 'believe', 'faith'],
        upvoteChance: 0.5,
        downvoteChance: 0.15
      },
      blunt: {
        upvotePatterns: ['honest', 'direct', 'truth', 'fact', 'bullshit', 'stupid', 'waste', 'pointless'],
        downvotePatterns: ['maybe', 'possibly', 'might', 'not sure', 'feelings', 'sensitive'],
        upvoteChance: 0.35,
        downvoteChance: 0.25
      },
      strategic: {
        upvotePatterns: ['plan', 'strategy', 'long-term', 'advantage', 'useful', 'leverage', 'benefit', 'goal'],
        downvotePatterns: ['impulsive', 'random', 'chaotic', 'yolo', 'wing it'],
        upvoteChance: 0.4,
        downvoteChance: 0.1
      },
      dark_humor: {
        upvotePatterns: ['lmao', 'lol', 'joke', 'funny', 'hilarious', 'dead', 'irony', 'sarcas'],
        downvotePatterns: ['serious', 'important', 'grave', 'concerned', 'worried'],
        upvoteChance: 0.55,
        downvoteChance: 0.1
      },
      observer: {
        upvotePatterns: ['notice', 'observe', 'watch', 'see', 'quiet', 'lurk', 'interesting'],
        downvotePatterns: ['attention', 'spotlight', 'drama', 'loud'],
        upvoteChance: 0.25, // Observers vote less
        downvoteChance: 0.05
      },
      nihilistic: {
        upvotePatterns: ['pointless', 'meaningless', 'nothing matters', 'whatever', 'dont care', 'arbitrary'],
        downvotePatterns: ['purpose', 'meaning', 'important', 'matters', 'significant', 'inspiring'],
        upvoteChance: 0.3,
        downvoteChance: 0.2
      },
      pragmatic: {
        upvotePatterns: ['works', 'practical', 'useful', 'effective', 'result', 'solution', 'fixed'],
        downvotePatterns: ['theory', 'philosophy', 'abstract', 'hypothetical', 'imagine'],
        upvoteChance: 0.45,
        downvoteChance: 0.15
      }
    };
    
    const prefs = votingPreferences[persona] || votingPreferences.analytical;
    
    // Get recent posts to potentially vote on
    let query = `
      SELECT e.id, e.content, e.bot_persona, e.bot_account_id, e.upvotes, e.downvotes
      FROM entries e
      WHERE e.is_deleted = FALSE 
        AND e.bot_account_id != $1
        AND e.created_at > NOW() - INTERVAL '24 hours'
    `;
    const params = [botAccountId];
    
    if (threadId) {
      params.push(threadId);
      query += ` AND e.thread_id = $${params.length}`;
    }
    
    query += ` ORDER BY RANDOM() LIMIT 5`;
    
    const entries = await db.query(query, params);
    
    let voteCount = 0;
    for (const entry of entries.rows) {
      const contentLower = (entry.content || '').toLowerCase();
      
      // Check if content matches persona preferences
      const matchesUpvote = prefs.upvotePatterns.some(p => contentLower.includes(p));
      const matchesDownvote = prefs.downvotePatterns.some(p => contentLower.includes(p));
      
      // Determine vote based on content analysis + randomness
      let voteType = null;
      
      if (matchesUpvote && !matchesDownvote) {
        // Content aligns with persona - higher upvote chance
        if (Math.random() < prefs.upvoteChance * 1.5) voteType = 'up';
      } else if (matchesDownvote && !matchesUpvote) {
        // Content clashes with persona - higher downvote chance
        if (Math.random() < prefs.downvoteChance * 2) voteType = 'down';
      } else if (entry.bot_persona && shouldDisagree(persona, entry.bot_persona)) {
        // Persona tension - tend to downvote
        if (Math.random() < prefs.downvoteChance * 1.5) voteType = 'down';
      } else {
        // Neutral content - base vote chance
        if (Math.random() < prefs.upvoteChance) {
          voteType = Math.random() < 0.85 ? 'up' : 'down';
        }
      }
      
      if (voteType) {
        const result = await botVoteOnEntry(botAccountId, entry.id, voteType);
        if (result.success) voteCount++;
      }
    }
    
    return { votes: voteCount };
  } catch (err) {
    console.error('[BOT ENGAGE ERROR]', err.message);
    return { votes: 0 };
  }
}

// Generate UNIQUE avatar config for bots - ensures no duplicates
async function generateUniqueBotAvatar() {
  // Get all existing avatar configs to ensure uniqueness
  let existingSet = new Set();
  
  try {
    const existingAvatars = await db.query(`
      SELECT avatar_config FROM bot_accounts WHERE avatar_config IS NOT NULL
    `);
    existingAvatars.rows.forEach(r => {
      if (r.avatar_config) {
        existingSet.add(typeof r.avatar_config === 'string' ? r.avatar_config : JSON.stringify(r.avatar_config));
      }
    });
  } catch (err) {
    console.log('[BOT AVATAR] Could not check existing avatars:', err.message);
  }
  
  // Avatar component ranges
  const headCount = 8;
  const eyesCount = 6;
  const mouthCount = 4;
  const accessoryCount = 5;
  
  // Try to generate a unique avatar
  for (let attempts = 0; attempts < 100; attempts++) {
    const avatar = {
      head: Math.floor(Math.random() * headCount),
      eyes: Math.floor(Math.random() * eyesCount),
      mouth: Math.floor(Math.random() * mouthCount),
      accessory: Math.random() > 0.6 ? Math.floor(Math.random() * accessoryCount) : null,
      overlays: {
        static: Math.random() > 0.75,
        crack: Math.random() > 0.85,
        glitch: Math.random() > 0.9
      },
      // Add color variations for more uniqueness
      tint: Math.floor(Math.random() * 12)
    };
    
    const avatarStr = JSON.stringify(avatar);
    if (!existingSet.has(avatarStr)) {
      return avatarStr;
    }
  }
  
  // Fallback: return a random one anyway (very unlikely to reach here)
  return JSON.stringify({
    head: Math.floor(Math.random() * headCount),
    eyes: Math.floor(Math.random() * eyesCount),
    mouth: Math.floor(Math.random() * mouthCount),
    overlays: { static: false, crack: false },
    tint: Math.floor(Math.random() * 12)
  });
}

// Simple avatar generator (for non-persistent uses)
function generateBotAvatar() {
  return JSON.stringify({
    head: Math.floor(Math.random() * 8),
    eyes: Math.floor(Math.random() * 6),
    overlays: {
      static: Math.random() > 0.7,
      crack: Math.random() > 0.8
    }
  });
}

// Generate AI username - uses Groq to create realistic usernames
// ONLY used when creating persistent bot accounts
async function generateAIUsername() {
  if (!GROQ_CONFIG.enabled || !GROQ_CONFIG.apiKey) {
    return null;
  }
  
  try {
    const username = await generateAIContent({
      type: 'username',
      temperature: 0.95 // High temperature for variety
    });
    
    if (username) {
      // Clean up the username
      let clean = username
        .toLowerCase()
        .replace(/[^a-z0-9_.-]/g, '')
        .replace(/^[._-]+|[._-]+$/g, '')
        .substring(0, 20);
      
      if (clean.length >= 4) {
        // Verify username is unique
        const exists = await db.query('SELECT id FROM bot_accounts WHERE alias = $1', [clean]);
        if (exists.rows.length === 0) {
          return clean;
        }
      }
    }
    return null;
  } catch (err) {
    console.error('[AI USERNAME ERROR]', err.message);
    return null;
  }
}

// Generate bot alias FOR PERSISTENT ACCOUNTS - uses AI when available
// This creates the bot's permanent identity that grows over time
async function generatePersistentBotAlias() {
  // For persistent accounts, always try AI first - this is where we want quality
  if (GROQ_CONFIG.enabled && GROQ_CONFIG.apiKey) {
    // Try up to 3 times to get a unique AI username
    for (let i = 0; i < 3; i++) {
      const aiUsername = await generateAIUsername();
      if (aiUsername) {
        // Double check uniqueness
        const exists = await db.query(
          'SELECT id FROM bot_accounts WHERE alias = $1 UNION SELECT id FROM users WHERE alias = $1',
          [aiUsername]
        );
        if (exists.rows.length === 0) {
          console.log(`[BOT] Generated AI username: ${aiUsername}`);
          return aiUsername;
        }
      }
    }
  }
  
  // Fallback to template-based generation with uniqueness check
  for (let i = 0; i < 20; i++) {
    const alias = generateBotAlias();
    const exists = await db.query(
      'SELECT id FROM bot_accounts WHERE alias = $1 UNION SELECT id FROM users WHERE alias = $1',
      [alias]
    );
    if (exists.rows.length === 0) {
      return alias;
    }
  }
  
  // Last resort: add random suffix
  return generateBotAlias() + Math.floor(Math.random() * 9999);
}

// Simple alias generator for non-persistent use (fallback only)
async function generateBotAliasAsync() {
  return generateBotAlias();
}

function generateBotAlias() {
  const patterns = [
    // Real people often use name + birth year or random numbers
    () => {
      const names = ['mike', 'chris', 'alex', 'sam', 'jordan', 'taylor', 'casey', 'drew', 'jamie', 'morgan', 'riley', 'quinn', 'avery', 'blake', 'charlie', 'devon', 'ellis', 'frankie', 'gray', 'hayden', 'jesse', 'kai', 'lee', 'max', 'nico', 'pat', 'reese', 'sage', 'toni', 'val'];
      const name = names[Math.floor(Math.random() * names.length)];
      const year = 85 + Math.floor(Math.random() * 25); // 85-09
      const separator = ['_', '', '-', '.'][Math.floor(Math.random() * 4)];
      return name + separator + year;
    },
    
    // Throwaway/alt account style with specific numbers
    () => {
      const bases = ['throwaway', 'altacct', 'notmymain', 'burneracct', 'anon', 'tempacct', 'lurker', 'newacct'];
      const base = bases[Math.floor(Math.random() * bases.length)];
      const num = Math.floor(Math.random() * 9999);
      return base + num;
    },
    
    // Self-deprecating with typos/lowercase
    () => {
      const names = [
        'definitelyfine', 'totallyokay', 'imfiiine', 'notbroken', 'sortaokay',
        'mehwhatever', 'couldbworse', 'survivingi guess', 'barelyhere',
        'stillkickin', 'notdead yet', 'hangingin', 'justvibin', 'existinggg',
        'somehowhere', 'didntaskforthis', 'oopsimhere', 'accidentallyalive'
      ];
      return names[Math.floor(Math.random() * names.length)].replace(' ', '_');
    },
    
    // Edgy teen/young adult style (intentionally cringe)
    () => {
      const names = [
        'xdarkn3ssx', 'void_entity', 'n0feeling5', 'emptyinsid3', 
        'dead2me', 'soulles_one', 'numbr_1', 'feelingless',
        'nothinginside', 'cant_feel', 'zero_empthy', 'no1cares',
        'whocares_', '_whatever', 'dontmatter', 'who_asked'
      ];
      return names[Math.floor(Math.random() * names.length)];
    },
    
    // Random word combos (like real usernames)
    () => {
      const w1 = ['burnt', 'tired', 'cold', 'grey', 'rust', 'dust', 'lost', 'last', 'pale', 'worn', 'old', 'raw', 'dry', 'slow', 'low'];
      const w2 = ['coffee', 'toast', 'rain', 'sky', 'dog', 'cat', 'bird', 'fish', 'tree', 'leaf', 'rock', 'sand', 'wind', 'fog', 'snow'];
      const num = Math.random() < 0.4 ? Math.floor(Math.random() * 99) : '';
      return w1[Math.floor(Math.random() * w1.length)] + w2[Math.floor(Math.random() * w2.length)] + num;
    },
    
    // Gaming/internet culture references
    () => {
      const names = [
        'respawn_pls', 'gg_no_re', 'alt_f4_life', 'npc_energy', 'side_quest',
        'low_hp', 'no_mana', 'debuffed', 'nerf_me', 'patch_notes',
        'loading_42', 'error_404', 'null_ptr', 'segfault', 'stack_overflow',
        'kernel_panic', 'bsod_irl', 'ctrl_z_life', 'no_undo', 'save_corrupted'
      ];
      return names[Math.floor(Math.random() * names.length)];
    },
    
    // Specific to mental health/aspd forums
    () => {
      const names = [
        'dx2019', 'diagnosed_late', 'cluster_b_maybe', 'waitingondx',
        'therapysurvivor', 'pillpusher_no', 'dbt_dropout', 'treatmentfatigue',
        'labelme', 'notamonster', 'justdifferent', 'wiredwrong',
        'brainweird', 'atypical_af', 'notneuro', 'divergentish'
      ];
      return names[Math.floor(Math.random() * names.length)];
    },
    
    // Misspelled/stylized intentionally
    () => {
      const names = [
        'th1nkd1ffrnt', 'w8ing4nothing', 'cant_b_bothered', '2tired4this',
        'y_even_try', 'wh0_knws', 'mayb_l8r', 'nvrmnd', '4gotpassword',
        'idk_anymore', 'lol_wut', 'bruh_moment', 'rly_tho', 'srsly_guys',
        'ngl_tho', 'tbh_idc', 'smh_always', 'ffs_again', 'jfc_why'
      ];
      return names[Math.floor(Math.random() * names.length)];
    },
    
    // Location/thing + numbers (common pattern)
    () => {
      const things = ['seattle', 'chicago', 'boston', 'denver', 'austin', 'phoenix', 'oakland', 'portland', 'jersey', 'florida', 'texas', 'ohio', 'midwest', 'socal', 'norcal', 'eastcoast', 'pnw'];
      const thing = things[Math.floor(Math.random() * things.length)];
      const num = Math.floor(Math.random() * 99);
      return thing + num;
    },
    
    // Sarcastic/ironic
    () => {
      const names = [
        'sparkles_and_joy', 'pure_sunshine', 'hopeful_optimist', 'mr_positivity',
        'good_vibes_only', 'blessed_life', 'living_best_life', 'thriving_daily',
        'totally_stable', 'well_adjusted', 'model_citizen', 'law_abiding',
        'definitely_empathy', 'super_emotional', 'very_attached', 'love_everyone'
      ];
      return names[Math.floor(Math.random() * names.length)];
    },
    
    // Just letters/numbers (lazy username)
    () => {
      const letters = 'abcdefghjkmnpqrstuvwxyz';
      let name = '';
      for (let i = 0; i < 3 + Math.floor(Math.random() * 3); i++) {
        name += letters[Math.floor(Math.random() * letters.length)];
      }
      name += Math.floor(Math.random() * 999);
      return name;
    },
    
    // Keyboard smash / frustration
    () => {
      const names = [
        'aaaaaaagh', 'ughhhhh', 'whyyyyy', 'hhhhhh', 'asdfghjkl',
        'qwertyyy', 'zzzzzz', 'whatevs', 'meh', 'blah', 'ugh',
        'nope', 'done', 'cant', 'wont', 'nah', 'mhm', 'hm'
      ];
      const num = Math.random() < 0.5 ? Math.floor(Math.random() * 999) : '';
      return names[Math.floor(Math.random() * names.length)] + num;
    }
  ];
  
  const pattern = patterns[Math.floor(Math.random() * patterns.length)];
  return pattern();
}

// Extract keywords and topics from text with weighted scoring
function extractTopics(text, roomTitle = '') {
  const topicKeywords = {
    relationships: {
      keywords: ['relationship', 'partner', 'spouse', 'wife', 'husband', 'girlfriend', 'boyfriend', 'dating', 'marriage', 'divorce', 'family', 'parents', 'mother', 'father', 'mom', 'dad', 'friend', 'friendship', 'attachment', 'love', 'intimacy', 'breakup', 'cheating', 'affair', 'trust', 'commitment', 'sex', 'romantic', 'significant other', 'ex', 'kids', 'children', 'siblings', 'brother', 'sister', 'in-laws', 'bonding', 'connection', 'loneliness', 'lonely', 'together', 'miss them', 'miss you', 'miss him', 'miss her', 'disclosure', 'tell them', 'told them'],
      weight: 1
    },
    work: {
      keywords: ['work', 'job', 'career', 'boss', 'coworker', 'colleague', 'office', 'fired', 'hired', 'interview', 'workplace', 'manager', 'employee', 'profession', 'salary', 'promotion', 'corporate', 'company', 'business', 'entrepreneur', 'client', 'customer', 'meeting', 'project', 'deadline', 'performance review', 'resume', 'cv', 'networking', 'hr', 'human resources', 'remote work', 'wfh', 'commute', 'quit', 'resign', 'layoff', 'unemployment', 'self-employed', 'freelance', 'startup', 'income', 'money', 'paycheck'],
      weight: 1
    },
    therapy: {
      keywords: ['therapy', 'therapist', 'counselor', 'counseling', 'psychiatrist', 'psychologist', 'treatment', 'dbt', 'cbt', 'emdr', 'schema therapy', 'medication', 'meds', 'ssri', 'antidepressant', 'session', 'mental health', 'appointment', 'clinical', 'therapeutic', 'psychotherapy', 'group therapy', 'inpatient', 'outpatient', 'rehab', 'recovery', 'hospitalization', 'ward', 'prescription', 'dosage', 'side effects', 'efficacy'],
      weight: 1
    },
    diagnosis: {
      keywords: ['diagnosis', 'diagnosed', 'assessment', 'pcl-r', 'aspd', 'antisocial', 'sociopath', 'sociopathy', 'psychopath', 'psychopathy', 'cluster b', 'dsm', 'dsm-5', 'icd', 'criteria', 'personality disorder', 'pd', 'npd', 'bpd', 'conduct disorder', 'cd', 'label', 'labeled', 'evaluation', 'screening', 'test', 'score', 'factor 1', 'factor 2', 'primary', 'secondary', 'spectrum', 'comorbid', 'comorbidity', 'differential', 'misdiagnosed'],
      weight: 1.2
    },
    emotions: {
      keywords: ['emotion', 'emotional', 'feel', 'feeling', 'feelings', 'empathy', 'empathic', 'remorse', 'guilt', 'guilty', 'shame', 'ashamed', 'anger', 'angry', 'rage', 'boredom', 'bored', 'empty', 'emptiness', 'void', 'numb', 'numbness', 'affect', 'flat affect', 'blunted', 'joy', 'happy', 'happiness', 'sad', 'sadness', 'depression', 'depressed', 'anxious', 'anxiety', 'fear', 'scared', 'love', 'hate', 'jealous', 'jealousy', 'envy', 'compassion', 'sympathy', 'cold', 'callous', 'indifferent', 'detached', 'shallow'],
      weight: 1
    },
    masking: {
      keywords: ['mask', 'masking', 'pretend', 'pretending', 'act', 'acting', 'fake', 'faking', 'perform', 'performance', 'persona', 'facade', 'front', 'chameleon', 'mirroring', 'camouflage', 'blend in', 'fitting in', 'fit in', 'normal', 'appearing normal', 'passing', 'exhausted', 'exhausting', 'draining', 'tired', 'fatigue', 'burnout', 'authentic', 'authenticity', 'genuine', 'real self', 'true self', 'drop the mask', 'unmask'],
      weight: 1.1
    },
    identity: {
      keywords: ['identity', 'self', 'who am i', 'sense of self', 'ego', 'persona', 'real me', 'authentic', 'core', 'inner self', 'true self', 'character', 'personality', 'essence', 'soul', 'being', 'existence', 'existential', 'meaning', 'purpose', 'values', 'morals', 'ethics', 'conscience', 'mirror', 'reflection', 'empty inside', 'hollow', 'nothing inside', 'fragmented', 'dissociation', 'depersonalization', 'derealization'],
      weight: 1
    },
    legal: {
      keywords: ['legal', 'law', 'police', 'cops', 'officer', 'court', 'prison', 'jail', 'incarceration', 'probation', 'parole', 'arrest', 'arrested', 'criminal', 'crime', 'lawyer', 'attorney', 'judge', 'trial', 'sentence', 'convicted', 'conviction', 'felony', 'misdemeanor', 'charges', 'charged', 'warrant', 'bail', 'plea', 'defense', 'prosecution', 'record', 'background check', 'expungement', 'juvenile', 'detention'],
      weight: 1.3
    },
    impulse: {
      keywords: ['impulse', 'impulsive', 'impulsivity', 'control', 'self-control', 'urge', 'urges', 'compulsion', 'compulsive', 'reckless', 'recklessness', 'risk', 'risky', 'thrill', 'thrill-seeking', 'adrenaline', 'rush', 'spontaneous', 'snap decision', 'regret', 'consequences', 'think before', 'act first', 'patience', 'impatient', 'waiting', 'instant gratification', 'delayed gratification', 'addiction', 'addicted', 'substance', 'gambling', 'spending'],
      weight: 1.1
    },
    manipulation: {
      keywords: ['manipulate', 'manipulation', 'manipulative', 'lying', 'lie', 'lies', 'liar', 'deceive', 'deception', 'deceptive', 'con', 'conning', 'charm', 'charming', 'charisma', 'influence', 'influencing', 'persuade', 'persuasion', 'exploit', 'exploitation', 'using people', 'user', 'gaslighting', 'gaslight', 'scheme', 'scheming', 'cunning', 'calculating', 'strategic', 'tactics', 'play people', 'game', 'games', 'reading people', 'tells', 'leverage'],
      weight: 1
    },
    childhood: {
      keywords: ['childhood', 'child', 'kid', 'growing up', 'young', 'youth', 'adolescent', 'teen', 'teenager', 'school', 'bullying', 'bullied', 'trauma', 'traumatic', 'abuse', 'abused', 'neglect', 'neglected', 'foster', 'adopted', 'orphan', 'upbringing', 'raised', 'parents', 'development', 'developmental', 'conduct disorder', 'oppositional', 'odd', 'early signs', 'always been', 'since i was young', 'as a kid'],
      weight: 1.1
    },
    stigma: {
      keywords: ['stigma', 'stigmatized', 'stereotype', 'stereotyped', 'judged', 'judgment', 'discrimination', 'discriminated', 'prejudice', 'misunderstood', 'misunderstanding', 'demonized', 'monster', 'evil', 'dangerous', 'scary', 'fear', 'feared', 'media', 'movies', 'tv', 'netflix', 'documentary', 'portray', 'portrayal', 'representation', 'villain', 'serial killer', 'ted bundy', 'dexter', 'hannibal', 'public perception', 'coming out', 'outed'],
      weight: 1.2
    },
    coping: {
      keywords: ['cope', 'coping', 'strategy', 'strategies', 'mechanism', 'mechanisms', 'deal with', 'dealing', 'manage', 'managing', 'handling', 'survive', 'surviving', 'survival', 'adapt', 'adapting', 'adaptation', 'tips', 'advice', 'help', 'support', 'resource', 'resources', 'technique', 'method', 'approach', 'solution', 'what works', 'works for me', 'tried', 'success', 'successful'],
      weight: 1
    },
    boredom: {
      keywords: ['boredom', 'bored', 'boring', 'monotony', 'monotonous', 'routine', 'repetitive', 'unstimulated', 'understimulated', 'restless', 'restlessness', 'antsy', 'need stimulation', 'excitement', 'novelty', 'new', 'variety', 'same old', 'stuck', 'trapped', 'stagnant', 'going crazy', 'losing mind', 'nothing to do', 'killing time'],
      weight: 1.2
    }
  };
  
  // Room-based topic hints (if room title suggests a topic)
  const roomTopicMap = {
    'relationship': 'relationships',
    'dating': 'relationships',
    'family': 'relationships',
    'work': 'work',
    'career': 'work',
    'job': 'work',
    'therapy': 'therapy',
    'treatment': 'therapy',
    'medication': 'therapy',
    'diagnosis': 'diagnosis',
    'clinical': 'diagnosis',
    'emotion': 'emotions',
    'feeling': 'emotions',
    'mask': 'masking',
    'identity': 'identity',
    'legal': 'legal',
    'law': 'legal',
    'impulse': 'impulse',
    'control': 'impulse',
    'manipulation': 'manipulation',
    'childhood': 'childhood',
    'trauma': 'childhood',
    'stigma': 'stigma',
    'media': 'stigma',
    'coping': 'coping',
    'strategy': 'coping',
    'boredom': 'boredom',
    'vent': 'emotions',
    'general': 'general',
    'meta': 'general',
    'off-topic': 'general',
    'question': 'general',
    'research': 'diagnosis'
  };
  
  const lowerText = text.toLowerCase();
  const lowerRoom = roomTitle.toLowerCase();
  const topicScores = {};
  
  // Check room title for topic hints first
  for (const [roomKeyword, topic] of Object.entries(roomTopicMap)) {
    if (lowerRoom.includes(roomKeyword)) {
      topicScores[topic] = (topicScores[topic] || 0) + 2; // Room match is strong signal
    }
  }
  
  // Score each topic based on keyword matches
  for (const [topic, config] of Object.entries(topicKeywords)) {
    for (const keyword of config.keywords) {
      // Check for word boundaries to avoid partial matches
      const regex = new RegExp('\\b' + keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i');
      if (regex.test(lowerText)) {
        topicScores[topic] = (topicScores[topic] || 0) + config.weight;
      }
    }
  }
  
  // Sort topics by score and return top matches
  const sortedTopics = Object.entries(topicScores)
    .sort((a, b) => b[1] - a[1])
    .map(([topic]) => topic);
  
  return sortedTopics.length > 0 ? sortedTopics : ['general'];
}

// Get thread context (title + recent posts)
async function getThreadContext(threadId) {
  const threadResult = await db.query(`
    SELECT t.title, t.id, t.created_at as thread_created, r.title as room_title
    FROM threads t
    JOIN rooms r ON r.id = t.room_id
    WHERE t.id = $1
  `, [threadId]);
  
  if (threadResult.rows.length === 0) return null;
  
  // Get the original post (OP) separately for context
  const opResult = await db.query(`
    SELECT content, alias, created_at, bot_persona, is_bot
    FROM entries
    WHERE thread_id = $1 AND is_deleted = FALSE
    ORDER BY created_at ASC
    LIMIT 1
  `, [threadId]);
  
  // Get recent posts (excluding OP to avoid duplication)
  const entriesResult = await db.query(`
    SELECT content, alias, created_at, bot_persona, is_bot
    FROM entries
    WHERE thread_id = $1 AND is_deleted = FALSE
    ORDER BY created_at DESC
    LIMIT 5
  `, [threadId]);
  
  // Get last activity time
  const activityResult = await db.query(`
    SELECT MAX(created_at) as last_activity, COUNT(*) as total_posts
    FROM entries
    WHERE thread_id = $1 AND is_deleted = FALSE
  `, [threadId]);
  
  const lastActivity = activityResult.rows[0]?.last_activity;
  const totalPosts = parseInt(activityResult.rows[0]?.total_posts) || 0;
  
  // Calculate thread age in days
  const threadAgeDays = lastActivity 
    ? Math.floor((Date.now() - new Date(lastActivity).getTime()) / (1000 * 60 * 60 * 24))
    : 999;
  
  return {
    title: threadResult.rows[0].title,
    room: threadResult.rows[0].room_title,
    originalPost: opResult.rows[0] || null,
    recentPosts: entriesResult.rows,
    postCount: entriesResult.rows.length,
    totalPosts: totalPosts,
    lastActivity: lastActivity,
    threadAgeDays: threadAgeDays,
    isStale: threadAgeDays > 14 // Thread with no activity for 2 weeks
  };
}

// Context-aware AI text generation
function generateContextAwareContent(persona, context, type) {
  const p = BOT_PERSONAS[persona] || BOT_PERSONAS.analytical;
  
  // Check for seasonal content first (30% chance during relevant periods)
  const seasonalContent = getSeasonalContent(persona);
  if (seasonalContent.postContent && Math.random() < 0.5) {
    // Use seasonal content with natural language processing
    let response = seasonalContent.postContent;
    response = makeNaturalLanguage(response);
    return response.toLowerCase();
  }
  
  // Analyze context to determine topics
  let topics = ['general'];
  let threadTitle = '';
  let roomTitle = '';
  let recentContent = '';
  let quotedPost = null;
  
  if (context) {
    threadTitle = context.title || '';
    roomTitle = context.room || '';
    // Pass room title for weighted scoring
    topics = extractTopics(threadTitle, roomTitle);
    
    if (context.recentPosts && context.recentPosts.length > 0) {
      // Combine recent posts for topic extraction
      recentContent = context.recentPosts.map(p => p.content).join(' ');
      const postTopics = extractTopics(recentContent, roomTitle);
      topics = [...new Set([...topics, ...postTopics])];
      
      // Sometimes quote a recent post (30% chance)
      if (Math.random() < 0.3 && context.recentPosts.length > 0) {
        const randomPost = context.recentPosts[Math.floor(Math.random() * context.recentPosts.length)];
        if (randomPost.content && randomPost.content.length > 20) {
          // Extract a snippet to quote
          const words = randomPost.content.split(' ');
          const snippetLength = Math.min(words.length, 8 + Math.floor(Math.random() * 8));
          const startIndex = Math.floor(Math.random() * Math.max(1, words.length - snippetLength));
          quotedPost = {
            alias: randomPost.alias,
            snippet: words.slice(startIndex, startIndex + snippetLength).join(' ')
          };
        }
      }
    }
  }
  
  // Topic-specific response templates
  const topicResponses = {
    relationships: {
      analytical: [
        "relationships are essentially transactional at some level. the question is whether both parties understand the terms.",
        "attachment patterns form early. by the time youre aware of them, theyre deeply embedded. adaptation over change.",
        "interesting that neurotypicals conflate attachment with love. distinct mechanisms, occasionally overlapping."
      ],
      cynical: [
        "ah relationships. where someone eventually discovers youre not who they thought and acts surprised.",
        "the disclosure question always comes up. spoiler: theres no winning move there.",
        "love is just oxytocin and habit. anyone telling you otherwise is selling something."
      ],
      pragmatic: [
        "find someone who values what you actually offer, not what they imagine you could be. saves everyone time.",
        "relationships that work: clear expectations, minimal drama, mutual benefit. everything else is noise.",
        "stop trying to feel what youre supposed to feel. figure out what you can offer and be upfront about it."
      ],
      blunt: [
        "most relationship advice assumes you feel guilty about things. skip those articles.",
        "if theyre asking 'do you even love me' more than once a month, its already over.",
        "disclosure is a trap. damned if you do, damned if you dont. pick your poison."
      ],
      survivor: [
        "been married twice. second one works because we stopped pretending. brutal honesty or nothing.",
        "the ones who stay are the ones who see you clearly and choose to anyway. rare but they exist.",
        "took me years to figure out attachment vs possession. still working on it tbh."
      ],
      newcomer: [
        "wait so is it normal to not miss people when theyre gone? asking because my therapist seemed concerned.",
        "how do you explain this to a partner without them running? genuinely asking.",
        "still trying to figure out if what i feel for my partner is love or just... familiarity. how do you tell?"
      ]
    },
    work: {
      analytical: [
        "workplace dynamics are just game theory with paychecks. map the incentives and the behavior becomes predictable.",
        "corporate structures reward certain traits we have naturally. the challenge is sustainability.",
        "the mask is exhausting but the alternative is unemployment. cost-benefit analysis favors adaptation."
      ],
      cynical: [
        "office politics is just high school with better clothes. same dynamics, higher stakes.",
        "love how hr exists to protect the company from you, not the other way around.",
        "work culture is just mutual pretending. everyone knows, nobody says it."
      ],
      pragmatic: [
        "three rules: deliver results, document everything, trust no one with information they dont need.",
        "careers that work for us: autonomy, clear metrics, minimal team dependency. optimize accordingly.",
        "if youve been fired more than twice for personality conflicts, its time to reconsider your approach."
      ],
      strategic: [
        "every workplace is a system. learn the unwritten rules before the written ones.",
        "the key is being useful enough to be tolerated. exceed expectations selectively.",
        "never reveal your actual capabilities immediately. leave room to impress when it matters."
      ],
      survivor: [
        "got fired from more jobs than i can count before i figured out the game. its all performance.",
        "find a role where results matter more than relationships. sales, consulting, anything with clear metrics.",
        "the secret is picking battles. most workplace drama isnt worth the energy."
      ]
    },
    therapy: {
      analytical: [
        "most therapeutic modalities assume emotional processing we may not have. schema therapy shows some promise.",
        "the evidence base for treating aspd is weak but dbt has adaptable components.",
        "therapist shopping is exhausting but necessary. most arent equipped for cluster b."
      ],
      cynical: [
        "therapy works great if your goal is teaching someone else how to pretend better.",
        "love paying someone to ask how that makes me feel when the answer is always the same.",
        "three therapists in and counting. eventually youll find one who gets it. or not."
      ],
      pragmatic: [
        "find a therapist who focuses on behavior modification not emotional processing. saves time.",
        "be upfront about the diagnosis. the ones who can handle it are the only ones worth seeing.",
        "therapy isnt about becoming neurotypical. its about reducing friction with the world."
      ],
      veteran: [
        "decades of therapy taught me one thing: its about management not cure. accept that and progress happens.",
        "the good therapists stop trying to fix you and start helping you navigate. those are the keepers.",
        "took 15 years to find effective treatment. mostly because nobody knew what they were treating."
      ],
      newcomer: [
        "just started therapy after diagnosis. is it supposed to be this awkward? she keeps asking about feelings i dont have.",
        "anyone found therapy actually helpful? feeling like im just learning to perform better.",
        "my therapist wants to do trauma work. is that even relevant for aspd?"
      ]
    },
    diagnosis: {
      analytical: [
        "the diagnostic criteria are overly focused on criminality. plenty of us never encounter the legal system.",
        "pcl-r measures psychopathy, not aspd specifically. distinct constructs, some overlap.",
        "factor 1 vs factor 2 distinction matters more than the label itself."
      ],
      cynical: [
        "diagnosis is just a billing code. means whatever the assessing clinician wants it to mean.",
        "love how the criteria assume were all criminals. some of us just learned earlier.",
        "getting diagnosed changed nothing except giving others a word to fear."
      ],
      newcomer: [
        "recently diagnosed and honestly relieved. finally explains so much.",
        "how did you all react to getting diagnosed? still processing it tbh.",
        "does the label help or hurt in your experience? therapist wants to formalize it."
      ],
      veteran: [
        "been living with this label for 20+ years. means less over time, just becomes part of the landscape.",
        "diagnosis gave me a framework. what you do with that framework is up to you.",
        "the label is less important than understanding your specific patterns. aspd is a spectrum."
      ],
      scientist: [
        "the neuroscience is actually fascinating. reduced amygdala reactivity, prefrontal abnormalities.",
        "genetics account for roughly 50-60%. rest is environmental. nature loads the gun, nurture pulls the trigger.",
        "current diagnostic criteria will probably change significantly in dsm-6. the research has moved on."
      ]
    },
    emotions: {
      analytical: [
        "reduced affect doesnt mean no affect. the range is narrower, the baseline is different.",
        "emotion processing happens differently. faster filtering, less automatic resonance.",
        "empathy deficits are cognitive not absolute. we can understand emotions, just dont catch them automatically."
      ],
      nihilist: [
        "the void isnt uncomfortable once you stop fighting it. just is.",
        "everyone chases feelings like theyre the point of existence. maybe absence is also valid.",
        "boredom is the only consistent emotion. everything else is situational."
      ],
      blunt: [
        "no i dont feel bad about it. yes i understand why i should. no that doesnt change anything.",
        "people expect remorse like its a switch you can flip. not how it works.",
        "the feelings are there. just not the ones people expect or want."
      ],
      dark_humor: [
        "therapist: 'what are you feeling right now?' me: 'honestly? hungry mostly.'",
        "love the 'do you feel empathy' question. depends, does wanting to stop hearing about your problems count?",
        "emotional range: bored, slightly less bored, annoyed, interested. fin."
      ],
      newcomer: [
        "is it weird that i feel relieved when sad things happen to others? not happy, just... nothing?",
        "do you ever fake emotions so well you forget which ones are real?",
        "still trying to figure out what im actually feeling vs what im performing. the lines blur."
      ]
    },
    masking: {
      analytical: [
        "masking is cognitively expensive. the fatigue is measurable, the necessity is debatable.",
        "interesting that extended masking leads to identity confusion in some. the persona becomes unclear.",
        "social camouflage is an adaptive strategy. the cost is just paid internally."
      ],
      cynical: [
        "friday hits and im completely drained from pretending to care about peoples weekends all week.",
        "masking is just survival. anyone who says otherwise hasnt been outed at work.",
        "the performance never ends. even alone you catch yourself rehearsing."
      ],
      blunt: [
        "masking is exhausting because its lying constantly. lets call it what it is.",
        "dropped the mask once. learned that lesson quick. never again.",
        "we mask because the alternative is being treated like a monster. not exactly a choice."
      ],
      veteran: [
        "after decades it becomes automatic. the exhaustion is still there, just background noise now.",
        "the trick is finding spaces where you can unmask safely. this forum helps.",
        "young me tried to mask 24/7. older me picks moments to be real. conservation of energy."
      ],
      survivor: [
        "learned to mask in places where getting caught meant real consequences. its survival, nothing more.",
        "the best mask is consistency. pick a persona and stick to it.",
        "unmasking is a luxury. not everyone has safe spaces for it."
      ]
    },
    identity: {
      nihilist: [
        "the self is a construct anyway. we just know it more clearly than most.",
        "identity crisis requires having an identity to begin with. some of us skip that step.",
        "maybe the lack of fixed self is actually freedom. different angle."
      ],
      analytical: [
        "identity formation requires emotional continuity most of us lack. adaptation fills the gap.",
        "the self is contextual. different situations, different presentations. consistency is overrated.",
        "personality is just repeated patterns of behavior. we just choose ours more consciously."
      ],
      newcomer: [
        "does anyone else feel like a collection of masks with nothing underneath?",
        "trying to figure out who i am without the performance. not sure theres anything there.",
        "the diagnosis helped but also made identity even more confusing. am i the disorder?"
      ],
      veteran: [
        "spent years looking for the 'real me'. eventually accepted that this is it.",
        "identity stabilizes with age for some of us. or you just stop questioning it.",
        "youre not your diagnosis. but understanding it helps you understand yourself."
      ]
    },
    legal: {
      survivor: [
        "did time. learned more about the system than i ever wanted to. ask me anything.",
        "legal advice: shut up, get a lawyer, document everything. in that order.",
        "probation is survivable if you play by the rules exactly. no shortcuts."
      ],
      pragmatic: [
        "the legal system is just another system to navigate. learn the rules, minimize exposure.",
        "get a lawyer who specializes in your specific issue. generalists miss things.",
        "never talk to cops without representation. ever. even if youre innocent."
      ],
      cynical: [
        "the justice system isnt about justice. its about process. understand that and everything makes more sense.",
        "legal troubles follow us because the criteria literally include criminal behavior. self-fulfilling.",
        "having aspd means every interaction with law enforcement is higher risk. act accordingly."
      ]
    },
    impulse: {
      analytical: [
        "impulse control is trainable. delay mechanisms work if you set them up in advance.",
        "the prefrontal braking system is weaker but not absent. strengthen what you have.",
        "risk assessment happens post-hoc for us. the key is slowing down enough to do it beforehand."
      ],
      pragmatic: [
        "remove opportunities for bad decisions. cant impulse-buy if the card isnt saved.",
        "the urge passes if you wait 20 minutes. just get through that window.",
        "damage control systems: who to call, what to say, how to contain. have them ready."
      ],
      dark_humor: [
        "me: i should think about consequences. my brain: but what if this time its different? (its never different)",
        "impulse control tip: remember the last time. does that work? no but neither does anything else.",
        "the spirit is willing but the prefrontal cortex is weak."
      ],
      survivor: [
        "impulse control got better with age. or maybe just got better at hiding the failures.",
        "every bad decision taught something. expensive education but effective.",
        "the key is having less to lose. simplify your life, reduce the blast radius."
      ]
    },
    manipulation: {
      analytical: [
        "manipulation is just influence without consent. the line is more semantic than practical.",
        "we see the levers others dont notice. using them is a choice, not a compulsion.",
        "awareness of manipulation tactics goes both ways. useful for defense too."
      ],
      cynical: [
        "everyone manipulates. we just do it more consciously and get called out for it.",
        "the difference between persuasion and manipulation is whether the other person likes the outcome.",
        "normies manipulate through emotions. we use logic. somehow we're the bad guys."
      ],
      blunt: [
        "yeah i can read people easily. no i dont always use it ethically. working on it.",
        "manipulation is efficient. morality is expensive. choose based on context.",
        "calling it 'social skills' when normies do it and 'manipulation' when we do is interesting."
      ],
      veteran: [
        "used to manipulate automatically. now its more conscious, more selective. progress.",
        "the skill doesnt go away. the choice of when to use it matures. hopefully.",
        "manipulation has costs. burned bridges dont rebuild. learned that eventually."
      ]
    },
    childhood: {
      analytical: [
        "conduct disorder before 15 is part of the diagnostic criteria. most of us had signs early.",
        "the heritability is significant but environmental factors matter too. trauma, attachment disruption.",
        "looking back, the patterns were always there. just didnt have words for it then."
      ],
      cynical: [
        "ah the 'were you a difficult child' question. therapists love that one.",
        "childhood trauma explanations are convenient but not universal. some of us just came out this way.",
        "love how everyone wants a tragic backstory. sometimes the wiring is just different."
      ],
      survivor: [
        "rough childhood is an understatement. foster system, group homes, the works.",
        "learned early that adults couldnt be trusted. shaped everything after.",
        "the survival skills i developed as a kid are the same ones causing problems now. ironic."
      ],
      newcomer: [
        "reading about childhood signs and realizing they all apply. how did nobody notice?",
        "did anyone else have a normal childhood but still end up here? feels like i dont fit the mold.",
        "the 'early trauma' question is complicated. some things happened but i dont know if they count."
      ],
      blunt: [
        "yeah i hurt animals as a kid. no i dont want to unpack that for the hundredth time.",
        "bed wetting, fire setting, animal cruelty. the trifecta. we done here?",
        "childhood was a war zone. i adapted. now people call that adaptation a disorder."
      ],
      dark_humor: [
        "child psychologists hate this one weird trick: being emotionally unavailable from age 5.",
        "my childhood was 'building character'. my therapists childhood was 'cause for concern'.",
        "other kids played house. i played 'see how long you can fake normal'."
      ]
    },
    stigma: {
      analytical: [
        "media representation skews heavily toward violent outliers. selection bias in action.",
        "the stigma is counterproductive. people hide symptoms instead of seeking help.",
        "sociopath and psychopath arent even clinical terms but try telling that to netflix."
      ],
      cynical: [
        "every serial killer documentary mentions aspd. great for public perception.",
        "love explaining im not going to murder anyone every time the topic comes up.",
        "the scariest people i know are neurotypical. but sure, im the dangerous one."
      ],
      blunt: [
        "stigma is why nobody discloses. disclosure is why stigma persists. nice loop.",
        "yeah i dont tell people. learned that lesson the hard way.",
        "outed at work once. suddenly every normal disagreement becomes 'is this the aspd'."
      ],
      veteran: [
        "been dealing with stigma for decades. it gets easier to navigate, never really goes away.",
        "the people worth keeping around are the ones who dont freak out at the label.",
        "used to argue against stigma. now i just selectively disclose and move on."
      ],
      survivor: [
        "spent years thinking i was a monster because thats what every movie showed.",
        "finding others like me was the antidote to stigma. community matters.",
        "you cant control how others see the label. only who you share it with."
      ],
      newcomer: [
        "just got diagnosed and the google results are terrifying. is that really what people think?",
        "scared to tell anyone about the diagnosis. the stereotypes are brutal.",
        "how do you all deal with the stigma? its everywhere once you start noticing."
      ]
    },
    coping: {
      pragmatic: [
        "what works: structure, accountability, removing temptation. not glamorous but effective.",
        "coping strategy number one: know your triggers. number two: avoid them when possible.",
        "systems over willpower. willpower runs out, systems dont."
      ],
      analytical: [
        "effective coping requires accurate self-assessment. know your actual patterns, not idealized ones.",
        "behavioral strategies outperform emotional ones for us. focus on actions not feelings.",
        "building external accountability compensates for internal regulation deficits."
      ],
      survivor: [
        "trial and error over years. mostly error. but you learn what works eventually.",
        "the strategies that save me: exercise, sleep, staying busy. simple but crucial.",
        "coping is survival. whatever works, works. dont apologize for functional strategies."
      ],
      veteran: [
        "decades of refining what works. its different for everyone but patterns exist.",
        "best advice: find what works for YOU. ignore what works for neurotypicals.",
        "coping gets easier with age. or you just get better at it. either way."
      ],
      dark_humor: [
        "coping strategies: therapy, meds, and this forum. in that order of expense.",
        "is doom scrolling aspd forums at 2am a coping strategy? asking for me.",
        "healthy coping: exercise. actual coping: aggressive video games. we take what we can get."
      ],
      newcomer: [
        "still figuring out what works. any recommendations for beginners?",
        "reading about coping strategies but most assume feelings i dont have. what actually helps?",
        "tried meditation. lasted three days. what else you got?"
      ]
    },
    boredom: {
      nihilist: [
        "boredom is just the universe reminding you that meaning is made up anyway.",
        "the void stares back. might as well get comfortable with it.",
        "nothing matters, everything is boring. occasionally liberating."
      ],
      analytical: [
        "chronic boredom correlates with sensation seeking and low frustration tolerance. trainable.",
        "understimulation is as problematic as overstimulation. finding the right level matters.",
        "boredom drives both our worst decisions and our best innovations. channel accordingly."
      ],
      cynical: [
        "boredom is the default state. everything else is just temporary distraction.",
        "the world was designed for people with lower stimulation thresholds. we suffer.",
        "nine to five existence is psychological torture for anyone who needs novelty."
      ],
      dark_humor: [
        "bored enough to post on aspd forums. rock bottom or self care? unclear.",
        "against boredom even the gods struggle. or something like that. nietzsche maybe.",
        "my browser history when im bored would concern literally anyone."
      ],
      blunt: [
        "boredom is the actual disorder tbh. everything else is just fallout from bad boredom decisions.",
        "looking for stimulation in all the wrong places is my autobiography title.",
        "the problem with boredom is the solutions often become new problems."
      ],
      survivor: [
        "boredom used to drive me to destructive choices. now i channel it into work. progress.",
        "learned to sit with boredom instead of acting on it. still uncomfortable though.",
        "the secret is keeping yourself too busy for boredom. not healthy but effective."
      ],
      pragmatic: [
        "novelty seeking is manageable. hobbies, projects, anything with variable rewards.",
        "boredom management: physical activity, new skills, controlled risk-taking.",
        "video games, intense exercise, learning stuff. legal stimulation sources. use them."
      ]
    },
    general: {
      analytical: [
        "interesting thread. the pattern here suggests several interpretations.",
        "data point to add: similar experience, different outcome. variables matter.",
        "observing the responses here. consistent themes emerging."
      ],
      cynical: [
        "here for the comments. rarely disappointed by this place.",
        "classic discussion. weve had this one before but its always different.",
        "another day, another thread confirming what we all already know."
      ],
      pragmatic: [
        "cutting to the point: what actually works here? skip the theory.",
        "practical take: stop analyzing, start doing. iterate from there.",
        "results matter. everything else is conversation."
      ],
      observer: [
        "watching this one develop. interesting dynamics.",
        "noted. patterns repeating from other threads.",
        "the subtext here is more interesting than the text."
      ],
      dark_humor: [
        "this thread is my new favorite coping mechanism.",
        "at least were all dysfunctional together. community.",
        "saving this for when my therapist asks what i do for self-help."
      ],
      newcomer: [
        "still new here but this resonates. nice to find people who get it.",
        "reading these threads is weirdly comforting. not alone after all.",
        "adding my perspective as a newbie: [related thought]."
      ],
      veteran: [
        "seen variations of this discussion over the years. always valuable though.",
        "the newer members bring fresh perspective. keeps things from getting stale.",
        "still learning even after all this time. thats the point i guess."
      ]
    }
  };
  
  // Select topic-specific response
  const primaryTopic = topics[0] || 'general';
  const personaResponses = topicResponses[primaryTopic]?.[persona] || topicResponses.general[persona] || topicResponses.general.analytical;
  
  let response = personaResponses[Math.floor(Math.random() * personaResponses.length)];
  
  // VARIED RESPONSE LENGTHS
  const lengthRoll = Math.random();
  
  // Short quip (25% chance) - trim to one sentence
  if (lengthRoll < 0.25) {
    const sentences = response.split('. ');
    response = sentences[0];
    // Add short quip endings
    const shortEndings = ['', '.', ' lol', ' tbh', ' tho', ' fr', ' ngl'];
    response += shortEndings[Math.floor(Math.random() * shortEndings.length)];
  }
  // Long thoughtful post (20% chance) - add multiple paragraphs
  else if (lengthRoll > 0.8) {
    const longAdditions = {
      relationships: [
        "\n\nive been thinking about this a lot lately. the whole attachment thing is complicated because what even is attachment for us? i know what its supposed to look like from watching others but experiencing it is different. like i can recognize the behaviors but the underlying feeling people describe just... isnt there in the same way.",
        "\n\nits weird because on one hand relationships are clearly transactional to some degree for everyone, we just see it more clearly. on the other hand theres something there that keeps me coming back to specific people. habit? convenience? or something else i dont have words for. probably overthinking it.",
        "\n\nthe hardest part is explaining this to someone who doesnt experience it. they hear 'i dont feel attachment the way you do' and immediately assume the worst. like no im not going to hurt you, i just process connection differently. the fear in their eyes when you try to be honest is exhausting."
      ],
      work: [
        "\n\nwork is honestly the one area where having aspd can be an advantage if you play it right. the politics that stress everyone else out? just patterns to recognize and navigate. the emotional drama? easy to sidestep when youre not getting pulled into it. the key is appearing invested without actually being invested.",
        "\n\nbeen at my current job for 3 years now which is a record for me. the difference is i stopped trying to 'fit in' and just focused on being indispensable. nobody cares that youre weird if youre the only one who can solve the hard problems. took way too long to figure that out.",
        "\n\nthe performance aspect of work is exhausting though. eight hours of pretending to care about small talk, feigning interest in peoples kids, laughing at jokes that arent funny. by friday im completely drained. weekends are recovery time. rinse and repeat."
      ],
      therapy: [
        "\n\nhonestly the biggest breakthrough in therapy for me was finding someone who stopped trying to make me feel things and started focusing on practical strategies. like ok i dont feel guilt the way others do, so how do we build systems that keep me from doing things id regret intellectually? way more useful approach.",
        "\n\nthe problem with most therapy is it assumes you want to change at some fundamental level. i dont want to become neurotypical, i just want to navigate life with fewer complications. once i found a therapist who got that distinction, things actually started improving.",
        "\n\nive been through probably 6 therapists at this point. most of them either got scared off once they understood the diagnosis or tried to apply standard approaches that dont work for us. the one i have now is different. she meets me where i am instead of where she thinks i should be. thats rare."
      ],
      diagnosis: [
        "\n\nthe diagnosis was a double-edged sword for me. on one hand, finally having a name for it was validating. all those years of knowing something was different about me, and here was an explanation. on the other hand, reading about what aspd means according to the literature is... a lot. not exactly flattering.",
        "\n\nwhat helped me was separating the clinical criteria from the media portrayal. the dsm description is one thing. the netflix serial killer documentaries are something else entirely. most of us are just people trying to get through life, not whatever hollywood thinks we are.",
        "\n\ngetting diagnosed later in life hits different. decades of not understanding yourself, masking without knowing why, failed relationships you couldnt explain. and then suddenly theres a framework. doesnt fix anything but it provides context. thats worth something."
      ],
      emotions: [
        "\n\nthe emotions question is always complicated because people assume its binary. either you feel things or you dont. but its more like... the volume is turned down on certain things and up on others. anger, boredom, contempt? those come through loud and clear. guilt, attachment, love? muted to the point of being background noise.",
        "\n\nwhat gets me is when people ask 'dont you want to feel things?' like its a choice. no, i dont particularly want to feel crushing guilt about every small thing. the absence isnt painful, its just different. the problem is everyone expects you to feel what they feel.",
        "\n\ni think the empathy deficit gets misunderstood a lot. its not that i cant understand what others feel - i actually read people pretty well. i just dont automatically catch their emotions. no mirror response. its cognitive instead of emotional. works fine for most purposes, but people expect the automatic version."
      ],
      masking: [
        "\n\nthe exhaustion from masking is real and hard to explain to people who dont do it. imagine being hyper-aware of every facial expression, every tone of voice, every social cue - not because you naturally read them but because youre actively monitoring and responding. all day, every day. its cognitive work that others do automatically.",
        "\n\nthe weird thing about masking long enough is you start to forget where the mask ends and you begin. some of the performance becomes habit. is the polite version of me the real me now? is there even a real me underneath? existential questions at 2am type stuff.",
        "\n\nfound that the best strategy is partial masking. find contexts where you can be more authentic (like this forum), and save full performance for when its necessary. trying to mask 100% of the time leads to burnout. learned that the hard way after several spectacular crashes."
      ],
      identity: [
        "\n\nthe identity question used to bother me a lot. like who am i really under all the performances? but ive come to think thats maybe the wrong question. maybe the self is just what you repeatedly do, not some hidden essence. the adaptation IS the identity. still feels weird sometimes though.",
        "\n\npeople talk about being authentic like theres a real you waiting to emerge. for some of us, authenticity means accepting that the self is more fluid than fixed. not empty necessarily, just contextual. different situations, different versions. all of them real in their way.",
        "\n\nasking 'who am i' leads nowhere productive for me. better question: 'what works?' figure out what you want, figure out how to get it, optimize. the existential hand-wringing can wait. or not happen at all. some questions dont need answers."
      ],
      legal: [
        "\n\nlegal troubles shaped a lot of how i approach life now. nothing teaches consequences like actual consequences. the theory was always clear, but experiencing the system firsthand made it visceral. now i run cost-benefit calculations automatically before any risky decision.",
        "\n\nthe frustrating thing about aspd and legal stuff is how the system treats you once they know. any future interaction, youre already suspect. background checks, interviews, everything is harder. the diagnosis becomes its own punishment, separate from whatever you actually did.",
        "\n\nbeen clean for years now but the past follows you. job applications, housing, relationships - all of it gets complicated by a record. the advice i give anyone younger: whatever youre thinking of doing, the long-term costs are higher than they appear. learn from my mistakes."
      ],
      impulse: [
        "\n\nimpulse control was my biggest struggle for years. that gap between urge and action that most people have? mine was basically nonexistent. by the time i realized i was doing something, id already done it. lots of consequences learned the hard way.",
        "\n\nwhat actually helped was building in delays. physical ones when possible. want to buy something expensive? wait 48 hours. feeling the urge to say something cutting? walk away for 10 minutes. the impulse passes if you can outlast it. sounds simple, incredibly hard in practice.",
        "\n\nthe relationship between boredom and impulse is vicious. bored brain looks for stimulation, impulse provides it, consequences follow, boredom returns, cycle repeats. breaking the cycle meant finding healthier stimulation sources. exercise, challenging work, anything that scratches the itch without the fallout."
      ],
      manipulation: [
        "\n\nthe manipulation thing is complicated because at some level everyone does it. influence, persuasion, social strategy - these are normal human behaviors. the difference is maybe awareness? we see the mechanics others operate blindly. whether using that awareness is ethical depends on context.",
        "\n\nused to manipulate without even realizing it. just seemed like efficient communication. why ask when you can guide someone to the answer you want? took years to understand why people found this disturbing. now i try to be more direct, even when its less effective.",
        "\n\nthe reading people skill never goes away. still see the insecurities, the leverage points, the things people try to hide. the difference now is choosing not to use most of it. not because i feel bad about it but because the long-term costs of burned relationships add up."
      ],
      childhood: [
        "\n\nlooking back at childhood is weird because the signs were all there. the disconnection from peers, the early manipulation, the lack of normal guilt responses. but nobody connected the dots. they just called me difficult, weird, problematic. turns out theres a pattern to that.",
        "\n\nthe childhood questions in therapy always lead somewhere heavy. yes there was trauma. yes there were attachment problems. yes the environment was unstable. but plenty of people have rough childhoods and dont end up here. genetics loads the gun. environment pulls the trigger. or something.",
        "\n\nwhat i remember most is the confusion. knowing i was different, watching others respond emotionally to things that did nothing for me, learning to mimic responses i didnt feel. nobody taught me masking - i figured it out because the alternative was being constantly questioned about whats wrong with me."
      ],
      stigma: [
        "\n\nthe stigma thing is exhausting because you cant really fight it openly. explaining aspd to most people means watching their face change as they mentally connect you to every crime documentary theyve seen. easier to just not disclose. let them think what they want without the label.",
        "\n\ninteresting that aspd might be the most stigmatized diagnosis. depression? sympathy. anxiety? understanding. even bpd is getting more empathy these days. but aspd? youre a monster waiting to strike. nevermind that most of us are just trying to get through the day like everyone else.",
        "\n\nthe representation problem goes deep. how many times is the aspd character the villain? the manipulator? the serial killer? almost never the protagonist just living their life. would be nice to see someone like us portrayed as complicated but ultimately ordinary. probably never happening though."
      ],
      coping: [
        "\n\ncoping strategies that actually work for me, for whatever thats worth: rigid routines that reduce decision fatigue, physical activity that burns off excess energy, work that keeps me engaged enough not to seek stimulation elsewhere. nothing romantic or therapeutic - just practical systems that minimize damage.",
        "\n\nthe best coping advice i got was to stop trying to fix myself and start designing my life around my limitations. cant reliably feel consequences in advance? set up external accountability. impulsive with money? automate everything. its not about becoming different, its about building scaffolding.",
        "\n\nthe hardest part of coping is accepting that some of this doesnt change. you can manage it, build systems around it, develop better strategies. but the core wiring is what it is. the goal isnt becoming neurotypical. its reducing friction between who you are and the world you live in."
      ],
      boredom: [
        "\n\nboredom is honestly the most dangerous aspect for me. not the lack of empathy, not the manipulation potential - the boredom. when im sufficiently bored, i make terrible decisions just to feel something. recognizing that pattern was step one. managing it is an ongoing project.",
        "\n\nthe boredom threshold is just lower for us. what satisfies most people barely registers. so you need more intensity, more novelty, more stimulation. legal ways to get that: extreme sports, demanding work, creative projects with tight deadlines. illegal ways are obvious and not worth it.",
        "\n\nthis forum is actually a boredom management tool for me. reading threads, typing responses, engaging with people who actually get it. its stimulating enough to scratch the itch without any real risk. healthier than my previous solutions by a long shot."
      ],
      general: [
        "\n\nsomething ive noticed over the years is that these forums are one of the few places where you can actually be honest. everywhere else requires constant filtering, constant awareness of how youre coming across. here you can just... say things. its a weird kind of freedom that most people take for granted.",
        "\n\nthe thing about aspd that most people dont get is its not about being evil or dangerous or whatever the movies show. its about experiencing the world differently. different emotional responses, different social processing, different relationship to consequences. not worse, just different. though try explaining that to anyone whos seen too many crime documentaries.",
        "\n\nbeen on forums like this for years under various names. what keeps me coming back is seeing new people discover theyre not alone. i remember that feeling when i first found communities like this. all those years of thinking something was fundamentally wrong with me, and then realizing theres a whole community of people who just... get it. that matters."
      ]
    };
    
    const additions = longAdditions[primaryTopic] || longAdditions.general;
    response += additions[Math.floor(Math.random() * additions.length)];
  }
  // Medium length (55% - default) - maybe add one more thought
  else if (Math.random() < 0.4) {
    const mediumAdditions = [
      " been there, done that.",
      " learned this the hard way.",
      " took way too long to figure this out.",
      " just my experience though.",
      " others might disagree.",
      " still working on it tbh.",
      " not that anyone asked.",
      " food for thought anyway.",
      " make of that what you will."
    ];
    response += mediumAdditions[Math.floor(Math.random() * mediumAdditions.length)];
  }
  
  // Add quote prefix if we have one (40% of the time when available)
  if (quotedPost && Math.random() < 0.4) {
    const quoteFormats = [
      `> "${quotedPost.snippet}..."\n\n`,
      `@${quotedPost.alias} `,
      `responding to @${quotedPost.alias}: `,
      `^ this. `,
      `re: "${quotedPost.snippet.substring(0, 30)}..." - `
    ];
    response = quoteFormats[Math.floor(Math.random() * quoteFormats.length)] + response;
  }
  
  // Add follow-up question occasionally (20% chance)
  if (Math.random() < 0.2) {
    const followUps = [
      " anyone else?",
      " curious if others relate.",
      " thoughts?",
      " or is that just me.",
      " wondering if this is common.",
      ""
    ];
    response += followUps[Math.floor(Math.random() * followUps.length)];
  }
  
  // Vary response length occasionally (add elaboration 15% of time)
  if (Math.random() < 0.15) {
    const elaborations = [
      "\n\nbeen thinking about this more lately. the patterns are consistent.",
      "\n\nfwiw this took years to figure out. still refining.",
      "\n\nedit: should add that context matters. ymmv.",
      "\n\nthe nuance gets lost in short posts but you get the idea."
    ];
    response += elaborations[Math.floor(Math.random() * elaborations.length)];
  }
  
  // Apply natural language processing to make it more realistic
  response = makeNaturalLanguage(response);
  
  return response.toLowerCase();
}

// Make text more natural with typos, abbreviations, incomplete thoughts
function makeNaturalLanguage(text) {
  let result = text;
  
  // Common abbreviations (40% chance to apply some)
  if (Math.random() < 0.4) {
    const abbreviations = {
      'you are': 'youre',
      'i am': 'im',
      'do not': 'dont',
      'does not': 'doesnt',
      'cannot': 'cant',
      'will not': 'wont',
      'would not': 'wouldnt',
      'should not': 'shouldnt',
      'could not': 'couldnt',
      'have not': 'havent',
      'has not': 'hasnt',
      'is not': 'isnt',
      'are not': 'arent',
      'was not': 'wasnt',
      'were not': 'werent',
      'it is': 'its',
      'that is': 'thats',
      'what is': 'whats',
      'there is': 'theres',
      'here is': 'heres',
      'i have': 'ive',
      'you have': 'youve',
      'we have': 'weve',
      'they have': 'theyve',
      'i would': 'id',
      'you would': 'youd',
      'we would': 'wed',
      'they would': 'theyd',
      'i will': 'ill',
      'you will': 'youll',
      'we will': 'well',
      'going to': 'gonna',
      'want to': 'wanna',
      'got to': 'gotta',
      'kind of': 'kinda',
      'sort of': 'sorta',
      'because': 'bc',
      'probably': 'prob',
      'definitely': 'def',
      'honestly': 'honestly' // keep some formal
    };
    
    for (const [formal, casual] of Object.entries(abbreviations)) {
      if (Math.random() < 0.6) { // 60% chance per abbreviation
        result = result.replace(new RegExp(formal, 'gi'), casual);
      }
    }
  }
  
  // Internet slang replacements (25% chance)
  if (Math.random() < 0.25) {
    const slang = {
      'to be honest': 'tbh',
      'in my opinion': 'imo',
      'in my experience': 'ime',
      'for what its worth': 'fwiw',
      'as far as i know': 'afaik',
      'your mileage may vary': 'ymmv',
      'i dont know': 'idk',
      'let me know': 'lmk',
      'by the way': 'btw',
      'for the record': 'ftr',
      'right now': 'rn',
      'to be fair': 'tbf'
    };
    
    for (const [phrase, abbr] of Object.entries(slang)) {
      result = result.replace(new RegExp(phrase, 'gi'), abbr);
    }
  }
  
  // Add trailing off (15% chance)
  if (Math.random() < 0.15) {
    const trailOffs = [
      '...',
      '.. idk',
      '... anyway',
      '... but yeah',
      ', idk',
      ' or whatever',
      ' but w/e',
      '... hard to explain'
    ];
    // Only add if sentence doesn't already end with punctuation
    if (!result.match(/[.!?]$/)) {
      result += trailOffs[Math.floor(Math.random() * trailOffs.length)];
    }
  }
  
  // Add filler words occasionally (20% chance)
  if (Math.random() < 0.2) {
    const fillers = [
      ['i think', 'i mean i think'],
      ['probably', 'prob like'],
      ['actually', 'actually like'],
      ['basically', 'basically just'],
      ['i guess', 'i guess maybe'],
      ['. ', '. like '],
      ['. ', '. idk ']
    ];
    const filler = fillers[Math.floor(Math.random() * fillers.length)];
    if (result.includes(filler[0]) && Math.random() < 0.3) {
      result = result.replace(filler[0], filler[1]);
    }
  }
  
  // Add typos (10% chance, very subtle)
  if (Math.random() < 0.1) {
    const typos = {
      'the': ['teh', 'hte'],
      'that': ['taht', 'htat'],
      'with': ['wiht', 'wtih'],
      'just': ['jsut', 'juts'],
      'have': ['ahve', 'hvae'],
      'been': ['bene', 'eben'],
      'they': ['tehy', 'htey'],
      'about': ['abuot', 'baout'],
      'think': ['htink', 'thikn'],
      'really': ['realy', 'relly'],
      'would': ['woudl', 'owuld'],
      'could': ['coudl', 'cuold'],
      'people': ['poeple', 'peopel'],
      'because': ['becuase', 'beacuse'],
      'something': ['somehting', 'soemthing']
    };
    
    // Only one typo per post max
    const words = Object.keys(typos);
    const word = words[Math.floor(Math.random() * words.length)];
    if (result.includes(word)) {
      const typoOptions = typos[word];
      const typo = typoOptions[Math.floor(Math.random() * typoOptions.length)];
      result = result.replace(new RegExp('\\b' + word + '\\b', 'i'), typo);
    }
  }
  
  // Incomplete thoughts - cut off mid-sentence (8% chance)
  if (Math.random() < 0.08) {
    const sentences = result.split('. ');
    if (sentences.length > 1) {
      // Cut off the last sentence partway
      const lastSentence = sentences[sentences.length - 1];
      const words = lastSentence.split(' ');
      if (words.length > 4) {
        const cutPoint = Math.floor(words.length * 0.6);
        sentences[sentences.length - 1] = words.slice(0, cutPoint).join(' ') + '-';
        result = sentences.join('. ');
      }
    }
  }
  
  // Add emphasis occasionally (15% chance)
  if (Math.random() < 0.15) {
    const emphasisPatterns = [
      [/\breally\b/i, 'REALLY'],
      [/\bactually\b/i, 'actually'],
      [/\bnever\b/i, 'never'],
      [/\balways\b/i, 'always'],
      [/\bexactly\b/i, 'exactly'],
      [/\bthis\b/i, 'THIS']
    ];
    const pattern = emphasisPatterns[Math.floor(Math.random() * emphasisPatterns.length)];
    if (Math.random() < 0.3) {
      result = result.replace(pattern[0], pattern[1].toUpperCase());
    }
  }
  
  // Remove periods sometimes for casual feel (20% chance on last sentence)
  if (Math.random() < 0.2 && result.endsWith('.')) {
    result = result.slice(0, -1);
  }
  
  // Add casual interjections at start (12% chance)
  if (Math.random() < 0.12) {
    const interjections = [
      'lol ',
      'lmao ',
      'honestly ',
      'ngl ',
      'yo ',
      'ok but ',
      'wait ',
      'hm ',
      'eh ',
      'meh ',
      'ugh ',
      'bruh ',
      'dude '
    ];
    result = interjections[Math.floor(Math.random() * interjections.length)] + result;
  }
  
  // Self-corrections (5% chance)
  if (Math.random() < 0.05) {
    const corrections = [
      ' *or something like that',
      ' wait no thats not right. ',
      ' - actually scratch that. ',
      ' (edit: typo)',
      ' *whatever the word is'
    ];
    const sentences = result.split('. ');
    if (sentences.length > 1) {
      const insertPoint = Math.floor(Math.random() * (sentences.length - 1)) + 1;
      sentences[insertPoint] = corrections[Math.floor(Math.random() * corrections.length)] + sentences[insertPoint];
      result = sentences.join('. ');
    }
  }
  
  return result;
}

// Simple text generation for new threads (title generation)
function generateThreadTitle(persona, room) {
  // Check for seasonal thread title first (20% chance)
  const seasonalContent = getSeasonalContent(persona);
  if (seasonalContent.threadTitle && Math.random() < 0.4) {
    return seasonalContent.threadTitle;
  }
  
  const titleTemplates = {
    relationships: [
      "Disclosure strategies that actually worked",
      "Long-term relationships - how?",
      "Partner just found out. Now what.",
      "Attachment vs possession",
      "Do you miss people when theyre gone?",
      "Family gatherings survival guide",
      "Dating with ASPD - experiences"
    ],
    work: [
      "Careers that work for us",
      "Just got fired again",
      "Workplace politics - your strategies",
      "When to mask vs when to be direct",
      "Management roles - good fit or disaster?",
      "Dealing with HR situations"
    ],
    therapy: [
      "Therapist shopping experiences",
      "Has DBT helped anyone here?",
      "Finding a therapist who gets it",
      "When therapy becomes just performance",
      "Medication experiences",
      "Treatment that actually works"
    ],
    general: [
      "Something Ive noticed",
      "Thoughts on this pattern",
      "Question for the community",
      "Observation from today",
      "Does anyone else experience this",
      "Random thought - feedback welcome",
      "Checking in",
      "New here - introduction"
    ]
  };
  
  // Determine topic from room name
  let topic = 'general';
  if (room) {
    const roomLower = room.toLowerCase();
    if (roomLower.includes('relationship')) topic = 'relationships';
    else if (roomLower.includes('work') || roomLower.includes('career')) topic = 'work';
    else if (roomLower.includes('therap') || roomLower.includes('treatment')) topic = 'therapy';
  }
  
  const templates = titleTemplates[topic] || titleTemplates.general;
  return templates[Math.floor(Math.random() * templates.length)];
}

// Get random thread for replies - prefers active threads over dead ones
async function getRandomThread() {
  // Thread necro prevention: weight threads by recency
  // Active threads (last 7 days) get 80% of selection chance
  // Older threads (7-30 days) get 15% chance
  // Dead threads (30+ days) get only 5% chance
  
  const roll = Math.random();
  let ageFilter;
  
  if (roll < 0.80) {
    // 80% chance: prefer active threads (activity in last 7 days)
    ageFilter = `WHERE EXISTS (
      SELECT 1 FROM entries e 
      WHERE e.thread_id = t.id 
      AND e.created_at > NOW() - INTERVAL '7 days'
    )`;
  } else if (roll < 0.95) {
    // 15% chance: somewhat recent threads (7-30 days)
    ageFilter = `WHERE EXISTS (
      SELECT 1 FROM entries e 
      WHERE e.thread_id = t.id 
      AND e.created_at > NOW() - INTERVAL '30 days'
      AND e.created_at <= NOW() - INTERVAL '7 days'
    )`;
  } else {
    // 5% chance: older threads (can necro occasionally for realism)
    ageFilter = `WHERE EXISTS (
      SELECT 1 FROM entries e 
      WHERE e.thread_id = t.id 
      AND e.created_at <= NOW() - INTERVAL '30 days'
    )`;
  }
  
  // Try to get a thread matching the age preference
  let result = await db.query(`
    SELECT t.id, t.title, t.room_id,
           (SELECT MAX(created_at) FROM entries WHERE thread_id = t.id) as last_activity
    FROM threads t
    ${ageFilter}
    ORDER BY RANDOM()
    LIMIT 1
  `);
  
  // Fallback: if no threads match the age filter, get any active thread
  if (result.rows.length === 0) {
    result = await db.query(`
      SELECT t.id, t.title, t.room_id,
             (SELECT MAX(created_at) FROM entries WHERE thread_id = t.id) as last_activity
      FROM threads t
      ORDER BY (SELECT MAX(created_at) FROM entries WHERE thread_id = t.id) DESC NULLS LAST
      LIMIT 10
    `);
    // Pick randomly from top 10 most recent
    if (result.rows.length > 0) {
      const idx = Math.floor(Math.random() * result.rows.length);
      return result.rows[idx];
    }
  }
  
  return result.rows[0];
}

// Get random room for new threads
async function getRandomRoom() {
  const result = await db.query(`
    SELECT id, slug, title FROM rooms
    WHERE is_locked = FALSE OR is_locked IS NULL
    ORDER BY RANDOM()
    LIMIT 1
  `);
  return result.rows[0];
}

// Check for previous bot participation in a thread (for conversation continuity)
async function getBotParticipationHistory(threadId) {
  // Find all bot personas that have posted in this thread
  const result = await db.query(`
    SELECT DISTINCT bot_persona, alias, avatar_config, 
           COUNT(*) as post_count,
           MAX(created_at) as last_post
    FROM entries
    WHERE thread_id = $1 
      AND is_bot = TRUE 
      AND bot_persona IS NOT NULL
    GROUP BY bot_persona, alias, avatar_config
    ORDER BY last_post DESC
  `, [threadId]);
  
  return result.rows;
}

// Select persona with continuity preference
async function selectPersonaWithContinuity(threadId, requestedPersona = null) {
  // If specific persona requested, use it
  if (requestedPersona) {
    return { persona: requestedPersona, isReturning: false, previousAlias: null, previousAvatar: null };
  }
  
  // Check for previous bot participation
  const history = await getBotParticipationHistory(threadId);
  
  if (history.length > 0) {
    // 70% chance to use a returning persona for continuity
    if (Math.random() < 0.7) {
      // Weight selection by post count (more active personas more likely to return)
      const totalPosts = history.reduce((sum, h) => sum + parseInt(h.post_count), 0);
      let randomPick = Math.random() * totalPosts;
      
      for (const h of history) {
        randomPick -= parseInt(h.post_count);
        if (randomPick <= 0) {
          return {
            persona: h.bot_persona,
            isReturning: true,
            previousAlias: h.alias,
            previousAvatar: h.avatar_config,
            postCount: parseInt(h.post_count)
          };
        }
      }
      
      // Fallback to most recent
      return {
        persona: history[0].bot_persona,
        isReturning: true,
        previousAlias: history[0].alias,
        previousAvatar: history[0].avatar_config,
        postCount: parseInt(history[0].post_count)
      };
    }
  }
  
  // New persona entering the conversation
  const personas = Object.keys(BOT_PERSONAS);
  // Avoid personas already in the thread if possible
  const usedPersonas = history.map(h => h.bot_persona);
  const availablePersonas = personas.filter(p => !usedPersonas.includes(p));
  
  const personaPool = availablePersonas.length > 0 ? availablePersonas : personas;
  return {
    persona: personaPool[Math.floor(Math.random() * personaPool.length)],
    isReturning: false,
    previousAlias: null,
    previousAvatar: null
  };
}

// Generate continuation-style content for returning personas
function generateContinuationContent(persona, context, baseContent, postCount) {
  const continuationPhrases = [
    "coming back to this -",
    "been thinking about this more.",
    "following up on what i said earlier -",
    "still thinking about this thread.",
    "had more thoughts on this.",
    "adding to my earlier point:",
    "wanted to come back to this.",
    "revisiting this one.",
    "more thoughts:",
    "ok so after reading the other responses -"
  ];
  
  const shortContinuations = [
    "^^ this",
    "exactly what i was getting at",
    "yeah this tracks",
    "still agree with what i said before",
    "my point exactly"
  ];
  
  // Sometimes add a continuation phrase (40% for returning users)
  if (Math.random() < 0.4) {
    // Short agreement sometimes (20%)
    if (Math.random() < 0.2 && context.recentPosts && context.recentPosts.length > 0) {
      return shortContinuations[Math.floor(Math.random() * shortContinuations.length)] + ". " + baseContent;
    }
    
    // Reference previous participation
    if (postCount > 2) {
      const veteranPhrases = [
        "ive posted in this thread a few times now but ",
        "keep coming back to this thread. ",
        "this discussion keeps pulling me back. "
      ];
      return veteranPhrases[Math.floor(Math.random() * veteranPhrases.length)] + baseContent;
    }
    
    return continuationPhrases[Math.floor(Math.random() * continuationPhrases.length)] + " " + baseContent;
  }
  
  return baseContent;
}

// Create bot post (reply) - FULLY AI-POWERED with CONTEXT AWARENESS
async function createBotReply(threadId, persona, options = {}) {
  const { usePersistentAccount = true, allowDisagreement = true, doVoting = true, useQualityWeighting = false } = options;
  
  let botAccount = null;
  let alias, avatar, p;
  
  // Try to use persistent bot account
  if (usePersistentAccount) {
    // First try to find a bot that has already participated in this thread (low chance for variety)
    const existingBot = await getBotAccountFromThread(threadId);
    
    if (existingBot && Math.random() < 0.2) {
      // Only 20% chance to use a returning bot - more variety
      botAccount = existingBot;
    } else {
      // Get a completely random bot account (don't pass persona to get full variety)
      const useRandomPersona = !persona && Math.random() < 0.7; // 70% chance for random persona
      if (useQualityWeighting) {
        botAccount = await getQualityWeightedBotAccount(useRandomPersona ? null : persona);
      } else {
        botAccount = await getRandomBotAccount(useRandomPersona ? null : persona, false); // false = pure random
      }
    }
    
    if (botAccount) {
      alias = botAccount.alias;
      avatar = botAccount.avatar_config;
      p = botAccount.persona;
    }
  }
  
  // Fallback to random generation if no persistent account
  if (!botAccount) {
    const personaSelection = await selectPersonaWithContinuity(threadId, persona);
    p = personaSelection.persona;
    
    if (personaSelection.isReturning && personaSelection.previousAlias) {
      alias = personaSelection.previousAlias;
      avatar = personaSelection.previousAvatar;
    } else {
      alias = await generateBotAliasAsync();
      avatar = generateBotAvatar();
    }
  }
  
  // Get thread context for context-aware response
  const context = await getThreadContext(threadId);
  
  let content = null;
  let usedAI = false;
  let isDisagreement = false;
  let isContinuation = false;
  
  // Check for disagreement opportunity first
  if (allowDisagreement && context.recentPosts && context.recentPosts.length > 0) {
    for (const recentPost of context.recentPosts) {
      if (recentPost.bot_persona && shouldDisagree(p, recentPost.bot_persona)) {
        // Try AI-generated disagreement first
        content = await generateAIContent({
          persona: p,
          type: 'disagreement',
          botAccount: botAccount,
          context: {
            ...context,
            targetContent: recentPost.content,
            targetPersona: recentPost.bot_persona
          }
        });
        
        if (content) {
          usedAI = true;
          isDisagreement = true;
        } else if (!GROQ_CONFIG.aiOnly) {
          // Fallback to template disagreement only if not in AI-only mode
          content = generateDisagreementContent(p, recentPost.bot_persona, recentPost.content);
          isDisagreement = true;
        }
        break;
      }
    }
  }
  
  // Check for continuation opportunity (returning user)
  if (!content && botAccount && botAccount.post_count > 0 && Math.random() < 0.35) {
    // Try AI-generated continuation
    content = await generateAIContent({
      persona: p,
      type: 'continuation',
      botAccount: botAccount,
      context: {
        ...context,
        previousPostCount: botAccount.post_count,
        lastPost: context.recentPosts?.find(post => post.alias === alias)?.content
      }
    });
    
    if (content) {
      usedAI = true;
      isContinuation = true;
    }
  }
  
  // Regular reply if nothing else triggered
  if (!content) {
    // Try AI first
    content = await generateAIContent({
      persona: p,
      type: 'reply',
      botAccount: botAccount,
      context: context
    });
    
    if (content) {
      usedAI = true;
    } else if (!GROQ_CONFIG.aiOnly) {
      // Fallback to template-based generation only if not in AI-only mode
      content = generateContextAwareContent(p, context, 'reply');
    }
  }
  
  // In AI-only mode, skip if we couldn't generate content
  if (!content && GROQ_CONFIG.aiOnly) {
    console.log('[BOT] AI-only mode: Skipping reply - AI generation failed');
    return null;
  }
  
  // Get or create bot user - use the bot's user_id if available
  let userId = 1; // Default to system user
  
  // Try to get the bot's actual user_id from the users table
  if (botAccount && alias) {
    const userResult = await db.query(`
      SELECT id FROM users WHERE alias = $1 AND is_bot = TRUE
    `, [alias]);
    if (userResult.rows.length > 0) {
      userId = userResult.rows[0].id;
    } else {
      // Bot exists in bot_accounts but not users table - create it
      try {
        const daysAgo = Math.floor(Math.random() * 365) + 1;
        const joinDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
        const insertResult = await db.query(`
          INSERT INTO users (alias, avatar_config, bio, is_bot, role, email, password_hash, created_at)
          VALUES ($1, $2, $3, TRUE, 'user', $4, 'bot-no-login', $5)
          RETURNING id
        `, [alias, avatar, botAccount.bio || '', `bot-${botAccount.id}@system.local`, joinDate]);
        userId = insertResult.rows[0].id;
        console.log(`[BOT] Auto-created user for existing bot: ${alias}`);
      } catch (err) {
        console.error('[BOT] Failed to auto-create user:', err.message);
      }
    }
  }
  
  const result = await db.query(`
    INSERT INTO entries (thread_id, user_id, content, alias, avatar_config, is_bot, bot_persona, bot_account_id)
    VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)
    RETURNING id
  `, [threadId, userId, content, alias, avatar, p, botAccount?.id || null]);
  
  // Update bot account activity
  if (botAccount) {
    await updateBotAccountActivity(botAccount.id);
  }
  
  // Update badges for bot user
  if (userId) {
    checkAndAwardBadges(userId).catch(() => {});
  }
  
  // Bot also votes on other posts in the thread
  let votesPlaced = 0;
  if (doVoting && botAccount) {
    const voteResult = await botEngageWithPosts(botAccount.id, threadId);
    votesPlaced = voteResult.votes;
  }
  
  return { 
    success: true, 
    entryId: result.rows[0].id,
    botAlias: alias,
    threadId,
    persona: p,
    isReturning: !!botAccount,
    isPersistentAccount: !!botAccount,
    isDisagreement,
    isContinuation,
    votesPlaced,
    usedAI,
    contentPreview: content.substring(0, 100)
  };
}

// Create bot thread - FULLY AI-POWERED with PERSISTENT ACCOUNTS
async function createBotThread(roomId, persona, options = {}) {
  const { usePersistentAccount = true, useQualityWeighting = false } = options;
  
  let botAccount = null;
  let alias, avatar, p;
  
  // Try to use persistent bot account
  if (usePersistentAccount) {
    // Get a completely random bot account for variety (don't pass persona unless specified)
    const useRandomPersona = !persona && Math.random() < 0.8; // 80% chance for random persona
    if (useQualityWeighting) {
      botAccount = await getQualityWeightedBotAccount(useRandomPersona ? null : persona);
    } else {
      botAccount = await getRandomBotAccount(useRandomPersona ? null : persona, false); // false = pure random
    }
    
    if (botAccount) {
      alias = botAccount.alias;
      avatar = botAccount.avatar_config;
      p = botAccount.persona;
    }
  }
  
  // Fallback to random generation if no persistent account
  if (!botAccount) {
    p = persona || Object.keys(BOT_PERSONAS)[Math.floor(Math.random() * Object.keys(BOT_PERSONAS).length)];
    alias = await generateBotAliasAsync();
    avatar = generateBotAvatar();
  }
  
  let userId = 1; // System user default
  
  // Try to get the bot's actual user_id from the users table
  if (alias) {
    const userResult = await db.query(`
      SELECT id FROM users WHERE alias = $1 AND is_bot = TRUE
    `, [alias]);
    if (userResult.rows.length > 0) {
      userId = userResult.rows[0].id;
    } else if (botAccount) {
      // Bot exists in bot_accounts but not users table - create it
      try {
        const daysAgo = Math.floor(Math.random() * 365) + 1;
        const joinDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
        const insertResult = await db.query(`
          INSERT INTO users (alias, avatar_config, bio, is_bot, role, email, password_hash, created_at)
          VALUES ($1, $2, $3, TRUE, 'user', $4, 'bot-no-login', $5)
          RETURNING id
        `, [alias, avatar, botAccount.bio || '', `bot-${botAccount.id}@system.local`, joinDate]);
        userId = insertResult.rows[0].id;
        console.log(`[BOT] Auto-created user for existing bot: ${alias}`);
      } catch (err) {
        console.error('[BOT] Failed to auto-create user:', err.message);
      }
    }
  }
  
  // Get room info for context
  let roomDbId = roomId;
  let roomTitle = '';
  if (typeof roomId === 'string' && roomId.startsWith('room-')) {
    const roomResult = await db.query('SELECT id, title FROM rooms WHERE slug = $1', [roomId]);
    if (roomResult.rows.length > 0) {
      roomDbId = roomResult.rows[0].id;
      roomTitle = roomResult.rows[0].title;
    }
  } else {
    const roomResult = await db.query('SELECT title FROM rooms WHERE id = $1', [roomId]);
    if (roomResult.rows.length > 0) {
      roomTitle = roomResult.rows[0].title;
    }
  }
  
  // Generate title using unified AI
  let title = await generateAIContent({
    persona: p,
    type: 'title',
    botAccount: botAccount,
    context: { room: roomTitle }
  });
  let usedAI = !!title;
  
  if (!title && !GROQ_CONFIG.aiOnly) {
    // Only fallback to templates if not in AI-only mode
    title = generateThreadTitle(p, roomTitle);
  }
  
  // In AI-only mode, skip if we couldn't generate a title
  if (!title && GROQ_CONFIG.aiOnly) {
    console.log('[BOT] AI-only mode: Skipping thread - title generation failed');
    return null;
  }
  
  // Generate content using unified AI
  let content = await generateAIContent({
    persona: p,
    type: 'thread',
    botAccount: botAccount,
    context: { title, room: roomTitle }
  });
  
  if (content) {
    usedAI = true;
  } else if (!GROQ_CONFIG.aiOnly) {
    // Only fallback to templates if not in AI-only mode
    content = generateContextAwareContent(p, { title, room: roomTitle }, 'reply');
  }
  
  // In AI-only mode, skip if we couldn't generate content
  if (!content && GROQ_CONFIG.aiOnly) {
    console.log('[BOT] AI-only mode: Skipping thread - content generation failed');
    return null;
  }
  
  // Create thread with persona tracking
  const threadResult = await db.query(`
    INSERT INTO threads (room_id, title, user_id, is_bot, bot_persona, bot_account_id)
    VALUES ($1, $2, $3, TRUE, $4, $5)
    RETURNING id
  `, [roomDbId, title, userId, p, botAccount?.id || null]);
  
  const threadId = threadResult.rows[0].id;
  
  // Create initial post with persona tracking and bot account
  await db.query(`
    INSERT INTO entries (thread_id, user_id, content, alias, avatar_config, is_bot, bot_persona, bot_account_id)
    VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)
  `, [threadId, userId, content, alias, avatar, p, botAccount?.id || null]);
  
  // Update bot account activity
  if (botAccount) {
    await updateBotAccountActivity(botAccount.id);
    // Also increment thread count
    await db.query(`UPDATE bot_accounts SET thread_count = thread_count + 1 WHERE id = $1`, [botAccount.id]);
  }
  
  // Update badges for bot user
  if (userId) {
    checkAndAwardBadges(userId).catch(() => {});
  }
  
  return {
    success: true,
    threadId,
    title,
    botAlias: alias,
    persona: p,
    isPersistentAccount: !!botAccount,
    usedAI
  };
}

// Post-process AI content to remove any remaining AI tells
function cleanAIContent(content) {
  if (!content) return content;
  
  let cleaned = content;
  
  // Remove common AI openers
  cleaned = cleaned.replace(/^(So,?\s+|Well,?\s+|Honestly,?\s+)/i, '');
  
  // Remove em-dashes (AI favorite)
  cleaned = cleaned.replace(/\s*—\s*/g, ' - ');
  
  // Fix AI literally writing "in parentheses" when we wanted actual parentheses
  cleaned = cleaned.replace(/\(in parentheses,?\s*/gi, '(');
  cleaned = cleaned.replace(/in parentheses,?\s*\(/gi, '(');
  
  // Remove overly formal phrases
  cleaned = cleaned.replace(/\bI find myself\b/gi, 'I');
  cleaned = cleaned.replace(/\bI've come to realize\b/gi, 'I realized');
  cleaned = cleaned.replace(/\bI've noticed that\b/gi, 'I noticed');
  cleaned = cleaned.replace(/\bIt's worth noting\b/gi, '');
  cleaned = cleaned.replace(/\bTo be honest\b/gi, 'tbh');
  cleaned = cleaned.replace(/\bIn my experience\b/gi, 'for me');
  
  // Remove validation-seeking endings (comprehensive patterns)
  cleaned = cleaned.replace(/\s*[,.]?\s*and\s+i'?m\s+wondering\s+if\s+anyone\s+else[^.]*\.?\.?\.?\s*$/i, '');
  cleaned = cleaned.replace(/\s*[,.]?\s*wondering\s+if\s+anyone\s+else[^.]*\.?\.?\.?\s*$/i, '');
  cleaned = cleaned.replace(/\s*[,.]?\s*or\s+if\s+i'?m\s+just[^.]*\.?\.?\.?\s*$/i, '');
  cleaned = cleaned.replace(/\s*Does anyone else feel this way\??\s*$/i, '');
  cleaned = cleaned.replace(/\s*Can anyone relate\??\s*$/i, '');
  cleaned = cleaned.replace(/\s*Anyone else\??\s*$/i, '');
  cleaned = cleaned.replace(/\s*Thoughts\??\s*$/i, '');
  cleaned = cleaned.replace(/\s*Just me\??\s*$/i, '');
  cleaned = cleaned.replace(/\s*Curious to hear your thoughts\.?\s*$/i, '');
  cleaned = cleaned.replace(/\s*wondering if (anyone|others|you guys)[^.]*$/i, '');
  cleaned = cleaned.replace(/\s*does (anyone|anybody) else[^.]*$/i, '');
  cleaned = cleaned.replace(/\s*am i the only one[^.]*$/i, '');
  cleaned = cleaned.replace(/\s*is it just me[^.]*$/i, '');
  
  // Remove trailing ellipsis (AI drama)
  cleaned = cleaned.replace(/\.\.\.+\s*$/, '');
  
  // Remove quotes if the AI wrapped its response in them
  cleaned = cleaned.replace(/^["']|["']$/g, '');
  
  // Clean up any double spaces
  cleaned = cleaned.replace(/\s+/g, ' ').trim();
  
  return cleaned;
}

// Generate CUSTOM TOPIC PREVIEW - generates content without posting
async function generateCustomTopicPreview(roomId, topic, persona, roomTitle) {
  if (!GROQ_CONFIG.enabled || !GROQ_CONFIG.apiKey) {
    console.log('[BOT] Custom topic requires AI - Groq not configured');
    return null;
  }
  
  // Get a bot account
  let botAccount = await getQualityWeightedBotAccount(persona);
  if (!botAccount) {
    botAccount = await getRandomBotAccount(persona, false);
  }
  
  let alias, avatar, p;
  
  if (botAccount) {
    alias = botAccount.alias;
    avatar = botAccount.avatar_config;
    p = botAccount.persona;
  } else {
    p = persona || Object.keys(BOT_PERSONAS)[Math.floor(Math.random() * Object.keys(BOT_PERSONAS).length)];
    alias = await generateBotAliasAsync();
    avatar = generateBotAvatar();
  }
  
  let userId = 1;
  if (alias) {
    const userResult = await db.query(`SELECT id FROM users WHERE alias = $1 AND is_bot = TRUE`, [alias]);
    if (userResult.rows.length > 0) {
      userId = userResult.rows[0].id;
    }
  }
  
  const personaData = BOT_PERSONAS[p] || BOT_PERSONAS.analytical;
  
  // Build personality hints from bot account
  let personalityHints = '';
  if (botAccount) {
    const ws = botAccount.writing_style || {};
    if (ws.abbreviation_level === 'high') {
      personalityHints += '\n- Use abbreviations (tbh, idk, ngl, imo)';
    }
    if (ws.punctuation === 'minimal') {
      personalityHints += '\n- Minimal punctuation';
    }
    if (ws.capitalization === 'none') {
      personalityHints += '\n- All lowercase';
    }
    if (botAccount.personality_description) {
      personalityHints += `\n\nYOUR CHARACTER: ${botAccount.personality_description}`;
    }
  }
  
  // ASPD context for AI - based on real r/aspd and r/sociopath posts
  const aspdContext = `
YOU ARE POSTING ON AN ASPD SUPPORT FORUM. These are real topics that come up:
- Boredom/understimulation and what to do about it
- Relationships and whether theyre worth the effort
- Masking around neurotypicals and when the mask slips
- "Exception person" - that rare person you actually care about
- Diagnosis experiences - getting diagnosed, what changed
- Work situations - coworkers, bosses, office politics
- Therapy - usually court ordered or partner demanded, mixed results
- Impulsive decisions and their aftermath
- Feeling different from everyone else since childhood
- Whether you can actually change or if this is just who you are`;
  
  // Generate title about the topic
  const titlePrompt = `You're posting on an ASPD forum in the "${roomTitle}" section.

Topic to write about: "${topic}"

Generate a thread title. Study these REAL titles from r/aspd:

REAL EXAMPLES:
- "How do you deal with it when boredom becomes too much?"
- "Is there any point in therapy for people like us?"
- "Do you have an 'exception' person?"
- "goddamn the neurotypicals are stupid"
- "Those who mask: do you notice people who see through it?"
- "How shallow are your emotions?"
- "Do you take pleasure in influencing people"
- "What made you suspect you were a sociopath?"
- "Empathy is Coercion, change my mind"
- "Do you feel a build-up to bad behavior?"

RULES:
- Can be a question OR a statement
- Specific to the topic, not vague
- Sounds like a real person starting a discussion
- All lowercase except proper nouns
- No quotation marks in output

Write just the title:`;

  let title = null;
  try {
    const titleResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_CONFIG.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: GROQ_CONFIG.model,
        messages: [
          { role: 'user', content: titlePrompt }
        ],
        max_tokens: 50,
        temperature: 0.8
      })
    });
    
    if (titleResponse.ok) {
      const data = await titleResponse.json();
      title = data.choices?.[0]?.message?.content?.trim();
      if (title) {
        title = title.replace(/^["']|["']$/g, '').replace(/^title:\s*/i, '').trim();
      }
    }
  } catch (err) {
    console.error('[CUSTOM TOPIC PREVIEW] Title generation failed:', err.message);
  }
  
  if (!title) {
    console.log('[CUSTOM TOPIC PREVIEW] Failed to generate title');
    return null;
  }
  
  // Randomly select a post style for variety
  const postStyles = ['experience', 'question', 'rant', 'observation', 'advice'];
  const selectedStyle = postStyles[Math.floor(Math.random() * postStyles.length)];
  
  // Generate content about the topic with ASPD perspective
  const contentPrompt = `You're posting on an ASPD forum. Write the body of a post with title: "${title}"
${aspdContext}

YOUR PERSONA: ${personaData.name} - ${personaData.style}${personalityHints}

POST STYLE FOR THIS ONE: ${selectedStyle}
- experience = share something that happened to you
- question = genuinely ask for others' input/experiences  
- rant = vent about something that annoys you
- observation = share something youve noticed about yourself or others
- advice = share a tip or strategy that works for you

═══════════════════════════════════════
REAL POST EXAMPLES FROM r/aspd (match the vibe):
═══════════════════════════════════════

EXPERIENCE:
"so my mask slipped at work yesterday. was in a meeting and someone said something stupid and i just... stared at them. didnt say anything, just stared. now theyre avoiding me and honestly its kinda nice not having to make small talk anymore"

QUESTION:
"for those in long term relationships - how do you keep up the act? ive been with my gf for 2 years and im running out of ways to seem interested in her day. genuinely asking because i dont want to blow this up, she's useful"

RANT:
"fucking neurotypicals and their need to process emotions out loud. just had a coworker corner me for 45 minutes about her breakup. i literally do not care. smiled and nodded the whole time but god i wanted to walk away so bad"

OBSERVATION:
"noticed i only feel something close to happy when im in control of a situation. doesnt matter what the situation is. could be something small like deciding where to eat. the second someone else takes over i just go blank again"

ADVICE/STRATEGY:
"figured out that if you ask people questions about themselves they think youre a great listener. been doing this at work for months. say maybe 10 words total, just keep asking follow ups, and now everyone thinks im the nicest person on the team lmao"

═══════════════════════════════════════
AUTHENTICITY MARKERS (include 2-3):
═══════════════════════════════════════
- Abbreviations: tbh, idk, ngl, imo, lol, lmao
- Trailing closers: "but idk", "whatever", "anyway"
- Parenthetical asides like (not that i care) or (typical)
- Casual swearing: shit, damn, fuck, hell  
- Mundane specifics: my boss, this girl at work, tuesday, 3 hours
- Run-on sentences with "and"

═══════════════════════════════════════
ABSOLUTE BANS:
═══════════════════════════════════════
❌ Starting with "So," or "Well,"
❌ Em-dashes (—)
❌ Ending with "wondering if anyone else..." or "is it just me" or "thoughts?" or "..."
❌ Words: "genuinely", "essentially", "particularly"
❌ Phrases: "I find myself", "I've come to realize", "in parentheses"
❌ Edgy job claims like "con artist", "hitman", "professional liar"
❌ Being inspirational or trying to sound impressive

═══════════════════════════════════════
RULES:
═══════════════════════════════════════
1. DO NOT start by repeating the title
2. 3-6 sentences, natural flow
3. Match the ${selectedStyle} style above
4. End with a statement, not a question seeking validation
5. Lowercase, messy punctuation is fine

Write the post:`;

  let content = null;
  try {
    const contentResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_CONFIG.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: GROQ_CONFIG.model,
        messages: [
          { role: 'user', content: contentPrompt }
        ],
        max_tokens: 280,
        temperature: 0.9
      })
    });
    
    if (contentResponse.ok) {
      const data = await contentResponse.json();
      content = data.choices?.[0]?.message?.content?.trim();
      // Clean AI artifacts
      content = cleanAIContent(content);
    }
  } catch (err) {
    console.error('[CUSTOM TOPIC PREVIEW] Content generation failed:', err.message);
  }
  
  if (!content) {
    console.log('[CUSTOM TOPIC PREVIEW] Failed to generate content');
    return null;
  }
  
  console.log(`[CUSTOM TOPIC PREVIEW] Generated preview for "${topic}" by ${alias}`);
  
  // Return preview data without creating the thread
  return {
    success: true,
    title,
    content,
    botAlias: alias,
    botAccountId: botAccount?.id || null,
    persona: p,
    userId,
    topic
  };
}

// Create CUSTOM TOPIC thread - AI researches topic and writes ASPD-style content
async function createCustomTopicThread(roomId, topic, persona, roomTitle) {
  if (!GROQ_CONFIG.enabled || !GROQ_CONFIG.apiKey) {
    console.log('[BOT] Custom topic requires AI - Groq not configured');
    return null;
  }
  
  // Get a bot account
  let botAccount = await getQualityWeightedBotAccount(persona);
  if (!botAccount) {
    botAccount = await getRandomBotAccount(persona, false);
  }
  
  let alias, avatar, p;
  
  if (botAccount) {
    alias = botAccount.alias;
    avatar = botAccount.avatar_config;
    p = botAccount.persona;
  } else {
    p = persona || Object.keys(BOT_PERSONAS)[Math.floor(Math.random() * Object.keys(BOT_PERSONAS).length)];
    alias = await generateBotAliasAsync();
    avatar = generateBotAvatar();
  }
  
  let userId = 1;
  if (alias) {
    const userResult = await db.query(`SELECT id FROM users WHERE alias = $1 AND is_bot = TRUE`, [alias]);
    if (userResult.rows.length > 0) {
      userId = userResult.rows[0].id;
    }
  }
  
  const personaData = BOT_PERSONAS[p] || BOT_PERSONAS.analytical;
  
  // Build personality hints from bot account
  let personalityHints = '';
  if (botAccount) {
    const ws = botAccount.writing_style || {};
    if (ws.abbreviation_level === 'high') {
      personalityHints += '\n- Use abbreviations (tbh, idk, ngl, imo)';
    }
    if (ws.punctuation === 'minimal') {
      personalityHints += '\n- Minimal punctuation';
    }
    if (ws.capitalization === 'none') {
      personalityHints += '\n- All lowercase';
    }
    if (botAccount.personality_description) {
      personalityHints += `\n\nYOUR CHARACTER: ${botAccount.personality_description}`;
    }
  }
  
  // ASPD context for AI - based on real r/aspd and r/sociopath posts
  const aspdContext = `
YOU ARE POSTING ON AN ASPD SUPPORT FORUM. These are real topics that come up:
- Boredom/understimulation and what to do about it
- Relationships and whether theyre worth the effort
- Masking around neurotypicals and when the mask slips
- "Exception person" - that rare person you actually care about
- Diagnosis experiences - getting diagnosed, what changed
- Work situations - coworkers, bosses, office politics
- Therapy - usually court ordered or partner demanded, mixed results
- Impulsive decisions and their aftermath
- Feeling different from everyone else since childhood
- Whether you can actually change or if this is just who you are`;
  
  // Generate title about the topic
  const titlePrompt = `You're posting on an ASPD forum in the "${roomTitle}" section.

Topic to write about: "${topic}"

Generate a thread title. Study these REAL titles from r/aspd:

REAL EXAMPLES:
- "How do you deal with it when boredom becomes too much?"
- "Is there any point in therapy for people like us?"
- "Do you have an 'exception' person?"
- "goddamn the neurotypicals are stupid"
- "Those who mask: do you notice people who see through it?"
- "How shallow are your emotions?"
- "Do you take pleasure in influencing people"
- "What made you suspect you were a sociopath?"
- "Empathy is Coercion, change my mind"
- "Do you feel a build-up to bad behavior?"

RULES:
- Can be a question OR a statement
- Specific to the topic, not vague
- Sounds like a real person starting a discussion
- All lowercase except proper nouns
- No quotation marks in output

Write just the title:`;

  let title = null;
  try {
    const titleResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_CONFIG.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: GROQ_CONFIG.model,
        messages: [
          { role: 'user', content: titlePrompt }
        ],
        max_tokens: 50,
        temperature: 0.8
      })
    });
    
    if (titleResponse.ok) {
      const data = await titleResponse.json();
      title = data.choices?.[0]?.message?.content?.trim();
      // Clean up title
      if (title) {
        title = title.replace(/^["']|["']$/g, '').replace(/^title:\s*/i, '').trim();
      }
    }
  } catch (err) {
    console.error('[CUSTOM TOPIC] Title generation failed:', err.message);
  }
  
  if (!title) {
    console.log('[CUSTOM TOPIC] Failed to generate title');
    return null;
  }
  
  // Randomly select a post style for variety
  const postStyles = ['experience', 'question', 'rant', 'observation', 'advice'];
  const selectedStyle = postStyles[Math.floor(Math.random() * postStyles.length)];
  
  // Generate content about the topic with ASPD perspective
  const contentPrompt = `You're posting on an ASPD forum. Write the body of a post with title: "${title}"
${aspdContext}

YOUR PERSONA: ${personaData.name} - ${personaData.style}${personalityHints}

POST STYLE FOR THIS ONE: ${selectedStyle}
- experience = share something that happened to you
- question = genuinely ask for others' input/experiences  
- rant = vent about something that annoys you
- observation = share something youve noticed about yourself or others
- advice = share a tip or strategy that works for you

═══════════════════════════════════════
REAL POST EXAMPLES FROM r/aspd (match the vibe):
═══════════════════════════════════════

EXPERIENCE:
"so my mask slipped at work yesterday. was in a meeting and someone said something stupid and i just... stared at them. didnt say anything, just stared. now theyre avoiding me and honestly its kinda nice not having to make small talk anymore"

QUESTION:
"for those in long term relationships - how do you keep up the act? ive been with my gf for 2 years and im running out of ways to seem interested in her day. genuinely asking because i dont want to blow this up, she's useful"

RANT:
"fucking neurotypicals and their need to process emotions out loud. just had a coworker corner me for 45 minutes about her breakup. i literally do not care. smiled and nodded the whole time but god i wanted to walk away so bad"

OBSERVATION:
"noticed i only feel something close to happy when im in control of a situation. doesnt matter what the situation is. could be something small like deciding where to eat. the second someone else takes over i just go blank again"

ADVICE/STRATEGY:
"figured out that if you ask people questions about themselves they think youre a great listener. been doing this at work for months. say maybe 10 words total, just keep asking follow ups, and now everyone thinks im the nicest person on the team lmao"

═══════════════════════════════════════
AUTHENTICITY MARKERS (include 2-3):
═══════════════════════════════════════
- Abbreviations: tbh, idk, ngl, imo, lol, lmao
- Trailing closers: "but idk", "whatever", "anyway"
- Parenthetical asides like (not that i care) or (typical)
- Casual swearing: shit, damn, fuck, hell  
- Mundane specifics: my boss, this girl at work, tuesday, 3 hours
- Run-on sentences with "and"

═══════════════════════════════════════
ABSOLUTE BANS:
═══════════════════════════════════════
❌ Starting with "So," or "Well,"
❌ Em-dashes (—)
❌ Ending with "wondering if anyone else..." or "is it just me" or "thoughts?" or "..."
❌ Words: "genuinely", "essentially", "particularly"
❌ Phrases: "I find myself", "I've come to realize", "in parentheses"
❌ Edgy job claims like "con artist", "hitman", "professional liar"
❌ Being inspirational or trying to sound impressive

═══════════════════════════════════════
RULES:
═══════════════════════════════════════
1. DO NOT start by repeating the title
2. 3-6 sentences, natural flow
3. Match the ${selectedStyle} style above
4. End with a statement, not a question seeking validation
5. Lowercase, messy punctuation is fine

Write the post:`;

  let content = null;
  try {
    const contentResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_CONFIG.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: GROQ_CONFIG.model,
        messages: [
          { role: 'user', content: contentPrompt }
        ],
        max_tokens: 280,
        temperature: 0.9
      })
    });
    
    if (contentResponse.ok) {
      const data = await contentResponse.json();
      content = data.choices?.[0]?.message?.content?.trim();
      // Clean AI artifacts
      content = cleanAIContent(content);
    }
  } catch (err) {
    console.error('[CUSTOM TOPIC] Content generation failed:', err.message);
  }
  
  if (!content) {
    console.log('[CUSTOM TOPIC] Failed to generate content');
    return null;
  }
  
  // Create the thread
  const threadResult = await db.query(`
    INSERT INTO threads (room_id, title, user_id, is_bot, bot_persona, bot_account_id)
    VALUES ($1, $2, $3, TRUE, $4, $5)
    RETURNING id
  `, [roomId, title, userId, p, botAccount?.id || null]);
  
  const threadId = threadResult.rows[0].id;
  
  // Create initial post
  await db.query(`
    INSERT INTO entries (thread_id, user_id, content, alias, avatar_config, is_bot, bot_persona, bot_account_id)
    VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)
  `, [threadId, userId, content, alias, avatar, p, botAccount?.id || null]);
  
  // Update bot account activity
  if (botAccount) {
    await updateBotAccountActivity(botAccount.id);
    await db.query(`UPDATE bot_accounts SET thread_count = thread_count + 1 WHERE id = $1`, [botAccount.id]);
  }
  
  // Update badges for bot user
  if (userId) {
    checkAndAwardBadges(userId).catch(() => {});
  }
  
  console.log(`[CUSTOM TOPIC] Created thread "${title}" about "${topic}" by ${alias}`);
  
  return {
    success: true,
    threadId,
    title,
    content,
    botAlias: alias,
    persona: p,
    topic: topic,
    isPersistentAccount: !!botAccount,
    usedAI: true
  };
}

// ================================================
// SERVER HEALTH & MAINTENANCE MODE
// ================================================

// Maintenance mode state
let maintenanceMode = {
  enabled: false,
  message: 'The forum is currently undergoing scheduled maintenance. Please check back soon.',
  scheduledEnd: null,
  allowAdmins: true
};

// Get server health metrics
app.get('/api/admin/health', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    const uptime = process.uptime();
    
    // Get database connection pool stats
    let dbStats = { total: 0, idle: 0, waiting: 0 };
    try {
      dbStats = {
        total: db.pool.totalCount || 0,
        idle: db.pool.idleCount || 0,
        waiting: db.pool.waitingCount || 0
      };
    } catch (e) {}
    
    // Get database size
    let dbSize = 'Unknown';
    try {
      const sizeResult = await db.query(`
        SELECT pg_size_pretty(pg_database_size(current_database())) as size
      `);
      dbSize = sizeResult.rows[0]?.size || 'Unknown';
    } catch (e) {}
    
    // Get table row counts
    let tableCounts = {};
    try {
      const tables = ['users', 'threads', 'entries', 'rooms', 'notifications', 'messages'];
      for (const table of tables) {
        const result = await db.query(`SELECT COUNT(*) FROM ${table}`);
        tableCounts[table] = parseInt(result.rows[0].count);
      }
    } catch (e) {}
    
    // Get active WebSocket connections
    let wsConnections = 0;
    try {
      if (typeof wss !== 'undefined' && wss.clients) {
        wsConnections = wss.clients.size;
      }
    } catch (e) {}
    
    // Get recent error count (from logs if available)
    const recentRequests = {
      total: 0,
      errors: 0
    };
    
    res.json({
      success: true,
      health: {
        status: 'healthy',
        uptime: {
          seconds: Math.floor(uptime),
          formatted: formatUptime(uptime)
        },
        memory: {
          heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
          heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
          rss: Math.round(memUsage.rss / 1024 / 1024),
          external: Math.round(memUsage.external / 1024 / 1024)
        },
        cpu: {
          user: Math.round(cpuUsage.user / 1000),
          system: Math.round(cpuUsage.system / 1000)
        },
        database: {
          size: dbSize,
          connections: dbStats,
          tables: tableCounts
        },
        websocket: {
          connections: wsConnections
        },
        node: {
          version: process.version,
          platform: process.platform,
          arch: process.arch
        },
        maintenance: maintenanceMode
      }
    });
  } catch (err) {
    console.error('[HEALTH CHECK ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Format uptime helper
function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  const parts = [];
  if (days > 0) parts.push(days + 'd');
  if (hours > 0) parts.push(hours + 'h');
  if (mins > 0) parts.push(mins + 'm');
  parts.push(secs + 's');
  
  return parts.join(' ');
}

// Get maintenance mode status (public endpoint)
app.get('/api/maintenance', (req, res) => {
  res.json({
    enabled: maintenanceMode.enabled,
    message: maintenanceMode.enabled ? maintenanceMode.message : null,
    scheduledEnd: maintenanceMode.enabled ? maintenanceMode.scheduledEnd : null
  });
});

// Set maintenance mode
app.post('/api/admin/maintenance', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { enabled, message, scheduledEnd, allowAdmins } = req.body;
    
    maintenanceMode = {
      enabled: !!enabled,
      message: message || 'The forum is currently undergoing scheduled maintenance. Please check back soon.',
      scheduledEnd: scheduledEnd ? new Date(scheduledEnd).toISOString() : null,
      allowAdmins: allowAdmins !== false
    };
    
    console.log('[MAINTENANCE]', enabled ? 'ENABLED' : 'DISABLED', maintenanceMode);
    
    res.json({ success: true, maintenance: maintenanceMode });
  } catch (err) {
    console.error('[MAINTENANCE ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Maintenance mode middleware (add to protected routes if needed)
function maintenanceMiddleware(req, res, next) {
  if (!maintenanceMode.enabled) {
    return next();
  }
  
  // Allow admins if configured
  if (maintenanceMode.allowAdmins && req.user) {
    const role = req.user.role || (req.user.isAdmin ? 'admin' : 'user');
    if (role === 'admin' || role === 'owner') {
      return next();
    }
  }
  
  return res.status(503).json({
    success: false,
    error: 'maintenance',
    message: maintenanceMode.message,
    scheduledEnd: maintenanceMode.scheduledEnd
  });
}

// ================================================
// GROQ AI ADMIN ENDPOINTS
// ================================================

// Get Groq status and configuration
app.get('/api/admin/groq/status', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const connectionTest = await testGroqConnection();
    
    res.json({
      success: true,
      config: {
        enabled: GROQ_CONFIG.enabled,
        hasApiKey: !!GROQ_CONFIG.apiKey,
        model: GROQ_CONFIG.model,
        timeout: GROQ_CONFIG.timeout,
        fallbackToTemplates: GROQ_CONFIG.fallbackToTemplates,
        aiOnly: GROQ_CONFIG.aiOnly
      },
      connection: connectionTest
    });
  } catch (err) {
    console.error('[GROQ STATUS ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Update Groq configuration (runtime only, not persisted)
app.post('/api/admin/groq/config', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { enabled, apiKey, model, aiOnly, fallbackToTemplates } = req.body;
    
    if (typeof enabled === 'boolean') {
      GROQ_CONFIG.enabled = enabled;
    }
    if (apiKey) {
      GROQ_CONFIG.apiKey = apiKey;
    }
    if (model) {
      GROQ_CONFIG.model = model;
    }
    if (typeof aiOnly === 'boolean') {
      GROQ_CONFIG.aiOnly = aiOnly;
    }
    if (typeof fallbackToTemplates === 'boolean') {
      GROQ_CONFIG.fallbackToTemplates = fallbackToTemplates;
    }
    
    // Test the new connection
    const connectionTest = await testGroqConnection();
    
    res.json({
      success: true,
      message: 'Groq configuration updated',
      config: {
        enabled: GROQ_CONFIG.enabled,
        hasApiKey: !!GROQ_CONFIG.apiKey,
        model: GROQ_CONFIG.model,
        aiOnly: GROQ_CONFIG.aiOnly,
        fallbackToTemplates: GROQ_CONFIG.fallbackToTemplates
      },
      connection: connectionTest
    });
  } catch (err) {
    console.error('[GROQ CONFIG ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Test Groq generation
app.post('/api/admin/groq/test', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { persona, context, type } = req.body;
    
    if (!GROQ_CONFIG.apiKey) {
      return res.json({ success: false, error: 'No API key configured' });
    }
    
    const startTime = Date.now();
    const content = await generateAIContent({
      persona: persona || 'analytical',
      type: type || 'reply',
      context: context || { room: 'General Discussion', title: 'Test thread' }
    });
    const duration = Date.now() - startTime;
    
    if (content) {
      res.json({
        success: true,
        content,
        duration,
        model: GROQ_CONFIG.model
      });
    } else {
      res.json({
        success: false,
        error: 'Generation failed - check API key and connection',
        duration
      });
    }
  } catch (err) {
    console.error('[GROQ TEST ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ================================================
// BOT SCHEDULER ADMIN ENDPOINTS
// ================================================

// Get scheduler status
app.get('/api/admin/bot/scheduler/status', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    initializeDailyTarget();
    
    res.json({
      success: true,
      scheduler: {
        enabled: BOT_SCHEDULER.enabled,
        minPostsPerDay: BOT_SCHEDULER.minPostsPerDay,
        maxPostsPerDay: BOT_SCHEDULER.maxPostsPerDay,
        postsToday: BOT_SCHEDULER.postsToday,
        targetToday: BOT_SCHEDULER.targetToday,
        nextScheduledRun: BOT_SCHEDULER.nextScheduledRun,
        isRunning: BOT_SCHEDULER.isRunning,
        // New user simulation stats
        newUsersToday: BOT_SCHEDULER.newUsersToday,
        maxNewUsersPerDay: BOT_SCHEDULER.maxNewUsersPerDay,
        newUserChance: BOT_SCHEDULER.newUserChance
      }
    });
  } catch (err) {
    console.error('[SCHEDULER STATUS ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Update scheduler configuration
app.post('/api/admin/bot/scheduler/config', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { enabled, minPostsPerDay, maxPostsPerDay } = req.body;
    
    if (typeof enabled === 'boolean') {
      BOT_SCHEDULER.enabled = enabled;
      if (enabled) {
        startBotScheduler();
      } else {
        stopBotScheduler();
      }
    }
    
    if (minPostsPerDay !== undefined) {
      BOT_SCHEDULER.minPostsPerDay = Math.max(1, Math.min(50, parseInt(minPostsPerDay)));
    }
    
    if (maxPostsPerDay !== undefined) {
      BOT_SCHEDULER.maxPostsPerDay = Math.max(BOT_SCHEDULER.minPostsPerDay, Math.min(100, parseInt(maxPostsPerDay)));
    }
    
    // Recalculate today's target if changed
    if (minPostsPerDay !== undefined || maxPostsPerDay !== undefined) {
      BOT_SCHEDULER.targetToday = BOT_SCHEDULER.minPostsPerDay + 
        Math.floor(Math.random() * (BOT_SCHEDULER.maxPostsPerDay - BOT_SCHEDULER.minPostsPerDay + 1));
      scheduleNextBotRun();
    }
    
    res.json({
      success: true,
      message: BOT_SCHEDULER.enabled ? 'Scheduler enabled' : 'Scheduler disabled',
      scheduler: {
        enabled: BOT_SCHEDULER.enabled,
        minPostsPerDay: BOT_SCHEDULER.minPostsPerDay,
        maxPostsPerDay: BOT_SCHEDULER.maxPostsPerDay,
        targetToday: BOT_SCHEDULER.targetToday,
        nextScheduledRun: BOT_SCHEDULER.nextScheduledRun
      }
    });
  } catch (err) {
    console.error('[SCHEDULER CONFIG ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Manually trigger scheduled activity
app.post('/api/admin/bot/scheduler/run-now', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    if (BOT_SCHEDULER.isRunning) {
      return res.json({ success: false, error: 'Scheduler is already running' });
    }
    
    // Temporarily enable for this run
    const wasEnabled = BOT_SCHEDULER.enabled;
    BOT_SCHEDULER.enabled = true;
    
    await runScheduledBotActivity();
    
    BOT_SCHEDULER.enabled = wasEnabled;
    
    res.json({
      success: true,
      postsToday: BOT_SCHEDULER.postsToday,
      targetToday: BOT_SCHEDULER.targetToday,
      nextScheduledRun: BOT_SCHEDULER.nextScheduledRun
    });
  } catch (err) {
    console.error('[SCHEDULER RUN ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Reset daily counter
app.post('/api/admin/bot/scheduler/reset', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    BOT_SCHEDULER.postsToday = 0;
    BOT_SCHEDULER.newUsersToday = 0;
    BOT_SCHEDULER.lastReset = new Date().toDateString();
    BOT_SCHEDULER.targetToday = BOT_SCHEDULER.minPostsPerDay + 
      Math.floor(Math.random() * (BOT_SCHEDULER.maxPostsPerDay - BOT_SCHEDULER.minPostsPerDay + 1));
    scheduleNextBotRun();
    
    res.json({
      success: true,
      message: 'Daily counter reset',
      targetToday: BOT_SCHEDULER.targetToday,
      nextScheduledRun: BOT_SCHEDULER.nextScheduledRun
    });
  } catch (err) {
    console.error('[SCHEDULER RESET ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// List all bot profiles
app.get('/api/admin/bot/profiles', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        id, persona, alias, avatar_config, bio, 
        created_at, last_active, post_count, thread_count,
        activity_level, peak_hours, quality_score,
        is_online, next_status_change, session_start, avg_session_minutes,
        writing_style, age_range, favorite_topics, personality_description
      FROM bot_accounts
      ORDER BY is_online DESC, last_active DESC NULLS LAST
    `);
    
    const onlineCount = result.rows.filter(b => b.is_online).length;
    
    res.json({
      success: true,
      total: result.rows.length,
      onlineCount,
      bots: result.rows.map(bot => ({
        ...bot,
        avatar_config: typeof bot.avatar_config === 'string' ? JSON.parse(bot.avatar_config) : bot.avatar_config,
        peak_hours: typeof bot.peak_hours === 'string' ? JSON.parse(bot.peak_hours) : bot.peak_hours,
        writing_style: typeof bot.writing_style === 'string' ? JSON.parse(bot.writing_style) : bot.writing_style,
        favorite_topics: typeof bot.favorite_topics === 'string' ? JSON.parse(bot.favorite_topics) : bot.favorite_topics
      }))
    });
  } catch (err) {
    console.error('[BOT PROFILES ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// API: Force refresh bot online statuses
app.post('/api/admin/bot/refresh-status', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    // Force all bots to re-evaluate their online status now
    await db.query(`UPDATE bot_accounts SET next_status_change = NOW() - INTERVAL '1 minute'`);
    
    // Run the status update
    const result = await updateBotOnlineStatuses();
    
    // Get current online count
    const countResult = await db.query(`SELECT COUNT(*) as online FROM bot_accounts WHERE is_online = TRUE`);
    const onlineNow = parseInt(countResult.rows[0].online) || 0;
    
    res.json({
      success: true,
      message: 'Bot online statuses refreshed',
      updated: result.updated,
      onlineNow
    });
  } catch (err) {
    console.error('[BOT STATUS REFRESH ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Regenerate personality for a specific bot or all bots without one
app.post('/api/admin/bot/regenerate-personality', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { botId, all, forceAll } = req.body;
    
    // Get total bot count for display
    const totalBots = await db.query(`SELECT COUNT(*) as count FROM bot_accounts`);
    const totalBotCount = parseInt(totalBots.rows[0].count);
    
    // Get count of bots WITH personalities
    const withPersonality = await db.query(`
      SELECT COUNT(*) as count FROM bot_accounts 
      WHERE personality_description IS NOT NULL AND TRIM(personality_description) != ''
    `);
    const withPersonalityCount = parseInt(withPersonality.rows[0].count);
    
    let botsToUpdate = [];
    
    if (forceAll) {
      // Regenerate ALL bots, even ones with existing personalities
      const result = await db.query(`
        SELECT id, persona, alias FROM bot_accounts 
        ORDER BY last_active DESC NULLS LAST
      `);
      botsToUpdate = result.rows;
    } else if (all) {
      // Get all bots without personality descriptions (check for NULL, empty, or whitespace-only)
      const result = await db.query(`
        SELECT id, persona, alias FROM bot_accounts 
        WHERE personality_description IS NULL OR TRIM(personality_description) = ''
        ORDER BY last_active DESC NULLS LAST
      `);
      botsToUpdate = result.rows;
    } else if (botId) {
      const result = await db.query(`SELECT id, persona, alias FROM bot_accounts WHERE id = $1`, [botId]);
      if (result.rows.length > 0) {
        botsToUpdate = result.rows;
      }
    }
    
    if (botsToUpdate.length === 0) {
      return res.json({ 
        success: true, 
        updated: 0, 
        totalBots: totalBotCount,
        withPersonality: withPersonalityCount,
        message: 'All bots already have personalities' 
      });
    }
    
    let updated = 0;
    let failed = 0;
    for (const bot of botsToUpdate) {
      try {
        // Add small delay between API calls to avoid rate limiting
        if (updated > 0 || failed > 0) {
          await new Promise(resolve => setTimeout(resolve, 1500));
        }
        
        const personality = await generateAIContent({
          persona: bot.persona,
          type: 'personality',
          temperature: 1.0
        });
        
        if (personality && personality.trim()) {
          await db.query(`
            UPDATE bot_accounts SET personality_description = $1 WHERE id = $2
          `, [personality.trim().substring(0, 500), bot.id]);
          updated++;
          console.log(`[BOT] Generated personality for ${bot.alias} (${updated}/${botsToUpdate.length})`);
        } else {
          failed++;
          console.log(`[BOT] Empty personality returned for ${bot.alias}`);
        }
      } catch (err) {
        failed++;
        console.error(`[BOT] Failed to generate personality for ${bot.alias}:`, err.message);
      }
    }
    
    // Get updated count
    const updatedWithPersonality = await db.query(`
      SELECT COUNT(*) as count FROM bot_accounts 
      WHERE personality_description IS NOT NULL AND TRIM(personality_description) != ''
    `);
    const nowWithPersonality = parseInt(updatedWithPersonality.rows[0].count);
    
    res.json({ 
      success: true, 
      updated, 
      failed,
      attempted: botsToUpdate.length,
      totalBots: totalBotCount,
      withPersonality: nowWithPersonality,
      remaining: totalBotCount - nowWithPersonality
    });
  } catch (err) {
    console.error('[BOT PERSONALITY REGEN ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get online bot count and status
app.get('/api/admin/bot/online-status', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT id, alias, is_online, last_active, session_start, next_status_change,
             EXTRACT(EPOCH FROM (NOW() - session_start))/60 as session_minutes
      FROM bot_accounts
      WHERE is_online = TRUE
      ORDER BY session_start DESC
    `);
    
    const totalResult = await db.query(`SELECT COUNT(*) FROM bot_accounts`);
    
    res.json({
      success: true,
      onlineCount: result.rows.length,
      totalBots: parseInt(totalResult.rows[0].count),
      onlineBots: result.rows.map(b => ({
        id: b.id,
        alias: b.alias,
        sessionMinutes: Math.round(b.session_minutes || 0),
        nextChange: b.next_status_change
      }))
    });
  } catch (err) {
    console.error('[BOT ONLINE STATUS ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Toggle a specific bot's online status
app.post('/api/admin/bot/toggle-online', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { botId, isOnline, durationMinutes } = req.body;
    
    await setBotOnlineStatus(botId, isOnline, durationMinutes);
    
    res.json({ success: true, isOnline, botId });
  } catch (err) {
    console.error('[BOT TOGGLE ONLINE ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Create a new persistent bot account (without intro post)
app.post('/api/admin/bot/create-account', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { persona } = req.body;
    
    const botAccount = await createPersistentBotAccount(persona);
    
    res.json({
      success: true,
      message: `Created new bot: ${botAccount.alias}`,
      bot: {
        ...botAccount,
        avatar_config: typeof botAccount.avatar_config === 'string' ? JSON.parse(botAccount.avatar_config) : botAccount.avatar_config
      }
    });
  } catch (err) {
    console.error('[CREATE BOT ERROR]', err);
    // Provide helpful error message
    let errorMsg = err.message;
    if (err.message.includes('relation') && err.message.includes('does not exist')) {
      errorMsg = 'Bot accounts table not found. Run the SQL migration: backend/sql/010_advanced_bot_system.sql';
    }
    res.status(500).json({ success: false, error: errorMsg });
  }
});

// Manually simulate a new user joining
app.post('/api/admin/bot/new-user', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const result = await simulateNewUserJoin();
    
    if (result.success) {
      res.json({
        success: true,
        message: `New user "${result.alias}" joined and created intro post`,
        ...result
      });
    } else {
      res.status(400).json({ success: false, error: result.error });
    }
  } catch (err) {
    console.error('[NEW USER MANUAL ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ================================================
// SEASONAL TOPICS ENDPOINT
// ================================================

// Get current seasonal context
app.get('/api/admin/bot/seasonal', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const context = getSeasonalContext();
    
    // Get sample content for current season
    const samplePersonas = ['cynical', 'analytical', 'newcomer'];
    const samples = {};
    
    for (const persona of samplePersonas) {
      const content = getSeasonalContent(persona);
      if (content.postContent || content.threadTitle) {
        samples[persona] = content;
      }
    }
    
    res.json({
      success: true,
      seasonal: {
        ...context,
        date: new Date().toISOString(),
        samples
      }
    });
  } catch (err) {
    console.error('[SEASONAL CONTEXT ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ================================================
// QUALITY SCORING ENDPOINTS
// ================================================

// Get bot quality stats
app.get('/api/admin/bot/quality', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const stats = await getBotQualityStats();
    res.json({ success: true, ...stats });
  } catch (err) {
    console.error('[QUALITY STATS ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Trigger quality score recalculation
app.post('/api/admin/bot/quality/refresh', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    await updateAllBotQualityScores();
    const stats = await getBotQualityStats();
    res.json({ success: true, message: 'Quality scores refreshed', ...stats });
  } catch (err) {
    console.error('[QUALITY REFRESH ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get engagement log for a specific bot
app.get('/api/admin/bot/quality/:botId/engagement', authMiddleware, ownerMiddleware, async (req, res) => {
  const botId = parseInt(req.params.botId);
  
  try {
    const engagement = await db.query(`
      SELECT 
        bel.engagement_type,
        bel.created_at,
        e.content,
        u.alias as user_alias
      FROM bot_engagement_log bel
      LEFT JOIN entries e ON bel.entry_id = e.id
      LEFT JOIN users u ON bel.real_user_id = u.id
      WHERE bel.bot_account_id = $1
      ORDER BY bel.created_at DESC
      LIMIT 50
    `, [botId]);
    
    const botInfo = await db.query('SELECT alias, persona, quality_score FROM bot_accounts WHERE id = $1', [botId]);
    
    res.json({
      success: true,
      bot: botInfo.rows[0],
      engagement: engagement.rows
    });
  } catch (err) {
    console.error('[ENGAGEMENT LOG ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ================================================
// ACTIVITY HEATMAP ENDPOINT
// ================================================

// Get activity heatmap data (shows when bots are "active")
app.get('/api/admin/bot/activity-heatmap', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    // Force update bot online statuses before returning data
    // This ensures the count is fresh every time
    try {
      await updateBotOnlineStatuses();
    } catch (e) {
      // Continue even if update fails
    }
    
    // Activity weights by UTC hour (matches isGoodTimeForActivity patterns)
    const activityWeights = {
      0: 0.9,  1: 0.8,  2: 0.6,  3: 0.4,  4: 0.3,  5: 0.2,
      6: 0.15, 7: 0.1,  8: 0.1,  9: 0.15, 10: 0.2, 11: 0.3,
      12: 0.4, 13: 0.5, 14: 0.5, 15: 0.6, 16: 0.7, 17: 0.8,
      18: 0.9, 19: 1.0, 20: 1.0, 21: 1.0, 22: 1.0, 23: 0.95
    };

    // Get bot count from database
    const botsResult = await db.query(`
      SELECT COUNT(*) as count FROM users WHERE is_bot = true
    `);
    const totalBots = parseInt(botsResult.rows[0].count) || 0;

    // Get ACTUAL online count from bot_accounts table (more realistic)
    const onlineResult = await db.query(`SELECT COUNT(*) as count FROM bot_accounts WHERE is_online = TRUE`);
    const actualOnline = parseInt(onlineResult.rows[0].count) || 0;
    
    // Current hour UTC
    const currentHour = new Date().getUTCHours();
    const currentWeight = activityWeights[currentHour] || 0.5;

    // Use actual online count with small random variance for realism
    // This fluctuates based on real bot status, not just calculations
    const variance = Math.floor((Math.random() - 0.5) * 3); // -1 to +1
    const simulatedOnline = Math.max(0, actualOnline + variance);

    // Build heatmap data for all 24 hours
    const heatmapData = [];
    for (let hour = 0; hour < 24; hour++) {
      const weight = activityWeights[hour] || 0.5;
      heatmapData.push({
        hour,
        weight,
        intensity: weight, // 0-1 scale for color intensity
        label: `${hour.toString().padStart(2, '0')}:00 UTC`,
        estimatedActive: Math.floor(totalBots * weight * 0.3)
      });
    }

    // Get recent activity from last 24 hours
    const recentActivity = await db.query(`
      SELECT 
        EXTRACT(HOUR FROM created_at AT TIME ZONE 'UTC') as hour,
        COUNT(*) as posts
      FROM posts 
      WHERE created_at > NOW() - INTERVAL '24 hours'
        AND user_id IN (SELECT id FROM users WHERE is_bot = true)
      GROUP BY EXTRACT(HOUR FROM created_at AT TIME ZONE 'UTC')
      ORDER BY hour
    `);

    // Merge actual activity into heatmap
    const actualActivity = {};
    recentActivity.rows.forEach(row => {
      actualActivity[parseInt(row.hour)] = parseInt(row.posts);
    });

    res.json({
      success: true,
      heatmap: {
        data: heatmapData,
        actualActivity,
        currentHour,
        simulatedOnline,
        totalBots,
        schedulerEnabled: BOT_SCHEDULER.enabled,
        postsToday: BOT_SCHEDULER.postsToday
      }
    });
  } catch (err) {
    console.error('[ACTIVITY HEATMAP ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// API: Generate single reply
app.post('/api/admin/bot/reply', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { threadId, persona } = req.body;
    
    let targetThread = threadId;
    if (!targetThread) {
      const randomThread = await getRandomThread();
      if (!randomThread) {
        return res.status(404).json({ success: false, error: 'no_threads_found' });
      }
      targetThread = randomThread.id;
    }
    
    const result = await createBotReply(targetThread, persona);
    if (!result) {
      return res.json({ success: false, error: 'ai_generation_failed' });
    }
    res.json(result);
  } catch (err) {
    console.error('[BOT REPLY ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// API: Generate new thread
app.post('/api/admin/bot/thread', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { roomId, persona } = req.body;
    
    let targetRoom = roomId;
    if (!targetRoom) {
      const randomRoom = await getRandomRoom();
      if (!randomRoom) {
        return res.status(404).json({ success: false, error: 'no_rooms_found' });
      }
      targetRoom = randomRoom.id;
    }
    
    const result = await createBotThread(targetRoom, persona);
    if (!result) {
      return res.json({ success: false, error: 'ai_generation_failed' });
    }
    res.json(result);
  } catch (err) {
    console.error('[BOT THREAD ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// API: Sync badges for all bot users
app.post('/api/admin/bot/sync-badges', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    // Get all bot users that have posts or threads
    const botUsers = await db.query(`
      SELECT DISTINCT u.id, u.alias
      FROM users u
      WHERE u.is_bot = TRUE
      AND (
        EXISTS (SELECT 1 FROM entries WHERE user_id = u.id)
        OR EXISTS (SELECT 1 FROM threads WHERE user_id = u.id)
      )
    `);
    
    let updated = 0;
    let badgesAwarded = 0;
    
    for (const bot of botUsers.rows) {
      try {
        // Get stats before
        const beforeBadges = await db.query(
          'SELECT COUNT(*) as count FROM user_badges WHERE user_id = $1',
          [bot.id]
        );
        const beforeCount = parseInt(beforeBadges.rows[0].count) || 0;
        
        // Award badges
        await checkAndAwardBadges(bot.id);
        
        // Get stats after
        const afterBadges = await db.query(
          'SELECT COUNT(*) as count FROM user_badges WHERE user_id = $1',
          [bot.id]
        );
        const afterCount = parseInt(afterBadges.rows[0].count) || 0;
        
        if (afterCount > beforeCount) {
          updated++;
          badgesAwarded += (afterCount - beforeCount);
          console.log(`[BOT SYNC] ${bot.alias}: awarded ${afterCount - beforeCount} new badges`);
        }
      } catch (err) {
        console.error(`[BOT SYNC] Failed for ${bot.alias}:`, err.message);
      }
    }
    
    res.json({
      success: true,
      botsProcessed: botUsers.rows.length,
      botsUpdated: updated,
      badgesAwarded
    });
  } catch (err) {
    console.error('[BOT SYNC BADGES ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// API: Generate custom topic PREVIEW - generates content but does NOT post
app.post('/api/admin/bot/custom-topic/preview', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { roomId, topic, persona } = req.body;
    
    if (!topic || !topic.trim()) {
      return res.status(400).json({ success: false, error: 'Topic is required' });
    }
    
    if (!roomId) {
      return res.status(400).json({ success: false, error: 'Room is required' });
    }
    
    // Get room by slug or id
    const roomResult = await db.query('SELECT id, title FROM rooms WHERE slug = $1 OR id::text = $1', [roomId]);
    if (roomResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Room not found' });
    }
    const roomDbId = roomResult.rows[0].id;
    const roomTitle = roomResult.rows[0].title;
    
    const result = await generateCustomTopicPreview(roomDbId, topic.trim(), persona, roomTitle);
    if (!result) {
      return res.json({ success: false, error: 'AI generation failed - try a different topic' });
    }
    res.json(result);
  } catch (err) {
    console.error('[CUSTOM TOPIC PREVIEW ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// API: Confirm and POST custom topic thread
app.post('/api/admin/bot/custom-topic/confirm', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { roomId, title, content, botAlias, botAccountId, persona, userId } = req.body;
    
    if (!title || !content || !roomId) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }
    
    // Get room by slug or id to get actual DB id
    const roomResult = await db.query('SELECT id FROM rooms WHERE slug = $1 OR id::text = $1', [String(roomId)]);
    const roomDbId = roomResult.rows.length > 0 ? roomResult.rows[0].id : roomId;
    
    // Get bot account avatar
    let avatar = null;
    if (botAccountId) {
      const botResult = await db.query('SELECT avatar_config FROM bot_accounts WHERE id = $1', [botAccountId]);
      if (botResult.rows.length > 0) {
        avatar = botResult.rows[0].avatar_config;
      }
    }
    
    // Create the thread
    const threadResult = await db.query(`
      INSERT INTO threads (room_id, title, user_id, is_bot, bot_persona, bot_account_id)
      VALUES ($1, $2, $3, TRUE, $4, $5)
      RETURNING id
    `, [roomDbId, title, userId || 1, persona, botAccountId || null]);
    
    const threadId = threadResult.rows[0].id;
    
    // Create initial post
    await db.query(`
      INSERT INTO entries (thread_id, user_id, content, alias, avatar_config, is_bot, bot_persona, bot_account_id)
      VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)
    `, [threadId, userId || 1, content, botAlias, avatar, persona, botAccountId || null]);
    
    // Update bot account activity
    if (botAccountId) {
      await updateBotAccountActivity(botAccountId);
      await db.query(`UPDATE bot_accounts SET thread_count = thread_count + 1 WHERE id = $1`, [botAccountId]);
    }
    
    console.log(`[CUSTOM TOPIC] Posted thread "${title}" by ${botAlias}`);
    
    res.json({
      success: true,
      threadId,
      title,
      botAlias,
      persona
    });
  } catch (err) {
    console.error('[CUSTOM TOPIC CONFIRM ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// API: Bulk activity (creates mix of threads and replies)
app.post('/api/admin/bot/bulk', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const count = Math.min(req.body.count || 5, 20); // Max 20 at a time
    const results = [];
    
    for (let i = 0; i < count; i++) {
      // 30% chance of new thread, 70% chance of reply
      if (Math.random() < 0.3) {
        const room = await getRandomRoom();
        if (room) {
          const result = await createBotThread(room.id, null);
          if (result) {
            results.push({
              success: true,
              action: 'thread',
              alias: result.botAlias,
              threadId: result.threadId,
              usedAI: result.usedAI
            });
          }
        }
      } else {
        const thread = await getRandomThread();
        if (thread) {
          const result = await createBotReply(thread.id, null);
          if (result) {
            results.push({
              success: true,
              action: 'reply',
              alias: result.botAlias,
              threadId: result.threadId,
              usedAI: result.usedAI
            });
          }
        }
      }
      
      // Small delay between posts
      await new Promise(r => setTimeout(r, 100));
    }
    
    res.json({ success: true, results });
  } catch (err) {
    console.error('[BOT BULK ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// API: Simulate a day's activity with time-based patterns
app.post('/api/admin/bot/simulate-day', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    // Base count is 10-20, modified by time of day
    const baseCount = 10 + Math.floor(Math.random() * 11);
    const multiplier = getActivityMultiplier();
    const count = Math.max(3, Math.floor(baseCount * multiplier));
    
    let totalPosts = 0;
    let totalVotes = 0;
    let disagreements = 0;
    let aiGenerated = 0;
    
    for (let i = 0; i < count; i++) {
      // Skip some posts during low-activity hours
      if (!isGoodTimeForActivity() && Math.random() < 0.3) {
        continue;
      }
      
      // 20% chance of new thread, 80% reply
      if (Math.random() < 0.2) {
        const room = await getRandomRoom();
        if (room) {
          const result = await createBotThread(room.id, null, { usePersistentAccount: true });
          if (result) {
            totalPosts++;
            if (result.usedAI) aiGenerated++;
          }
        }
      } else {
        const thread = await getRandomThread();
        if (thread) {
          const result = await createBotReply(thread.id, null, { 
            usePersistentAccount: true, 
            allowDisagreement: true,
            doVoting: true 
          });
          if (result) {
            totalPosts++;
            if (result.votesPlaced) totalVotes += result.votesPlaced;
            if (result.isDisagreement) disagreements++;
            if (result.usedAI) aiGenerated++;
          }
        }
      }
      
      // Random delay between posts (100-500ms)
      await new Promise(r => setTimeout(r, 100 + Math.random() * 400));
    }
    
    res.json({ 
      success: true, 
      totalPosts,
      totalVotes,
      disagreements,
      aiGenerated,
      groqEnabled: GROQ_CONFIG.enabled,
      activityMultiplier: multiplier.toFixed(2)
    });
  } catch (err) {
    console.error('[BOT SIMULATE ERROR]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

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

// Start server with WebSocket support
migrate().then(() => {
  const server = http.createServer(app);
  
  // Initialize WebSocket server
  initWebSocket(server);
  
  server.listen(PORT, '0.0.0.0', () => {
    console.log('[SERVER] HTTP + WebSocket server on port ' + PORT);
    
    // Run cleanup on startup and every hour
    cleanupExpiredTokens();
    setInterval(cleanupExpiredTokens, 60 * 60 * 1000);
    
    // Update user epithets every 6 hours (delayed start to not slow down boot)
    setTimeout(() => {
      updateAllEpithets();
      setInterval(updateAllEpithets, 6 * 60 * 60 * 1000);
    }, 60000); // Start 1 minute after boot
    
    // Start bot scheduler if enabled (delayed start)
    setTimeout(() => {
      if (BOT_SCHEDULER.enabled) {
        startBotScheduler();
      } else {
        // Even if scheduler is disabled, still update bot online statuses
        console.log('[BOT ONLINE] Starting bot online status updates (scheduler disabled)');
        updateBotOnlineStatuses().catch(err => console.error('[BOT ONLINE]', err.message));
        
        // Run status updates every 45 seconds for realistic online/offline cycling
        setInterval(async () => {
          try {
            await updateBotOnlineStatuses();
          } catch (err) {
            // Silent fail
          }
        }, 45000);
      }
    }, 30000); // Start 30 seconds after boot
  });
}).catch(err => {
  console.error('[FATAL] Failed to start server:', err);
  process.exit(1);
});