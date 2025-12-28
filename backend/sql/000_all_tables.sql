-- Combined migration: Run this in pgAdmin Query Tool on aspd_forum database

-- 001: Users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  alias TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

-- 002: Forum tables
CREATE TABLE IF NOT EXISTS rooms (
  id SERIAL PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threads (
  id SERIAL PRIMARY KEY,
  room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entries (
  id SERIAL PRIMARY KEY,
  thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  avatar_config JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threads_room_id ON threads(room_id);
CREATE INDEX IF NOT EXISTS idx_entries_thread_id ON entries(thread_id);

-- 004: Anonymous posting support
ALTER TABLE entries ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE entries ADD COLUMN IF NOT EXISTS alias TEXT;

-- 005: Abuse tools
ALTER TABLE entries ADD COLUMN IF NOT EXISTS shadow_banned BOOLEAN DEFAULT FALSE;
ALTER TABLE threads ADD COLUMN IF NOT EXISTS slow_mode_interval INTEGER DEFAULT NULL;
ALTER TABLE entries ADD COLUMN IF NOT EXISTS ip_hash TEXT DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_entries_thread_ip_time ON entries(thread_id, ip_hash, created_at DESC);

-- 006: Admin tools
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id INTEGER NOT NULL,
  admin_id INTEGER REFERENCES users(id),
  details JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC);

CREATE TABLE IF NOT EXISTS post_audit (
  id SERIAL PRIMARY KEY,
  entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  ip_hash TEXT,
  alias TEXT,
  content_length INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_post_audit_entry ON post_audit(entry_id);
CREATE INDEX IF NOT EXISTS idx_post_audit_ip ON post_audit(ip_hash);

-- 003: Seed data (rooms and threads)
INSERT INTO rooms (slug, title) VALUES
  ('room-001', 'GENERAL DISCUSSION'),
  ('room-002', 'CLINICAL LITERATURE'),
  ('room-003', 'DIAGNOSTIC CRITERIA'),
  ('room-004', 'BEHAVIORAL PATTERNS'),
  ('room-005', 'TREATMENT DISCOURSE'),
  ('room-006', 'OFF-TOPIC')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO threads (room_id, slug, title) VALUES
  (1, 'sig-001', 'Pattern recognition in social contexts'),
  (1, 'sig-002', 'Emotional processing differences'),
  (1, 'sig-003', 'Long-term strategic thinking'),
  (1, 'sig-004', 'Risk assessment mechanisms'),
  (2, 'sig-005', 'Hare PCL-R validity discussion'),
  (2, 'sig-006', 'DSM-5 vs ICD-11 criteria comparison'),
  (3, 'sig-007', 'Factor 1 vs Factor 2 traits'),
  (3, 'sig-008', 'Comorbidity patterns')
ON CONFLICT (slug) DO NOTHING;
