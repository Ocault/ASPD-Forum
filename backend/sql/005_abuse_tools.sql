-- Abuse escalation tools migration

-- Shadow-ban support: entries can be silently hidden
ALTER TABLE entries ADD COLUMN IF NOT EXISTS shadow_banned BOOLEAN DEFAULT FALSE;

-- Slow-mode support: per-thread posting interval (seconds)
ALTER TABLE threads ADD COLUMN IF NOT EXISTS slow_mode_interval INTEGER DEFAULT NULL;

-- Track IP for slow-mode enforcement
ALTER TABLE entries ADD COLUMN IF NOT EXISTS ip_hash TEXT DEFAULT NULL;

-- Index for efficient slow-mode lookups
CREATE INDEX IF NOT EXISTS idx_entries_thread_ip_time ON entries(thread_id, ip_hash, created_at DESC);
