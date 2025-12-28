-- Admin tools and audit logging migration

-- Admin role support
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;

-- Audit log for moderation
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

-- Post audit log (stores ip_hash, alias for all posts)
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

-- Character limit constant (for highlighting)
-- Posts exceeding this are flagged in audit
-- Default: 2000 characters
