-- Bot Online/Offline Status System
-- Makes bots appear online/offline randomly with individual timers

-- Add online status tracking to bot_accounts
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS is_online BOOLEAN DEFAULT FALSE;
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS next_status_change TIMESTAMP;
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS session_start TIMESTAMP;
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS avg_session_minutes INTEGER DEFAULT 45;

-- Also sync online status to users table for profile display
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_online BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT NOW();

-- Index for quick online bot lookups
CREATE INDEX IF NOT EXISTS idx_bot_accounts_online ON bot_accounts(is_online);
CREATE INDEX IF NOT EXISTS idx_bot_accounts_status_change ON bot_accounts(next_status_change);
CREATE INDEX IF NOT EXISTS idx_users_online ON users(is_online);

-- Initialize some bots as online with random next change times
UPDATE bot_accounts 
SET 
  is_online = RANDOM() < 0.3, -- 30% start online
  session_start = CASE WHEN RANDOM() < 0.3 THEN NOW() - (RANDOM() * INTERVAL '30 minutes') ELSE NULL END,
  next_status_change = NOW() + (RANDOM() * INTERVAL '2 hours'),
  avg_session_minutes = 20 + FLOOR(RANDOM() * 120) -- 20-140 minute average sessions
WHERE next_status_change IS NULL;

-- Sync is_online to users table for bots
UPDATE users u
SET is_online = ba.is_online,
    last_seen = ba.last_active
FROM bot_accounts ba
WHERE u.alias = ba.alias AND u.is_bot = TRUE;
