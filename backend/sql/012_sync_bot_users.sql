-- Sync existing bot_accounts to users table
-- This makes all bot profiles viewable as real user profiles

-- Insert users records for any bot_accounts that don't have one yet
INSERT INTO users (alias, avatar_config, bio, is_bot, role, email, password_hash, created_at)
SELECT 
  ba.alias,
  ba.avatar_config,
  ba.bio,
  TRUE,
  'user',
  'bot-' || ba.id || '@system.local',
  'bot-no-login',
  -- Random join date 1-365 days ago for realism
  NOW() - (FLOOR(RANDOM() * 365) + 1) * INTERVAL '1 day'
FROM bot_accounts ba
WHERE NOT EXISTS (
  SELECT 1 FROM users u WHERE u.alias = ba.alias
);

-- Update existing bot users to match their bot_account data
UPDATE users u
SET 
  avatar_config = ba.avatar_config,
  bio = COALESCE(ba.bio, u.bio),
  is_bot = TRUE
FROM bot_accounts ba
WHERE u.alias = ba.alias;

-- Show count of synced bots
DO $$
DECLARE
  bot_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO bot_count FROM bot_accounts;
  RAISE NOTICE 'Synced % bot accounts to users table', bot_count;
END $$;
