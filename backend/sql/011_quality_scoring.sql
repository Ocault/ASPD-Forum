-- Quality Scoring System: Track bot engagement and favor successful patterns
-- Run this migration to enable quality-based bot selection

-- =====================================================
-- BOT QUALITY METRICS
-- =====================================================

-- Add quality metrics to bot_accounts
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS quality_score FLOAT DEFAULT 0.5;
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS total_upvotes INTEGER DEFAULT 0;
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS total_downvotes INTEGER DEFAULT 0;
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS real_user_replies INTEGER DEFAULT 0;
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS real_user_reactions INTEGER DEFAULT 0;
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS last_quality_update TIMESTAMP DEFAULT NOW();

-- Index for quality-based selection
CREATE INDEX IF NOT EXISTS idx_bot_accounts_quality ON bot_accounts(quality_score DESC);

-- =====================================================
-- ENGAGEMENT TRACKING TABLE
-- =====================================================

-- Track individual engagement events for analysis
CREATE TABLE IF NOT EXISTS bot_engagement_log (
  id SERIAL PRIMARY KEY,
  bot_account_id INTEGER REFERENCES bot_accounts(id) ON DELETE CASCADE,
  entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
  engagement_type VARCHAR(20) NOT NULL, -- 'upvote', 'downvote', 'reply', 'reaction'
  real_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bot_engagement_bot ON bot_engagement_log(bot_account_id);
CREATE INDEX IF NOT EXISTS idx_bot_engagement_entry ON bot_engagement_log(entry_id);
CREATE INDEX IF NOT EXISTS idx_bot_engagement_type ON bot_engagement_log(engagement_type);
CREATE INDEX IF NOT EXISTS idx_bot_engagement_time ON bot_engagement_log(created_at DESC);

-- =====================================================
-- TOPIC SUCCESS TRACKING
-- =====================================================

-- Track which topics/keywords get good engagement
CREATE TABLE IF NOT EXISTS bot_topic_scores (
  id SERIAL PRIMARY KEY,
  topic_keyword VARCHAR(100) NOT NULL,
  persona VARCHAR(50),
  success_count INTEGER DEFAULT 0,
  fail_count INTEGER DEFAULT 0,
  avg_engagement FLOAT DEFAULT 0,
  last_updated TIMESTAMP DEFAULT NOW(),
  UNIQUE(topic_keyword, persona)
);

CREATE INDEX IF NOT EXISTS idx_bot_topic_keyword ON bot_topic_scores(topic_keyword);
CREATE INDEX IF NOT EXISTS idx_bot_topic_persona ON bot_topic_scores(persona);
CREATE INDEX IF NOT EXISTS idx_bot_topic_engagement ON bot_topic_scores(avg_engagement DESC);
