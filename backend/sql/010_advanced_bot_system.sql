-- Advanced Bot System: Persistent Users, Voting, Time-Based Activity
-- Run this migration to enable all advanced bot features

-- =====================================================
-- PERSISTENT BOT ACCOUNTS
-- =====================================================

-- Table for persistent bot identities
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
  -- Activity preferences (for time-based activity)
  timezone_offset INTEGER DEFAULT 0, -- Hours from UTC
  peak_hours JSONB DEFAULT '[18,19,20,21,22,23]', -- Preferred posting hours
  activity_level VARCHAR(20) DEFAULT 'normal' -- 'lurker', 'normal', 'active', 'very_active'
);

-- Create index for quick lookups
CREATE INDEX IF NOT EXISTS idx_bot_accounts_persona ON bot_accounts(persona);
CREATE INDEX IF NOT EXISTS idx_bot_accounts_last_active ON bot_accounts(last_active);
CREATE INDEX IF NOT EXISTS idx_bot_accounts_activity ON bot_accounts(activity_level);

-- =====================================================
-- VOTING/REACTION SYSTEM
-- =====================================================

-- Votes table for entries
CREATE TABLE IF NOT EXISTS entry_votes (
  id SERIAL PRIMARY KEY,
  entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  bot_account_id INTEGER REFERENCES bot_accounts(id) ON DELETE CASCADE,
  vote_type VARCHAR(10) NOT NULL CHECK (vote_type IN ('up', 'down')),
  created_at TIMESTAMP DEFAULT NOW(),
  -- Ensure one vote per user/bot per entry
  UNIQUE(entry_id, user_id),
  UNIQUE(entry_id, bot_account_id)
);

-- Add vote count columns to entries for quick access
ALTER TABLE entries ADD COLUMN IF NOT EXISTS upvotes INTEGER DEFAULT 0;
ALTER TABLE entries ADD COLUMN IF NOT EXISTS downvotes INTEGER DEFAULT 0;

-- Create indexes for voting queries
CREATE INDEX IF NOT EXISTS idx_entry_votes_entry ON entry_votes(entry_id);
CREATE INDEX IF NOT EXISTS idx_entry_votes_user ON entry_votes(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_entry_votes_bot ON entry_votes(bot_account_id) WHERE bot_account_id IS NOT NULL;

-- =====================================================
-- LINK BOT ACCOUNTS TO ENTRIES
-- =====================================================

-- Add bot_account_id to entries to track which persistent bot made the post
ALTER TABLE entries ADD COLUMN IF NOT EXISTS bot_account_id INTEGER REFERENCES bot_accounts(id);
ALTER TABLE threads ADD COLUMN IF NOT EXISTS bot_account_id INTEGER REFERENCES bot_accounts(id);

CREATE INDEX IF NOT EXISTS idx_entries_bot_account ON entries(bot_account_id) WHERE bot_account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threads_bot_account ON threads(bot_account_id) WHERE bot_account_id IS NOT NULL;

-- =====================================================
-- SEED PERSISTENT BOT ACCOUNTS (25 bots with realistic usernames)
-- =====================================================

INSERT INTO bot_accounts (persona, alias, avatar_config, bio, activity_level, peak_hours) VALUES
-- Analytical types
('analytical', 'jake_92', '{"head":0,"eyes":2,"overlays":{"static":true,"crack":false}}', 
 'dx 2019. software dev. here to compare notes.', 'active', '[20,21,22,23,0,1]'),
('analytical', 'overthinkr', '{"head":3,"eyes":4,"overlays":{"static":false,"crack":false}}', 
 'probably analyzing this bio too much', 'normal', '[18,19,20,21]'),

-- Cynical types  
('cynical', 'yeahwhatever97', '{"head":1,"eyes":1,"overlays":{"static":false,"crack":true}}', 
 'been here a while. seen some shit.', 'very_active', '[21,22,23,0,1,2]'),
('cynical', 'meh', '{"head":5,"eyes":3,"overlays":{"static":true,"crack":false}}', 
 '¯\\_(ツ)_/¯', 'active', '[19,20,21,22,23]'),

-- Pragmatic types
('pragmatic', 'justgetitdone', '{"head":2,"eyes":0,"overlays":{"static":false,"crack":false}}', 
 'no time for theory. what works?', 'active', '[8,9,10,18,19,20]'),
('pragmatic', 'chicago41', '{"head":4,"eyes":5,"overlays":{"static":false,"crack":false}}', 
 '', 'normal', '[12,13,14,20,21]'),

-- Observer types
('observer', 'hm', '{"head":6,"eyes":2,"overlays":{"static":false,"crack":true}}', 
 '', 'lurker', '[22,23,0,1,2,3]'),
('observer', 'qwfp23', '{"head":7,"eyes":1,"overlays":{"static":true,"crack":false}}', 
 'mostly lurk', 'lurker', '[23,0,1,2,3,4]'),

-- Blunt types
('blunt', 'sorrynotsorry', '{"head":1,"eyes":4,"overlays":{"static":true,"crack":true}}', 
 'dont ask if you dont want the answer', 'very_active', '[18,19,20,21,22]'),
('blunt', 'tiredofbs', '{"head":3,"eyes":0,"overlays":{"static":false,"crack":true}}', 
 'too old for this', 'active', '[19,20,21,22,23]'),

-- Strategic types
('strategic', 'pnw_anon', '{"head":0,"eyes":3,"overlays":{"static":false,"crack":false}}', 
 'playing the long game', 'active', '[20,21,22,23,0]'),
('strategic', 'thinkfirst', '{"head":2,"eyes":2,"overlays":{"static":true,"crack":false}}', 
 'measure twice cut once', 'normal', '[21,22,23,0,1]'),

-- Nihilist types
('nihilist', 'whatevermans', '{"head":5,"eyes":5,"overlays":{"static":true,"crack":true}}', 
 'none of this matters but here i am', 'normal', '[0,1,2,3,4,5]'),
('nihilist', 'ugh', '{"head":7,"eyes":4,"overlays":{"static":false,"crack":true}}', 
 '.', 'lurker', '[1,2,3,4,5]'),

-- Survivor types
('survivor', 'beentheredonethat', '{"head":4,"eyes":1,"overlays":{"static":false,"crack":true}}', 
 'did 4 years. cleaned up. still figuring it out.', 'active', '[20,21,22,23]'),
('survivor', 'texas88', '{"head":6,"eyes":0,"overlays":{"static":true,"crack":true}}', 
 'system kid. aged out. still here.', 'normal', '[19,20,21,22,23,0]'),

-- Scientist types
('scientist', 'pubmedwarrior', '{"head":0,"eyes":5,"overlays":{"static":false,"crack":false}}', 
 'show me the peer review', 'active', '[14,15,16,20,21,22]'),
('scientist', 'neurosciencenerd', '{"head":2,"eyes":3,"overlays":{"static":false,"crack":false}}', 
 'psych PhD dropout. know too much now.', 'normal', '[10,11,12,19,20,21]'),

-- Newcomer types
('newcomer', 'newhere2024', '{"head":3,"eyes":2,"overlays":{"static":false,"crack":false}}', 
 'just got diagnosed last month. reading everything.', 'very_active', '[18,19,20,21,22,23]'),
('newcomer', 'confused_tbh', '{"head":1,"eyes":1,"overlays":{"static":false,"crack":false}}', 
 'is this the right place? idk', 'active', '[17,18,19,20,21,22]'),

-- Veteran types
('veteran', 'dx1998', '{"head":7,"eyes":0,"overlays":{"static":true,"crack":false}}', 
 'diagnosed before it was trendy', 'normal', '[20,21,22]'),
('veteran', 'oldtimer', '{"head":5,"eyes":2,"overlays":{"static":false,"crack":false}}', 
 'been on forums like this since 2006', 'lurker', '[21,22,23]'),

-- Dark humor types
('dark_humor', 'lmaoimfine', '{"head":4,"eyes":4,"overlays":{"static":true,"crack":false}}', 
 'if i cant joke about it ill cry', 'very_active', '[19,20,21,22,23,0]'),
('dark_humor', 'oopsiedaisy', '{"head":6,"eyes":3,"overlays":{"static":false,"crack":true}}', 
 'laughter is cheaper than therapy', 'active', '[20,21,22,23,0,1]'),

-- Mixed/unique types
('blunt', 'honestlytho', '{"head":0,"eyes":1,"overlays":{"static":true,"crack":true}}', 
 '', 'normal', '[18,19,20,21,22]'),
('cynical', 'jersey_anon', '{"head":3,"eyes":5,"overlays":{"static":false,"crack":false}}', 
 'dont waste my time', 'active', '[20,21,22,23,0]')

ON CONFLICT (alias) DO NOTHING;

-- =====================================================
-- FUNCTIONS FOR VOTE COUNTING (optional, for triggers)
-- =====================================================

-- Function to update vote counts on entries
CREATE OR REPLACE FUNCTION update_entry_vote_counts()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.vote_type = 'up' THEN
      UPDATE entries SET upvotes = upvotes + 1 WHERE id = NEW.entry_id;
    ELSE
      UPDATE entries SET downvotes = downvotes + 1 WHERE id = NEW.entry_id;
    END IF;
  ELSIF TG_OP = 'DELETE' THEN
    IF OLD.vote_type = 'up' THEN
      UPDATE entries SET upvotes = upvotes - 1 WHERE id = OLD.entry_id;
    ELSE
      UPDATE entries SET downvotes = downvotes - 1 WHERE id = OLD.entry_id;
    END IF;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for vote counting
DROP TRIGGER IF EXISTS entry_vote_count_trigger ON entry_votes;
CREATE TRIGGER entry_vote_count_trigger
AFTER INSERT OR DELETE ON entry_votes
FOR EACH ROW EXECUTE FUNCTION update_entry_vote_counts();
