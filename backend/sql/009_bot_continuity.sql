-- Bot Continuity System
-- Track which persona created each bot post for conversation continuity

-- Add bot_persona column to entries table
ALTER TABLE entries ADD COLUMN IF NOT EXISTS bot_persona VARCHAR(50);

-- Add bot_persona column to threads table (for thread starters)
ALTER TABLE threads ADD COLUMN IF NOT EXISTS bot_persona VARCHAR(50);

-- Create index for faster lookups of bot posts in threads
CREATE INDEX IF NOT EXISTS idx_entries_thread_bot ON entries(thread_id, is_bot) WHERE is_bot = TRUE;

-- Create index for persona lookups
CREATE INDEX IF NOT EXISTS idx_entries_bot_persona ON entries(bot_persona) WHERE bot_persona IS NOT NULL;
