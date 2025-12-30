-- Bot System - Add is_bot column to entries and threads
-- Run this in pgAdmin against your Railway database

-- Add is_bot column to entries
ALTER TABLE entries ADD COLUMN IF NOT EXISTS is_bot BOOLEAN DEFAULT FALSE;

-- Add is_bot column to threads
ALTER TABLE threads ADD COLUMN IF NOT EXISTS is_bot BOOLEAN DEFAULT FALSE;

-- Create index for filtering bot content if needed
CREATE INDEX IF NOT EXISTS idx_entries_is_bot ON entries(is_bot) WHERE is_bot = TRUE;
CREATE INDEX IF NOT EXISTS idx_threads_is_bot ON threads(is_bot) WHERE is_bot = TRUE;

-- Done!
-- The bot system is now ready. Access it via Admin Panel > Owner Tools > AI Bot System
