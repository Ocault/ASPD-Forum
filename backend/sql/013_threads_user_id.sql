-- Add user_id column to threads table for tracking thread authors
-- This is needed for bot threads to be attributed to the correct bot user

ALTER TABLE threads ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;

-- Make slug nullable (threads are accessed by ID now, not slug)
ALTER TABLE threads ALTER COLUMN slug DROP NOT NULL;

-- Set default user_id for existing threads (use first entry's user_id if available)
UPDATE threads t
SET user_id = (
  SELECT user_id FROM entries e 
  WHERE e.thread_id = t.id 
  ORDER BY e.created_at ASC 
  LIMIT 1
)
WHERE t.user_id IS NULL;

-- Index for performance
CREATE INDEX IF NOT EXISTS idx_threads_user_id ON threads(user_id);
