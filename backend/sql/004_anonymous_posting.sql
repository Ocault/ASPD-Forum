-- Migration: Add alias column for anonymous posting
-- Run after 002_forum_tables.sql

-- Make user_id nullable for anonymous posts
ALTER TABLE entries ALTER COLUMN user_id DROP NOT NULL;

-- Add alias column for anonymous posts
ALTER TABLE entries ADD COLUMN IF NOT EXISTS alias TEXT;

-- For existing entries with user_id, alias will be fetched from users table via JOIN
-- New anonymous entries will have user_id = NULL and alias set directly
