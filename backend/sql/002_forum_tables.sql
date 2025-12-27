-- Forum tables

CREATE TABLE IF NOT EXISTS rooms (
  id SERIAL PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threads (
  id SERIAL PRIMARY KEY,
  room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entries (
  id SERIAL PRIMARY KEY,
  thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  avatar_config JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threads_room_id ON threads(room_id);
CREATE INDEX IF NOT EXISTS idx_entries_thread_id ON entries(thread_id);

-- Seed data
INSERT INTO rooms (slug, title) VALUES
  ('room-001', 'GENERAL DISCUSSION'),
  ('room-002', 'CLINICAL LITERATURE'),
  ('room-003', 'DIAGNOSTIC CRITERIA'),
  ('room-004', 'BEHAVIORAL PATTERNS'),
  ('room-005', 'TREATMENT DISCOURSE'),
  ('room-006', 'OFF-TOPIC')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO threads (room_id, slug, title) VALUES
  (1, 'sig-001', 'Pattern recognition in social contexts'),
  (1, 'sig-002', 'Emotional processing differences'),
  (1, 'sig-003', 'Long-term strategic thinking'),
  (1, 'sig-004', 'Risk assessment mechanisms'),
  (2, 'sig-005', 'Hare PCL-R validity discussion'),
  (2, 'sig-006', 'DSM-5 vs ICD-11 criteria comparison'),
  (3, 'sig-007', 'Factor 1 vs Factor 2 traits'),
  (3, 'sig-008', 'Comorbidity patterns')
ON CONFLICT (slug) DO NOTHING;
