INSERT INTO users (id, alias, password_hash)
VALUES (
  1,
  'observer@local',
  '$2b$10$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
)
ON CONFLICT (id) DO NOTHING;

-- Seed data for forum tables
-- Run after 002_forum_tables.sql

-- Clear existing seed data (optional, comment out if not needed)
-- DELETE FROM entries;
-- DELETE FROM threads;
-- DELETE FROM rooms WHERE id <= 6;

-- Rooms
INSERT INTO rooms (id, slug, title) VALUES
  (1, 'room-001', 'GENERAL DISCUSSION'),
  (2, 'room-002', 'CLINICAL LITERATURE'),
  (3, 'room-003', 'BEHAVIORAL PATTERNS')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Room 1: General Discussion
INSERT INTO threads (id, room_id, slug, title) VALUES
  (1, 1, 'sig-001', 'Pattern recognition in social contexts'),
  (2, 1, 'sig-002', 'Emotional processing differences'),
  (3, 1, 'sig-003', 'Long-term strategic thinking')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Room 2: Clinical Literature
INSERT INTO threads (id, room_id, slug, title) VALUES
  (4, 2, 'sig-004', 'Hare PCL-R validity discussion'),
  (5, 2, 'sig-005', 'DSM-5 vs ICD-11 criteria comparison')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Room 3: Behavioral Patterns
INSERT INTO threads (id, room_id, slug, title) VALUES
  (6, 3, 'sig-006', 'Factor 1 vs Factor 2 traits'),
  (7, 3, 'sig-007', 'Impulse control mechanisms'),
  (8, 3, 'sig-008', 'Environmental adaptation strategies')
ON CONFLICT (slug) DO NOTHING;

-- Entries for Thread 1: Pattern recognition
INSERT INTO entries (id, thread_id, user_id, content, avatar_config) VALUES
  (1, 1, 1, 'The capacity to decode behavioral patterns operates on a fundamentally different mechanism. Systematic observation filtered through utility rather than emotional resonance.', '{"head": 0, "eyes": 0, "overlays": {"static": false, "crack": false}}'),
  (2, 1, 1, 'Pattern matching happens automatically but the output is strategic. You map the leverage points without the compassion response.', '{"head": 1, "eyes": 1, "overlays": {"static": true, "crack": false}}'),
  (3, 1, 1, 'Recognition is not compulsion. Observation can remain neutral. The assumption that pattern recognition leads to exploitation is itself a pattern.', '{"head": 2, "eyes": 0, "overlays": {"static": false, "crack": true}}')
ON CONFLICT DO NOTHING;

-- Entries for Thread 2: Emotional processing
INSERT INTO entries (id, thread_id, user_id, content, avatar_config) VALUES
  (4, 2, 1, 'Emotional processing operates on a different frequency. Recognition without resonance. The signal arrives but does not propagate.', '{"head": 0, "eyes": 2, "overlays": {"static": false, "crack": false}}'),
  (5, 2, 1, 'The absence of automatic emotional mirroring is not a deficit. It is a different configuration of the same underlying system.', '{"head": 1, "eyes": 0, "overlays": {"static": true, "crack": true}}')
ON CONFLICT DO NOTHING;

-- Entries for Thread 3: Strategic thinking
INSERT INTO entries (id, thread_id, user_id, content, avatar_config) VALUES
  (6, 3, 1, 'Long-term planning without emotional interference. Each decision point evaluated on outcome probability rather than immediate feeling.', '{"head": 2, "eyes": 2, "overlays": {"static": false, "crack": false}}'),
  (7, 3, 1, 'The clinical literature pathologizes what professional contexts reward. Strategic thinking is the same mechanism with different framing.', '{"head": 0, "eyes": 1, "overlays": {"static": false, "crack": false}}'),
  (8, 3, 1, 'Context determines the label. The cognitive process itself remains morally neutral. Information processing without editorial overlay.', '{"head": 1, "eyes": 2, "overlays": {"static": true, "crack": false}}')
ON CONFLICT DO NOTHING;

-- Entries for Thread 4: PCL-R validity
INSERT INTO entries (id, thread_id, user_id, content, avatar_config) VALUES
  (9, 4, 1, 'The PCL-R measures specific behavioral markers but conflates correlation with causation. Presence of traits does not predict specific outcomes.', '{"head": 2, "eyes": 1, "overlays": {"static": false, "crack": true}}'),
  (10, 4, 1, 'Inter-rater reliability varies significantly across studies. The subjective element in scoring undermines claims of objectivity.', '{"head": 0, "eyes": 0, "overlays": {"static": false, "crack": false}}')
ON CONFLICT DO NOTHING;

-- Entries for Thread 5: DSM vs ICD
INSERT INTO entries (id, thread_id, user_id, content, avatar_config) VALUES
  (11, 5, 1, 'DSM-5 emphasizes behavioral criteria while ICD-11 focuses on personality dysfunction. Different frameworks yield different populations.', '{"head": 1, "eyes": 0, "overlays": {"static": false, "crack": false}}'),
  (12, 5, 1, 'The categorical vs dimensional debate remains unresolved. Both systems impose artificial boundaries on continuous variation.', '{"head": 2, "eyes": 2, "overlays": {"static": true, "crack": false}}'),
  (13, 5, 1, 'Cultural bias in diagnostic criteria remains underexamined. What constitutes dysfunction varies across social contexts.', '{"head": 0, "eyes": 1, "overlays": {"static": false, "crack": true}}')
ON CONFLICT DO NOTHING;

-- Entries for Thread 6: Factor analysis
INSERT INTO entries (id, thread_id, user_id, content, avatar_config) VALUES
  (14, 6, 1, 'Factor 1 traits correlate with social success in competitive environments. Factor 2 traits correlate with institutional contact.', '{"head": 1, "eyes": 1, "overlays": {"static": false, "crack": false}}'),
  (15, 6, 1, 'The factor structure may reflect measurement artifact rather than underlying psychological reality. Replication across cultures is inconsistent.', '{"head": 2, "eyes": 0, "overlays": {"static": false, "crack": false}}')
ON CONFLICT DO NOTHING;

-- Entries for Thread 7: Impulse control
INSERT INTO entries (id, thread_id, user_id, content, avatar_config) VALUES
  (16, 7, 1, 'Impulse control is trainable. The assumption of fixed deficits ignores neuroplasticity and learned behavioral modification.', '{"head": 0, "eyes": 2, "overlays": {"static": true, "crack": false}}'),
  (17, 7, 1, 'Delay discounting studies show significant individual variation. Population averages obscure the range of actual capability.', '{"head": 1, "eyes": 0, "overlays": {"static": false, "crack": true}}'),
  (18, 7, 1, 'Environmental structure matters more than internal disposition. Impulse expression depends on context and consequence.', '{"head": 2, "eyes": 1, "overlays": {"static": false, "crack": false}}')
ON CONFLICT DO NOTHING;

-- Entries for Thread 8: Environmental adaptation
INSERT INTO entries (id, thread_id, user_id, content, avatar_config) VALUES
  (19, 8, 1, 'Adaptation strategies vary by environment. Corporate contexts reward different trait expressions than institutional ones.', '{"head": 0, "eyes": 0, "overlays": {"static": false, "crack": false}}'),
  (20, 8, 1, 'Successful adaptation requires accurate environmental reading. Misreading context produces suboptimal outcomes regardless of capability.', '{"head": 1, "eyes": 2, "overlays": {"static": true, "crack": true}}')
ON CONFLICT DO NOTHING;

-- Reset sequences to continue after seed data
SELECT setval('rooms_id_seq', (SELECT MAX(id) FROM rooms));
SELECT setval('threads_id_seq', (SELECT MAX(id) FROM threads));
SELECT setval('entries_id_seq', (SELECT MAX(id) FROM entries));
