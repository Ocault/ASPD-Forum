-- STEP 1: First run this to see what rooms you have
-- SELECT id, slug, title FROM rooms ORDER BY id;

-- STEP 2: Create the missing rooms (4-14)
INSERT INTO rooms (id, slug, title) VALUES
  (4, 'room-004', 'RELATIONSHIPS'),
  (5, 'room-005', 'WORK + CAREER'),
  (6, 'room-006', 'LEGAL'),
  (7, 'room-007', 'TREATMENT'),
  (8, 'room-008', 'IDENTITY'),
  (9, 'room-009', 'QUESTIONS'),
  (10, 'room-010', 'MEDIA'),
  (11, 'room-011', 'VENT'),
  (12, 'room-012', 'META'),
  (13, 'room-013', 'RESEARCH'),
  (14, 'room-014', 'OFF-TOPIC');

-- STEP 3: Now add threads to all rooms

-- Room 1: General Discussion
INSERT INTO threads (room_id, slug, title)
SELECT 1, 'thread-workplace-01', 'How do you handle workplace politics?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-workplace-01');

INSERT INTO threads (room_id, slug, title)
SELECT 1, 'thread-boredom-01', 'The boredom problem - what actually helps'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-boredom-01');

INSERT INTO threads (room_id, slug, title)
SELECT 1, 'thread-masking-01', 'Exhaustion from constant masking'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-masking-01');

-- Room 2: Clinical Literature
INSERT INTO threads (room_id, slug, title)
SELECT 2, 'thread-primary-secondary', 'Primary vs secondary - does the distinction matter?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-primary-secondary');

INSERT INTO threads (room_id, slug, title)
SELECT 2, 'thread-comorb-01', 'ADHD comorbidity and impulse control'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-comorb-01');

-- Room 3: Behavioral Patterns
INSERT INTO threads (room_id, slug, title)
SELECT 3, 'thread-anger-01', 'Managing anger without suppression'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-anger-01');

INSERT INTO threads (room_id, slug, title)
SELECT 3, 'thread-decisions-01', 'Decision making under pressure'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-decisions-01');

-- Room 4: Relationships
INSERT INTO threads (room_id, slug, title)
SELECT 4, 'thread-disclosure-01', 'To disclose or not - partner relationships'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-disclosure-01');

INSERT INTO threads (room_id, slug, title)
SELECT 4, 'thread-attachment-01', 'What does attachment actually feel like to you?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-attachment-01');

INSERT INTO threads (room_id, slug, title)
SELECT 4, 'thread-longterm-01', 'Anyone in a long-term relationship? How?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-longterm-01');

INSERT INTO threads (room_id, slug, title)
SELECT 4, 'thread-family-01', 'Dealing with family expectations'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-family-01');

-- Room 5: Work + Career
INSERT INTO threads (room_id, slug, title)
SELECT 5, 'thread-careers-01', 'Careers that actually work for us'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-careers-01');

INSERT INTO threads (room_id, slug, title)
SELECT 5, 'thread-management-01', 'Managing people - strategies that work'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-management-01');

INSERT INTO threads (room_id, slug, title)
SELECT 5, 'thread-fired-01', 'Got fired again - pattern or bad luck?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-fired-01');

INSERT INTO threads (room_id, slug, title)
SELECT 5, 'thread-interview-01', 'Interview masking techniques'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-interview-01');

-- Room 6: Legal
INSERT INTO threads (room_id, slug, title)
SELECT 6, 'thread-lawyer-01', 'Finding a lawyer who gets it'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-lawyer-01');

INSERT INTO threads (room_id, slug, title)
SELECT 6, 'thread-probation-01', 'Surviving probation/parole'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-probation-01');

INSERT INTO threads (room_id, slug, title)
SELECT 6, 'thread-record-01', 'Life with a criminal record'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-record-01');

-- Room 7: Treatment
INSERT INTO threads (room_id, slug, title)
SELECT 7, 'thread-therapy-01', 'Has therapy ever actually helped?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-therapy-01');

INSERT INTO threads (room_id, slug, title)
SELECT 7, 'thread-dbt-01', 'DBT for ASPD - experiences'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-dbt-01');

INSERT INTO threads (room_id, slug, title)
SELECT 7, 'thread-meds-01', 'Medication experiences - what its actually for'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-meds-01');

-- Room 8: Identity
INSERT INTO threads (room_id, slug, title)
SELECT 8, 'thread-identity-01', 'Do you have a stable sense of self?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-identity-01');

INSERT INTO threads (room_id, slug, title)
SELECT 8, 'thread-values-01', 'Values without morality - how do you decide what matters?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-values-01');

INSERT INTO threads (room_id, slug, title)
SELECT 8, 'thread-empty-01', 'The emptiness - is it just me?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-empty-01');

-- Room 9: Questions
INSERT INTO threads (room_id, slug, title)
SELECT 9, 'thread-q-diagnosis', 'How did you get diagnosed?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-q-diagnosis');

INSERT INTO threads (room_id, slug, title)
SELECT 9, 'thread-q-feel', 'What DO you actually feel?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-q-feel');

INSERT INTO threads (room_id, slug, title)
SELECT 9, 'thread-q-different', 'When did you realize you were different?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-q-different');

-- Room 10: Media
INSERT INTO threads (room_id, slug, title)
SELECT 10, 'thread-media-accurate', 'Most accurate ASPD portrayal in media?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-media-accurate');

INSERT INTO threads (room_id, slug, title)
SELECT 10, 'thread-media-cringe', 'Worst ASPD stereotypes in movies/TV'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-media-cringe');

INSERT INTO threads (room_id, slug, title)
SELECT 10, 'thread-media-books', 'Books that actually get it'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-media-books');

-- Room 11: Vent
INSERT INTO threads (room_id, slug, title)
SELECT 11, 'thread-vent-stigma', 'Sick of the stigma'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-vent-stigma');

INSERT INTO threads (room_id, slug, title)
SELECT 11, 'thread-vent-therapists', 'Therapists who refuse to treat us'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-vent-therapists');

INSERT INTO threads (room_id, slug, title)
SELECT 11, 'thread-vent-alone', 'Sometimes being different is just lonely'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-vent-alone');

-- Room 12: Meta
INSERT INTO threads (room_id, slug, title)
SELECT 12, 'thread-meta-rules', 'Forum rules discussion'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-meta-rules');

INSERT INTO threads (room_id, slug, title)
SELECT 12, 'thread-meta-features', 'Feature requests for the site'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-meta-features');

INSERT INTO threads (room_id, slug, title)
SELECT 12, 'thread-meta-introduce', 'Introduce yourself (if you want)'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-meta-introduce');

-- Room 13: Research
INSERT INTO threads (room_id, slug, title)
SELECT 13, 'thread-research-brain', 'Brain scan studies - what they actually show'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-research-brain');

INSERT INTO threads (room_id, slug, title)
SELECT 13, 'thread-research-genetics', 'Genetics vs environment debate'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-research-genetics');

-- Room 14: Off-Topic
INSERT INTO threads (room_id, slug, title)
SELECT 14, 'thread-offtopic-games', 'What games are you playing?'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-offtopic-games');

INSERT INTO threads (room_id, slug, title)
SELECT 14, 'thread-offtopic-music', 'Music recommendations'
WHERE NOT EXISTS (SELECT 1 FROM threads WHERE slug = 'thread-offtopic-music');

-- STEP 4: Add entries (posts) to threads

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1, 
  'workplace politics is actually where i excel tbh. mapping out who has actual power vs who thinks they do, who has dirt on who, where the alliances are. i treat it like a game because thats essentially what it is. the people who struggle are the ones who think work should be "fair"',
  '{"head": 0, "eyes": 2, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-workplace-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'boredom is genuinely dangerous for me. thats when the stupid ideas start seeming like good ideas. ive learned to recognize when im getting to that point and force myself to do something physical. gym, long walk, whatever. burns off some of that energy before i do something ill regret.',
  '{"head": 2, "eyes": 1, "overlays": {"static": false, "crack": true}}'
FROM threads t WHERE t.slug = 'thread-boredom-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'the masking exhaustion is real. pretending to care about peoples weekends, their kids, their problems. saying the right things at the right times. smiling when i feel nothing. by friday im completely drained from performing "normal person" all week.',
  '{"head": 1, "eyes": 2, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-masking-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'never tell them the diagnosis name. tried that once - she started googling and found all the "psychopath red flags" articles and suddenly everything i did was suspicious. even things shed been fine with before became "manipulation" after she had a label to apply.',
  '{"head": 0, "eyes": 1, "overlays": {"static": false, "crack": true}}'
FROM threads t WHERE t.slug = 'thread-disclosure-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'attachment for me is more like... possessiveness plus habit. this person is mine, theyre useful, theyre familiar. if they left id be annoyed and inconvenienced more than heartbroken. is that attachment? i genuinely dont know what its supposed to feel like.',
  '{"head": 2, "eyes": 2, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-attachment-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'most therapy assumes you feel guilty about things and want to be different. neither applies to me. the only therapist who helped was one who stopped trying to make me feel things and instead focused on "okay, you dont feel remorse - how do we keep you out of situations where that becomes a problem?"',
  '{"head": 0, "eyes": 0, "overlays": {"static": true, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-therapy-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'probably around 12-13. everyone else was so affected by things that didnt register for me at all. someone would be crying about something and id just be standing there thinking "why is this a big deal?" thought everyone else was being dramatic. eventually realized no, i was the odd one out.',
  '{"head": 2, "eyes": 0, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-q-different'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'every time ASPD comes up online its "run, this person will destroy your life" like were all serial killers. most of us are just going to work, paying bills, trying to get through life like everyone else. the stigma makes it impossible to be honest about what we deal with.',
  '{"head": 1, "eyes": 1, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-vent-stigma'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);
