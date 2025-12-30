-- Additional forum content to fill out rooms
-- Run this via pgAdmin against the Railway database

-- More threads for General Discussion (room 1)
INSERT INTO threads (room_id, slug, title) VALUES
  (1, 'thread-workplace-01', 'How do you handle workplace politics?'),
  (1, 'thread-boredom-01', 'The boredom problem - what actually helps'),
  (1, 'thread-masking-01', 'Exhaustion from constant masking')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Clinical Literature (room 2)
INSERT INTO threads (room_id, slug, title) VALUES
  (2, 'thread-primary-secondary', 'Primary vs secondary - does the distinction matter?'),
  (2, 'thread-comorb-01', 'ADHD comorbidity and impulse control')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Behavioral Patterns (room 3)
INSERT INTO threads (room_id, slug, title) VALUES
  (3, 'thread-anger-01', 'Managing anger without suppression'),
  (3, 'thread-decisions-01', 'Decision making under pressure')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Relationships room (room 4)
INSERT INTO threads (room_id, slug, title) VALUES
  (4, 'thread-disclosure-01', 'To disclose or not - partner relationships'),
  (4, 'thread-attachment-01', 'What does attachment actually feel like to you?'),
  (4, 'thread-longterm-01', 'Anyone in a long-term relationship? How?'),
  (4, 'thread-family-01', 'Dealing with family expectations')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Work/Career room (room 5)
INSERT INTO threads (room_id, slug, title) VALUES
  (5, 'thread-careers-01', 'Careers that actually work for us'),
  (5, 'thread-management-01', 'Managing people - strategies that work'),
  (5, 'thread-fired-01', 'Got fired again - pattern or bad luck?'),
  (5, 'thread-interview-01', 'Interview masking techniques')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Legal room (room 6)
INSERT INTO threads (room_id, slug, title) VALUES
  (6, 'thread-lawyer-01', 'Finding a lawyer who gets it'),
  (6, 'thread-probation-01', 'Surviving probation/parole'),
  (6, 'thread-record-01', 'Life with a criminal record')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Treatment room (room 7)
INSERT INTO threads (room_id, slug, title) VALUES
  (7, 'thread-therapy-01', 'Has therapy ever actually helped?'),
  (7, 'thread-dbt-01', 'DBT for ASPD - experiences'),
  (7, 'thread-meds-01', 'Medication experiences - what its actually for')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Identity room (room 8)
INSERT INTO threads (room_id, slug, title) VALUES
  (8, 'thread-identity-01', 'Do you have a stable sense of self?'),
  (8, 'thread-values-01', 'Values without morality - how do you decide what matters?'),
  (8, 'thread-empty-01', 'The emptiness - is it just me?')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Questions room (room 9)
INSERT INTO threads (room_id, slug, title) VALUES
  (9, 'thread-q-diagnosis', 'How did you get diagnosed?'),
  (9, 'thread-q-feel', 'What DO you actually feel?'),
  (9, 'thread-q-different', 'When did you realize you were different?')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Media room (room 10)
INSERT INTO threads (room_id, slug, title) VALUES
  (10, 'thread-media-accurate', 'Most accurate ASPD portrayal in media?'),
  (10, 'thread-media-cringe', 'Worst ASPD stereotypes in movies/TV'),
  (10, 'thread-media-books', 'Books that actually get it')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Vent room (room 11)
INSERT INTO threads (room_id, slug, title) VALUES
  (11, 'thread-vent-stigma', 'Sick of the stigma'),
  (11, 'thread-vent-therapists', 'Therapists who refuse to treat us'),
  (11, 'thread-vent-alone', 'Sometimes being different is just lonely')
ON CONFLICT (slug) DO NOTHING;

-- Threads for Meta room (room 12)
INSERT INTO threads (room_id, slug, title) VALUES
  (12, 'thread-meta-rules', 'Forum rules discussion'),
  (12, 'thread-meta-features', 'Feature requests for the site'),
  (12, 'thread-meta-introduce', 'Introduce yourself (if you want)')
ON CONFLICT (slug) DO NOTHING;

-- Now add entries (posts) to the threads
-- Using NOT EXISTS to prevent duplicates

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1, 
  'workplace politics is actually where i excel tbh. mapping out who has actual power vs who thinks they do, who has dirt on who, where the alliances are. i treat it like a game because thats essentially what it is. the people who struggle are the ones who think work should be "fair"',
  '{"head": 0, "eyes": 2, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-workplace-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'my approach: document everything, trust no one, and never let them see you sweat. HR is not your friend. your manager is not your friend. even the people you like at work are not your friends - theyre coworkers. act accordingly.',
  '{"head": 1, "eyes": 0, "overlays": {"static": true, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-workplace-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id AND e.content LIKE '%document everything%');

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'boredom is genuinely dangerous for me. thats when the stupid ideas start seeming like good ideas. ive learned to recognize when im getting to that point and force myself to do something physical. gym, long walk, whatever. burns off some of that energy before i do something ill regret.',
  '{"head": 2, "eyes": 1, "overlays": {"static": false, "crack": true}}'
FROM threads t WHERE t.slug = 'thread-boredom-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'video games help a lot. competitive multiplayer specifically - gives me something to win at without real world consequences. the dopamine hit from winning scratches the same itch as other... less legal... activities used to.',
  '{"head": 0, "eyes": 0, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-boredom-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id AND e.content LIKE '%video games%');

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'the masking exhaustion is real. pretending to care about peoples weekends, their kids, their problems. saying the right things at the right times. smiling when i feel nothing. by friday im completely drained from performing "normal person" all week.',
  '{"head": 1, "eyes": 2, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-masking-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'i found a remote job specifically to reduce how much masking i have to do. video calls only a few times a week, mostly async communication. game changer for my quality of life. still have to mask but way less.',
  '{"head": 2, "eyes": 0, "overlays": {"static": true, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-masking-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id AND e.content LIKE '%remote job%');

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'never tell them the diagnosis name. tried that once - she started googling and found all the "psychopath red flags" articles and suddenly everything i did was suspicious. even things shed been fine with before became "manipulation" after she had a label to apply.',
  '{"head": 0, "eyes": 1, "overlays": {"static": false, "crack": true}}'
FROM threads t WHERE t.slug = 'thread-disclosure-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'i describe specific traits instead of the diagnosis. "i dont feel emotions as strongly as most people" or "i have trouble with empathy" lands way better than "i have ASPD" which triggers everyones true crime podcast knowledge.',
  '{"head": 1, "eyes": 0, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-disclosure-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id AND e.content LIKE '%specific traits%');

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
  'schema therapy worked better than anything else for me. focuses on patterns and practical changes rather than insight and emotion. still not magic but actually useful unlike the 5 talk therapists before who just wanted me to access feelings i dont have.',
  '{"head": 1, "eyes": 1, "overlays": {"static": false, "crack": true}}'
FROM threads t WHERE t.slug = 'thread-therapy-01'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id AND e.content LIKE '%schema therapy%');

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'probably around 12-13. everyone else was so affected by things that didnt register for me at all. someone would be crying about something and id just be standing there thinking "why is this a big deal?" thought everyone else was being dramatic. eventually realized no, i was the odd one out.',
  '{"head": 2, "eyes": 0, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-q-different'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'for me it was when a pet died and i felt literally nothing. everyone expected me to be sad and i had to fake it. thats when i first consciously realized i was performing emotions rather than having them. before that i just thought i was good at staying calm.',
  '{"head": 0, "eyes": 2, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-q-different'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id AND e.content LIKE '%pet died%');

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'every time ASPD comes up online its "run, this person will destroy your life" like were all serial killers. most of us are just going to work, paying bills, trying to get through life like everyone else. the stigma makes it impossible to be honest about what we deal with.',
  '{"head": 1, "eyes": 1, "overlays": {"static": false, "crack": false}}'
FROM threads t WHERE t.slug = 'thread-vent-stigma'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id);

INSERT INTO entries (thread_id, user_id, content, avatar_config)
SELECT t.id, 1,
  'the worst part is you cant even defend yourself without people saying "thats exactly what a psychopath would say." heads they win, tails you lose. say nothing and youre hiding. speak up and youre manipulating. literally no way to win.',
  '{"head": 2, "eyes": 0, "overlays": {"static": true, "crack": true}}'
FROM threads t WHERE t.slug = 'thread-vent-stigma'
AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.thread_id = t.id AND e.content LIKE '%defend yourself%');
