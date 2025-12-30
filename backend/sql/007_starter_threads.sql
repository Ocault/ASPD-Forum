-- ============================================
-- ASPD Forum - Starter Content
-- Run this after user account exists
-- Replace USER_ID with your actual user ID
-- ============================================

-- Get room IDs first (these are created by the migrate function)
-- general = 'general'
-- questions = 'questions' 
-- stories = 'stories'
-- relationships = 'relationships'
-- coping = 'coping'
-- diagnosis = 'diagnosis'

-- ============================================
-- THREAD 1: General Discussion - "finally found somewhere that gets it"
-- ============================================
INSERT INTO threads (room_id, user_id, slug, title)
SELECT r.id, u.id, 'finally-found-somewhere', 'finally found somewhere that gets it'
FROM rooms r, users u 
WHERE r.slug = 'general' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT (slug) DO NOTHING;

INSERT INTO entries (thread_id, user_id, alias, content)
SELECT t.id, u.id, u.alias, 
'been lurking for a bit before posting. 24, got the diagnosis at 19. not from some therapist i chose to see - cops and courts basically forced the eval after years of shit catching up to me. school expulsions, workplace "incidents", the usual.

the thing that always got me was how everyone acts like theres something broken that needs fixing. nah. my brain just works different. took me years to stop trying to perform being normal and just figure out how to actually navigate life without constantly fucking things up for myself.

anyway. glad this place exists. every other mental health space is full of people who want you to feel bad about yourself or "heal" into being someone youre not.'
FROM threads t, users u
WHERE t.slug = 'finally-found-somewhere' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT DO NOTHING;

-- ============================================
-- THREAD 2: Coping - "what actually works vs what therapists tell you"
-- ============================================
INSERT INTO threads (room_id, user_id, slug, title)
SELECT r.id, u.id, 'what-actually-works', 'what actually works vs what therapists tell you'
FROM rooms r, users u 
WHERE r.slug = 'coping' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT (slug) DO NOTHING;

INSERT INTO entries (thread_id, user_id, alias, content)
SELECT t.id, u.id, u.alias,
'therapists love telling you to "practice empathy" or "think about how others feel." cool advice if your brain actually did that automatically. mine doesnt.

heres what actually helped me stop burning every bridge:

**1. delay everything by 24 hours**
someone pisses you off at work? dont respond. wait a day. half the time you wont even care anymore and you avoided doing something stupid.

**2. treat social rules like a game**
i stopped seeing it as "being fake" and started seeing it as just... playing a different game. you learn the rules, you play by them when it benefits you, you move on.

**3. find outlets that dont fuck up your life**
i go to the gym a lot. competitive stuff helps too. channel that energy somewhere it doesnt get you fired or arrested.

**4. be honest with yourself about consequences**
not morality lectures. just pure "if i do X, Y happens, do i want Y?" thats it. simple cost-benefit.

what works for you lot?'
FROM threads t, users u
WHERE t.slug = 'what-actually-works' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT DO NOTHING;

-- ============================================
-- THREAD 3: Diagnosis - "court-ordered diagnosis gang"
-- ============================================
INSERT INTO threads (room_id, user_id, slug, title)
SELECT r.id, u.id, 'court-ordered-diagnosis', 'court-ordered diagnosis gang'
FROM rooms r, users u 
WHERE r.slug = 'diagnosis' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT (slug) DO NOTHING;

INSERT INTO entries (thread_id, user_id, alias, content)
SELECT t.id, u.id, u.alias,
'curious how many people here got their diagnosis the "official" way - aka not voluntarily.

mine came at 19 after my third workplace incident in a year plus a history the court pulled up from when i was a minor. judge ordered a psych eval as part of the whole process.

honestly? getting the actual diagnosis was weirdly helpful. not because it changed anything about me but because it gave me a framework. like "oh thats why that happens" instead of just thinking i was constantly fucking up for no reason.

the psychiatrist was useless though. gave me a pamphlet about personality disorders and suggested group therapy. yeah right.

anyone actually found treatment that wasnt complete bullshit? or did you just figure your own shit out like most of us'
FROM threads t, users u
WHERE t.slug = 'court-ordered-diagnosis' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT DO NOTHING;

-- ============================================
-- THREAD 4: Relationships - "being upfront vs masking"
-- ============================================
INSERT INTO threads (room_id, user_id, slug, title)
SELECT r.id, u.id, 'upfront-vs-masking', 'being upfront vs masking - relationships'
FROM rooms r, users u 
WHERE r.slug = 'relationships' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT (slug) DO NOTHING;

INSERT INTO entries (thread_id, user_id, alias, content)
SELECT t.id, u.id, u.alias,
'genuine question for people in long-term relationships

do you tell them? like actually tell them about the diagnosis and what it means?

ive gone back and forth. last relationship i didnt say anything and she eventually figured out something was "off" and it ended badly. current situation im considering just being upfront from the start but also... that conversation never goes well does it

the moment you say ASPD people hear "sociopath" and think youre going to murder them in their sleep. thanks hollywood.

how do you lot handle it? full honesty? selective honesty? just let them figure it out? genuinely asking because i keep fucking this up'
FROM threads t, users u
WHERE t.slug = 'upfront-vs-masking' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT DO NOTHING;

-- ============================================
-- THREAD 5: Stories - "the moment you realized you were different"
-- ============================================
INSERT INTO threads (room_id, user_id, slug, title)
SELECT r.id, u.id, 'moment-you-realized', 'the moment you realized you were different'
FROM rooms r, users u 
WHERE r.slug = 'stories' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT (slug) DO NOTHING;

INSERT INTO entries (thread_id, user_id, alias, content)
SELECT t.id, u.id, u.alias,
'ill go first

i was maybe 12 or 13. kid at school had his bike stolen. everyone was upset for him, some girls were literally crying. i remember just watching them thinking "why?" like genuinely not understanding what the big deal was. it wasnt their bike.

teacher pulled me aside later because apparently my face during the whole thing was "concerning." i learned to fake the right expressions after that but that was the first time i realized my reactions werent like everyone elses.

everyone has a moment like this right? that first "oh... im not like them" realization. what was yours'
FROM threads t, users u
WHERE t.slug = 'moment-you-realized' AND u.alias = 'YOUR_USERNAME'
ON CONFLICT DO NOTHING;
