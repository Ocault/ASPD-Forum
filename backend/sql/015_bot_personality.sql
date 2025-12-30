-- Bot Personality Enhancement
-- Adds unique personality traits to each bot for more realistic behavior

-- Add personality columns to bot_accounts
ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS writing_style JSONB DEFAULT '{}';
-- writing_style contains:
--   abbreviation_level: 'low', 'medium', 'high' (how much they use tbh, idk, etc)
--   punctuation: 'minimal', 'normal', 'proper' (do they use periods?)
--   capitalization: 'none', 'sentences', 'proper' (lowercase always? or capitalize?)
--   emoji_usage: 'never', 'rare', 'sometimes' (do they use emojis?)
--   response_length: 'brief', 'medium', 'verbose' (typical response length)

ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS personality_traits JSONB DEFAULT '[]';
-- Array of specific traits like ['sarcastic', 'helpful', 'blunt', 'philosophical', 'empathetic']

ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS favorite_topics JSONB DEFAULT '[]';
-- Topics they're more likely to engage with: ['work', 'relationships', 'therapy', 'diagnosis', 'coping']

ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS age_range VARCHAR(20);
-- e.g., '20s', '30s', '40s', '50s' - affects perspective and references

ALTER TABLE bot_accounts ADD COLUMN IF NOT EXISTS personality_description TEXT;
-- AI-generated unique ASPD personality description for this specific bot

-- Function to generate random personality
CREATE OR REPLACE FUNCTION generate_bot_personality()
RETURNS TRIGGER AS $$
DECLARE
  abbreviation_options TEXT[] := ARRAY['low', 'medium', 'high'];
  punctuation_options TEXT[] := ARRAY['minimal', 'normal', 'proper'];
  capitalization_options TEXT[] := ARRAY['none', 'sentences', 'proper'];
  emoji_options TEXT[] := ARRAY['never', 'rare', 'sometimes'];
  length_options TEXT[] := ARRAY['brief', 'medium', 'verbose'];
  age_options TEXT[] := ARRAY['20s', '30s', '30s', '40s']; -- weighted toward 30s
  
  all_topics TEXT[] := ARRAY['work', 'relationships', 'therapy', 'diagnosis', 'coping', 'family', 'anger', 'manipulation', 'empathy', 'identity', 'legal', 'substances'];
  selected_topics TEXT[];
  num_topics INT;
BEGIN
  -- Generate writing style
  NEW.writing_style := jsonb_build_object(
    'abbreviation_level', abbreviation_options[1 + floor(random() * 3)],
    'punctuation', punctuation_options[1 + floor(random() * 3)],
    'capitalization', capitalization_options[1 + floor(random() * 3)],
    'emoji_usage', emoji_options[1 + floor(random() * 3)],
    'response_length', length_options[1 + floor(random() * 3)]
  );
  
  -- Generate age range
  NEW.age_range := age_options[1 + floor(random() * 4)];
  
  -- Select 2-4 random favorite topics
  num_topics := 2 + floor(random() * 3);
  selected_topics := ARRAY(SELECT unnest(all_topics) ORDER BY random() LIMIT num_topics);
  NEW.favorite_topics := to_jsonb(selected_topics);
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to new bots
DROP TRIGGER IF EXISTS trg_bot_personality ON bot_accounts;
CREATE TRIGGER trg_bot_personality
  BEFORE INSERT ON bot_accounts
  FOR EACH ROW
  WHEN (NEW.writing_style = '{}' OR NEW.writing_style IS NULL)
  EXECUTE FUNCTION generate_bot_personality();

-- Update existing bots with random personalities
UPDATE bot_accounts SET
  writing_style = jsonb_build_object(
    'abbreviation_level', (ARRAY['low', 'medium', 'high'])[1 + floor(random() * 3)],
    'punctuation', (ARRAY['minimal', 'normal', 'proper'])[1 + floor(random() * 3)],
    'capitalization', (ARRAY['none', 'sentences', 'proper'])[1 + floor(random() * 3)],
    'emoji_usage', (ARRAY['never', 'rare', 'sometimes'])[1 + floor(random() * 3)],
    'response_length', (ARRAY['brief', 'medium', 'verbose'])[1 + floor(random() * 3)]
  ),
  age_range = (ARRAY['20s', '30s', '30s', '40s'])[1 + floor(random() * 4)],
  favorite_topics = (SELECT to_jsonb(ARRAY(
    SELECT unnest(ARRAY['work', 'relationships', 'therapy', 'diagnosis', 'coping', 'family', 'anger', 'manipulation', 'empathy', 'identity', 'legal', 'substances']) 
    ORDER BY random() 
    LIMIT (2 + floor(random() * 3))
  )))
WHERE writing_style = '{}' OR writing_style IS NULL;
