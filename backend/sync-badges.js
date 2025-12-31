require('dotenv').config();
const db = require('./db');

async function syncBotBadges() {
  try {
    console.log('Syncing badges for all users...');
    
    // Get all users who have posts
    const usersWithPosts = await db.query(`
      SELECT u.id, u.alias,
        (SELECT COUNT(*) FROM entries e WHERE e.user_id = u.id AND e.is_deleted = FALSE) as post_count
      FROM users u
      WHERE EXISTS (SELECT 1 FROM entries e WHERE e.user_id = u.id AND e.is_deleted = FALSE)
    `);
    
    console.log('Found', usersWithPosts.rows.length, 'users with posts');
    
    let awarded = 0;
    for (const user of usersWithPosts.rows) {
      const postCount = parseInt(user.post_count) || 0;
      
      // Count threads where this user made the first post
      const threadResult = await db.query(`
        SELECT COUNT(DISTINCT e.thread_id) as thread_count
        FROM entries e
        WHERE e.user_id = $1
        AND e.id = (SELECT MIN(id) FROM entries WHERE thread_id = e.thread_id)
      `, [user.id]);
      const threadCount = parseInt(threadResult.rows[0]?.thread_count) || 0;
      
      const badges = [];
      if (postCount >= 1) badges.push('first-post');
      if (postCount >= 10) badges.push('ten-posts');
      if (postCount >= 50) badges.push('fifty-posts');
      if (postCount >= 100) badges.push('hundred-posts');
      if (postCount >= 500) badges.push('five-hundred-posts');
      if (threadCount >= 1) badges.push('first-thread');
      if (threadCount >= 10) badges.push('ten-threads');
      
      console.log(`  ${user.alias}: ${postCount} posts, ${threadCount} threads`);
      
      for (const slug of badges) {
        try {
          const result = await db.query(`
            INSERT INTO user_badges (user_id, badge_id)
            SELECT $1, b.id FROM badges b WHERE b.slug = $2
            ON CONFLICT (user_id, badge_id) DO NOTHING
            RETURNING badge_id
          `, [user.id, slug]);
          
          if (result.rows.length > 0) {
            awarded++;
            console.log('    + Awarded', slug);
          }
        } catch (err) {
          console.error('    Error awarding', slug, ':', err.message);
        }
      }
    }
    
    console.log('Done! Awarded', awarded, 'total badges');
  } catch (err) {
    console.error('Error:', err);
  }
  process.exit(0);
}

syncBotBadges();
