const { Pool } = require('pg');
const Redis = require('ioredis');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

const postgresUrl = process.env.POSTGRES_URL || 'postgresql://sideris:sideris@localhost:5432/sideris';
const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

async function clearDashboard() {
  console.log('🧹 Clearing SIDERIS Dashboard Data...');

  // 1. Clear PostgreSQL tables
  console.log(`Connecting to PostgreSQL at: ${postgresUrl.replace(/:[^:]+@/, ':****@')}`);
  const pool = new Pool({ connectionString: postgresUrl });
  try {
    const client = await pool.connect();
    try {
      console.log('Truncating PostgreSQL tables...');
      await client.query('TRUNCATE TABLE attack_events, attack_sessions RESTART IDENTITY CASCADE;');
      console.log('✅ PostgreSQL tables truncated successfully.');
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('❌ Error clearing PostgreSQL:', err.message);
  } finally {
    await pool.end();
  }

  // 2. Clear Redis keys starting with "sideris:"
  console.log(`Connecting to Redis at: ${redisUrl}`);
  const redis = new Redis(redisUrl);
  try {
    let cursor = '0';
    let deletedCount = 0;
    do {
      const [newCursor, keys] = await redis.scan(cursor, 'MATCH', 'sideris:*', 'COUNT', 100);
      cursor = newCursor;
      if (keys.length > 0) {
        await redis.del(...keys);
        deletedCount += keys.length;
      }
    } while (cursor !== '0');
    console.log(`✅ Deleted ${deletedCount} Redis keys matching "sideris:*".`);

    // 3. Recreate the stream and consumer groups so running consumers don't crash
    console.log('Recreating Redis stream and consumer groups...');
    const STREAM_NAME = 'sideris:events';
    await redis.xgroup('CREATE', STREAM_NAME, 'sideris_group', '$', 'MKSTREAM');
    await redis.xgroup('CREATE', STREAM_NAME, 'sideris_storage', '0', 'MKSTREAM');
    console.log('✅ Redis stream and consumer groups (sideris_group, sideris_storage) recreated.');

    // 4. Publish clear_all command to clear worker L1 cache
    console.log('Publishing clear_all command to worker threads...');
    await redis.publish('sideris:commands', JSON.stringify({ action: 'clear_all' }));
    console.log('✅ Sent clear_all command.');
  } catch (err) {
    console.error('❌ Error clearing/recreating Redis:', err.message);
  } finally {
    await redis.quit();
  }

  console.log('🎉 SIDERIS Dashboard has been cleared! Ready for a fresh test.');
}

clearDashboard();
