// ──────────────────────────────────────────────────────────
// src/storage/writer.js
// Sideris 2.0 — PostgreSQL Storage Writer
//
// Consumes the sideris:events Redis stream (as a separate
// consumer group: sideris_storage) and persists every event
// to PostgreSQL for SOC investigation via the dashboard.
//
// Tables managed:
//   attack_sessions — one row per unique session_id
//   attack_events   — one row per stream event
//
// The writer is idempotent: it uses ON CONFLICT DO NOTHING /
// DO UPDATE so it is safe to restart without duplicating data.
// ──────────────────────────────────────────────────────────

'use strict';

const { Pool }  = require('pg');
const Redis     = require('ioredis');
const os        = require('os');
const path      = require('path');
const dotenv    = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const config = require('../shared/config');

// ── Constants ─────────────────────────────────────────────
const STREAM_NAME    = config.streamName    || 'sideris:events';
const STORAGE_GROUP  = 'sideris_storage';
const CONSUMER_NAME  = `writer-${os.hostname()}-${process.pid}`;
const BLOCK_MS       = 5000;   // block time for XREADGROUP
const BATCH_SIZE     = 50;     // messages per poll

// ── PostgreSQL connection pool ────────────────────────────
const pool = new Pool({ connectionString: config.postgresUrl });

pool.on('error', (err) => {
  console.error('[writer] PG pool error:', err.message);
});

// ── Redis reader client ───────────────────────────────────
const redis = new Redis(config.redisUrl);
redis.on('error', (err) => console.error('[writer] Redis error:', err.message));

// ══════════════════════════════════════════════════════════
// SCHEMA BOOTSTRAP
// Creates tables if they do not exist.
// ══════════════════════════════════════════════════════════

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attack_sessions (
      session_id       TEXT        PRIMARY KEY,
      start_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      end_time         TIMESTAMPTZ,
      ip_address       TEXT,
      user_agent       TEXT,
      final_risk_score INTEGER     NOT NULL DEFAULT 0,
      session_score    FLOAT       NOT NULL DEFAULT 0,
      verdict          TEXT        NOT NULL DEFAULT 'normal',
      event_count      INTEGER     NOT NULL DEFAULT 0,
      highest_score       FLOAT       NOT NULL DEFAULT 0,
      highest_threat_level TEXT        NOT NULL DEFAULT 'allow',
      highest_block_type   TEXT        NOT NULL DEFAULT 'soft',
      last_mitigation     TEXT        NOT NULL DEFAULT 'allow',
      mitigation_reason   TEXT        NOT NULL DEFAULT '',
      guard_source        TEXT        NOT NULL DEFAULT 'automatic',
      first_suspicious_at TIMESTAMPTZ,
      first_mitigated_at  TIMESTAMPTZ,
      highest_score_at    TIMESTAMPTZ,
      updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS attack_events (
      id               BIGSERIAL   PRIMARY KEY,
      stream_id        TEXT        UNIQUE NOT NULL,
      session_id       TEXT        NOT NULL REFERENCES attack_sessions(session_id)
                                   ON DELETE CASCADE,
      timestamp        TIMESTAMPTZ NOT NULL,
      source           TEXT        NOT NULL,
      event_type       TEXT        NOT NULL,
      attack_type      TEXT        NOT NULL DEFAULT 'unknown',
      data             JSONB,
      impact           FLOAT       NOT NULL DEFAULT 0,
      confidence       FLOAT       NOT NULL DEFAULT 0,
      persistence      FLOAT       NOT NULL DEFAULT 0,
      event_score      FLOAT       NOT NULL DEFAULT 0,
      risk_score_delta INTEGER     NOT NULL DEFAULT 0,
      ingest_time      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Migrate existing tables to add new columns safely
  const alterCmds = [
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS session_score FLOAT NOT NULL DEFAULT 0`,
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS highest_score FLOAT NOT NULL DEFAULT 0`,
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS highest_threat_level TEXT NOT NULL DEFAULT 'allow'`,
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS highest_block_type TEXT NOT NULL DEFAULT 'soft'`,
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS last_mitigation TEXT NOT NULL DEFAULT 'allow'`,
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS mitigation_reason TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS guard_source TEXT NOT NULL DEFAULT 'automatic'`,
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS first_suspicious_at TIMESTAMPTZ`,
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS first_mitigated_at TIMESTAMPTZ`,
    `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS highest_score_at TIMESTAMPTZ`,
    `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS attack_type  TEXT  NOT NULL DEFAULT 'unknown'`,
    `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS impact       FLOAT NOT NULL DEFAULT 0`,
    `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS confidence   FLOAT NOT NULL DEFAULT 0`,
    `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS persistence  FLOAT NOT NULL DEFAULT 0`,
    `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS event_score  FLOAT NOT NULL DEFAULT 0`,
  ];
  for (const cmd of alterCmds) {
    try { await pool.query(cmd); } catch { /* column already exists */ }
  }

  // Indexes for fast dashboard queries
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_session
      ON attack_events(session_id);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_timestamp
      ON attack_events(timestamp DESC);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_source
      ON attack_events(source);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_type
      ON attack_events(event_type);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_updated
      ON attack_sessions(updated_at DESC);
  `);

  console.log('[writer] Schema ready: attack_sessions, attack_events');
}

// ══════════════════════════════════════════════════════════
// CONSUMER GROUP BOOTSTRAP
// ══════════════════════════════════════════════════════════

async function initConsumerGroup() {
  try {
    await redis.xgroup('CREATE', STREAM_NAME, STORAGE_GROUP, '0', 'MKSTREAM');
    console.log(`[writer] Created consumer group ${STORAGE_GROUP}`);
  } catch (err) {
    if (!err.message.includes('BUSYGROUP')) throw err;
    console.log(`[writer] Consumer group ${STORAGE_GROUP} already exists`);
  }
}

// ══════════════════════════════════════════════════════════
// FIELD EXTRACTOR
// Stream entries use flat key=value pairs; extract them all.
// ══════════════════════════════════════════════════════════

function extractFields(rawFields) {
  const fields = {};
  for (let i = 0; i < rawFields.length; i += 2) {
    fields[rawFields[i]] = rawFields[i + 1];
  }
  return fields;
}

// ══════════════════════════════════════════════════════════
// UPSERT SESSION
// Insert or update the session row with latest known values.
// ══════════════════════════════════════════════════════════

async function upsertSession(client, payload, sessionId) {
  const ip        = payload.data?.ip        || payload.ingest_ip || null;
  const userAgent = payload.data?.userAgent || null;
  const ts        = new Date(payload.timestamp || Date.now());

  await client.query(`
    INSERT INTO attack_sessions
      (session_id, start_time, ip_address, user_agent, event_count, updated_at)
    VALUES
      ($1, $2, $3, $4, 1, NOW())
    ON CONFLICT (session_id) DO UPDATE SET
      end_time      = EXCLUDED.start_time,
      ip_address    = COALESCE(attack_sessions.ip_address, EXCLUDED.ip_address),
      user_agent    = COALESCE(attack_sessions.user_agent, EXCLUDED.user_agent),
      event_count   = attack_sessions.event_count + 1,
      updated_at    = NOW()
  `, [sessionId, ts, ip, userAgent]);
}

// ══════════════════════════════════════════════════════════
// INSERT EVENT
// Insert one event row, skipping if stream_id already exists.
// ══════════════════════════════════════════════════════════

async function insertEvent(client, streamId, payload) {
  const sessionId = payload.session_id || 'unknown';
  const ts        = new Date(payload.timestamp || Date.now());
  const source    = payload.source     || 'unknown';
  const eventType = payload.event_type || 'unknown';
  const data      = payload.data       || {};

  await client.query(`
    INSERT INTO attack_events
      (stream_id, session_id, timestamp, source, event_type, data)
    VALUES
      ($1, $2, $3, $4, $5, $6)
    ON CONFLICT (stream_id) DO NOTHING
  `, [streamId, sessionId, ts, source, eventType, JSON.stringify(data)]);
}

// ══════════════════════════════════════════════════════════
// PROCESS ONE MESSAGE
// ══════════════════════════════════════════════════════════

async function processMessage(streamId, rawFields) {
  const fields = extractFields(rawFields);

  let payload;
  try {
    payload = JSON.parse(fields.payload || '{}');
  } catch {
    console.warn(`[writer] Invalid JSON in message ${streamId} — skipping`);
    return;
  }

  const sessionId = payload.session_id
    || fields.session_id
    || 'unknown';

  // Ensure session row exists first (foreign key constraint)
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await upsertSession(client, payload, sessionId);
    await insertEvent(client, streamId, payload);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(`[writer] TX error for ${streamId}:`, err.message);
  } finally {
    client.release();
  }
}

// ══════════════════════════════════════════════════════════
// MAIN CONSUMER LOOP
// ══════════════════════════════════════════════════════════

async function startWriter() {
  console.log(`[writer] Starting storage consumer: ${CONSUMER_NAME}`);

  await initSchema();
  await initConsumerGroup();

  // Process any pending messages from a previous crashed run first
  await drainPending();

  console.log('[writer] Entering main consume loop...');

  while (true) {
    try {
      const response = await redis.xreadgroup(
        'GROUP', STORAGE_GROUP, CONSUMER_NAME,
        'BLOCK', BLOCK_MS,
        'COUNT', BATCH_SIZE,
        'STREAMS', STREAM_NAME, '>'
      );

      if (!response || response.length === 0) continue;

      const [, messages] = response[0];
      const ids = [];

      for (const [streamId, rawFields] of messages) {
        await processMessage(streamId, rawFields);
        ids.push(streamId);
      }

      // Acknowledge all processed messages in one call
      if (ids.length > 0) {
        await redis.xack(STREAM_NAME, STORAGE_GROUP, ...ids);
        console.log(`[writer] Stored ${ids.length} event(s) → PostgreSQL`);
      }

    } catch (err) {
      console.error('[writer] Consume loop error:', err.message);
      await new Promise(r => setTimeout(r, 2000));
    }
  }
}

// ── Drain any unacknowledged pending messages ─────────────
async function drainPending() {
  try {
    const pending = await redis.xpending(
      STREAM_NAME, STORAGE_GROUP, '-', '+', 100
    );
    if (!pending || pending.length === 0) return;

    console.log(`[writer] Draining ${pending.length} pending messages from previous run...`);

    const ids = pending.map(p => p[0]);
    const claimed = await redis.xclaim(
      STREAM_NAME, STORAGE_GROUP, CONSUMER_NAME, 0, ...ids
    );

    for (const [streamId, rawFields] of claimed) {
      await processMessage(streamId, rawFields);
    }
    if (ids.length > 0) {
      await redis.xack(STREAM_NAME, STORAGE_GROUP, ...ids);
    }
  } catch (err) {
    // XPENDING may fail on a fresh stream — that's fine
    if (!err.message.includes('ERR')) {
      console.warn('[writer] Pending drain skipped:', err.message);
    }
  }
}

// ══════════════════════════════════════════════════════════
// GRACEFUL SHUTDOWN
// ══════════════════════════════════════════════════════════

async function shutdown() {
  console.log('[writer] Shutting down gracefully...');
  await redis.quit();
  await pool.end();
  process.exit(0);
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);

startWriter().catch(err => {
  console.error('[writer] Fatal error:', err.message);
  process.exit(1);
});
