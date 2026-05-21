// ──────────────────────────────────────────────────────────
// src/detector/worker.js
// Sideris 2.0 — Detection Worker (Orchestrator)
//
// Reads events from the sideris:events Redis stream and runs
// them through the full scoring pipeline:
//
//   eventAnalyzer → scoringEngine → sessionTracker
//      → decisionEngine → Redis + PostgreSQL update
//
// This file is intentionally thin. All logic lives in the
// four modules it delegates to.
// ──────────────────────────────────────────────────────────
'use strict';

const Redis          = require('ioredis');
const os             = require('os');
const config         = require('../shared/config');
const pool           = require('../shared/pgPool');
const analyzer       = require('./eventAnalyzer');
const scoring        = require('./scoringEngine');
const tracker        = require('./sessionTracker');
const { decide, getGuardDirective, isHardBlock } = require('./decisionEngine');

// ── Redis clients ─────────────────────────────────────────
const redis     = new Redis(config.redisUrl);
const publisher = new Redis(config.redisUrl);

redis.on('error',     err => console.error('[worker] Redis error:',     err.message));
publisher.on('error', err => console.error('[worker] Publisher error:', err.message));

// ── Constants ─────────────────────────────────────────────
const STREAM_NAME   = config.streamName    || 'sideris:events';
const GROUP_NAME    = config.consumerGroup || 'sideris_group';
const CONSUMER_NAME = `${os.hostname()}-${process.pid}`;
const ALERT_CHANNEL = config.alertChannel  || 'sideris:alerts';
const SESSION_TTL   = config.sessionTtlSec || 1800;
const PROCESSED_TTL = 3600;

// ── Bootstrap: create consumer group ─────────────────────
async function initStream() {
  try {
    await redis.xgroup('CREATE', STREAM_NAME, GROUP_NAME, '$', 'MKSTREAM');
    console.log(`[worker] Created consumer group ${GROUP_NAME}`);
  } catch (err) {
    if (!err.message.includes('BUSYGROUP')) {
      console.error('[worker] Failed to create group:', err.message);
      process.exit(1);
    }
    console.log(`[worker] Consumer group ${GROUP_NAME} already exists`);
  }
}

// ── Extract flat fields from stream entry ─────────────────
function extractFields(rawFields) {
  const out = {};
  for (let i = 0; i < rawFields.length; i += 2) out[rawFields[i]] = rawFields[i + 1];
  return out;
}

// ── PostgreSQL: update attack_sessions ────────────────────
async function persistSession(state, decision) {
  try {
    await pool.query(`
      INSERT INTO attack_sessions
        (session_id, start_time, ip_address, user_agent,
         event_count, final_risk_score, session_score, verdict, updated_at)
      VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7, NOW())
      ON CONFLICT (session_id) DO UPDATE SET
        end_time         = NOW(),
        ip_address       = COALESCE(attack_sessions.ip_address, EXCLUDED.ip_address),
        user_agent       = COALESCE(attack_sessions.user_agent, EXCLUDED.user_agent),
        event_count      = EXCLUDED.event_count,
        final_risk_score = EXCLUDED.final_risk_score,
        session_score    = EXCLUDED.session_score,
        verdict          = EXCLUDED.verdict,
        updated_at       = NOW()
    `, [
      state.session_id,
      state.ip_address,
      state.user_agent,
      state.event_count,
      Math.round(state.session_score),
      state.session_score,
      decision.verdict,
    ]);
  } catch (err) {
    console.error('[worker] PG session upsert error:', err.message);
  }
}

// ── PostgreSQL: update attack_events scoring columns ──────
async function persistEventScore(streamId, scoringResult) {
  try {
    // Retry once — the storage writer may not have inserted the row yet
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await pool.query(`
        UPDATE attack_events SET
          attack_type = $1,
          impact      = $2,
          confidence  = $3,
          persistence = $4,
          event_score = $5
        WHERE stream_id = $6
      `, [
        scoringResult.attack_type,
        scoringResult.impact,
        scoringResult.confidence,
        scoringResult.persistence,
        scoringResult.event_score,
        streamId,
      ]);

      if (result.rowCount > 0) break;
      if (attempt === 0) await new Promise(r => setTimeout(r, 150));
    }
  } catch (err) {
    console.error('[worker] PG event score update error:', err.message);
  }
}

// ── Guard directive: write to Redis ───────────────────────
async function applyGuard(sessionId, decision) {
  const directive = getGuardDirective(decision.action);
  if (!directive) return;

  const guardKey = `sideris:guard:${sessionId}`;
  const current  = await redis.hget(guardKey, 'action');

  // Only escalate — never downgrade within a session lifecycle
  const LEVELS = { challenge: 1, rate_limit: 2, block: 3 };
  const currentLevel  = LEVELS[current]   || 0;
  const proposedLevel = LEVELS[directive]  || 0;

  if (proposedLevel > currentLevel) {
    const fields = [
      'action',     directive,
      'risk_score', String(Math.round(decision.score)),
      'updated_at', String(Date.now()),
      'block_type', isHardBlock(decision.action) ? 'hard' : 'soft',
    ];
    await redis.hset(guardKey, ...fields);

    // hard_block: no TTL (persists until SOC unblocks)
    // soft_block / others: TTL-based auto-expire
    if (!isHardBlock(decision.action)) {
      await redis.expire(guardKey, SESSION_TTL);
    }

    // Increment the dashboard metrics counter for this action type.
    // guard.js (pub/sub path) only covers block/challenge via Lua;
    // rate_limit actions are set exclusively here, so we must count them.
    await redis.incr(`sideris:metrics:guard:${directive}`);
  }
}

// ── Alert publisher ───────────────────────────────────────
async function publishAlert(state, decision, bonuses) {
  // Only publish on level changes that matter (≥suspicious)
  if (decision.level < 2) return;

  const alertKey = `sideris:alert_sent:${state.session_id}:${decision.verdict}`;
  const alreadySent = await redis.exists(alertKey);
  if (alreadySent) return;

  await redis.set(alertKey, '1', 'EX', SESSION_TTL);

  const payload = JSON.stringify({
    session_id:     state.session_id,
    session_score:  state.session_score,
    risk_score:     state.session_score,   // guard.js reads this field
    verdict:        decision.verdict,
    action:         decision.action,
    bonus_reasons:  bonuses,
    ip_address:     state.ip_address,
    timestamp:      Date.now(),
  });
  await publisher.publish(ALERT_CHANNEL, payload);
  console.log(`[ALERT] ${decision.verdict.toUpperCase()}: session=${state.session_id.substring(0,8)}... score=${state.session_score} action=${decision.action}`);
}

// ── Core pipeline for one event ───────────────────────────
async function processMessage(streamId, rawFields) {
  const fields = extractFields(rawFields);

  // Parse payload JSON
  let event;
  try { event = JSON.parse(fields.payload || '{}'); }
  catch { console.warn(`[worker] Bad JSON in ${streamId}`); return; }

  const sessionId = event.session_id || 'unknown';

  // 1. Analyze → attack_type, category, behavior_signal, impact, base_confidence
  const analyzed = analyzer.analyze(event);

  // 2. Get current session state (L1 cache → Redis)
  const sessionState = await tracker.getSession(sessionId);

  // 3. Score → event_score = impact × confidence × persistence
  const scoringResult = scoring.compute(analyzed, sessionState);

  // 4. Update session tracker (increments counters, applies bonuses, decays)
  const { state, newReasons } = await tracker.update(sessionId, scoringResult, event);

  // 5. Decide → verdict + action
  const decision = decide(state.session_score);

  // 6. Log
  console.log(
    `[SCORE] session=${sessionId.substring(0,8)}...` +
    ` cat=${(scoringResult.category || 'normal').padEnd(15)}` +
    ` type=${scoringResult.attack_type.padEnd(20)}` +
    ` impact=${scoringResult.impact}` +
    ` conf=${scoringResult.confidence}` +
    ` pers=${scoringResult.persistence}` +
    ` evt_score=${scoringResult.event_score}` +
    ` sess_score=${state.session_score}` +
    ` verdict=${decision.verdict}` +
    (newReasons.length ? ` BONUS=[${newReasons.join(',')}]` : '')
  );

  // 7. Persist to PostgreSQL (non-blocking — failures are logged, not fatal)
  persistSession(state, decision);
  persistEventScore(streamId, scoringResult);

  // 8. Apply guard directive to Redis
  await applyGuard(sessionId, decision);

  // 9. Publish alert on threshold crossings
  await publishAlert(state, decision, newReasons);

  // 10. Global metrics
  await redis.incr('sideris:metrics:processed');
}

// ── Dead letter recovery ──────────────────────────────────
function startDeadLetterRecovery() {
  setInterval(async () => {
    try {
      const claimed = await redis.xautoclaim(
        STREAM_NAME, GROUP_NAME, CONSUMER_NAME, 60000, '0-0', 'COUNT', 50
      );
      if (!claimed) return;
      const [, messages] = claimed;
      if (!messages || messages.length === 0) return;
      console.log(`[worker] Recovering ${messages.length} stale messages`);
      for (const [id, fields] of messages) {
        await processMessage(id, fields);
        await redis.xack(STREAM_NAME, GROUP_NAME, id);
      }
    } catch (err) {
      console.error('[worker] Dead-letter error:', err.message);
    }
  }, 60_000);
}

// ── Main consumer loop ────────────────────────────────────
async function startWorker() {
  console.log(`[worker] Starting: ${CONSUMER_NAME}`);
  console.log(`[worker] Pipeline: eventAnalyzer → scoringEngine → sessionTracker → decisionEngine`);

  await initStream();
  tracker.startDecayTimer();
  startDeadLetterRecovery();

  while (true) {
    try {
      const response = await redis.xreadgroup(
        'GROUP', GROUP_NAME, CONSUMER_NAME,
        'BLOCK', 5000,
        'COUNT', 10,
        'STREAMS', STREAM_NAME, '>'
      );

      if (!response || response.length === 0) continue;

      const [, messages] = response[0];
      const ids = [];

      for (const [streamId, rawFields] of messages) {
        // Idempotency check
        const done = await redis.exists(`sideris:processed:${streamId}`);
        if (done) { ids.push(streamId); continue; }

        // Lock to prevent race between parallel workers
        const lock = await redis.set(`sideris:lock:${streamId}`, '1', 'NX', 'EX', 30);
        if (lock !== 'OK') continue;

        await processMessage(streamId, rawFields);
        await redis.set(`sideris:processed:${streamId}`, '1', 'EX', PROCESSED_TTL);
        ids.push(streamId);
      }

      if (ids.length > 0) {
        await redis.xack(STREAM_NAME, GROUP_NAME, ...ids);
      }

    } catch (err) {
      console.error('[worker] Loop error:', err.message);
      await new Promise(r => setTimeout(r, 1000));
    }
  }
}

// ── Graceful shutdown ─────────────────────────────────────
async function shutdown() {
  console.log('[worker] Shutting down...');
  await redis.quit();
  await publisher.quit();
  await pool.end();
  process.exit(0);
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);

startWorker().catch(err => {
  console.error('[worker] Fatal:', err.message);
  process.exit(1);
});
