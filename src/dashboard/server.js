// ──────────────────────────────────────────────────────────
// src/dashboard/server.js
// Sideris 2.0 — Metrics & Dashboard API
//
// Endpoints:
//   GET  /sessions          — all active sessions with category breakdowns
//   GET  /guards            — all active guard directives
//   GET  /metrics           — aggregate counters
//   POST /unblock/:sessionId — SOC manual unblock
//   POST /block/:sessionId   — SOC manual block
// ──────────────────────────────────────────────────────────

const express = require('express');
const cors = require('cors');
const Redis = require('ioredis');
const config = require('../shared/config');

const app = express();
const redis = new Redis(config.redisUrl);
const PORT = config.dashboardPort || 8080;

app.use(cors());
app.use(express.json());

// Log every incoming request for debugging
app.use((req, res, next) => {
  console.log(`[dashboard] ${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// Helper function to scan keys efficiently with hard limits
async function scanKeys(pattern, maxCount = 50) {
  return new Promise((resolve, reject) => {
    let keys = [];
    const stream = redis.scanStream({ match: pattern, count: 100 });

    stream.on('data', (resultKeys) => {
      for (const k of resultKeys) {
        if (keys.length < maxCount) keys.push(k);
      }
      // Hard break early to prevent unbounded database sweeps
      if (keys.length >= maxCount) {
        stream.pause();
        stream.destroy();
        resolve(keys);
      }
    });

    stream.on('end', () => resolve(keys));
    stream.on('error', (err) => reject(err));
  });
}

// ══════════════════════════════════════════════════════════
// GET /sessions — enriched session data for dashboard
// ══════════════════════════════════════════════════════════
//
// Response shape per session:
// {
//   session_id, ip_address, session_score, event_count, verdict, level,
//   category_counts: { authentication, injection, fuzzing, bot, dos, session_abuse },
//   login_attempts, unique_username_count,
//   url_counts: { sql_injection: 3, xss: 1, ... },
//   is_blocked, block_type,
//   risk_reasons: [ { rule, category, signal, score, total, timestamp, time } ],
//   last_seen, user_agent
// }
app.get('/sessions', async (req, res) => {
  try {
    const keys = await scanKeys('sideris:session:*', 50);
    if (keys.length === 0) return res.json([]);

    // Phase 1: Fetch all hash fields for every session
    const pipeline = redis.pipeline();
    keys.forEach(key => pipeline.hgetall(key));

    const results = await pipeline.exec();

    // Phase 2: For each valid session, fetch risk_reasons list + guard status
    const enrichPipeline = redis.pipeline();
    const validIndices = [];

    results.forEach((result, i) => {
      const data = result[1];
      if (data && data.session_id) {
        validIndices.push(i);
        enrichPipeline.lrange(`sideris:session:${data.session_id}:risk_reasons`, 0, 49);
        enrichPipeline.hgetall(`sideris:guard:${data.session_id}`);
      }
    });

    const enrichResults = await enrichPipeline.exec();

    // Phase 3: Assemble enriched session objects
    const sessions = [];
    let enrichIdx = 0;

    for (const i of validIndices) {
      const data = results[i][1];
      const reasonsRaw = enrichResults[enrichIdx][1] || [];
      const guardData  = enrichResults[enrichIdx + 1][1] || {};
      enrichIdx += 2;

      // Parse category_counts
      let categoryCounts = { authentication: 0, injection: 0, fuzzing: 0, bot: 0, dos: 0, session_abuse: 0 };
      try { categoryCounts = JSON.parse(data.category_counts || '{}'); } catch {}
      // Ensure all 6 keys exist
      for (const cat of ['authentication', 'injection', 'fuzzing', 'bot', 'dos', 'session_abuse']) {
        if (!categoryCounts[cat]) categoryCounts[cat] = 0;
      }

      // Parse url_counts
      let urlCounts = {};
      try { urlCounts = JSON.parse(data.url_counts || '{}'); } catch {}

      // Parse risk_reasons JSON strings
      const riskReasons = reasonsRaw.map(r => {
        try { return JSON.parse(r); } catch { return null; }
      }).filter(r => r !== null);

      // Determine level from score
      const sessionScore = parseFloat(data.session_score || data.risk_score || '0');
      let level = 'normal';
      if (sessionScore >= 50) level = 'critical';
      else if (sessionScore >= 30) level = 'very_high';
      else if (sessionScore >= 20) level = 'high';
      else if (sessionScore >= 10) level = 'suspicious';

      // Guard status
      const isBlocked = guardData.action === 'block';
      const guardAction = guardData.action || null;
      const blockType = guardData.block_type || null;

      sessions.push({
        session_id:           data.session_id,
        ip_address:           data.ip_address || null,
        user_agent:           data.user_agent || null,
        session_score:        sessionScore,
        risk_score:           sessionScore,         // backward compat
        event_count:          parseInt(data.event_count || '0', 10),
        verdict:              data.verdict || 'allow',
        level,
        last_seen:            parseInt(data.last_seen || Date.now().toString(), 10),

        // Category breakdown
        category_counts:      categoryCounts,

        // Per-type breakdown
        url_counts:           urlCounts,

        // Auth tracking
        login_attempts:       parseInt(data.login_attempts || '0', 10),
        failed_login_count:   parseInt(data.failed_login_count || '0', 10),
        unique_username_count: JSON.parse(data.unique_usernames || '[]').length,

        // Guard status
        is_blocked:           isBlocked,
        guard_action:         guardAction,
        block_type:           blockType,

        // Detection flags
        scanner_detected:     data.scanner_detected === '1',
        scan_detected:        data.scan_detected === '1',
        exploit_detected:     data.exploit_detected === '1',
        count_404:            parseInt(data.count_404 || '0', 10),

        // Behavior timeline (last 50 risk reasons)
        risk_reasons:         riskReasons,

        // Bonuses applied
        bonus_applied:        JSON.parse(data.bonus_applied || '[]'),
      });
    }

    // Sort by risk score descending
    sessions.sort((a, b) => b.session_score - a.session_score);

    res.json(sessions);
  } catch (err) {
    console.error('[dashboard] /sessions error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ══════════════════════════════════════════════════════════
// GET /guards — all active guard directives
// ══════════════════════════════════════════════════════════
app.get('/guards', async (req, res) => {
  try {
    const keys = await scanKeys('sideris:guard:*', 50);
    if (keys.length === 0) return res.json([]);

    const pipeline = redis.pipeline();
    keys.forEach(key => pipeline.hgetall(key));

    const results = await pipeline.exec();

    const guards = results.map((result, i) => {
       const keyParts = keys[i].split(':');
       const session_id = keyParts.slice(2).join(':'); // handle colons in ID
       const data = result[1];
       if (!data || !data.action) return null;
       return {
         session_id,
         action:      data.action,
         block_type:  data.block_type || null,
         risk_score:  parseInt(data.risk_score || '0', 10),
         reason:      data.reason || null,
         updated_at:  parseInt(data.updated_at || '0', 10),
       };
    }).filter(g => g !== null);

    // Sort heavily penalized actions first (block > challenge)
    const weight = { 'block': 3, 'rate_limit': 2, 'challenge': 1 };
    guards.sort((a, b) => (weight[b.action] || 0) - (weight[a.action] || 0));

    res.json(guards);
  } catch (err) {
    console.error('[dashboard] /guards error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ══════════════════════════════════════════════════════════
// GET /metrics — aggregate counters
// ══════════════════════════════════════════════════════════
app.get('/metrics', async (req, res) => {
  try {
    const targetKeys = [
      'sideris:metrics:guard:block',
      'sideris:metrics:guard:challenge',
      'sideris:metrics:guard:rate_limit',
      'sideris:metrics:processed'
    ];

    const values = await redis.mget(...targetKeys);

    // Normalize mapping (null => 0)
    res.json({
      blocks: parseInt(values[0] || '0', 10),
      challenges: parseInt(values[1] || '0', 10),
      rate_limits: parseInt(values[2] || '0', 10),
      processed: parseInt(values[3] || '0', 10)
    });
  } catch (err) {
    console.error('[dashboard] /metrics error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ══════════════════════════════════════════════════════════
// POST /unblock/:sessionId — SOC manual unblock
//
// Removes guard directive, writes audit log, decrements block metric.
// ══════════════════════════════════════════════════════════
app.post('/unblock/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  const { reason } = req.body || {};

  if (!sessionId) {
    return res.status(400).json({ error: 'Missing sessionId' });
  }

  try {
    const guardKey = `sideris:guard:${sessionId}`;
    const guardData = await redis.hgetall(guardKey);

    if (!guardData || !guardData.action) {
      return res.status(404).json({ error: 'No active guard for this session' });
    }

    // Remove the guard
    await redis.del(guardKey);

    // Decrement block metric
    if (guardData.action === 'block') {
      await redis.decr('sideris:metrics:guard:block');
    } else if (guardData.action === 'challenge') {
      await redis.decr('sideris:metrics:guard:challenge');
    } else if (guardData.action === 'rate_limit') {
      await redis.decr('sideris:metrics:guard:rate_limit');
    }

    // Write audit log
    const auditEntry = JSON.stringify({
      action:      'unblock',
      session_id:  sessionId,
      previous:    guardData.action,
      block_type:  guardData.block_type || null,
      reason:      reason || 'SOC manual unblock',
      timestamp:   Date.now(),
      time:        new Date().toISOString(),
    });
    await redis.lpush('sideris:audit:log', auditEntry);
    await redis.ltrim('sideris:audit:log', 0, 499); // keep last 500

    console.log(`[SOC] UNBLOCK: session=${sessionId} previous_action=${guardData.action} reason=${reason || 'manual'}`);

    res.json({
      success:    true,
      session_id: sessionId,
      previous:   guardData.action,
      message:    'Session unblocked successfully',
    });
  } catch (err) {
    console.error('[dashboard] /unblock error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ══════════════════════════════════════════════════════════
// POST /block/:sessionId — SOC manual block
//
// Creates a hard_block guard directive, writes audit log.
// ══════════════════════════════════════════════════════════
app.post('/block/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  const { reason } = req.body || {};

  if (!sessionId) {
    return res.status(400).json({ error: 'Missing sessionId' });
  }

  try {
    const guardKey = `sideris:guard:${sessionId}`;

    // Set hard block (no TTL — persists until SOC unblocks)
    await redis.hset(guardKey,
      'action',     'block',
      'block_type', 'hard',
      'risk_score', '0',
      'reason',     reason || 'SOC manual block',
      'updated_at', String(Date.now())
    );
    // No EXPIRE — hard block persists

    // Increment block metric
    await redis.incr('sideris:metrics:guard:block');

    // Write audit log
    const auditEntry = JSON.stringify({
      action:      'manual_block',
      session_id:  sessionId,
      reason:      reason || 'SOC manual block',
      timestamp:   Date.now(),
      time:        new Date().toISOString(),
    });
    await redis.lpush('sideris:audit:log', auditEntry);
    await redis.ltrim('sideris:audit:log', 0, 499);

    console.log(`[SOC] BLOCK: session=${sessionId} reason=${reason || 'manual'}`);

    res.json({
      success:    true,
      session_id: sessionId,
      message:    'Session blocked successfully',
    });
  } catch (err) {
    console.error('[dashboard] /block error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ══════════════════════════════════════════════════════════
// STARTUP
// ══════════════════════════════════════════════════════════
app.listen(PORT, () => {
   console.log(`[dashboard] Sideris Metrics API running on http://localhost:${PORT}`);
});
