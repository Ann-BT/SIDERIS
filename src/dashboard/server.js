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
const pool = require('../shared/pgPool');

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

// Format a timestamp as Apache Combined Log Format datetime string
// e.g. 18/Jun/2025:10:30:45 +0000
function formatCLF(tsMs) {
  const d = new Date(tsMs);
  const mo = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getUTCDate())}/${mo[d.getUTCMonth()]}/${d.getUTCFullYear()}:${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
}

// Build one Combined Log Format line from event data fields
function toCLF(ts, data, ingestIp) {
  const ip      = data.ip      || ingestIp || '-';
  const method  = data.method  || '-';
  const path    = data.endpoint|| '-';
  const status  = data.status  || '-';
  const ua      = data.userAgent ? `"${data.userAgent}"` : '"-"';
  return `${ip} - - [${formatCLF(ts)}] "${method} ${path} HTTP/1.1" ${status} - "-" ${ua}`;
}

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
      const guardData = enrichResults[enrichIdx + 1][1] || {};
      enrichIdx += 2;

      // Parse category_counts
      let categoryCounts = { authentication: 0, injection: 0, fuzzing: 0, bot: 0, dos: 0, session_abuse: 0 };
      try { categoryCounts = JSON.parse(data.category_counts || '{}'); } catch { }
      // Ensure all 6 keys exist
      for (const cat of ['authentication', 'injection', 'fuzzing', 'bot', 'dos', 'session_abuse']) {
        if (!categoryCounts[cat]) categoryCounts[cat] = 0;
      }

      // Parse url_counts
      let urlCounts = {};
      try { urlCounts = JSON.parse(data.url_counts || '{}'); } catch { }

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
        session_id: data.session_id,
        ip_address: data.ip_address || null,
        user_agent: data.user_agent || null,
        session_score: sessionScore,
        risk_score: sessionScore,         // backward compat
        event_count: parseInt(data.event_count || '0', 10),
        verdict: data.verdict || 'allow',
        level,
        last_seen: parseInt(data.last_seen || Date.now().toString(), 10),

        // Category breakdown
        category_counts: categoryCounts,

        // Per-type breakdown
        url_counts: urlCounts,

        // Auth tracking
        login_attempts: parseInt(data.login_attempts || '0', 10),
        failed_login_count: parseInt(data.failed_login_count || '0', 10),
        unique_username_count: JSON.parse(data.unique_usernames || '[]').length,

        // Guard status
        is_blocked: isBlocked,
        guard_action: guardAction,
        block_type: blockType,

        // Detection flags
        scanner_detected: data.scanner_detected === '1',
        scan_detected: data.scan_detected === '1',
        exploit_detected: data.exploit_detected === '1',
        count_404: parseInt(data.count_404 || '0', 10),

        // Behavior timeline (last 50 risk reasons)
        risk_reasons: riskReasons,

        // Bonuses applied
        bonus_applied: JSON.parse(data.bonus_applied || '[]'),

        // Stateful adaptive security state machine fields
        highest_score: parseFloat(data.highest_score || '0'),
        highest_threat_level: data.highest_threat_level || 'allow',
        highest_block_type: data.highest_block_type || 'soft',
        last_mitigation: data.last_mitigation || 'allow',
        mitigation_reason: data.mitigation_reason || (guardData.reason || ''),
        active_mitigation: guardAction || 'allow',
        guard_source: guardData.guard_source || null,
        first_suspicious_at: parseInt(data.first_suspicious_at || '0', 10),
        first_mitigated_at: parseInt(data.first_mitigated_at || '0', 10),
        highest_score_at: parseInt(data.highest_score_at || '0', 10),
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

    // Fetch IP addresses for the guard sessions in parallel
    const sessionPipeline = redis.pipeline();
    results.forEach((result, i) => {
      const keyParts = keys[i].split(':');
      const session_id = keyParts.slice(2).join(':');
      const data = result[1];
      if (data && data.action) {
        sessionPipeline.hget(`sideris:session:${session_id}`, 'ip_address');
      }
    });

    const sessionIps = await sessionPipeline.exec();
    let sessionIpIdx = 0;

    const guards = results.map((result, i) => {
      const keyParts = keys[i].split(':');
      const session_id = keyParts.slice(2).join(':'); // handle colons in ID
      const data = result[1];
      if (!data || !data.action) return null;

      const ip_address = sessionIps[sessionIpIdx] ? sessionIps[sessionIpIdx][1] : null;
      sessionIpIdx++;

      return {
        session_id,
        action: data.action,
        block_type: data.block_type || null,
        risk_score: parseInt(data.risk_score || '0', 10),
        reason: data.reason || null,
        updated_at: parseInt(data.updated_at || '0', 10),
        ip_address: ip_address || '—'
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

    // Reset the live score and last mitigation in Redis (leave peak history intact)
    const sessionKey = `sideris:session:${sessionId}`;
    await redis.hset(sessionKey,
      'session_score', '0.00',
      'last_mitigation', 'allow'
    );

    // Publish unblock synchronization message to worker threads
    await redis.publish('sideris:commands', JSON.stringify({
      action: 'unblock',
      session_id: sessionId
    }));

    // Sync unblock to Postgres
    try {
      await pool.query(`
        UPDATE attack_sessions SET
          session_score = 0,
          last_mitigation = 'allow'
        WHERE session_id = $1
      `, [sessionId]);
    } catch (pgErr) {
      console.error('[dashboard] PG unblock sync error:', pgErr.message);
    }

    // Write audit log
    const auditEntry = JSON.stringify({
      action: 'unblock',
      session_id: sessionId,
      previous: guardData.action,
      block_type: guardData.block_type || null,
      reason: reason || 'SOC manual unblock',
      timestamp: Date.now(),
      time: new Date().toISOString(),
    });
    await redis.lpush('sideris:audit:log', auditEntry);
    await redis.ltrim('sideris:audit:log', 0, 499); // keep last 500

    console.log(`[SOC] UNBLOCK: session=${sessionId} previous_action=${guardData.action} reason=${reason || 'manual'}`);

    res.json({
      success: true,
      session_id: sessionId,
      previous: guardData.action,
      message: 'Session unblocked successfully',
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
      'action', 'block',
      'block_type', 'hard',
      'risk_score', '0',
      'reason', reason || 'SOC manual block',
      'guard_source', 'analyst',
      'updated_at', String(Date.now())
    );
    // No EXPIRE — hard block persists

    // Update session state in Redis
    const sessionKey = `sideris:session:${sessionId}`;
    await redis.hset(sessionKey,
      'last_mitigation', 'block',
      'mitigation_reason', reason || 'SOC manual block',
      'guard_source', 'analyst',
      'highest_threat_level', 'hard_block',
      'highest_block_type', 'hard'
    );

    // Sync to Postgres
    try {
      await pool.query(`
        UPDATE attack_sessions SET
          last_mitigation = 'block',
          mitigation_reason = $1,
          guard_source = 'analyst',
          highest_threat_level = 'hard_block',
          highest_block_type = 'hard'
        WHERE session_id = $2
      `, [reason || 'SOC manual block', sessionId]);
    } catch (pgErr) {
      console.error('[dashboard] PG manual block sync error:', pgErr.message);
    }

    // Increment block metric
    await redis.incr('sideris:metrics:guard:block');

    // Write audit log
    const auditEntry = JSON.stringify({
      action: 'manual_block',
      session_id: sessionId,
      reason: reason || 'SOC manual block',
      timestamp: Date.now(),
      time: new Date().toISOString(),
    });
    await redis.lpush('sideris:audit:log', auditEntry);
    await redis.ltrim('sideris:audit:log', 0, 499);

    console.log(`[SOC] BLOCK: session=${sessionId} reason=${reason || 'manual'}`);

    res.json({
      success: true,
      session_id: sessionId,
      message: 'Session blocked successfully',
    });
  } catch (err) {
    console.error('[dashboard] /block error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ══════════════════════════════════════════════════════════
// POST /challenge/:sessionId — SOC manual CAPTCHA challenge
//
// Issues a CAPTCHA challenge guard directive. The proxy will
// inject the CAPTCHA overlay into the next HTML response from
// the session, prompting human verification.
// ══════════════════════════════════════════════════════════
app.post('/challenge/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  const { reason } = req.body || {};

  if (!sessionId) {
    return res.status(400).json({ error: 'Missing sessionId' });
  }

  try {
    const guardKey = `sideris:guard:${sessionId}`;

    // Only set challenge if no stronger action is already in place
    const existing = await redis.hget(guardKey, 'action');
    if (existing === 'block') {
      return res.status(409).json({ error: 'Session is already hard-blocked. Unblock before issuing challenge.' });
    }

    await redis.hset(guardKey,
      'action',     'challenge',
      'block_type', 'captcha',
      'risk_score', '0',
      'reason',     reason || 'SOC manual CAPTCHA challenge',
      'guard_source', 'analyst',
      'updated_at', String(Date.now())
    );
    // Challenge expires after 30 minutes if not solved
    await redis.expire(guardKey, 1800);

    // Update session state in Redis
    const sessionKey = `sideris:session:${sessionId}`;
    const currLevel = await redis.hget(sessionKey, 'highest_threat_level') || 'allow';
    const LEVELS = { allow: 0, rate_limit: 1, captcha: 2, soft_block: 3, hard_block: 4 };
    if ((LEVELS[currLevel] || 0) < 2) {
      await redis.hset(sessionKey, 'highest_threat_level', 'captcha');
    }
    await redis.hset(sessionKey,
      'last_mitigation', 'challenge',
      'mitigation_reason', reason || 'SOC manual CAPTCHA challenge',
      'guard_source', 'analyst'
    );

    // Sync to Postgres
    try {
      await pool.query(`
        UPDATE attack_sessions SET
          last_mitigation = 'challenge',
          mitigation_reason = $1,
          guard_source = 'analyst',
          highest_threat_level = CASE
            WHEN highest_threat_level IN ('allow', 'rate_limit') THEN 'captcha'
            ELSE highest_threat_level
          END
        WHERE session_id = $2
      `, [reason || 'SOC manual CAPTCHA challenge', sessionId]);
    } catch (pgErr) {
      console.error('[dashboard] PG manual challenge sync error:', pgErr.message);
    }

    // Increment challenge metric
    await redis.incr('sideris:metrics:guard:challenge');

    // Write audit log
    const auditEntry = JSON.stringify({
      action:     'challenge',
      session_id: sessionId,
      block_type: 'captcha',
      reason:     reason || 'SOC manual CAPTCHA challenge',
      timestamp:  Date.now(),
      time:       new Date().toISOString(),
    });
    await redis.lpush('sideris:audit:log', auditEntry);
    await redis.ltrim('sideris:audit:log', 0, 499);

    console.log(`[SOC] CHALLENGE: session=${sessionId} type=captcha reason=${reason || 'manual'}`);

    res.json({
      success:    true,
      session_id: sessionId,
      message:    'CAPTCHA challenge issued. User will see verification on next page load.',
    });
  } catch (err) {
    console.error('[dashboard] /challenge error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ══════════════════════════════════════════════════════════
// GET /logs — live access log stream
//
// Reads latest entries from the sideris:events Redis stream.
// Level is derived from HTTP status code.
// ══════════════════════════════════════════════════════════
app.get('/logs', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);

    // XREVRANGE returns newest-first; we fetch then reverse for oldest→newest display
    const entries = await redis.xrevrange('sideris:events', '+', '-', 'COUNT', limit);

    const logs = entries.reverse().map(([streamId, fields]) => {
      const obj = {};
      for (let i = 0; i < fields.length; i += 2) obj[fields[i]] = fields[i + 1];

      let payload = {};
      try { payload = JSON.parse(obj.payload || '{}'); } catch { }

      // Only show backend access logs, skip agent beacon events
      const source = payload.source || obj.source || '';
      if (source !== 'backend') return null;

      const data = payload.data || {};
      const status = data.status || 0;
      const method = data.method || obj.event_type || 'EVENT';
      const endpoint = data.endpoint || '/';
      const duration = data.duration != null ? `${data.duration}ms` : '';
      const ip = data.ip || payload.ingest_ip || '?';
      const sessionId = payload.session_id || obj.session_id || '';
      const sid = sessionId.slice(0, 12);


      let level = 'INFO';
      if (status >= 500) level = 'ERROR';
      else if (status === 403) level = 'CRITICAL';
      else if (status >= 400) level = 'WARN';

      const ts = parseInt(streamId.split('-')[0], 10) || payload.ingest_time || Date.now();
      const message = (data.method && data.endpoint)
        ? toCLF(ts, data, payload.ingest_ip)
        : `${obj.event_type || 'event'} from ${ip}${sid ? ` sess:${sid}…` : ''}`;

      return { ts, timestamp: new Date(ts).toISOString(), level, service: source, message };
    }).filter(Boolean);

    res.json(logs);
  } catch (err) {
    console.error('[dashboard] /logs error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ══════════════════════════════════════════════════════════
// GET /session-logs/:sessionId — export raw session log
// ══════════════════════════════════════════════════════════
app.get('/session-logs/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  if (!sessionId) return res.status(400).json({ error: 'Missing sessionId' });

  try {
    // Fetch session hash, risk reasons, and guard data in parallel
    const [sessionData, reasonsRaw, guardData] = await Promise.all([
      redis.hgetall(`sideris:session:${sessionId}`),
      redis.lrange(`sideris:session:${sessionId}:risk_reasons`, 0, -1),
      redis.hgetall(`sideris:guard:${sessionId}`),
    ]);

    const riskReasons = reasonsRaw.map(r => {
      try { return JSON.parse(r); } catch { return null; }
    }).filter(Boolean);

    // Scan the events stream for backend access logs belonging to this session
    // Limit scan to 5000 most recent entries to keep export fast
    const streamEntries = await redis.xrevrange('sideris:events', '+', '-', 'COUNT', 5000);
    const accessLogs = [];
    for (const [streamId, fields] of streamEntries) {
      const obj = {};
      for (let i = 0; i < fields.length; i += 2) obj[fields[i]] = fields[i + 1];
      // Filter: backend source + matching session_id
      if (obj.source !== 'backend') continue;
      if (obj.session_id !== sessionId) continue;
      let payload = {};
      try { payload = JSON.parse(obj.payload || '{}'); } catch {}
      const ts = parseInt(streamId.split('-')[0], 10);
      const d = payload.data || {};
      accessLogs.push({
        clf:       toCLF(ts, d, payload.ingest_ip),
        timestamp: new Date(ts).toISOString(),
        method:    d.method    || null,
        endpoint:  d.endpoint  || null,
        status:    d.status    || null,
        duration:  d.duration  || null,
        ip:        d.ip        || payload.ingest_ip || null,
        user_agent:d.userAgent || null,
      });
    }
    // Sort oldest-first
    accessLogs.reverse();

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition',
      `attachment; filename="sideris-session-${sessionId.slice(0, 12)}.json"`);
    res.json({
      exported_at:  new Date().toISOString(),
      session_id:   sessionId,
      session:      sessionData  || {},
      guard:        guardData    || {},
      risk_reasons: riskReasons,
      access_logs:  accessLogs,
    });
  } catch (err) {
    console.error('[dashboard] /session-logs error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// ══════════════════════════════════════════════════════════
// STARTUP
// ══════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`[dashboard] Sideris Metrics API running on http://localhost:${PORT}`);
});
