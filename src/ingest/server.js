// ──────────────────────────────────────────────────────────
// src/ingest/server.js
// Sideris 2.0 — Ingest Server (Phase 3)
//
// Express server on INGEST_PORT (default 5000).
// Receives beacon batches from agent.js, enriches events
// with server timestamp and client IP, writes raw events
// to events.jsonl and normalized events to normalized.jsonl.
// Also serves agent.js statically and exposes a health check.
// ──────────────────────────────────────────────────────────

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const config = require('../shared/config');
const Redis = require('ioredis');

const app = express();
const PORT = config.ingestPort;

// Initialize Redis client
const redis = new Redis(config.redisUrl);
redis.on('error', (err) => console.error('[ingest] Redis error:', err.message));

// ══════════════════════════════════════════════════════════
// CORS CONFIGURATION
// Only the proxy (and its configured origin) may post to ingest.
// Reflecting any origin with credentials=true was a security hole —
// an attacker could post fake telemetry from any site.
// ══════════════════════════════════════════════════════════

// Build the set of allowed origins:
//   1. The explicit proxy origin from env (PROXY_ORIGIN)
//   2. The proxy itself on PROXY_PORT (localhost variants)
//   3. The config.allowedOrigins list (target site origins)
const PROXY_PORT = parseInt(process.env.PROXY_PORT || '4000', 10);
const INGEST_ALLOWED_ORIGINS = new Set([
  ...(config.allowedOrigins || []),
  `http://localhost:${PROXY_PORT}`,
  `http://127.0.0.1:${PROXY_PORT}`,
  ...(process.env.PROXY_ORIGIN ? [process.env.PROXY_ORIGIN] : []),
]);

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (same-origin, curl, server-to-server)
    if (!origin) return callback(null, true);
    if (INGEST_ALLOWED_ORIGINS.has(origin)) {
      return callback(null, true);
    }
    console.warn(`[ingest] CORS blocked origin: ${origin}`);
    return callback(new Error('CORS: origin not allowed'), false);
  },
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: config.allowedHeaders,
  credentials: true
};

app.use(cors(corsOptions));

// Handle OPTIONS preflight explicitly
app.options('*', cors(corsOptions));


// ══════════════════════════════════════════════════════════
// BODY PARSING
// ══════════════════════════════════════════════════════════

// Parse standard application/json bodies
app.use(express.json({ limit: config.bodyLimit }));

// Parse text/plain bodies (sendBeacon often sends JSON as text/plain)
app.use(express.text({ limit: config.bodyLimit, type: 'text/plain' }));

// Auto-convert text/plain JSON strings into parsed objects
// This handles navigator.sendBeacon which may strip Content-Type
app.use((req, res, next) => {
  if (typeof req.body === 'string' && req.body.length > 0) {
    try {
      req.body = JSON.parse(req.body);
    } catch (e) {
      // Not valid JSON — leave as-is
    }
  }
  next();
});

// ══════════════════════════════════════════════════════════
// GUARD LAYER (PHASE 3)
// ══════════════════════════════════════════════════════════

app.use(async (req, res, next) => {
  // If we don't have Redis active, skip to allow processing or let internal errors handle it
  if (redis.status !== 'ready') return next();

  // Route whitelist (if any). Health should always be reachable.
  if (req.path === '/sideris/health' || req.path === '/sideris/agent.js') {
     return next();
  }

  // 1. Safe extraction of Session ID
  let sessionId = req.headers['x-sideris-session'];
  
  // Fallback to extraction from body contents
  if (!sessionId && req.body) {
    if (Array.isArray(req.body) && req.body.length > 0) {
       sessionId = req.body[0].sessionId || req.body[0].session_id;
    } else if (req.body.events && req.body.events.length > 0) {
       sessionId = req.body.events[0].sessionId || req.body.events[0].session_id;
    } else {
       sessionId = req.body.session_id; // For generic payloads
    }
  }

  if (!sessionId || typeof sessionId !== 'string') {
    return next(); // Pass through unidentified traffic. Worker handles generation later.
  }

  // 2. Fetch Guard Directives (Optimized HGET)
  const action = await redis.hget(`sideris:guard:${sessionId}`, 'action');

  // 3. Enforce Matrix
  if (action === 'block') {
     return res.status(403).json({ ok: false, error: 'blocked', code: 'E_GUARD_BLOCK' });
  }
  
  if (action === 'challenge') {
     return res.status(429).json({ ok: false, error: 'captcha_required', code: 'E_GUARD_CHALLENGE' });
  }

  if (action === 'rate_limit') {
     await new Promise(resolve => setTimeout(resolve, 500));
     return next();
  }

  next();
});

// ══════════════════════════════════════════════════════════
// ENDPOINTS
// ══════════════════════════════════════════════════════════

// ── POST /sideris/ingest — receive beacon batches ────────
app.post('/sideris/ingest', async (req, res) => {
  if (redis.status !== 'ready') {
    return res.status(503).json({ ok: false, error: 'Service Unavailable - Redis not connected' });
  }

  // Accept both array directly and { events: [...] } wrapper
  let events = req.body;
  if (!Array.isArray(events)) {
    events = req.body?.events;
  }

  if (!Array.isArray(events) || events.length === 0) {
    return res.status(400).json({ ok: false, error: 'No events array in body' });
  }

  // Extract client IP correctly using the first value from X-Forwarded-For (if present)
  const forwarded = req.headers['x-forwarded-for'];
  const clientIp = forwarded
    ? forwarded.split(',')[0].trim()
    : req.socket.remoteAddress || 'unknown';

  const pipeline = redis.pipeline();
  let validEventCount = 0;

  for (const event of events) {
    const enrichedEvent = {
       session_id: event.sessionId || event.session_id || "unknown",
       timestamp: event.ts || event.clientTs || Date.now(),
       source: "agent",
       event_type: event.type || "unknown",
       data: event.data || {},
       ingest_ip: clientIp,
       ingest_time: Date.now()
    };

    const jsonStr = JSON.stringify(enrichedEvent);
    
    const size = Buffer.byteLength(jsonStr, 'utf8');
    if (size > 64 * 1024) {
       console.warn(`[ingest] Skipped oversized event (${size} bytes)`);
       continue;
    }

    // Write payload + top-level fields so stream is queryable without JSON parsing
    pipeline.xadd(
      'sideris:events', 'MAXLEN', '~', 100000, '*',
      'payload',    jsonStr,
      'source',     enrichedEvent.source,
      'session_id', enrichedEvent.session_id,
      'event_type', enrichedEvent.event_type
    );
    validEventCount++;
  }

  if (validEventCount === 0) {
     return res.json({ ok: true, received: events.length, processed: 0 });
  }

  try {
     await pipeline.exec();
     return res.json({ ok: true, received: events.length, processed: validEventCount });
  } catch (err) {
     console.error('[ingest] Pipeline exec error:', err.message);
     return res.status(500).json({ ok: false, error: 'Internal Server Error' });
  }
});


// ── POST /api/events — receive backend access logs from proxy ─
app.post('/api/events', async (req, res) => {
  if (redis.status !== 'ready') {
    return res.status(503).json({ ok: false, error: 'Service Unavailable - Redis not connected' });
  }

  const event = req.body;

  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return res.status(400).json({ ok: false, error: 'Expected a single event object' });
  }

  const enrichedEvent = {
    session_id:  event.sessionId || 'unknown',
    timestamp:   event.timestamp  || Date.now(),
    source:      'backend',
    event_type:  event.type       || 'backend_log',
    inline_blocked: event.inline_blocked || false,
    data: {
      method:    event.method,
      endpoint:  event.endpoint,
      status:    event.status,
      userAgent: event.userAgent,
      duration:  event.duration,
      ip:        event.ip,
      body:      event.body  || null,   // POST body (for injection detection)
      query:     event.query || null,   // URL query params
    },
    ingest_ip:   req.socket.remoteAddress || 'unknown',
    ingest_time: Date.now()
  };

  const jsonStr = JSON.stringify(enrichedEvent);

  try {
    // Write payload + top-level fields so stream is queryable without JSON parsing
    await redis.xadd(
      'sideris:events', 'MAXLEN', '~', 100000, '*',
      'payload',    jsonStr,
      'source',     enrichedEvent.source,
      'session_id', enrichedEvent.session_id,
      'event_type', enrichedEvent.event_type
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error('[ingest] /api/events error:', err.message);
    return res.status(500).json({ ok: false, error: 'Internal Server Error' });
  }
});


// ── GET /sideris/agent.js — serve agent script ──────────
const agentPath = path.resolve(__dirname, '../agent/agent.js');

app.get('/sideris/agent.js', (req, res) => {
  if (!fs.existsSync(agentPath)) {
    return res.status(404).json({ error: 'agent.js not found at ' + agentPath });
  }
  res.set('Content-Type', 'text/javascript');
  res.set('Cache-Control', 'no-cache');
  res.sendFile(agentPath);
});

// ── GET /sideris/health — health check ──────────────────
app.get('/sideris/health', (req, res) => {
  res.json({
    status: redis.status === 'ready' ? 'ok' : 'degraded',
    redis: redis.status,
    ts: Date.now()
  });
});

// ── POST /sideris/challenge/verify — recovery route ─────
// Simulates a captcha or challenge successful verification
app.post('/sideris/challenge/verify', async (req, res) => {
  const { session_id, token } = req.body;
  if (!session_id || !token) {
    return res.status(400).json({ error: 'Missing parameters' });
  }

  // Example: In a real system, you verify `token` against Google reCAPTCHA
  const guardKey = `sideris:guard:${session_id}`;
  
  const currentAction = await redis.hget(guardKey, 'action');
  
  if (currentAction === 'block') {
    // Blocks generally aren't removable by simple CAPTCHAs
    return res.status(403).json({ error: 'Session permanently denied.' });
  }

  // Demote to rate_limit or delete
  await redis.del(guardKey);
  console.log(`[ingest] Guard challenge passed for session: ${session_id}`);

  res.json({ ok: true, message: 'Challenge verified. Restrictions lifted.' });
});

// ══════════════════════════════════════════════════════════
// STARTUP
// ══════════════════════════════════════════════════════════

// Ensure logs directory exists
fs.mkdirSync(config.logsDir, { recursive: true });

app.listen(PORT, () => {
  console.log(`Sideris Ingest running on http://localhost:${PORT}`);
  console.log(`Serving agent.js from ${agentPath}`);
  console.log(`Redis config: ${config.redisUrl}`);
});
