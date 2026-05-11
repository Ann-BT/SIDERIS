// ──────────────────────────────────────────────────────────
// src/proxy/server.js
// Sideris 2.0 — Backend Access Log Proxy + Agent Injector
//
// Runs on PROXY_PORT (default 4000).
// Forwards ALL requests transparently to Juice Shop on
// TARGET_URL (default http://localhost:3000).
//
// Session resolution priority (per request):
//   1. Cookie: sideris_sid         (set by agent.js on page load)
//   2. Header: X-Sideris-Session   (set by agent's patched XHR/fetch)
//   3. Fallback: proxy-generated temp ID (prefix: prx-)
//
// This ensures EVERY request — including native browser
// navigation that bypasses XHR patching — carries a session ID
// and is correlated with the correct agent session.
// ──────────────────────────────────────────────────────────

'use strict';

const express      = require('express');
const cookieParser = require('cookie-parser');
const Redis        = require('ioredis');
const path         = require('path');
const fs           = require('fs');
const dotenv       = require('dotenv');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const PROXY_PORT = parseInt(process.env.PROXY_PORT  || '4000', 10);
const TARGET_URL = process.env.TARGET_URL            || 'http://localhost:3000';
const INGEST_URL = (process.env.INGEST_URL           || 'http://localhost:5000') + '/api/events';

// agent.js is served from our own source tree
const AGENT_PATH = path.resolve(__dirname, '../agent/agent.js');

// ── Snippet injected into every HTML <head> ───────────────
// Points the agent at the ingest server (port 5000, not the proxy).
const AGENT_SNIPPET = `
<script>
  window.SIDERIS_INGEST_URL = 'http://localhost:5000/sideris/ingest';
</script>
<script src="/sideris/agent.js" defer></script>`.trim();

// ── Lightweight unique ID for fallback sessions ────────────
function generateProxyId() {
  return 'prx-' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

// ── Session ID resolver ────────────────────────────────────
// Priority: cookie → header → generated temp ID
function resolveSessionId(req) {
  // 1. Cookie (set by agent.js on EVERY page — covers all navigation)
  if (req.cookies && req.cookies.sideris_sid) {
    return { id: req.cookies.sideris_sid, source: 'cookie' };
  }
  // 2. Header (set by agent's patched XHR / fetch)
  const header = req.headers['x-sideris-session'] || req.headers['x-session-id'];
  if (header) {
    return { id: header, source: 'header' };
  }
  // 3. Fallback — pre-agent requests (first HTML load before agent runs)
  return { id: generateProxyId(), source: 'generated' };
}

const app = express();

// Parse cookies before any middleware uses them
app.use(cookieParser());

// Capture request body for injection scanning WITHOUT consuming the stream.
// We buffer the raw body then re-attach it so http-proxy-middleware can forward it.
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks);
      // Store raw buffer for the proxy to re-send
      req.rawBody = rawBody;
      // Parse for our logging
      try {
        req.body = JSON.parse(rawBody.toString('utf8'));
      } catch {
        req.body = rawBody.toString('utf8');
      }
      next();
    });
  } else {
    next();
  }
});

// ══════════════════════════════════════════════════════════
// ROUTE: /sideris/agent.js — serve agent script directly
// Must be registered BEFORE the proxy middleware so it is
// handled locally and not forwarded to Juice Shop.
// ══════════════════════════════════════════════════════════

app.get('/sideris/agent.js', (req, res) => {
  if (!fs.existsSync(AGENT_PATH)) {
    return res.status(404).send('/* Sideris agent.js not found */');
  }
  res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(AGENT_PATH);
});

// ══════════════════════════════════════════════════════════
// GUARD ENFORCEMENT + INLINE ATTACK BLOCKING
// Phase 1: Check existing Redis guard (from previous blocks)
// Phase 2: Scan URL + body for critical attack patterns
// ══════════════════════════════════════════════════════════

const guardRedis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
guardRedis.on('error', err => console.error('[proxy] Guard Redis error:', err.message));

const BLOCK_PAGE = `<!DOCTYPE html>
<html><head><title>Access Denied — SIDERIS</title>
<style>
  body { background: #0a0a12; color: #e2e8f0; font-family: system-ui; display: flex;
         justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
  .box { text-align: center; max-width: 500px; padding: 3rem;
         border: 1px solid rgba(248,113,113,0.3); border-radius: 12px;
         background: rgba(20,20,35,0.9); }
  h1 { color: #f87171; font-size: 2rem; margin: 0 0 1rem; }
  p { color: #94a3b8; line-height: 1.6; }
  .code { font-family: monospace; color: #f59e0b; }
</style></head>
<body><div class="box">
  <h1>🛡️ Access Denied</h1>
  <p>Your session has been blocked by <strong>SIDERIS</strong> due to detected malicious activity.</p>
  <p class="code">ERR_GUARD_BLOCK</p>
  <p>If you believe this is an error, contact the security team.</p>
</div></body></html>`;

// ── Critical attack patterns for inline detection ─────────

const CRITICAL_PATTERNS = [
  { name: 'sql_injection', re: /(UNION[\s\/\*]+SELECT|'\s*OR\s*['"\d]|OR\s+1\s*=\s*1|--\s*$|DROP\s+TABLE|INSERT\s+INTO|EXEC\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\(|LOAD_FILE\s*\(|INTO\s+OUTFILE)/i },
  { name: 'xss',           re: /(<script[\s>]|javascript\s*:|on(error|load|click|mouseover)\s*=|<iframe[\s>]|<svg[^>]+onload|document\.cookie|eval\s*\()/i },
  { name: 'cmd_injection',  re: /([;&|`]|\$\()\s*(ls|id|cat|wget|curl|whoami|uname|bash|sh|python|nc|ping)\s/i },
  { name: 'ssti',           re: /\{\{[\s\S]{0,50}\}\}|\$\{[\s\S]{0,50}\}|<%=[\s\S]{0,50}%>/  },
  { name: 'xxe',            re: /<!DOCTYPE[^>]*\[|<!ENTITY\s/i },
  { name: 'ssrf',           re: /(https?:\/\/(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|0\.0\.0\.0)|file:\/\/|gopher:\/\/)/i },
  { name: 'path_traversal', re: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%2e%2e%5c)/i },
];

function scanPayload(url, body) {
  const bodyStr = typeof body === 'string' ? body
    : (body && typeof body === 'object') ? JSON.stringify(body)
    : '';
  const combined = url + ' ' + bodyStr;
  for (const pat of CRITICAL_PATTERNS) {
    if (pat.re.test(combined)) return pat.name;
  }
  return null;
}

app.use(async (req, res, next) => {
  // Skip guard check for sideris internal routes
  if (req.path.startsWith('/sideris/')) return next();

  const session = resolveSessionId(req);
  const sid = session.id;

  // ── Phase 1: Check existing guard ───────────────────────
  if (sid && !sid.startsWith('prx-')) {
    try {
      const action = await guardRedis.hget(`sideris:guard:${sid}`, 'action');
      if (action === 'block') {
        return res.status(403).json({ error: 'blocked', code: 'E_GUARD_BLOCK' });
      }
    } catch (err) {
      console.error('[proxy] Guard check error:', err.message);
    }
  }

  // ── Phase 2: Inline critical payload scan ───────────────
  // Detect injection attacks in real-time and block BEFORE
  // the request reaches Juice Shop. No async pipeline delay.
  const detected = scanPayload(req.originalUrl, req.body);
  if (detected) {
    const effectiveSid = sid || 'unknown';
    console.log(`[PROXY] ⚡ INSTANT BLOCK: ${detected} detected in ${req.method} ${req.originalUrl} (session=${effectiveSid})`);

    if (effectiveSid !== 'unknown') {
      try {
        // 1. Set hard_block guard
        await guardRedis.hset(`sideris:guard:${effectiveSid}`,
          'action',     'block',
          'block_type', 'hard',
          'risk_score', '100',
          'reason',     `Inline detection: ${detected}`,
          'updated_at', String(Date.now())
        );
        await guardRedis.incr('sideris:metrics:guard:block');

        // 2. Update session state so the dashboard shows the attack
        const sessionKey = `sideris:session:${effectiveSid}`;
        const categoryMap = {
          sql_injection: 'injection', xss: 'injection',
          cmd_injection: 'injection', ssti: 'injection',
          xxe: 'injection', ssrf: 'injection', path_traversal: 'fuzzing',
        };
        const cat = categoryMap[detected] || 'injection';

        // Read existing category_counts or create new
        const existing = await guardRedis.hget(sessionKey, 'category_counts');
        const catCounts = existing ? JSON.parse(existing) : {authentication:0,injection:0,fuzzing:0,bot:0,dos:0,session_abuse:0};
        catCounts[cat] = (catCounts[cat] || 0) + 1;

        const existingUrlCounts = await guardRedis.hget(sessionKey, 'url_counts');
        const urlCounts = existingUrlCounts ? JSON.parse(existingUrlCounts) : {};
        urlCounts[detected] = (urlCounts[detected] || 0) + 1;

        // Write session state for dashboard
        await guardRedis.hset(sessionKey,
          'session_id',      effectiveSid,
          'session_score',   '100',
          'event_count',     String(parseInt(await guardRedis.hget(sessionKey, 'event_count') || '0', 10) + 1),
          'ip_address',      req.ip || '::1',
          'user_agent',      req.headers['user-agent'] || 'unknown',
          'last_seen',       String(Date.now()),
          'verdict',         'critical',
          'category_counts', JSON.stringify(catCounts),
          'url_counts',      JSON.stringify(urlCounts),
          'bonus_applied',   JSON.stringify([`inline_${detected}`]),
          'login_attempts',  await guardRedis.hget(sessionKey, 'login_attempts') || '0',
          'failed_login_count', await guardRedis.hget(sessionKey, 'failed_login_count') || '0',
          'unique_usernames', await guardRedis.hget(sessionKey, 'unique_usernames') || '[]',
          'scanner_detected', await guardRedis.hget(sessionKey, 'scanner_detected') || '0',
          'scan_detected',   '1',
          'exploit_detected', '1',
          'count_404',       await guardRedis.hget(sessionKey, 'count_404') || '0',
        );
        await guardRedis.expire(sessionKey, 86400);

        // 3. Also fire the event to ingest so it shows in the timeline
        fetch(INGEST_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'backend_log', sessionId: effectiveSid,
            timestamp: Date.now(), ip: req.ip, method: req.method,
            endpoint: req.originalUrl, status: 403,
            userAgent: req.headers['user-agent'] || 'unknown',
            duration: 0,
            body: req.body, query: req.query,
          })
        }).catch(() => {});
      } catch (err) {
        console.error('[proxy] Inline block write error:', err.message);
      }
    }

    return res.status(403).json({ error: 'blocked', code: 'E_ATTACK_DETECTED', attack: detected });
  }

  next();
});

// ══════════════════════════════════════════════════════════
// LOGGING MIDDLEWARE
// Records start time and attaches res.on("finish") listener.
// All logging and event sending happens ONLY inside finish.
// ══════════════════════════════════════════════════════════

app.use((req, res, next) => {
  const start = Date.now();

  // Skip logging for internal sideris routes, socket.io polling, and static assets
  const isInternal = req.path.startsWith('/sideris/');
  const isSocketIo = req.path.includes('/socket.io');
  const isStatic   = req.path.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/i);

  if (!isInternal && !isSocketIo && !isStatic) {
    const session = resolveSessionId(req);

    res.on('finish', () => {
      // Safely extract body (may be string, object, or undefined)
      let bodyData = null;
      if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
        bodyData = req.body;
      } else if (typeof req.body === 'string' && req.body.length > 0) {
        try { bodyData = JSON.parse(req.body); } catch { bodyData = req.body; }
      }

      const event = {
        type:      'backend_log',
        sessionId: session.id,
        sessionSource: session.source,   // cookie | header | generated
        timestamp: Date.now(),
        ip:        req.ip,
        method:    req.method,
        endpoint:  req.originalUrl,
        status:    res.statusCode,
        userAgent: req.headers['user-agent'] || 'unknown',
        duration:  Date.now() - start,
        body:      bodyData,
        query:     Object.keys(req.query || {}).length > 0 ? req.query : null,
      };

      console.log(
        `[PROXY] ${event.method} ${event.endpoint} → ${event.status}` +
        ` (session=${event.sessionId} via ${session.source})`
      );

      // Fire-and-forget — do NOT await, do NOT block response
      fetch(INGEST_URL, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(event)
      }).catch(() => {});
    });
  }

  next();
});

// ══════════════════════════════════════════════════════════
// PROXY — created ONCE at top-level.
// Uses responseInterceptor to inject the agent snippet into
// HTML responses. All other responses are passed through
// unchanged (binary-safe buffer return).
// ══════════════════════════════════════════════════════════

const proxy = createProxyMiddleware({
  target:      TARGET_URL,
  changeOrigin: true,
  logLevel:    'silent',

  // selfHandleResponse is required when using responseInterceptor
  selfHandleResponse: true,

  on: {
    // Re-write the body we consumed in our raw-body middleware
    proxyReq: (proxyReq, req) => {
      if (req.rawBody && req.rawBody.length > 0) {
        proxyReq.setHeader('Content-Length', req.rawBody.length);
        proxyReq.write(req.rawBody);
        proxyReq.end();
      }
    },
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes) => {
      const contentType = proxyRes.headers['content-type'] || '';

      // Only modify text/html responses
      if (!contentType.includes('text/html')) {
        return responseBuffer; // pass binary/JSON/etc. unchanged
      }

      const html = responseBuffer.toString('utf8');

      // Inject agent snippet right before </head>.
      // Falls back to prepending if </head> is not found (edge case).
      if (html.includes('</head>')) {
        return html.replace('</head>', `${AGENT_SNIPPET}\n</head>`);
      }
      return AGENT_SNIPPET + '\n' + html;
    })
  }
});

app.use('/', proxy);

// ══════════════════════════════════════════════════════════
// STARTUP
// ══════════════════════════════════════════════════════════

app.listen(PROXY_PORT, () => {
  console.log(`[proxy] Sideris Proxy running on    http://localhost:${PROXY_PORT}`);
  console.log(`[proxy] Forwarding traffic to       ${TARGET_URL}`);
  console.log(`[proxy] Agent injected into HTML    /sideris/agent.js`);
  console.log(`[proxy] Backend logs sent to        ${INGEST_URL}`);
  console.log(`[proxy] Session resolution order    cookie → header → generated`);
});
