// scripts/live-test.js
// Sends real events to the live ingest server and shows what the scoring pipeline logs.
// Run this while `npm run start-all` is open in another terminal.
// The [SCORE] and [ALERT] lines will appear in the start-all terminal in real-time.
'use strict';
const http = require('http');

const INGEST   = 'http://localhost:5000';
const DASH     = 'http://localhost:6001';

// ── HTTP helper ──────────────────────────────────────────
function post(url, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const opts = Object.assign(require('url').parse(url), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    });
    const req = http.request(opts, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve(raw); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function get(url) {
  return new Promise((resolve, reject) => {
    http.get(url, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve(raw); } });
    }).on('error', reject);
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Send events for a session ──────────────────────────
async function sendEvents(sessionId, events) {
  for (const ev of events) {
    await post(`${INGEST}/api/events`, {
      source:     ev.source || 'backend',
      session_id: sessionId,
      events:     [{ event_type: ev.type, data: ev.data }],
    });
    await sleep(150);
  }
}

// ── Get session from dashboard ─────────────────────────
async function getSession(sessionId) {
  try {
    const all = await get(`${DASH}/sessions`);
    return all.find(s => s.session_id === sessionId) || null;
  } catch { return null; }
}

// ── Test runner ────────────────────────────────────────
async function run() {
  const sep = '═'.repeat(62);
  const now = Date.now();

  // ── PHASE 1: Normal browsing ─────────────────────────
  const sid1 = `test-normal-${now}`;
  console.log(`\n${sep}`);
  console.log('  PHASE 1 — NORMAL BROWSING  (should stay at 0 pts)');
  console.log(`${sep}`);
  console.log(`  Session: ${sid1}\n`);
  console.log('  Sending events to ingest server...');

  await sendEvents(sid1, [
    { type: 'backend_log', data: { method:'GET',  endpoint:'/',                                    status:'200', userAgent:'Mozilla/5.0' } },
    { type: 'backend_log', data: { method:'GET',  endpoint:'/api/Products',                        status:'200', userAgent:'Mozilla/5.0' } },
    { type: 'backend_log', data: { method:'GET',  endpoint:'/api/Products/1',                      status:'200', userAgent:'Mozilla/5.0' } },
    { type: 'backend_log', data: { method:'POST', endpoint:'/api/BasketItems',                     status:'200', userAgent:'Mozilla/5.0' } },
    { type: 'backend_log', data: { method:'GET',  endpoint:'/api/Challenges/?name=Score%20Board',  status:'304', userAgent:'Mozilla/5.0' } },
    { type: 'backend_log', data: { method:'GET',  endpoint:'/rest/admin/application-configuration',status:'304', userAgent:'Mozilla/5.0' } },
    { type: 'backend_log', data: { method:'GET',  endpoint:'/rest/admin/application-version',      status:'304', userAgent:'Mozilla/5.0' } },
    { type: 'backend_log', data: { method:'GET',  endpoint:'/rest/languages',                      status:'200', userAgent:'Mozilla/5.0' } },
    { type: 'backend_log', data: { method:'GET',  endpoint:'/rest/user/whoami?fields=email',       status:'200', userAgent:'Mozilla/5.0' } },
    { source:'agent', type: 'page_view',         data: { url:'/' } },
    { source:'agent', type: 'session_start',     data: {} },
    { source:'agent', type: 'liveness_snapshot', data: {} },
    { source:'agent', type: 'no_plugins',        data: {} },
    { source:'agent', type: 'fast_mouse',        data: {} },
    { source:'agent', type: 'rapid_requests',    data: {} },
  ]);

  await sleep(1500);
  const s1 = await getSession(sid1);
  const score1 = s1 ? parseFloat(s1.session_score || 0) : '???';
  const verdict1 = s1 ? (s1.verdict || s1.level || 'unknown') : '???';
  console.log(`\n  ✅ Result: session_score=${score1}  verdict=${verdict1}`);
  console.log(score1 === 0 ? '  🟢 CORRECT — normal browsing scored 0' : '  🔴 WRONG — should be 0');

  // ── PHASE 2: Attack simulation ───────────────────────
  const sid2 = `test-attack-${now}`;
  console.log(`\n${sep}`);
  console.log('  PHASE 2 — ATTACK SIMULATION  (should score HIGH)');
  console.log(`${sep}`);
  console.log(`  Session: ${sid2}\n`);
  console.log('  Sending attack events to ingest server...');

  await sendEvents(sid2, [
    // SQL Injection
    { type: 'backend_log', data: { method:'GET',  endpoint:"/rest/products/search?q=' OR 1=1--", status:'200', userAgent:'Mozilla/5.0' } },
    // XSS
    { type: 'backend_log', data: { method:'GET',  endpoint:'/search?q=<script>alert(1)</script>', status:'200', userAgent:'Mozilla/5.0' } },
    // Scanner tool UA
    { type: 'backend_log', data: { method:'GET',  endpoint:'/login',                             status:'200', userAgent:'sqlmap/1.7.8#stable' } },
    // Sensitive file access
    { type: 'backend_log', data: { method:'GET',  endpoint:'/.env',                              status:'404', userAgent:'Mozilla/5.0' } },
    { type: 'backend_log', data: { method:'GET',  endpoint:'/.git/config',                       status:'404', userAgent:'Mozilla/5.0' } },
    // Path traversal
    { type: 'backend_log', data: { method:'GET',  endpoint:'/../../etc/passwd',                  status:'400', userAgent:'Mozilla/5.0' } },
    // CMS probe
    { type: 'backend_log', data: { method:'GET',  endpoint:'/wp-admin/',                         status:'404', userAgent:'Mozilla/5.0' } },
    // SSRF
    { type: 'backend_log', data: { method:'GET',  endpoint:'/fetch?url=http://192.168.1.1/admin',status:'200', userAgent:'Mozilla/5.0' } },
    // Command injection
    { type: 'backend_log', data: { method:'GET',  endpoint:'/ping?host=127.0.0.1;id',            status:'200', userAgent:'Mozilla/5.0' } },
    // Agent: headless browser
    { source:'agent', type: 'headless_browser', data: {} },
  ]);

  await sleep(2000);
  const s2 = await getSession(sid2);
  const score2 = s2 ? parseFloat(s2.session_score || 0) : '???';
  const verdict2 = s2 ? (s2.verdict || s2.level || 'unknown') : '???';
  const bonus2  = s2 && s2.bonus_applied ? s2.bonus_applied : [];
  console.log(`\n  🔴 Result: session_score=${score2}  verdict=${verdict2}`);
  if (bonus2.length) console.log(`  🔔 Bonuses applied: ${bonus2.join(', ')}`);
  console.log(score2 >= 30 ? '  🔴 CORRECT — attack scored high' : '  ⚠  Lower than expected');

  console.log(`\n${sep}`);
  console.log('  Check your start-all terminal for the live [SCORE] and [ALERT] lines!');
  console.log(sep);
}

run().catch(console.error);
