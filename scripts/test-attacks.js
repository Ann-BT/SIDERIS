// scripts/test-attacks.js
// SIDERIS Comprehensive Attack & Defense Test Suite (Rewritten)
//
// Tests all defense layers, actions, and behavioral bonuses:
//   Layer 1 — Inline proxy blocking (instant, pre-pipeline)
//   Layer 2 — Behavioral scoring actions (Allow, Rate Limit, Challenge, Soft Block, Hard Block)
//   Layer 3 — Behavioral Correlation Bonuses (Credential Stuffing, IP Switch, Endpoint Hammer, 404 Storm)
//
// Generates randomized session names and client IP addresses for each test.
'use strict';

const http  = require('http');
const https = require('https');

const PROXY_URL   = 'http://localhost:4000';  // WAF Proxy (for inline scanning)
const INGEST_URL  = 'http://localhost:5000';  // Ingest Server (for event simulation)
const DASH_URL    = 'http://localhost:6001';  // Dashboard API (for assertions)

const PASS = '✅';
const FAIL = '❌';

let totalPass = 0;
let totalFail = 0;

// Random Adjectives and Nouns for realistic session names
const ADJECTIVES = ['cyber', 'shadow', 'silent', 'phantom', 'omega', 'delta', 'alpha', 'stealth', 'rapid', 'rogue'];
const NOUNS = ['hacker', 'ninja', 'spider', 'scout', 'phantom', 'operative', 'runner', 'spectre', 'ghost', 'recon'];

function randomSessionId(prefix = 'sess') {
  const adj = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
  const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
  const randNum = Math.floor(Math.random() * 9000) + 1000;
  return `${prefix}_${adj}_${noun}_${randNum}`;
}

function randomIp() {
  return `192.168.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`;
}

// HTTP Request Helpers

function request(method, rawUrl, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(rawUrl);
    const lib = u.protocol === 'https:' ? https : http;
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: u.hostname,
      port:     u.port,
      path:     u.pathname + u.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        ...headers,
      },
    };
    const req = lib.request(opts, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = raw; }
        resolve({ status: res.statusCode, body: parsed, headers: res.headers });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

const get  = (url, opts) => request('GET',  url, opts);
const post = (url, body, opts) => request('POST', url, { body, ...opts });
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Assertion & Logging Helpers
function assert(label, condition, got = '') {
  if (condition) {
    console.log(`  ${PASS} ${label}`);
    totalPass++;
  } else {
    console.log(`  ${FAIL} ${label}  ← got: ${JSON.stringify(got)}`);
    totalFail++;
  }
}

function section(title) {
  const line = '═'.repeat(70);
  console.log(`\n${line}`);
  console.log(`  ${title}`);
  console.log(line);
}

// Polling Helper to fetch session state from Dashboard API
async function getSession(sid, maxAttempts = 15, interval = 200) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const r = await get(`${DASH_URL}/session-logs/${sid}`);
      if (r.status === 200 && r.body?.session && r.body.session.session_score !== undefined) {
        const s = r.body.session;
        const score = parseFloat(s.session_score || s.risk_score || 0);
        
        // Determine level from score (same mapping as Dashboard UI)
        let level = 'normal';
        if (score >= 50) level = 'critical';
        else if (score >= 30) level = 'very_high';
        else if (score >= 20) level = 'high';
        else if (score >= 10) level = 'suspicious';

        return {
          session_id:    sid,
          session_score: score,
          level,
          guard_action:  r.body.guard?.action || null,
          block_type:    r.body.guard?.block_type || null,
          bonus_applied: s.bonus_applied || JSON.parse(s.bonus_applied || '[]'),
        };
      }
    } catch (e) {
      // Ignore network errors during polling
    }
    await sleep(interval);
  }
  return null;
}

// Helper to send backend event directly to Ingest (bypassing WAF proxy scanner)
async function sendEventToIngest(sid, ip, details) {
  return post(`${INGEST_URL}/api/events`, {
    sessionId: sid,
    timestamp: Date.now(),
    type: 'backend_log',
    ip,
    userAgent: 'Mozilla/5.0 (Test Client)',
    ...details
  });
}

// TEST SUITES

// --- Test 1: Benign Browsing (Action: Allow) ---
async function testAllow() {
  section('CASE 1: NORMAL USER BROWSING (Expect: Allow / 0 Score)');
  const sid = randomSessionId();
  const ip = randomIp();
  console.log(`  [Session]: ${sid}  [IP]: ${ip}`);

  await sendEventToIngest(sid, ip, { method: 'GET', endpoint: '/', status: 200 });
  await sendEventToIngest(sid, ip, { method: 'GET', endpoint: '/api/Products', status: 200 });
  await sendEventToIngest(sid, ip, { method: 'GET', endpoint: '/assets/index.js', status: 200 });

  const session = await getSession(sid);
  assert('Session score is 0', session?.session_score === 0, session?.session_score);
  assert('Session level is "normal"', session?.level === 'normal', session?.level);
  assert('No guard action applied', session?.guard_action === null, session?.guard_action);
}

// --- Test 2: Inline Proxy Blocking (Layer 1 - Hard Block) ---
async function testInlineBlocking() {
  section('CASE 2: INLINE PROXY SCANNER BLOCK (Expect: Instant 403 / Hard Block)');
  const sid = randomSessionId();
  const ip = randomIp();
  console.log(`  [Session]: ${sid}  [IP]: ${ip}`);

  // Send SQL injection payload via WAF Proxy (Port 4000)
  const url = `${PROXY_URL}/rest/user/login`;
  try {
    const r = await post(url, { email: "' OR 1=1--", password: 'x' }, { headers: { 'X-Sideris-Session': sid } });
    
    assert('Proxy returned HTTP 403 instantly', r.status === 403, r.status);
    assert('Response body is E_ATTACK_DETECTED', r.body?.code === 'E_ATTACK_DETECTED', r.body);

    // Verify guard state in Dashboard
    const session = await getSession(sid);
    assert('Session has peak score of at least 50', session?.session_score >= 50, session?.session_score);
    assert('Guard has set action: "block"', session?.guard_action === 'block', session?.guard_action);
    assert('Guard has block_type: "hard"', session?.block_type === 'hard', session?.block_type);
  } catch (e) {
    assert('Inline proxy request failed', false, e.message);
  }
}

// --- Test 3: Behavioral Rate Limiting (Action: Rate Limit) ---
async function testRateLimit() {
  section('CASE 3: BEHAVIORAL RATE LIMIT (Expect: 500ms Delayed Ingestion)');
  const sid = randomSessionId();
  const ip = randomIp();
  console.log(`  [Session]: ${sid}  [IP]: ${ip}`);

  // Send 3 scanning hits using a crawler user agent to CMS admin path
  // scanner_tool: impact=3, confidence=1.3 => 3.9 score each.
  // 3 hits will cross 10 points threshold for Rate Limiting.
  for (let i = 0; i < 3; i++) {
    await sendEventToIngest(sid, ip, {
      method: 'GET',
      endpoint: '/wp-admin/login.php',
      userAgent: 'Nikto/2.1.6',
      status: 404
    });
  }

  const session = await getSession(sid);
  console.log(`  Score: ${session?.session_score}  Level: ${session?.level}`);
  assert('Session score is between 10 and 20', session?.session_score >= 10 && session?.session_score < 20, session?.session_score);
  assert('Guard action set to "rate_limit"', session?.guard_action === 'rate_limit', session?.guard_action);

  // Measure latency to verify 500ms delay on subsequent requests
  const start = Date.now();
  await post(`${INGEST_URL}/sideris/ingest`,
    [{ sessionId: sid, ts: Date.now(), type: 'page_view', data: {} }],
    { headers: { 'X-Sideris-Session': sid } }
  );
  const latency = Date.now() - start;
  console.log(`  Subsequent request latency: ${latency}ms`);
  assert('Latency is delayed by at least 500ms', latency >= 500, latency);
}

// --- Test 4: Behavioral Challenge (Action: Challenge/CAPTCHA) ---
async function testChallenge() {
  section('CASE 4: BEHAVIORAL CHALLENGE (Expect: CAPTCHA Overlay / 429 status)');
  const sid = randomSessionId();
  const ip = randomIp();
  console.log(`  [Session]: ${sid}  [IP]: ${ip}`);

  // Send 5 file_exposure events directly to Ingest to bypass inline proxy blocking
  // 5 events will cross the 20-point challenge threshold (~22.4 score)
  for (let i = 0; i < 5; i++) {
    await sendEventToIngest(sid, ip, {
      method: 'GET',
      endpoint: `/api/feedback/.env?i=${i}`
    });
    await sleep(50);
  }

  const session = await getSession(sid);
  console.log(`  Score: ${session?.session_score}  Level: ${session?.level}`);
  assert('Session score is between 20 and 30', session?.session_score >= 20 && session?.session_score < 30, session?.session_score);
  assert('Guard action set to "challenge"', session?.guard_action === 'challenge', session?.guard_action);

  // Subsequent API requests to Ingest should return 429 CAPTCHA required
  const r = await post(`${INGEST_URL}/sideris/ingest`,
    [{ sessionId: sid, ts: Date.now(), type: 'page_view', data: {} }],
    { headers: { 'X-Sideris-Session': sid } }
  );
  assert('Ingest endpoint returns 429 for challenged session', r.status === 429, r.status);
  assert('Ingest response contains E_GUARD_CHALLENGE code', r.body?.code === 'E_GUARD_CHALLENGE', r.body);
}

// --- Test 5: Behavioral Soft Block (Action: Soft Block) ---
// Demonstrates CAPTCHA verification verification, challenge clearance,
// and subsequent automatic escalation to a soft block on additional attacks.
async function testSoftBlock() {
  section('CASE 5: BEHAVIORAL SOFT BLOCK (Expect: Challenge solved -> new attack -> Soft Block)');
  const sid = randomSessionId();
  const ip = randomIp();
  console.log(`  [Session]: ${sid}  [IP]: ${ip}`);

  // 1. Build score up to challenge threshold (~28.8 score)
  for (let i = 0; i < 6; i++) {
    await sendEventToIngest(sid, ip, {
      method: 'GET',
      endpoint: `/api/feedback/.env?i=${i}`
    });
    await sleep(50);
  }

  let session = await getSession(sid);
  assert('Session has active challenge guard', session?.guard_action === 'challenge', session?.guard_action);

  // Give the async Redis Pub/Sub alerts pipeline in guard.js a moment to settle
  // before we delete the guard key.
  await sleep(500);

  // 2. Solve the CAPTCHA via WAF Proxy validation endpoint to bypass Ingest guard middleware restriction
  console.log('  Solving CAPTCHA challenge via proxy /sideris/captcha-verify...');
  const verifyRes = await post(`${PROXY_URL}/sideris/captcha-verify`, {
    session_id: sid
  });
  assert('CAPTCHA verification response is successful', verifyRes.status === 200 && verifyRes.body?.ok === true, verifyRes.body);

  // 3. Send 1 more attack event.
  // The score will cross 30 (soft block threshold, ~35.2 score).
  // Since the active challenge guard was solved/deleted, the block is applied immediately.
  for (let i = 6; i < 7; i++) {
    await sendEventToIngest(sid, ip, {
      method: 'GET',
      endpoint: `/api/feedback/.env?i=${i}`
    });
    await sleep(50);
  }

  session = await getSession(sid);
  console.log(`  Score: ${session?.session_score}  Level: ${session?.level}  Guard: ${session?.guard_action}`);
  assert('Session score is between 30 and 50', session?.session_score >= 30 && session?.session_score < 50, session?.session_score);
  assert('Guard action set to "block"', session?.guard_action === 'block', session?.guard_action);
  assert('Block type is "soft"', session?.block_type === 'soft', session?.block_type);

  // 4. Subsequent API requests should return 403 blocked
  const r = await post(`${INGEST_URL}/sideris/ingest`,
    [{ sessionId: sid, ts: Date.now(), type: 'page_view', data: {} }],
    { headers: { 'X-Sideris-Session': sid } }
  );
  assert('Ingest returns 403 for blocked session', r.status === 403, r.status);
  assert('Ingest response contains E_GUARD_BLOCK code', r.body?.code === 'E_GUARD_BLOCK', r.body);
}

// --- Test 6: Behavioral Hard Block (Action: Hard Block) ---
async function testHardBlock() {
  section('CASE 6: BEHAVIORAL HARD BLOCK (Expect: Permanent Block / 403 status)');
  const sid = randomSessionId();
  const ip = randomIp();
  console.log(`  [Session]: ${sid}  [IP]: ${ip}`);

  // Send 8 SQLi events directly to Ingest to cross 50 points
  // Since score is >= 50, it bypasses the CAPTCHA grace period and blocks immediately.
  for (let i = 0; i < 8; i++) {
    await sendEventToIngest(sid, ip, {
      method: 'POST',
      endpoint: '/api/feedback',
      body: { query: `UNION SELECT ${i},2,3--` }
    });
    await sleep(50);
  }

  const session = await getSession(sid);
  console.log(`  Score: ${session?.session_score}  Level: ${session?.level}`);
  assert('Session score is >= 50', session?.session_score >= 50, session?.session_score);
  assert('Guard action set to "block"', session?.guard_action === 'block', session?.guard_action);
  assert('Block type is "hard"', session?.block_type === 'hard', session?.block_type);
}

// --- Test 7: Credential Stuffing & Brute Force (Behavioral Bonus) ---
async function testCredentialStuffing() {
  section('CASE 7: CREDENTIAL STUFFING / BRUTE FORCE DETECTION');
  const sid = randomSessionId('brute');
  const ip = randomIp();
  console.log(`  [Session]: ${sid}  [IP]: ${ip}`);

  // Send 20 failed login attempts on auth endpoints targeting different users
  for (let i = 0; i < 20; i++) {
    await sendEventToIngest(sid, ip, {
      method: 'POST',
      endpoint: '/rest/user/login',
      status: 401,
      body: { email: `attacker_${i}@victim.com`, password: 'bad_password' }
    });
    await sleep(30);
  }

  const session = await getSession(sid);
  console.log(`  Score: ${session?.session_score}  Applied Bonuses: ${JSON.stringify(session?.bonus_applied)}`);
  assert('Applied "brute_force" behavioral bonus (+10 pts)', session?.bonus_applied.includes('brute_force'), session?.bonus_applied);
  assert('Applied "password_spray" or "credential_stuffing" behavioral bonus (+12/15 pts)', 
    session?.bonus_applied.includes('credential_stuffing') || session?.bonus_applied.includes('password_spray'), 
    session?.bonus_applied
  );
}

// --- Test 8: Session IP Switch (Behavioral Bonus) ---
async function testIpSwitch() {
  section('CASE 8: SESSION IP SWITCH CORRELATION');
  const sid = randomSessionId('ipchange');
  const ip1 = randomIp();
  const ip2 = randomIp();
  const ip3 = randomIp();
  console.log(`  [Session]: ${sid}  [IPs]: ${ip1} → ${ip2} → ${ip3}`);

  // Send event from IP 1
  await sendEventToIngest(sid, ip1, { method: 'GET', endpoint: '/products', status: 200 });
  await sleep(100);
  // Send event from IP 2
  await sendEventToIngest(sid, ip2, { method: 'GET', endpoint: '/basket', status: 200 });
  await sleep(100);
  // Send event from IP 3
  await sendEventToIngest(sid, ip3, { method: 'GET', endpoint: '/checkout', status: 200 });

  const session = await getSession(sid);
  console.log(`  Applied Bonuses: ${JSON.stringify(session?.bonus_applied)}`);
  assert('Applied "session_ip_switch" behavioral bonus (+8 pts)', session?.bonus_applied.includes('session_ip_switch'), session?.bonus_applied);
}

// --- Test 9: DoS Endpoint Hammering (Behavioral Bonus) ---
async function testEndpointHammer() {
  section('CASE 9: DOS ENDPOINT HAMMERING DETECTION');
  const sid = randomSessionId('dos');
  const ip = randomIp();
  console.log(`  [Session]: ${sid}  [IP]: ${ip}`);

  // Send 22 requests to the same endpoint in rapid succession
  // Endpoint hits must be non-normal events to count. We will trigger 404s.
  for (let i = 0; i < 22; i++) {
    await sendEventToIngest(sid, ip, {
      method: 'GET',
      endpoint: '/api/nonexistent-target-route',
      status: 404
    });
    await sleep(20);
  }

  const session = await getSession(sid);
  console.log(`  Applied Bonuses: ${JSON.stringify(session?.bonus_applied)}`);
  assert('Applied "endpoint_hammer" behavioral bonus (+10 pts)', session?.bonus_applied.includes('endpoint_hammer'), session?.bonus_applied);
}

// --- Test 10: 404 Directory Fuzzing Storm (Behavioral Bonus) ---
async function test404Storm() {
  section('CASE 10: 404 DIRECTORY FUZZING STORM');
  const sid = randomSessionId('fuzz');
  const ip = randomIp();
  console.log(`  [Session]: ${sid}  [IP]: ${ip}`);

  // Send 16 requests targeting distinct non-existent pages (resulting in 404s)
  for (let i = 0; i < 16; i++) {
    await sendEventToIngest(sid, ip, {
      method: 'GET',
      endpoint: `/api/route-number-${i}`,
      status: 404
    });
    await sleep(30);
  }

  const session = await getSession(sid);
  console.log(`  Applied Bonuses: ${JSON.stringify(session?.bonus_applied)}`);
  assert('Applied "404_storm" behavioral bonus (+8 pts)', session?.bonus_applied.includes('404_storm'), session?.bonus_applied);
}

// MAIN RUNNER

async function main() {
  console.log('\n' + '█'.repeat(70));
  console.log('  SIDERIS — Advanced Attack & Defense Test Suite');
  console.log('  Running 10 test scenarios with randomized sessions and IPs.');
  console.log('█'.repeat(70));

  // Quick service connectivity checks
  console.log('\n  Checking service connectivity...');
  const checks = [
    { label: 'Ingest (5000)', url: `${INGEST_URL}/sideris/health` },
    { label: 'Dashboard (6001)', url: `${DASH_URL}/health` },
    { label: 'Proxy (4000)', url: `${PROXY_URL}/sideris/agent.js` },
  ];

  let allUp = true;
  for (const c of checks) {
    try {
      const r = await get(c.url);
      console.log(`  ${PASS} ${c.label} — Connected (HTTP ${r.status})`);
    } catch (e) {
      console.log(`  ${FAIL} ${c.label} — Offline (${e.message})`);
      allUp = false;
    }
  }

  if (!allUp) {
    console.log('\n  ⚠️  Sideris services are offline. Run `npm run start-all` first.');
    process.exit(1);
  }

  console.log('\n  Starting test suites...');
  await testAllow();
  await testInlineBlocking();
  await testRateLimit();
  await testChallenge();
  await testSoftBlock();
  await testHardBlock();
  await testCredentialStuffing();
  await testIpSwitch();
  await testEndpointHammer();
  await test404Storm();

  // Results summary
  const total = totalPass + totalFail;
  console.log('\n' + '═'.repeat(70));
  console.log(`  RESULTS: ${totalPass}/${total} passed`);
  if (totalFail === 0) {
    console.log('  🟢 ALL SCENARIOS PASSED — Project features working correctly.');
  } else {
    console.log(`  🔴 ${totalFail} test case(s) FAILED — review logs above.`);
  }
  console.log('═'.repeat(70) + '\n');

  process.exit(totalFail > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('[runner] Fatal error:', err.message);
  process.exit(1);
});
