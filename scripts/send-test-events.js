// scripts/send-test-events.js — sends events using the CORRECT ingest API format
'use strict';
const http = require('http');

// Backend log event → POST /api/events  (single flat event with sessionId camelCase)
function sendBackend(sessionId, method, endpoint, status, userAgent) {
  const body = JSON.stringify({
    sessionId, method, endpoint,
    status: String(status),
    userAgent: userAgent || 'Mozilla/5.0 (Sideris-Test)',
    timestamp: Date.now(), ip: '127.0.0.1', duration: 5
  });
  return post('http://localhost:5000/api/events', body);
}

// Agent event → POST /sideris/ingest  (array of {sessionId, type, data})
function sendAgent(sessionId, type, data) {
  const body = JSON.stringify([{ sessionId, type, data: data || {}, ts: Date.now() }]);
  return post('http://localhost:5000/sideris/ingest', body);
}

function post(url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(d) }); } catch { resolve({ status: res.statusCode, body: d }); } });
    });
    req.on('error', reject);
    req.write(body); req.end();
  });
}

function getSessions() {
  return new Promise((res, rej) => {
    http.get('http://localhost:6001/sessions', r => {
      let d = ''; r.on('data', c => d += c);
      r.on('end', () => { try { res(JSON.parse(d)); } catch { res([]); } });
    }).on('error', rej);
  });
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function run() {
  const ts = Date.now();
  const sidNormal = 'test-normal-' + ts;
  const sidAttack = 'test-attack-' + ts;

  // PHASE 1: Normal Browsing
  console.log('\n' + '═'.repeat(58));
  console.log('  PHASE 1 — NORMAL BROWSING  (expect score ≈ 0)');
  console.log('═'.repeat(58));
  console.log('  Session:', sidNormal, '\n');

  const normalReqs = [
    ['GET',  '/',                                    200],
    ['GET',  '/api/Products',                        200],
    ['GET',  '/api/Products/42',                     200],
    ['POST', '/api/BasketItems',                     200],
    ['GET',  '/rest/admin/application-configuration',304],
    ['GET',  '/rest/admin/application-version',      304],
    ['GET',  '/rest/languages',                      200],
    ['GET',  '/rest/user/whoami',                    200],
    ['GET',  '/api/Challenges',                      200],
    ['POST', '/api/Users/login',                     200],
  ];
  for (const [method, endpoint, status] of normalReqs) {
    const r = await sendBackend(sidNormal, method, endpoint, status);
    console.log(`  ${r.status===200?'✓':'✗'} backend_log  ${method} ${endpoint} → ${status}`);
    await sleep(80);
  }
  // Agent events
  for (const type of ['page_view','session_start','liveness_snapshot','no_plugins','fast_mouse','rapid_requests']) {
    const r = await sendAgent(sidNormal, type, {});
    console.log(`  ${r.status===200?'✓':'✗'} agent       ${type}`);
    await sleep(60);
  }

  await sleep(2000);
  const all1 = await getSessions();
  const s1 = all1.find(s => s.session_id === sidNormal);
  console.log('\n  ── Result ────────────────────────────────────────');
  if (s1) {
    const sc1 = parseFloat(s1.session_score || s1.risk_score || 0);
    console.log(`  session_score : ${sc1}`);
    console.log(`  verdict       : ${s1.verdict || '-'}`);
    console.log(`  level         : ${s1.level || '-'}`);
    console.log(sc1 === 0 ? '  ✅ CORRECT — normal browsing scored 0' : `  ⚠ Unexpected: ${sc1} pts`);
  } else {
    console.log('  (Session not in dashboard yet — see [SCORE] lines in start-all terminal)');
  }

  // PHASE 2: Attack Simulation
  console.log('\n' + '═'.repeat(58));
  console.log('  PHASE 2 — ATTACK SIMULATION  (expect HIGH score)');
  console.log('═'.repeat(58));
  console.log('  Session:', sidAttack, '\n');

  const attackReqs = [
    // SQLi
    ['GET',  "/rest/products/search?q=' OR 1=1--",  200, 'sqlmap/1.7.8'],
    ['GET',  "/rest/products/search?q=1 UNION SELECT 1,2,3--", 200, 'sqlmap/1.7.8'],
    // XSS
    ['GET',  '/search?q=<script>alert(document.cookie)</script>', 200, 'Mozilla/5.0'],
    // Scanner UA
    ['GET',  '/login', 200, 'Nikto/2.1.6'],
    // Sensitive files
    ['GET',  '/.env',        404, 'Mozilla/5.0'],
    ['GET',  '/.git/config', 404, 'Mozilla/5.0'],
    ['GET',  '/phpinfo.php', 404, 'Mozilla/5.0'],
    // CMS probe
    ['GET',  '/wp-admin/',   404, 'Mozilla/5.0'],
    ['GET',  '/phpmyadmin/', 404, 'Mozilla/5.0'],
    // SSRF
    ['GET',  '/fetch?url=http://192.168.1.1/admin',  200, 'Mozilla/5.0'],
    // CMDi
    ['GET',  '/ping?host=127.0.0.1;id',              200, 'Mozilla/5.0'],
    // Path traversal
    ['GET',  '/download?file=../../etc/passwd',       400, 'Mozilla/5.0'],
    // LFI wrapper
    ['GET',  '/page?include=php://filter/convert.base64-encode/resource=/etc/passwd', 200, 'Mozilla/5.0'],
  ];
  for (const [method, endpoint, status, ua] of attackReqs) {
    const r = await sendBackend(sidAttack, method, endpoint, status, ua);
    console.log(`  ${r.status===200?'✓':'✗'} backend_log  ${method} ${endpoint.substring(0,50)} → ${status}`);
    await sleep(100);
  }
  // Agent: headless browser detected
  const ra = await sendAgent(sidAttack, 'headless_browser', { webdriver: true });
  console.log(`  ${ra.status===200?'✓':'✗'} agent       headless_browser`);

  await sleep(2500);
  const all2 = await getSessions();
  const s2 = all2.find(s => s.session_id === sidAttack);
  console.log('\n  ── Result ────────────────────────────────────────');
  if (s2) {
    const sc2 = parseFloat(s2.session_score || s2.risk_score || 0);
    console.log(`  session_score : ${sc2}`);
    console.log(`  verdict       : ${s2.verdict || '-'}`);
    console.log(`  level         : ${s2.level || '-'}`);
    if (s2.bonus_applied && s2.bonus_applied.length) console.log(`  bonuses       : ${s2.bonus_applied.join(', ')}`);
    console.log(sc2 >= 30 ? `  🔴 CORRECT — attack scored ${sc2} pts` : `  ⚠ Lower than expected: ${sc2}`);
  } else {
    // Show top sessions
    console.log('  Session not in dashboard. Top sessions right now:');
    all2.sort((a,b)=>parseFloat(b.session_score||b.risk_score||0)-parseFloat(a.session_score||a.risk_score||0))
      .slice(0,5).forEach(s => {
        const sc = parseFloat(s.session_score||s.risk_score||0);
        console.log(`    ${(s.session_id||'?').substring(0,36)} | score=${sc.toFixed(1)} | ${s.level||'-'}`);
      });
  }

  console.log('\n' + '═'.repeat(58));
  console.log('  ✅ Done! Check your start-all terminal for all the');
  console.log('     [SCORE] and [ALERT] log lines generated above.');
  console.log('═'.repeat(58) + '\n');
}

run().catch(e => { console.error('Error:', e.message); });
