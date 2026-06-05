// scripts/test-scoring.js — Generic scoring test
'use strict';
const analyzer = require('../src/detector/eventAnalyzer');
const scoring  = require('../src/detector/scoringEngine');

function makeBackend(method, endpoint, status, extra = {}) {
  return { source: 'backend', event_type: 'backend_log',
    data: { method, endpoint, status: String(status), userAgent: extra.ua || 'Mozilla/5.0', ...extra } };
}
function makeAgent(type) { return { source: 'agent', event_type: type, data: {} }; }

function run(label, event, session = {}) {
  const a = analyzer.analyze(event);
  const r = scoring.compute(a, session);
  console.log(
    `  [${label.padEnd(40)}] ${r.attack_type.padEnd(22)} score=${String(r.event_score).padStart(5)}`
  );
  return r.event_score;
}

// NORMAL BROWSING (any app)
console.log('\n══════════════════════════════════════════════════════════');
console.log('  NORMAL BROWSING (any web app) — expect ALL 0 pts');
console.log('══════════════════════════════════════════════════════════\n');
let n = 0;
n += run('GET / home',                  makeBackend('GET',  '/',                       200));
n += run('GET /about',                  makeBackend('GET',  '/about',                  200));
n += run('GET /products',               makeBackend('GET',  '/products',               200));
n += run('GET /products/42',            makeBackend('GET',  '/products/42',            200));
n += run('POST /users/register',        makeBackend('POST', '/users/register',         200));
n += run('POST /users/login',           makeBackend('POST', '/users/login',            200));
n += run('GET /admin/dashboard',        makeBackend('GET',  '/admin/dashboard',        200));
n += run('GET /api/orders',             makeBackend('GET',  '/api/orders',             200));
n += run('POST /api/checkout',          makeBackend('POST', '/api/checkout',           200));
n += run('GET /uploads/photo.jpg',      makeBackend('GET',  '/uploads/photo.jpg',      200));
n += run('POST /upload (image)',        makeBackend('POST', '/upload?type=avatar',     200));
n += run('GET /rest/admin/app-config',  makeBackend('GET',  '/rest/admin/application-configuration', 304));
n += run('GET /rest/languages',         makeBackend('GET',  '/rest/languages',         200));
n += run('404 occasional typo',         makeBackend('GET',  '/typo-page',              404));
n += run('agent: page_view',            makeAgent('page_view'));
n += run('agent: session_start',        makeAgent('session_start'));
n += run('agent: no_plugins',           makeAgent('no_plugins'));
n += run('agent: fast_mouse',           makeAgent('fast_mouse'));
n += run('agent: rapid_requests',       makeAgent('rapid_requests'));
n += run('agent: liveness_snapshot',    makeAgent('liveness_snapshot'));
console.log(`\n  ▶ Total: ${n.toFixed(2)} pts — ${n === 0.5 ? '🟢 CORRECT' : '🔴 WRONG (should be 0.5)'}\n`);

// ATTACK SCENARIOS
console.log('══════════════════════════════════════════════════════════');
console.log('  ATTACK SCENARIOS — expect HIGH scores');
console.log('══════════════════════════════════════════════════════════\n');

console.log('--- Scenario 1: SQLi via search ---');
let s1 = 0;
s1 += run("SQLi in query string",  makeBackend('GET', "/search?q=' OR 1=1--",         200));
s1 += run("UNION SELECT payload",  makeBackend('GET', "/items?id=1 UNION SELECT 1,2", 200));
console.log(`  Total: ${s1.toFixed(2)} pts — ${s1 >= 15 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 2: XSS ---');
let s2 = 0;
s2 += run("XSS in param",          makeBackend('GET', '/search?q=<script>alert(1)</script>', 200));
s2 += run("XSS in body",           { source: 'backend', event_type: 'backend_log',
  data: { method: 'POST', endpoint: '/comments', status: '200',
          body: '<img src=x onerror=alert(1)>', userAgent: 'Mozilla/5.0' }});
console.log(`  Total: ${s2.toFixed(2)} pts — ${s2 >= 12 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 3: Scanner tool (sqlmap) ---');
let s3 = 0;
s3 += run("sqlmap User-Agent",     makeBackend('GET', '/login', 200, { ua: 'sqlmap/1.7.8' }));
s3 += run("sqlmap 2nd req",        makeBackend('GET', '/users?id=1', 200, { ua: 'sqlmap/1.7.8' }));
console.log(`  Total: ${s3.toFixed(2)} pts — ${s3 >= 10 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 4: Directory brute force (gobuster 404 storm) ---');
let s4 = 0;
const sess4 = { count_404: 14 }; // already 14, next one triggers storm
for (let i = 0; i < 5; i++) {
  s4 += run(`404 path fuzz #${i+1}`, makeBackend('GET', `/fuzz${i}`, 404), sess4);
  sess4.count_404++;
}
console.log(`  Total: ${s4.toFixed(2)} pts — ${s4 >= 3 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 5: Command injection ---');
let s5 = 0;
s5 += run("CMDi in URL param (?cmd=ls)",   makeBackend('GET', '/ping?host=127.0.0.1;id',    200));
s5 += run("CMDi param direct (cmd=ls)",    makeBackend('GET', '/run?cmd=ls%20-la',           200));
s5 += run("CMDi via body (command=whoami)",{ source:'backend', event_type:'backend_log',
  data:{ method:'POST', endpoint:'/exec', status:'200',
         body:'command=whoami', userAgent:'Mozilla/5.0' }});
console.log(`  Total: ${s5.toFixed(2)} pts — ${s5 >= 16 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 5b: LFI via PHP wrapper ---');
let s5b = 0;
s5b += run("LFI php://filter",    makeBackend('GET', '/page?file=php://filter/convert.base64-encode/resource=/etc/passwd', 200));
s5b += run("LFI phar:// wrapper", makeBackend('GET', '/load?f=phar://shell.phar', 200));
console.log(`  Total: ${s5b.toFixed(2)} pts — ${s5b >= 12 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 5c: SSTI (Jinja2 / Twig) ---');
let s5c = 0;
s5c += run("SSTI {{7*7}}",      makeBackend('GET', '/render?name={{7*7}}',       200));
s5c += run("SSTI ${7*7} Twig",  makeBackend('GET', '/template?t=${7*7}',         200));
console.log(`  Total: ${s5c.toFixed(2)} pts — ${s5c >= 14 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 6: Sensitive file access (.env, .git) ---');
let s6 = 0;
s6 += run(".env file",             makeBackend('GET', '/.env',              200));
s6 += run(".git/config",           makeBackend('GET', '/.git/config',       200));
s6 += run("phpinfo.php",           makeBackend('GET', '/phpinfo.php',       200));
s6 += run("wp-config.php",         makeBackend('GET', '/wp-config.php',     200));
console.log(`  Total: ${s6.toFixed(2)} pts — ${s6 >= 20 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 7: CMS admin probe on non-CMS app ---');
let s7 = 0;
s7 += run("/wp-admin probe",       makeBackend('GET', '/wp-admin/',         404));
s7 += run("/phpmyadmin probe",     makeBackend('GET', '/phpmyadmin/',       404));
console.log(`  Total: ${s7.toFixed(2)} pts — ${s7 >= 15 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 8: SSRF via parameter ---');
let s8 = 0;
s8 += run("SSRF internal IP",      makeBackend('GET', '/fetch?url=http://192.168.1.1/admin', 200));
s8 += run("SSRF file:// scheme",   makeBackend('GET', '/proxy?target=file:///etc/passwd', 200));
console.log(`  Total: ${s8.toFixed(2)} pts — ${s8 >= 14 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 9: HTTP method abuse (TRACE/CONNECT) ---');
let s9 = 0;
s9 += run("TRACE method",          makeBackend('TRACE',   '/',    200));
s9 += run("CONNECT method",        makeBackend('CONNECT', '/',    200));
console.log(`  Total: ${s9.toFixed(2)} pts — ${s9 >= 6 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);

console.log('--- Scenario 10: Agent-side bot detection ---');
let s10 = 0;
s10 += run("Headless browser",     makeAgent('headless_browser'));
s10 += run("Suspicious URL agent", makeAgent('suspicious_url'));
console.log(`  Total: ${s10.toFixed(2)} pts — ${s10 >= 10 ? '🔴 Detected ✓' : '⚠ Too low'}\n`);
