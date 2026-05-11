// Test the inline critical patterns against real attack payloads
const CRITICAL_PATTERNS = [
  { name: 'sql_injection', re: /(UNION[\s\/\*]+SELECT|'\s*OR\s*['"\d]|OR\s+1\s*=\s*1|--\s*$|DROP\s+TABLE|INSERT\s+INTO|EXEC\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\(|LOAD_FILE\s*\(|INTO\s+OUTFILE)/i },
  { name: 'xss',           re: /(<script[\s>]|javascript\s*:|on(error|load|click|mouseover)\s*=|<iframe[\s>]|<svg[^>]+onload|document\.cookie|eval\s*\()/i },
  { name: 'cmd_injection',  re: /([;&|`]|\$\()\s*(ls|id|cat|wget|curl|whoami|uname|bash|sh|python|nc|ping)\s/i },
  { name: 'path_traversal', re: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%2e%2e%5c)/i },
  { name: 'ssrf',           re: /(https?:\/\/(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|0\.0\.0\.0)|file:\/\/|gopher:\/\/)/i },
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

const tests = [
  // SQLi attacks
  { label: "Juice Shop SQLi login", url: "/rest/user/login", body: {email:"admin@juice-sh.op' OR 1=1--", password:"x"} },
  { label: "UNION SELECT", url: "/rest/products/search?q=1 UNION SELECT 1,2,3--", body: null },
  { label: "DROP TABLE", url: "/api/test", body: "'; DROP TABLE users;--" },
  { label: "SLEEP injection", url: "/api/test", body: {id: "1' AND SLEEP(5)--"} },
  
  // XSS
  { label: "Script tag XSS", url: "/search?q=<script>alert(1)</script>", body: null },
  { label: "Event handler XSS", url: "/api/test", body: {name: '<img onerror=alert(1) src=x>'} },
  
  // Path traversal  
  { label: "Path traversal", url: "/download?file=../../etc/passwd", body: null },
  
  // SSRF
  { label: "SSRF to localhost", url: "/fetch?url=http://localhost:8080/admin", body: null },
  
  // NORMAL — should NOT trigger
  { label: "Normal login", url: "/rest/user/login", body: {email:"user@test.com", password:"pass123"} },
  { label: "Normal search", url: "/rest/products/search?q=apple juice", body: null },
  { label: "Normal browsing", url: "/api/Products/42", body: null },
  { label: "OR in email (safe)", url: "/rest/user/login", body: {email:"victor@example.com", password:"p"} },
];

console.log('\n  INLINE PAYLOAD SCAN TEST');
console.log('  ' + '═'.repeat(55));
let pass = true;
for (const t of tests) {
  const result = scanPayload(t.url, t.body);
  const expected = t.label.includes('Normal') || t.label.includes('safe');
  const isBlock = result !== null;
  const ok = expected ? !isBlock : isBlock;
  if (!ok) pass = false;
  console.log(`  ${ok ? '✅' : '❌'} ${t.label.padEnd(30)} → ${result || 'PASS'}`);
}
console.log('  ' + '═'.repeat(55));
console.log(pass ? '  ✅ All tests passed!' : '  ❌ Some tests FAILED');
