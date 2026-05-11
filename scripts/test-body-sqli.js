const a = require('../src/detector/eventAnalyzer');

// Test SQLi in POST body (like Juice Shop login)
const r1 = a.analyze({
  source: 'backend',
  event_type: 'backend_log',
  data: {
    endpoint: '/rest/user/login',
    status: '200',
    method: 'POST',
    body: { email: "admin@juice-sh.op' OR 1=1--", password: 'x' }
  }
});
console.log('SQLi in POST body:', r1.attack_type, '| cat:', r1.category, '| impact:', r1.impact);

// Test normal login fail (401)
const r2 = a.analyze({
  source: 'backend',
  event_type: 'backend_log',
  data: { endpoint: '/rest/user/login', status: '401', method: 'POST', body: { email: 'user@test.com', password: 'wrong' } }
});
console.log('Normal 401:', r2.attack_type, '| cat:', r2.category, '| impact:', r2.impact);

// Test normal successful login (200)
const r3 = a.analyze({
  source: 'backend',
  event_type: 'backend_log',
  data: { endpoint: '/rest/user/login', status: '200', method: 'POST', body: { email: 'user@test.com', password: 'correct' } }
});
console.log('Normal 200 login:', r3.attack_type, '| cat:', r3.category, '| impact:', r3.impact);
