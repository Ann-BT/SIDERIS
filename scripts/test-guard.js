// scripts/test-guard.js
const http = require('http');
const config = require('../src/shared/config');

const ingestUrl = `http://localhost:${config.ingestPort}/sideris/ingest`;

function postData(url, data) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(data);
    const parsedUrl = new URL(url);

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port,
      path: parsedUrl.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req = http.request(options, (res) => {
      let responseBody = '';
      res.on('data', chunk => responseBody += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          body: JSON.parse(responseBody)
        });
      });
    });

    req.on('error', (e) => reject(e));
    req.write(payload);
    req.end();
  });
}

const mockAttack = Array(5).fill(0).map(() => ({
    sessionId: "hacker-session-666",
    ts: Date.now(),
    type: "no_mouse", // base risk +3. 5 of them = 15 total > block threshold
    data: {}
}));

async function runTest() {
  console.log(`[TEST] Phase 1 - Sending Attack Payload (5x no_mouse events)...`);
  const res1 = await postData(ingestUrl, mockAttack);
  console.log(`[TEST] Result 1 Status:`, res1.statusCode);
  console.log(`[TEST] Result 1 Body:`, res1.body);
  
  if(res1.statusCode !== 200) {
     console.error("[TEST] Failed to send attack payload.");
     return;
  }

  console.log(`\n[TEST] Waiting 2 seconds for Detector and Guard to process stream and lock session...`);
  await new Promise(r => setTimeout(r, 2000));

  console.log(`\n[TEST] Phase 2 - Sending Follow Up Payload on same session...`);
  const res2 = await postData(ingestUrl, [{ sessionId: "hacker-session-666", ts: Date.now(), type: "test" }]);
  console.log(`[TEST] Expected: 403 Forbidden`);
  console.log(`[TEST] Actual Status:`, res2.statusCode);
  console.log(`[TEST] Actual Body:`, res2.body);

  if (res2.statusCode === 403 && res2.body.error === 'blocked') {
      console.log(`\n[TEST] SUCCESS! Guard Mode successfully intercepted and blocked the attacker. Phase 3 works.`);
  } else {
      console.log(`\n[TEST] FAILURE! Guard Mode did not block the attacker.`);
  }
}

runTest();
