// ──────────────────────────────────────────────────────────
// scripts/test-redis-ingest.js
// Sideris 2.0 — Post-Refactor Integration Test
//
// Sends a mock batch of events to the ingest endpoint, then
// connects to Redis to retrieve and verify them.
// To run: node scripts/test-redis-ingest.js
// ──────────────────────────────────────────────────────────

const http = require('http');
const Redis = require('ioredis');
const config = require('../src/shared/config');

const ingestUrl = `http://localhost:${config.ingestPort}/sideris/ingest`;
const redis = new Redis(config.redisUrl);

const mockBatch = [
  {
    sessionId: "test-session-123",
    ts: Date.now(),
    type: "test_event",
    data: { hello: "world" }
  },
  {
    session_id: "test-session-123",
    clientTs: Date.now(),
    type: "another_event",
    data: { foo: "bar" }
  }
];

// Helper to make a POST request natively
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

async function runTest() {
  try {
    console.log(`[TEST] Sending ${mockBatch.length} mock events to ${ingestUrl}...`);
    
    const response = await postData(ingestUrl, mockBatch);
    console.log(`[TEST] Response status: ${response.statusCode}`);
    console.log(`[TEST] Response body:`, response.body);

    if (response.statusCode >= 400) {
      console.error("[TEST] FAILED: Server returned error status.");
      process.exit(1);
    }

    console.log(`\n[TEST] Waiting 500ms for Redis writes to settle...`);
    await new Promise(r => setTimeout(r, 500));

    console.log(`[TEST] Connecting to Redis at ${config.redisUrl} and running an RPOP...`);
    
    const queueName = 'sideris:events';
    const queueLength = await redis.xlen(queueName);
    console.log(`[TEST] Stream '${queueName}' length is now: ${queueLength}`);
    
    if (queueLength < mockBatch.length) {
        console.warn(`[TEST] Warning: Stream length (${queueLength}) is less than expected (${mockBatch.length}). They may have been consumed or not written.`);
    }

    // Retrieve events using XREAD
    const streamData = await redis.xread('STREAMS', queueName, '0-0');
    if (!streamData || streamData.length === 0 || streamData[0][1].length === 0) {
        console.error(`[TEST] FAILED: Could not XREAD any events from the stream.`);
        process.exit(1);
    }

    const firstMsg = streamData[0][1][0]; // [messageId, [fields...]]
    const msgId = firstMsg[0];
    const fields = firstMsg[1];

    let payloadStr = null;
    for(let i=0; i<fields.length; i+=2){
       if (fields[i] === 'payload') {
         payloadStr = fields[i+1];
         break;
       }
    }

    if (!payloadStr) {
       console.error(`[TEST] FAILED: Payload field missing in stream message.`);
       process.exit(1);
    }

    const poppedEvent = JSON.parse(payloadStr);
    console.log(`[TEST] Successfully read event ${msgId} from stream:`);
    console.dir(poppedEvent, { depth: null, colors: true });

    if (!poppedEvent.session_id || !poppedEvent.timestamp || !poppedEvent.source || !poppedEvent.event_type || !poppedEvent.ingest_ip) {
       console.error(`[TEST] FAILED: Populated event schema is invalid!`);
       process.exit(1); 
    }

    console.log(`\n[TEST] SUCCESS! All components working correctly.`);
    
  } catch (err) {
    console.error('[TEST] Error during test execution:', err);
  } finally {
    redis.quit();
  }
}

runTest();
