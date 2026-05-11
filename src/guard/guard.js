// ──────────────────────────────────────────────────────────
// src/guard/guard.js
// Sideris 2.0 — Guard Mode Service (Phase 3)
//
// Subscribes to the sideris:alerts Pub/Sub channel.
// Evaluates payload risks to determine protective actions 
// (block > rate_limit > challenge) and enforces them atomically.
// ──────────────────────────────────────────────────────────

const Redis = require('ioredis');
const config = require('../shared/config');

const subscriber = new Redis(config.redisUrl);
const redis = new Redis(config.redisUrl);

const ALERT_CHANNEL = config.alertChannel || 'sideris:alerts';
const OFFENSE_TTL = 86400; // 24 hours penalty decay

// Define weights for atomic evaluation
const ACTION_WEIGHTS = {
  'block': 3,
  'rate_limit': 2,
  'challenge': 1
};

// Define baseline action parameters
// These must align with src/detector/decisionEngine.js thresholds
const ACTION_THRESHOLDS = [
  { action: 'block',     minScore: 30, baseTtl: 1800 }, // 30 mins
  { action: 'challenge', minScore: 20, baseTtl: 600 }   // 10 mins
];

// ── Lua Atomicity Script ──────────────────────────────────
// This script ensures priority logic is completely atomic.
// It receives: 
// KEYS[1] = guard key ('sideris:guard:{id}')
// KEYS[2] = metrics key ('sideris:metrics:guard:{action}')
// ARGV[1] = intended action (e.g. 'block')
// ARGV[2] = numeric weight of intended action
// ARGV[3] = intended reason
// ARGV[4] = intended risk_score
// ARGV[5] = timestamp
// ARGV[6] = calculated TTL
//
// It checks if current action in Hash has a higher weight. 
// If so, it aborts. If it succeeds, it sets Hash, sets TTL, 
// and increments the metric natively inside the lock.

const LUA_ENFORCE_GUARD = `
  local current_action = redis.call('HGET', KEYS[1], 'action')
  local current_weight = 0
  
  if current_action == 'block' then current_weight = 3
  elseif current_action == 'rate_limit' then current_weight = 2
  elseif current_action == 'challenge' then current_weight = 1
  end
  
  local intended_weight = tonumber(ARGV[2])
  
  if current_weight > intended_weight then
    return 0 -- Abort: Exisiting action overrides this intended action
  end
  
  -- Execute Write
  redis.call('HSET', KEYS[1], 'action', ARGV[1], 'reason', ARGV[3], 'risk_score', ARGV[4], 'updated_at', ARGV[5])
  redis.call('EXPIRE', KEYS[1], ARGV[6])
  redis.call('INCR', KEYS[2])
  
  return 1 -- Success
`;

redis.defineCommand('enforceGuard', {
  numberOfKeys: 2,
  lua: LUA_ENFORCE_GUARD
});

// ── Processing Logic ──────────────────────────────────────

async function processAlert(payloadStr) {
  let payload;
  try {
    payload = JSON.parse(payloadStr);
  } catch (err) {
    console.warn('[guard] Dropped malformed JSON alert payload.');
    return;
  }

  const { session_id, risk_score } = payload;
  
  if (!session_id || typeof session_id !== 'string') return;
  if (!risk_score) return;

  // Determine required action
  let intendedAction = null;
  let baseTtl = 0;

  for (const threshold of ACTION_THRESHOLDS) {
     if (risk_score >= threshold.minScore) {
       intendedAction = threshold.action;
       baseTtl = threshold.baseTtl;
       break;
     }
  }

  // Under normal thresholds, ignore
  if (!intendedAction) return;

  // Cooldown Deduplication AFTER decision validation
  // Prevent spamming the same action repetetively. Action specific lock.
  const cooldownKey = `sideris:guard:cooldown:${session_id}:${intendedAction}`;
  const allowProcessing = await redis.set(cooldownKey, '1', 'NX', 'EX', 10);
  if (allowProcessing !== 'OK') {
     // Alert exactly of this action was processed <10s ago, silently skip
     return;
  }

  // Escalation Tracking
  const offensesKey = `sideris:offenses:${session_id}`;
  const offenseCount = await redis.hincrby(offensesKey, 'count', 1);
  await redis.expire(offensesKey, OFFENSE_TTL);

  // Dynamic Punishment Scaling (e.g., offense 2 gets 2x the standard block interval)
  const finalTtl = baseTtl * Math.max(1, offenseCount);

  // Enforce Atomic Lua Policy
  const guardKey = `sideris:guard:${session_id}`;
  const metricsKey = `sideris:metrics:guard:${intendedAction}`;
  const weight = ACTION_WEIGHTS[intendedAction] || 0;

  const result = await redis.enforceGuard(
    guardKey,
    metricsKey,
    intendedAction,
    weight.toString(),
    'risk_threshold',
    risk_score.toString(),
    Date.now().toString(),
    finalTtl.toString()
  );

  if (result === 1) {
    console.log(`[GUARD] ENFORCED: Session ${session_id} action=${intendedAction} score=${risk_score} ttl=${finalTtl}s (offense #${offenseCount})`);
  } else {
    // Current action is stronger, ignoring...
    console.log(`[GUARD] ABORTED: Session ${session_id} action=${intendedAction} (Priority overridden by stronger existing rule)`);
  }
}

// ── Startup Loop ──────────────────────────────────────────

async function startGuard() {
  console.log(`[guard] Initializing Sideris Defense Subsystem...`);
  
  subscriber.on('message', async (channel, message) => {
    if (channel === ALERT_CHANNEL) {
      await processAlert(message);
    }
  });

  subscriber.subscribe(ALERT_CHANNEL, (err, count) => {
    if (err) {
      console.error('[guard] Failed to subscribe to alerts channel:', err.message);
      process.exit(1);
    }
    console.log(`[guard] Listening on channel '${ALERT_CHANNEL}' for real-time risk alerts.`);
  });
  
  // Handle gracefully Redis reconnect drops
  subscriber.on('error', (err) => {
     console.error('[guard] Subscriber redis error:', err.message);
  });
  redis.on('error', (err) => {
     console.error('[guard] Writer redis error:', err.message);
  });
}

// Handle graceful shutdown
process.on('SIGINT', () => {
   console.log('[guard] Shutting down gracefully...');
   subscriber.quit();
   redis.quit();
   process.exit(0);
});

startGuard();
