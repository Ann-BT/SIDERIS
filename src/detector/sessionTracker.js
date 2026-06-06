// src/detector/sessionTracker.js
// Sideris 2.0 — Session Tracker (Category-Aware)
//
// Manages per-session state with two-tier storage:
//   L1: In-memory Map  (zero-latency reads)
//   L2: Redis HSET      (survives restarts)
//
// Session schema (Redis key: sideris:session:{id}):
// {
//   session_id,
//   session_score,           // cumulative risk score
//   event_count,
//   ip_address,
//   known_ips,               // array of all IPs seen for this session
//   user_agent,
//   last_seen,               // epoch ms
//   verdict,                 // current verdict string
//
// // ── Category counts
//   category_counts: {
//     authentication: N, injection: N, fuzzing: N,
//     bot: N, dos: N, session_abuse: N
//   },
//
// // ── Per-type counters
//   url_counts: { sql_injection: 3, xss: 1, ... },
//
// // ── Auth tracking
//   login_attempts,          // total login-endpoint hits
//   failed_login_count,      // 401/403 on auth endpoints
//   unique_usernames,        // distinct usernames attempted
//
// // ── Rate tracking
//   requests_per_second,     // from agent telemetry
//   request_timestamps,      // last 60s of request times (for rate calc)
//   endpoint_hits: { "/api/login": 25, ... },
//
// // ── Detection flags
//   scanner_detected,
//   scan_detected,
//   exploit_detected,
//   count_404,
//   payload_variation_count,
//   unique_payloads,
//   mouse_moves,
//
// // ── Bonus dedup
//   bonus_applied,           // array of bonus keys already applied
//
// // ── Behavior log
//   // Stored separately in Redis List: sideris:session:{id}:risk_reasons
//   // Each entry: { rule, category, signal, score, timestamp }
// }
'use strict';

const Redis = require('ioredis');
const config = require('../shared/config');

const redis = new Redis(config.redisUrl);
const CACHE_TTL = 1800; // 30 minutes in-memory cache
const REDIS_TTL = 86400; // 24 hours in Redis
const DECAY_INTERVAL = 30_000;
const DECAY_FACTOR = 0.99;

const { THREAT_LEVELS } = require('../shared/severity');
const { decide, getGuardDirective } = require('./decisionEngine');

redis.on('error', err => console.error('[sessionTracker] Redis:', err.message));

// L1 in-memory cache
const cache = new Map(); // sessionId → state

// BONUS RULES — applied once per session per key
// These detect compound behavioral patterns that confirm
// attack intent beyond individual events.
const BONUS_RULES = [
  // Authentication bonuses
  {
    key: 'brute_force',
    check: s => s.failed_login_count >= 15,
    points: 10,
    label: 'Brute force: 15+ failed logins',
    category: 'authentication',
  },
  {
    key: 'password_spray',
    check: s => (s.unique_usernames || []).length >= 3 && s.login_attempts >= 5,
    points: 12,
    label: 'Password spray: 3+ usernames attempted',
    category: 'authentication',
  },
  {
    key: 'credential_stuffing',
    check: s => s.login_attempts >= 20 && s.failed_login_count >= 15,
    points: 15,
    label: 'Credential stuffing: 20+ rapid login attempts',
    category: 'authentication',
  },

  // Fuzzing bonuses
  {
    key: '404_storm',
    check: s => (s.count_404 || 0) >= 15,
    points: 8,
    label: '404 storm: path scanning (15+ 404s)',
    category: 'fuzzing',
  },
  {
    key: 'scanner_detected',
    check: s => s.scanner_detected === true,
    points: 8,
    label: 'Scanner tool detected via User-Agent',
    category: 'fuzzing',
  },
  {
    key: 'payload_variation',
    check: s => (s.payload_variation_count || 0) >= 5,
    points: 10,
    label: 'Payload variation: 5+ unique attack payloads',
    category: 'fuzzing',
  },

  // Injection bonuses
  {
    key: 'scan_exploit_combo',
    check: s => s.scan_detected && s.exploit_detected,
    points: 12,
    label: 'Recon → exploit combo: scanning then attacking',
    category: 'injection',
  },
  {
    key: 'multi_vector',
    check: s => {
      const cats = s.category_counts || {};
      const active = Object.keys(cats).filter(k => k !== 'normal' && cats[k] > 0);
      return active.length >= 3;
    },
    points: 10,
    label: 'Multi-vector: 3+ attack categories detected',
    category: 'injection',
  },

  // Bot bonuses
  {
    key: 'bot_speed',
    check: s => s.event_count > 20 && (s.requests_per_second || 0) > 10 && (s.mouse_moves || 0) === 0,
    points: 8,
    label: 'Bot-like speed: high RPS + no mouse movement',
    category: 'bot',
  },
  {
    key: 'headless_confirmed',
    check: s => {
      const cats = s.category_counts || {};
      return (cats.bot || 0) >= 3 && (s.mouse_moves || 0) === 0;
    },
    points: 10,
    label: 'Confirmed headless: multiple bot signals + no mouse',
    category: 'bot',
  },

  // DoS bonuses
  {
    key: 'dos_flood',
    check: s => {
      // Rate calculated from request_timestamps
      const timestamps = s.request_timestamps || [];
      if (timestamps.length < 50) return false;
      const window = timestamps[timestamps.length - 1] - timestamps[0];
      return window > 0 && window <= 60000; // 50+ requests in 60s
    },
    points: 15,
    label: 'DoS flood: 50+ requests in 60 seconds',
    category: 'dos',
  },
  {
    key: 'endpoint_hammer',
    check: s => {
      const hits = s.endpoint_hits || {};
      return Object.values(hits).some(count => count >= 20);
    },
    points: 10,
    label: 'Endpoint hammer: 20+ hits on same endpoint',
    category: 'dos',
  },

  // Session abuse bonuses
  {
    key: 'session_ip_switch',
    check: s => (s.known_ips || []).length >= 2,
    points: 8,
    label: 'Session used from 2+ different IPs',
    category: 'session_abuse',
  },
];

// Fresh session template
function freshSession(sessionId) {
  return {
    session_id: sessionId,
    session_score: 0,
    event_count: 0,
    ip_address: null,
    known_ips: [],
    user_agent: null,
    last_seen: Date.now(),
    verdict: 'allow',

    // Category counts
    category_counts: { authentication: 0, injection: 0, fuzzing: 0, bot: 0, dos: 0, session_abuse: 0 },

    // Per-type counters
    url_counts: {},

    // Auth tracking
    login_attempts: 0,
    failed_login_count: 0,
    unique_usernames: [],

    // Rate tracking
    requests_per_second: 0,
    request_timestamps: [],
    endpoint_hits: {},

    // Detection flags
    scanner_detected: false,
    scan_detected: false,
    exploit_detected: false,
    count_404: 0,
    payload_variation_count: 0,
    unique_payloads: [],
    mouse_moves: 0,

    // Bonus dedup
    bonus_applied: [],

    // Stateful adaptive defense parameters
    highest_score: 0,
    highest_threat_level: 'allow',
    highest_block_type: 'soft',
    last_mitigation: 'allow',
    mitigation_reason: '',
    guard_source: 'automatic',
    first_suspicious_at: 0,
    first_mitigated_at: 0,
    highest_score_at: 0,
    captcha_solved: false,
  };
}

// REDIS SERIALIZATION
function toRedisFields(s) {
  return [
    'session_score', s.session_score.toFixed(2),
    'event_count', String(s.event_count),
    'ip_address', s.ip_address || '',
    'known_ips', JSON.stringify(s.known_ips || []),
    'user_agent', s.user_agent || '',
    'last_seen', String(s.last_seen),
    'verdict', s.verdict,
    'category_counts', JSON.stringify(s.category_counts),
    'url_counts', JSON.stringify(s.url_counts),
    'login_attempts', String(s.login_attempts),
    'failed_login_count', String(s.failed_login_count),
    'unique_usernames', JSON.stringify((s.unique_usernames || []).slice(-50)),
    'requests_per_second', (s.requests_per_second || 0).toFixed(2),
    'request_timestamps', JSON.stringify((s.request_timestamps || []).slice(-100)),
    'endpoint_hits', JSON.stringify(s.endpoint_hits || {}),
    'scanner_detected', s.scanner_detected ? '1' : '0',
    'scan_detected', s.scan_detected ? '1' : '0',
    'exploit_detected', s.exploit_detected ? '1' : '0',
    'count_404', String(s.count_404 || 0),
    'payload_variation_count', String(s.payload_variation_count),
    'unique_payloads', JSON.stringify((s.unique_payloads || []).slice(-20)),
    'mouse_moves', String(s.mouse_moves || 0),
    'bonus_applied', JSON.stringify(s.bonus_applied),
    'highest_score', (s.highest_score || 0).toFixed(2),
    'highest_threat_level', s.highest_threat_level || 'allow',
    'highest_block_type', s.highest_block_type || 'soft',
    'last_mitigation', s.last_mitigation || 'allow',
    'mitigation_reason', s.mitigation_reason || '',
    'guard_source', s.guard_source || 'automatic',
    'first_suspicious_at', String(s.first_suspicious_at || 0),
    'first_mitigated_at', String(s.first_mitigated_at || 0),
    'highest_score_at', String(s.highest_score_at || 0),
    'captcha_solved', s.captcha_solved ? '1' : '0',
  ];
}

function fromRedisFields(sessionId, h) {
  if (!h || !h.session_score) return null;
  return {
    session_id: sessionId,
    session_score: parseFloat(h.session_score || '0'),
    event_count: parseInt(h.event_count || '0', 10),
    ip_address: h.ip_address || null,
    known_ips: JSON.parse(h.known_ips || '[]'),
    user_agent: h.user_agent || null,
    last_seen: parseInt(h.last_seen || '0', 10),
    verdict: h.verdict || 'allow',
    category_counts: JSON.parse(h.category_counts || '{"authentication":0,"injection":0,"fuzzing":0,"bot":0,"dos":0,"session_abuse":0}'),
    url_counts: JSON.parse(h.url_counts || '{}'),
    login_attempts: parseInt(h.login_attempts || '0', 10),
    failed_login_count: parseInt(h.failed_login_count || '0', 10),
    unique_usernames: JSON.parse(h.unique_usernames || '[]'),
    requests_per_second: parseFloat(h.requests_per_second || '0'),
    request_timestamps: JSON.parse(h.request_timestamps || '[]'),
    endpoint_hits: JSON.parse(h.endpoint_hits || '{}'),
    scanner_detected: h.scanner_detected === '1',
    scan_detected: h.scan_detected === '1',
    exploit_detected: h.exploit_detected === '1',
    count_404: parseInt(h.count_404 || '0', 10),
    payload_variation_count: parseInt(h.payload_variation_count || '0', 10),
    unique_payloads: JSON.parse(h.unique_payloads || '[]'),
    mouse_moves: parseInt(h.mouse_moves || '0', 10),
    bonus_applied: JSON.parse(h.bonus_applied || '[]'),
    highest_score: parseFloat(h.highest_score || '0'),
    highest_threat_level: h.highest_threat_level || 'allow',
    highest_block_type: h.highest_block_type || 'soft',
    last_mitigation: h.last_mitigation || 'allow',
    mitigation_reason: h.mitigation_reason || '',
    guard_source: h.guard_source || 'automatic',
    first_suspicious_at: parseInt(h.first_suspicious_at || '0', 10),
    first_mitigated_at: parseInt(h.first_mitigated_at || '0', 10),
    highest_score_at: parseInt(h.highest_score_at || '0', 10),
    captcha_solved: h.captcha_solved === '1',
  };
}

async function saveToRedis(state) {
  const key = `sideris:session:${state.session_id}`;
  const pipe = redis.pipeline();
  pipe.hset(key, 'session_id', state.session_id, ...toRedisFields(state));
  pipe.expire(key, REDIS_TTL);
  try { await pipe.exec(); }
  catch (err) { console.error('[sessionTracker] Redis save error:', err.message); }
}

// Get or create session
async function getSession(sessionId) {
  if (cache.has(sessionId)) return cache.get(sessionId);

  try {
    const h = await redis.hgetall(`sideris:session:${sessionId}`);
    const loaded = fromRedisFields(sessionId, h);
    const state = loaded || freshSession(sessionId);
    cache.set(sessionId, state);
    return state;
  } catch {
    const state = freshSession(sessionId);
    cache.set(sessionId, state);
    return state;
  }
}

// Apply behavior bonuses (idempotent)
function applyBonuses(state) {
  let bonusTotal = 0;
  const newReasons = [];

  for (const rule of BONUS_RULES) {
    if (!state.bonus_applied.includes(rule.key) && rule.check(state)) {
      state.bonus_applied.push(rule.key);
      state.session_score += rule.points;
      bonusTotal += rule.points;
      newReasons.push(rule.label);
    }
  }

  return { bonusTotal, newReasons };
}

// UPDATE — process one scored event into session state
async function update(sessionId, scoringResult, event) {
  const state = await getSession(sessionId);
  if (event.inline_blocked) {
    // Proxy already updated Redis session state, event_count, category_counts, url_counts, etc.
    // We just return the loaded state without modifying it, and skip writing to risk_reasons list.
    return {
      state: { ...state },
      bonusTotal: 0,
      newReasons: [],
    };
  }
  const data = event.data || {};
  const { attack_type, category, behavior_signal, event_score } = scoringResult;
  const now = event.timestamp || Date.now();

  // Basic counters
  state.event_count++;
  state.last_seen = now;

  // IP tracking (session abuse detection)
  const eventIp = data.ip || event.ingest_ip || null;
  if (eventIp) {
    if (!state.ip_address) state.ip_address = eventIp;
    if (!state.known_ips.includes(eventIp)) {
      state.known_ips.push(eventIp);
    }
  }
  state.user_agent = state.user_agent || data.userAgent || null;

  // Category counts
  if (category && category !== 'normal' && state.category_counts.hasOwnProperty(category)) {
    state.category_counts[category]++;
  }

  // Per-type counters
  state.url_counts[attack_type] = (state.url_counts[attack_type] || 0) + 1;

  // Auth tracking
  if (attack_type === 'auth_failure' || attack_type === 'credential_stuffing' || attack_type === 'password_spray') {
    state.login_attempts++;
    state.failed_login_count++;

    // Extract username from POST body for spray detection
    const username = data.body?.email || data.body?.username || data.body?.user || data.query?.email || data.query?.username || null;
    if (username && typeof username === 'string' && !state.unique_usernames.includes(username)) {
      state.unique_usernames.push(username);
    }
  }

  // 404 counter
  if (attack_type === 'recon_404') state.count_404++;

  // Scanner flag
  if (attack_type === 'scanner_tool') state.scanner_detected = true;

  // Scan / exploit flags
  if (['directory_traversal', 'cms_admin_probe', 'recon_404', 'file_exposure', 'scanner_tool', 'http_method_abuse'].includes(attack_type)) {
    state.scan_detected = true;
  }
  if (['sql_injection', 'xss', 'cmd_injection', 'ssti', 'xxe', 'ssrf', 'file_upload_exploit'].includes(attack_type)) {
    state.exploit_detected = true;
  }

  // Rate tracking (rolling 60-second window)
  // Only count NON-NORMAL events to avoid false DoS detection
  // from normal Juice Shop background polling (304s, config fetches, etc.)
  if (attack_type !== 'normal_browsing') {
    state.request_timestamps.push(now);
    const cutoff = now - 60000;
    state.request_timestamps = state.request_timestamps.filter(t => t > cutoff);

    // Endpoint hit counter (for DoS endpoint_hammer detection)
    const endpoint = data.endpoint || '';
    if (endpoint) {
      const path = endpoint.split('?')[0];
      state.endpoint_hits[path] = (state.endpoint_hits[path] || 0) + 1;
    }
  }

  // Payload variation
  const isBenign = ['normal_browsing', 'recon_404', 'auth_failure'].includes(attack_type);
  if (!isBenign) {
    const payloadStr = JSON.stringify(data.query || data.body || '');
    if (payloadStr !== '""' && payloadStr !== '{}' && payloadStr !== 'null') {
      if (!state.unique_payloads.includes(payloadStr)) {
        state.unique_payloads.push(payloadStr);
      }
      state.payload_variation_count = state.unique_payloads.length;
    }
  }

  // Agent-provided real-time metrics
  if (event.source === 'agent') {
    if (data.rps != null) state.requests_per_second = data.rps;
    if (data.mouseMoves != null) state.mouse_moves = data.mouseMoves;
  }

  // Add event score to session
  state.session_score = parseFloat((state.session_score + event_score).toFixed(2));

  // Apply behavior bonuses (idempotent)
  const { bonusTotal, newReasons } = applyBonuses(state);

  // Timestamps & State Machine updates
  if (state.session_score >= 10) {
    if (!state.first_suspicious_at || state.first_suspicious_at === 0) {
      state.first_suspicious_at = now;
    }
  }

  if (state.session_score > (state.highest_score || 0)) {
    state.highest_score = state.session_score;
    state.highest_score_at = now;
  }

  const decision = decide(state.session_score);
  // Sync verdict into session state so Redis hash stays accurate
  state.verdict = decision.verdict;
  if (decision && decision.action && decision.action !== 'allow') {
    if (!state.first_mitigated_at || state.first_mitigated_at === 0) {
      state.first_mitigated_at = now;
    }
    state.last_mitigation = getGuardDirective(decision.action);
    
    const activeRules = Object.keys(state.url_counts)
      .filter(k => k !== 'normal_browsing')
      .map(k => k.replace(/_/g, ' '));
    state.mitigation_reason = activeRules.length > 0 
      ? activeRules.join(', ') 
      : (attack_type || 'risk_threshold');

    const currentHighestWeight = THREAT_LEVELS[state.highest_threat_level] || 0;
    const newWeight = THREAT_LEVELS[decision.action] || 0;

    if (newWeight > currentHighestWeight) {
      state.highest_threat_level = decision.action;
      state.highest_block_type = decision.action === 'hard_block' ? 'hard' : 'soft';
    }
  }

  // Persist risk reason to Redis list (for timeline in dashboard)
  if (event_score > 0 || newReasons.length > 0) {
    let customSignal = behavior_signal || '';
    if (attack_type !== 'normal_browsing') {
      const parts = [];
      if (data.query) {
        const qStr = typeof data.query === 'object' ? JSON.stringify(data.query) : String(data.query);
        parts.push(`query: ${qStr.substring(0, 150)}${qStr.length > 150 ? '...' : ''}`);
      }
      if (data.body) {
        const bStr = typeof data.body === 'object' ? JSON.stringify(data.body) : String(data.body);
        parts.push(`body: ${bStr.substring(0, 150)}${bStr.length > 150 ? '...' : ''}`);
      }
      if (parts.length > 0) {
        customSignal = `${customSignal} [${parts.join(', ')}]`;
      }
    }

    const reasonEntry = JSON.stringify({
      rule: attack_type,
      category: category || 'normal',
      signal: customSignal,
      score: `+${event_score}`,
      total: state.session_score,
      timestamp: now,
      time: new Date(now).toISOString(),
    });
    try {
      const reasonKey = `sideris:session:${sessionId}:risk_reasons`;
      await redis.lpush(reasonKey, reasonEntry);
      await redis.ltrim(reasonKey, 0, 99);  // keep last 100
      await redis.expire(reasonKey, REDIS_TTL);
    } catch (err) {
      console.error('[sessionTracker] risk_reasons push error:', err.message);
    }
  }

  // Save updated state
  cache.set(sessionId, state);
  await saveToRedis(state);

  return {
    state: { ...state },
    bonusTotal,
    newReasons,
  };
}

// DECAY TIMER — score × 0.95 every 30 seconds
// Also evicts sessions idle longer than TTL.
function startDecayTimer() {
  setInterval(async () => {
    const now = Date.now();
    for (const [sessionId, state] of cache.entries()) {
      // Evict sessions idle longer than TTL
      if (now - state.last_seen > CACHE_TTL * 1000) {
        cache.delete(sessionId);
        continue;
      }
      if (state.session_score > 0) {
        state.session_score = parseFloat((state.session_score * DECAY_FACTOR).toFixed(2));
        if (state.session_score < 20 && state.captcha_solved) {
          state.captcha_solved = false;
        }

        // Guard release on score decay
        // If score has decayed into the safe zone (< 10) and the session
        // currently has a non-permanent guard directive, release it.
        // Hard blocks (score ever crossed 50) are exempt — those require
        // manual review via the SOC dashboard.
        if (state.session_score < 10 && state.highest_block_type !== 'hard') {
          try {
            const guardKey = `sideris:guard:${sessionId}`;
            const guardData = await redis.hgetall(guardKey);
            if (guardData && guardData.action && guardData.block_type !== 'hard') {
              await redis.del(guardKey);
              if (state.ip_address) {
                await redis.del(`sideris:guard:ip:${state.ip_address}`);
              }
              console.log(`[sessionTracker] Guard auto-released for ${sessionId} (score decayed to ${state.session_score})`);
            }
          } catch (err) {
            console.error('[sessionTracker] Guard release error:', err.message);
          }
        }

        await saveToRedis(state);
      }
    }
  }, DECAY_INTERVAL);
}

function clearCache(sessionId) {
  cache.delete(sessionId);
}

module.exports = { getSession, update, startDecayTimer, clearCache };
