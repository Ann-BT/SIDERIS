// src/detector/decisionEngine.js
// Sideris 2.0 — Decision Engine
//
// Maps session_score → verdict + action.
//
// Decision matrix:
//   score >= 50  → CRITICAL  → hard_block  (full deny, SOC manual unblock only)
//   score >= 30  → VERY_HIGH → soft_block  (block with auto-expire, SOC can unblock)
//   score >= 20  → HIGH      → captcha     (challenge response required)
//   score >= 10  → SUSPICIOUS → rate_limit (slow down requests)
//   score < 10   → NORMAL    → allow       (no enforcement)
//
// Pure function — no I/O.
'use strict';

// Decision thresholds
const THRESHOLDS = [
  { min: 50, verdict: 'critical',   action: 'hard_block',  level: 5 },
  { min: 30, verdict: 'very_high',  action: 'soft_block',  level: 4 },
  { min: 20, verdict: 'high',       action: 'captcha',     level: 3 },
  { min: 10, verdict: 'suspicious', action: 'rate_limit',  level: 2 },
  { min:  0, verdict: 'normal',     action: 'allow',       level: 1 },
];

function decide(sessionScore) {
  const score = Math.max(0, sessionScore);
  for (const t of THRESHOLDS) {
    if (score >= t.min) {
      return {
        verdict: t.verdict,
        action:  t.action,
        level:   t.level,
        score:   parseFloat(score.toFixed(2)),
      };
    }
  }
  return { verdict: 'normal', action: 'allow', level: 1, score: 0 };
}

// Maps action → guard directive stored in Redis
// soft_block and hard_block both result in 'block' guard
// but the TTL and unblock policy differ:
//   hard_block: no auto-expire, requires SOC manual unblock
//   soft_block: auto-expires after escalation-scaled TTL, SOC can unblock
const ACTION_TO_GUARD = {
  allow:      null,
  rate_limit: 'rate_limit',
  captcha:    'challenge',
  soft_block: 'block',
  hard_block: 'block',
};

function getGuardDirective(action) {
  return ACTION_TO_GUARD[action] || null;
}

// Returns whether this action is a hard block (no TTL expiry)
function isHardBlock(action) {
  return action === 'hard_block';
}

module.exports = { decide, getGuardDirective, isHardBlock, THRESHOLDS };
