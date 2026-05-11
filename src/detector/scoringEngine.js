// ──────────────────────────────────────────────────────────
// src/detector/scoringEngine.js
// Sideris 2.0 — Scoring Engine (Category-Aware)
//
// Formula: event_score = impact × confidence × persistence
//
// Persistence logic:
//   ONE_TIME   (1.0) — first occurrence of this attack_type
//   REPEATED   (1.3) — 3+ same attack_type in session
//   SUSTAINED  (1.6) — 5+ same attack_type in session
//   FLOOD      (2.0) — real attack type at >10 rps
//
// Confidence refinement:
//   - Repeated attacks raise confidence floor
//   - Multi-category attacks raise confidence (attacker pivoting)
//   - Benign types are never boosted
//
// Pure function — no I/O.
// ──────────────────────────────────────────────────────────
'use strict';

// ── Confidence levels ──────────────────────────────────────
const CONFIDENCE = {
  WEAK_ANOMALY:    0.5,
  UNUSUAL:         0.8,
  KNOWN_SIGNATURE: 1.0,
  STRONG_PAYLOAD:  1.2,
  CONFIRMED:       1.5,
};

// ── Persistence multipliers ────────────────────────────────
const PERSISTENCE = {
  ONE_TIME:   1.0,
  REPEATED:   1.3,
  SUSTAINED:  1.6,
  FLOOD:      2.0,
};

// ── Types that never get FLOOD multiplier ──────────────────
const BENIGN_TYPES = new Set(['normal_browsing', 'recon_404']);

// ── Types that use special counters for persistence ────────
const AUTH_TYPES = new Set(['auth_failure', 'credential_stuffing', 'password_spray']);

// ── Determine persistence from session state ───────────────
//
// Logic:
//   IF attack is real (not benign) AND rps > 10  → FLOOD (2.0)
//   IF same attack_type seen 5+ times            → SUSTAINED (1.6)
//   IF same attack_type seen 3+ times            → REPEATED (1.3)
//   ELSE                                         → ONE_TIME (1.0)
//
// Auth types use failed_login_count instead of url_counts.
// recon_404 uses count_404.
function getPersistence(attackType, sessionState) {
  // FLOOD only for real attack types at high request rate
  if (!BENIGN_TYPES.has(attackType) && !AUTH_TYPES.has(attackType)) {
    if ((sessionState.requests_per_second || 0) > 10) {
      return PERSISTENCE.FLOOD;
    }
  }

  // Auth types — use login attempt counter
  if (AUTH_TYPES.has(attackType)) {
    const attempts = sessionState.login_attempts || sessionState.failed_login_count || 0;
    if (attempts >= 10) return PERSISTENCE.SUSTAINED;
    if (attempts >= 5)  return PERSISTENCE.REPEATED;
    return PERSISTENCE.ONE_TIME;
  }

  // recon_404 — use dedicated 404 counter
  if (attackType === 'recon_404') {
    const c = sessionState.count_404 || 0;
    if (c >= 20) return PERSISTENCE.SUSTAINED;
    if (c >= 10) return PERSISTENCE.REPEATED;
    return PERSISTENCE.ONE_TIME;
  }

  // All other attack types — use per-type counter from url_counts
  const repeatCount = (sessionState.url_counts || {})[attackType] || 0;
  if (repeatCount >= 5) return PERSISTENCE.SUSTAINED;
  if (repeatCount >= 3) return PERSISTENCE.REPEATED;
  return PERSISTENCE.ONE_TIME;
}


// ── Refine confidence using session context ────────────────
//
// Logic:
//   - Benign types: confidence is never boosted
//   - 5+ repetitions of same attack type → confidence floor = KNOWN_SIGNATURE
//   - 3+ repetitions → floor = UNUSUAL
//   - 2+ different attack categories in session → +0.1 confidence
//     (attacker is pivoting = higher certainty of malicious intent)
function getConfidence(base, attackType, sessionState) {
  if (BENIGN_TYPES.has(attackType)) return parseFloat(base.toFixed(2));

  let conf = base;
  const repeatCount = (sessionState.url_counts || {})[attackType] || 0;

  // Repetition raises confidence floor
  if (repeatCount >= 5 && conf < CONFIDENCE.KNOWN_SIGNATURE) {
    conf = CONFIDENCE.KNOWN_SIGNATURE;
  } else if (repeatCount >= 3 && conf < CONFIDENCE.UNUSUAL) {
    conf = CONFIDENCE.UNUSUAL;
  }

  // Multi-category pivot bonus: if session has 2+ attack categories,
  // confidence gets a small boost (attacker is not just noise)
  const catCounts = sessionState.category_counts || {};
  const activeCategories = Object.keys(catCounts).filter(
    k => k !== 'normal' && catCounts[k] > 0
  ).length;
  if (activeCategories >= 2) {
    conf = Math.min(conf + 0.1, CONFIDENCE.CONFIRMED);
  }

  return parseFloat(conf.toFixed(2));
}

// ── Main compute function ─────────────────────────────────
//
// Input:  analyzed  = { attack_type, category, behavior_signal, impact, base_confidence }
//         session   = current session state from sessionTracker
// Output: { attack_type, category, behavior_signal, impact, confidence, persistence, event_score }
function compute(analyzed, sessionState) {
  const { attack_type, category, behavior_signal, impact, base_confidence } = analyzed;

  const confidence  = getConfidence(base_confidence, attack_type, sessionState);
  const persistence = getPersistence(attack_type, sessionState);
  const event_score = parseFloat((impact * confidence * persistence).toFixed(2));

  return {
    attack_type,
    category:        category || 'normal',
    behavior_signal: behavior_signal || '',
    impact,
    confidence,
    persistence,
    event_score,
  };
}

module.exports = { compute, CONFIDENCE, PERSISTENCE };
