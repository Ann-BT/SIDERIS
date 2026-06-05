// scripts/show-scoring-sample.js
// Shows a sample scoring output: event scores + session scores from PostgreSQL
'use strict';
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const pool = new Pool({ connectionString: process.env.POSTGRES_URL });

(async () => {
  // 1. Event score breakdown for recent events
  const events = await pool.query(`
    SELECT session_id, source, event_type, attack_type,
           impact, confidence, persistence, event_score, timestamp
    FROM attack_events
    WHERE event_score > 0
    ORDER BY event_score DESC
    LIMIT 15
  `);
  console.log('\n=== Top 15 Scored Events ===');
  console.log('  ' + 'session'.padEnd(10) + 'source'.padEnd(10) + 'attack_type'.padEnd(24) +
    'impact'.padEnd(8) + 'conf'.padEnd(6) + 'pers'.padEnd(6) + 'score');
  events.rows.forEach(r =>
    console.log(
      '  ' + r.session_id.substring(0,8).padEnd(10) +
      r.source.padEnd(10) +
      (r.attack_type || 'unknown').padEnd(24) +
      String(r.impact).padEnd(8) +
      String(r.confidence).padEnd(6) +
      String(r.persistence).padEnd(6) +
      r.event_score
    )
  );

  // 2. Session score summary
  const sessions = await pool.query(`
    SELECT s.session_id, s.session_score, s.verdict,
           s.event_count, s.ip_address,
           COUNT(CASE WHEN e.source='agent'   THEN 1 END) AS agent_events,
           COUNT(CASE WHEN e.source='backend' THEN 1 END) AS backend_events,
           MAX(e.event_score)  AS max_event_score,
           AVG(e.event_score)  AS avg_event_score
    FROM attack_sessions s
    LEFT JOIN attack_events e ON e.session_id = s.session_id
    GROUP BY s.session_id, s.session_score, s.verdict, s.event_count, s.ip_address
    ORDER BY s.session_score DESC
  `);
  console.log('\n=== Session Score Summary ===');
  sessions.rows.forEach(r =>
    console.log(
      '  sid=' + r.session_id.substring(0,8) + '...' +
      '  score=' + parseFloat(r.session_score || 0).toFixed(2).padEnd(8) +
      '  verdict=' + (r.verdict || 'normal').padEnd(12) +
      '  agent=' + r.agent_events +
      '  backend=' + r.backend_events +
      '  max_event=' + parseFloat(r.max_event_score || 0).toFixed(2) +
      '  avg_event=' + parseFloat(r.avg_event_score || 0).toFixed(2)
    )
  );

  // 3. Attack type distribution
  const types = await pool.query(`
    SELECT attack_type, COUNT(*) as cnt,
           AVG(event_score) as avg_score,
           MAX(event_score) as max_score
    FROM attack_events
    WHERE attack_type != 'unknown'
    GROUP BY attack_type ORDER BY avg_score DESC
  `);
  console.log('\n=== Attack Type Distribution ===');
  types.rows.forEach(r =>
    console.log(
      '  ' + (r.attack_type || '?').padEnd(24) +
      ' count=' + String(r.cnt).padEnd(6) +
      ' avg_score=' + parseFloat(r.avg_score || 0).toFixed(2).padEnd(8) +
      ' max_score=' + parseFloat(r.max_score || 0).toFixed(2)
    )
  );

  console.log('\n');
  await pool.end();
})().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
