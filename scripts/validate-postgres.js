// scripts/validate-postgres.js
// Run once to validate the PostgreSQL storage layer.
'use strict';

const { Pool } = require('pg');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const pool = new Pool({ connectionString: process.env.POSTGRES_URL });
const TARGET = '17d3a403-d7ac-40fd-92cf-795c735e6d8d';

(async () => {
  // A. Tables
  const tables = await pool.query(`
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' ORDER BY table_name
  `);
  console.log('\n=== A. Tables ===');
  tables.rows.forEach(r => console.log('  ✓', r.table_name));

  // B. Row counts
  const evtCount = await pool.query('SELECT COUNT(*) FROM attack_events');
  const sesCount = await pool.query('SELECT COUNT(*) FROM attack_sessions');
  console.log('\n=== B. Row Counts ===');
  console.log('  attack_events  :', evtCount.rows[0].count);
  console.log('  attack_sessions:', sesCount.rows[0].count);

  // C. Source breakdown
  const sources = await pool.query(`
    SELECT source, COUNT(*) AS cnt
    FROM attack_events GROUP BY source ORDER BY source
  `);
  console.log('\n=== C. Events by Source ===');
  sources.rows.forEach(r => console.log('  ' + r.source.padEnd(10) + ':', r.cnt));

  // D. Session integrity check
  const sessionCheck = await pool.query(`
    SELECT source, COUNT(*) AS cnt,
           MIN(timestamp) AS first, MAX(timestamp) AS last
    FROM attack_events WHERE session_id = $1
    GROUP BY source ORDER BY source
  `, [TARGET]);

  console.log('\n=== D. Session Integrity: ' + TARGET.substring(0,16) + '... ===');
  sessionCheck.rows.forEach(r =>
    console.log(
      '  source=' + r.source.padEnd(8) +
      ' events=' + r.cnt +
      '  first=' + new Date(r.first).toISOString() +
      '  last='  + new Date(r.last).toISOString()
    )
  );
  const hasAgent   = sessionCheck.rows.some(r => r.source === 'agent');
  const hasBackend = sessionCheck.rows.some(r => r.source === 'backend');
  console.log('  UNIFIED:', (hasAgent && hasBackend)
    ? '✅ YES — agent + backend share same session_id'
    : '❌ NO (only one source found so far)'
  );

  // E. Timeline (first 12 events)
  const timeline = await pool.query(`
    SELECT timestamp, source, event_type
    FROM attack_events WHERE session_id = $1
    ORDER BY timestamp ASC LIMIT 12
  `, [TARGET]);
  console.log('\n=== E. Event Timeline (first 12) ===');
  timeline.rows.forEach(r =>
    console.log(
      '  ' + new Date(r.timestamp).toISOString() +
      '  ' + r.source.padEnd(8) +
      '  ' + r.event_type
    )
  );

  // F. Top sessions with joint event counts
  const sessions = await pool.query(`
    SELECT s.session_id, s.event_count, s.ip_address,
           s.final_risk_score, s.verdict,
           COUNT(CASE WHEN e.source='agent'   THEN 1 END) AS agent_events,
           COUNT(CASE WHEN e.source='backend' THEN 1 END) AS backend_events
    FROM attack_sessions s
    LEFT JOIN attack_events e ON e.session_id = s.session_id
    GROUP BY s.session_id, s.event_count, s.ip_address,
             s.final_risk_score, s.verdict
    ORDER BY s.event_count DESC LIMIT 5
  `);
  console.log('\n=== F. Top Sessions ===');
  sessions.rows.forEach(r =>
    console.log(
      '  sid=' + r.session_id.substring(0,8) + '...' +
      '  total=' + r.event_count +
      '  agent=' + r.agent_events +
      '  backend=' + r.backend_events +
      '  score=' + r.final_risk_score +
      '  verdict=' + r.verdict +
      '  ip=' + (r.ip_address || 'n/a')
    )
  );

  // G. Indexes
  const indexes = await pool.query(`
    SELECT indexname FROM pg_indexes
    WHERE tablename IN ('attack_events','attack_sessions')
    ORDER BY indexname
  `);
  console.log('\n=== G. Indexes ===');
  indexes.rows.forEach(r => console.log('  ✓', r.indexname));

  console.log('\n');
  await pool.end();
})().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
