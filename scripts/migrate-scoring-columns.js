// scripts/migrate-scoring-columns.js
// One-time migration: add scoring columns to existing PG tables.
'use strict';
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const pool = new Pool({ connectionString: process.env.POSTGRES_URL });

const CMDS = [
  `ALTER TABLE attack_sessions ADD COLUMN IF NOT EXISTS session_score FLOAT NOT NULL DEFAULT 0`,
  `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS attack_type   TEXT  NOT NULL DEFAULT 'unknown'`,
  `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS impact        FLOAT NOT NULL DEFAULT 0`,
  `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS confidence    FLOAT NOT NULL DEFAULT 0`,
  `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS persistence   FLOAT NOT NULL DEFAULT 0`,
  `ALTER TABLE attack_events   ADD COLUMN IF NOT EXISTS event_score   FLOAT NOT NULL DEFAULT 0`,
];

(async () => {
  for (const cmd of CMDS) {
    try {
      await pool.query(cmd);
      console.log('  ✓ OK  :', cmd.replace(/\s+/g, ' ').substring(0, 70));
    } catch (e) {
      console.log('  ⚠ SKIP:', e.message.substring(0, 80));
    }
  }
  console.log('\nMigration complete.');
  await pool.end();
})().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
