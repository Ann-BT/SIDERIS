// ──────────────────────────────────────────────────────────
// src/shared/pgPool.js
// Shared PostgreSQL connection pool for all Sideris workers.
// ──────────────────────────────────────────────────────────
'use strict';

const { Pool } = require('pg');
const path     = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL
    || 'postgresql://sideris:sideris@localhost:5432/sideris',
  max:             5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 3000,
});

pool.on('error', (err) => {
  console.error('[pg] Unexpected pool error:', err.message);
});

module.exports = pool;
