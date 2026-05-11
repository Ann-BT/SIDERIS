// ──────────────────────────────────────────────────────────
// src/shared/config.js
// Centralized configuration for all Sideris servers.
// Reads from .env, validates required variables, exports
// ports, paths, and the target URL.
// ──────────────────────────────────────────────────────────

const path = require('path');
const dotenv = require('dotenv');

// Load .env from project root
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

// ── Required env var validation ──────────────────────────
const REQUIRED = ['INGEST_PORT', 'DASHBOARD_PORT', 'REDIS_URL'];

for (const key of REQUIRED) {
  if (!process.env[key]) {
    console.error(`[config] ERROR: Missing required environment variable: ${key}`);
    console.error(`[config] Make sure .env exists in the project root with: ${REQUIRED.join(', ')}`);
    process.exit(1);
  }
}

// ── Exported configuration ───────────────────────────────
const config = {
  // Server ports
  ingestPort: parseInt(process.env.INGEST_PORT, 10),
  dashboardPort: parseInt(process.env.DASHBOARD_PORT, 10),
  proxyPort: parseInt(process.env.PROXY_PORT || '4000', 10),
  targetUrl: process.env.TARGET_URL || 'http://localhost:3000',

  // Redis connection string
  redisUrl: process.env.REDIS_URL,

  // PostgreSQL connection string
  postgresUrl: process.env.POSTGRES_URL || 'postgresql://sideris:sideris@localhost:5432/sideris',

  // Redis Stream configs
  streamName: 'sideris:events',
  consumerGroup: 'sideris_group',
  alertChannel: 'sideris:alerts',
  sessionTtlSec: 1800,

  // Log file paths (relative to project root)
  logsDir: path.resolve(__dirname, '../../logs'),
  eventsLog: path.resolve(__dirname, '../../logs/events.jsonl'),
  serverLog: path.resolve(__dirname, '../../logs/server.jsonl'),
  normalizedLog: path.resolve(__dirname, '../../logs/normalized.jsonl'),
  sessionsLog: path.resolve(__dirname, '../../logs/sessions.jsonl'),
  detectionsLog: path.resolve(__dirname, '../../logs/detections.jsonl'),

  // CORS allowed origins (Juice Shop at :3000)
  allowedOrigins: [
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ],

  // CORS allowed headers
  allowedHeaders: ['Content-Type', 'X-Sideris-Session'],

  // Ingest body size limit
  bodyLimit: '1mb',

  // SSE keepalive interval (ms)
  sseKeepAlive: 15000
};

module.exports = config;
