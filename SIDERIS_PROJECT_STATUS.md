# SIDERIS 2.0 — Project Status Report
**Date:** April 23, 2026
**Version:** 2.0.0

## Project Overview
SIDERIS 2.0 is a real-time web attack detection and behavioral analysis system designed for security research. It monitors **OWASP Juice Shop** (running on port 3000) by injecting a JavaScript agent via the browser console, providing layered defense and monitoring.

## 1. Core Architecture
The system consists of these integrated components:

| Component | Port | Role |
|-----------|------|------|
| **Sideris Agent** | N/A | Self-contained JavaScript beacon (`agent.js`) injected via console to monitor client-side behavior. |
| **Sideris Ingest** | 5000 | Data collection endpoint. Receives behavioral beacons, pushes to Redis Streams, enforces guard actions. |
| **Sideris Detector** | N/A | Redis Streams consumer. Scores sessions for risk, emits alerts for high-risk sessions. |
| **Sideris Guard** | N/A | Subscribes to alert channel. Enforces block/challenge/rate-limit actions with escalation tracking. |
| **Dashboard API** | 6001 | REST API serving sessions, guards, and metrics from Redis for the frontend. |
| **Dashboard UI** | 5173 | React frontend (Vite) with real-time polling, glassmorphism design, risk-level color mapping. |

---

## 2. Features Done (Detailed)

### A. Sideris Agent (`src/agent/agent.js`)
*   **Session Management**: Generates UUID v4 sessions with a 30-minute idle expiration.
*   **Device Fingerprinting**: Collects extensive browser technical data (User Agent, Platform, WebGL, Hardware Concurrency, etc.).
*   **Behavioral Monitoring**: Mouse speed, typing patterns, scroll behavior, click rates.
*   **Interaction Tracking**: Instant form fill detection, navigation tracking, clipboard monitoring.
*   **Network Instrumentation**: Monkey-patches XHR and Fetch to inject `X-Sideris-Session` header. Login detection.
*   **Resilient Delivery**: Primary `fetch()` with `Content-Type: application/json`, `sendBeacon` fallback for page unloads, `localStorage` retry buffer.

### B. Sideris Ingest (`src/ingest/server.js`)
*   **Batch Ingestion**: High-throughput endpoint (`/sideris/ingest`) receiving event batches.
*   **Multi-format Parsing**: Handles both `application/json` and `text/plain` bodies (for `sendBeacon` compatibility).
*   **Guard Enforcement**: Checks Redis for guard directives — returns 403 (blocked) or 429 (challenge) inline.
*   **Challenge Recovery**: `/sideris/challenge/verify` endpoint to lift non-block restrictions.

### C. Sideris Detector (`src/detector/worker.js`)
*   **Redis Streams Consumer**: Uses Consumer Groups for reliable message processing.
*   **Risk Scoring**: Per-event increments (fast_typing +2, rapid_click +2, no_mouse +3) with burst penalties.
*   **Session State**: Tracks event counts, risk scores, and levels (normal/suspicious/attacker) in Redis hashes.
*   **Alert Emission**: Publishes to `sideris:alerts` when risk exceeds thresholds (8 = challenge, 12 = block).
*   **Dead Letter Recovery**: Auto-claims idle messages from other crashed consumers.

### D. Sideris Guard (`src/guard/guard.js`)
*   **Atomic Enforcement**: Lua scripts ensure priority-based action locking (block > rate_limit > challenge).
*   **Cooldown Deduplication**: Prevents alert spam with per-session, per-action 10s cooldown.
*   **Escalation Tracking**: Offense counter with dynamic TTL scaling (repeat offenders get longer bans).

### E. Dashboard API (`src/dashboard/server.js`)
*   **Optimized Scanning**: Uses Redis `SCAN` streams with hard limits (50 keys max).
*   **Pipeline Fetching**: `HMGET` via pipelines for bulk session/guard data retrieval.
*   **Endpoints**: `GET /sessions`, `GET /guards`, `GET /metrics`.

### F. Dashboard UI (`src/dashboard/ui`)
*   **Real-Time Polling**: 3-second interval with `useEffect` cleanup.
*   **Risk Visualization**: Color-coded badges (green/yellow/red), relative timestamps.
*   **Glassmorphism Design**: Dark-mode, premium aesthetics.

---

## 3. Data Flow

```
Browser (Juice Shop :3000)
  → agent.js collects: clicks, typing, mouse, scrolls, form fills, login attempts
  → fetch POST → Ingest (:5000) /sideris/ingest
    → Guard check (Redis lookup) → Allow / Block 403 / Challenge 429
    → XADD to Redis Stream (sideris:events)
      → Detector (consumer group) reads stream
        → Updates sideris:session:{id} hash (risk_score, event_count, etc.)
        → If risk ≥ 8: PUBLISH sideris:alerts
          → Guard subscribes → HSET sideris:guard:{id} (block/challenge)
            → Next ingest request hits guard middleware → enforced
  → Dashboard API (:6001) reads Redis → React UI (:5173) polls API
```

---

## 4. Current Status

**All core components are functional.**

- [x] Client-side behavior collection (Agent)
- [x] Event ingestion and Redis streaming (Ingest)
- [x] Risk scoring and alerting (Detector)
- [x] Automated enforcement (Guard)
- [x] Dashboard API
- [x] Dashboard UI
- [x] Console injection workflow
- [x] Cross-origin delivery fix (fetch + text/plain parsing)
