# Sideris 2.0

Real-time web attack detection and behavioral analysis system for security research.

## 🚀 Quick Links
* **[Production Deployment Guide](./DEPLOYMENT.md)** — Learn how to set up SIDERIS to protect your live website in minutes.
* **[Testing Guide](./docs/testing_guide.md)** — Scenarios and scripts for validating SIDERIS detections.

---

## 🏗️ Architecture

```
Juice Shop (:3000) + agent.js (injected automatically via WAF Proxy)
        ↓ beacon (fetch/sendBeacon)
  Sideris Ingest (:5000) → Redis Stream
        ↓
  Detector Worker → Risk Scoring → sideris:alerts
        ↓
  Guard Service → Block / Challenge (enforced on Ingest)
        ↓
  Dashboard API (:6001) → React UI (:5173)
```

---

## 🛠️ Local Development & Testing

SIDERIS includes a full developer test suite with vulnerable applications (OWASP Juice Shop, Discourse, and Medusa Commerce) to simulate real attack vectors.

To start the local developer test suite:

### 1. Start Services via Docker Compose
Use the development docker-compose file to spin up SIDERIS, Redis, PostgreSQL, and all testing targets:
```bash
docker compose -f docker-compose.dev.yml up -d
```

### 2. Verify Client-Side Agent
Access your test application (e.g. Juice Shop on proxy port `4000` or original target port `3001`). Open your browser console (F12) and run:
```javascript
SiderisAgent.getSessionId()
```
The telemetry agent should be successfully injected and active.

### 3. Open the SOC Dashboard
Navigate to the React dashboard at:
* **Dashboard Interface**: `http://localhost:5173`
* **Metrics API**: `http://localhost:6001/sessions`

---

## 📁 Project Structure

```
SIDERIS 2.0/
├── src/
│   ├── agent/agent.js         # Browser behavior collector (injected automatically by proxy)
│   ├── ingest/server.js       # Event ingestion API + guard enforcement
│   ├── detector/worker.js     # Redis stream consumer + risk scoring
│   ├── guard/guard.js         # Defensive actions (block/challenge)
│   ├── dashboard/
│   │   ├── server.js          # Metrics API
│   │   └── ui/                # React dashboard (Vite)
│   └── shared/
│       └── config.js          # Centralized configuration
├── scripts/
│   ├── start-all.js           # Launch all services
│   ├── test-guard.js          # Guard integration test
│   └── test-redis-ingest.js   # Ingest integration test
└── docs/
    └── testing_guide.md       # Validation scenarios
```

See [TESTING.md](./TESTING.md) for detailed test instructions.

