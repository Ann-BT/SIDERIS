# Sideris 2.0

Real-time web attack detection and behavioral analysis system for security research.

## Architecture

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

## Quick Start

```bash
# 1. Start Juice Shop
docker start fervent_edison

# 2. Start Redis
# (already running via Docker on port 6379)

# 3. Install dependencies
npm install

# 4. Launch all services
npm run start-all

# 5. Open Juice Shop directly
#    http://localhost:3000

# 6. Verify agent loads automatically in browser (F12 Console):
#    SiderisAgent.getSessionId()

# 7. Open dashboard
#    http://localhost:5173  (Vite dev server)
#    API: http://localhost:6001/sessions
```

## Scripts

| Command | Description |
|---------|-------------|
| `npm run start-all` | Start ingest + detector + guard + dashboard |
| `npm run ingest` | Ingest server on :5000 |
| `npm run detect` | Detector worker (Redis stream consumer) |
| `npm run guard` | Guard enforcement service |
| `npm run dashboard` | Dashboard API on :6001 |

## Project Structure

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
