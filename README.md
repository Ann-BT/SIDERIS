# Sideris 2.0

SIDERIS (Sidecar Integrated Detection, Event Reporting, & Intelligence System) is a real-time web attack detection and behavioral analysis system for security research.

## Quick Links
* **[Production Deployment Guide](./DEPLOYMENT.md)** — Learn how to set up SIDERIS to protect your live website in minutes.

---

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

---

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
└── scripts/
    ├── start-all.js           # Launch all SIDERIS services natively
    └── setup-sideris.js       # Interactive configuration installer
```



