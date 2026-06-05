# Sideris 2.0

SIDERIS (Sidecar Integrated Detection, Event Reporting, and Intelligence System) is a real-time web application firewall (WAF) and client-side behavioral analysis proxy.

Because hoping your users will play nice is not a security strategy.

---

## What is SIDERIS?

SIDERIS sits in front of your website like a reverse proxy with severe trust issues. It intercepts traffic, automatically injects a client-side telemetry agent into served HTML, statefully scores user behavior in real time, and dynamically enforces progressive defenses (like rate-limiting, CAPTCHAs, or hard blocks) when risk thresholds are crossed.

It keeps your site safe from bots, brute-force scanners, and malicious exploitation attempts without requiring any modifications to your backend code.

---

## Visual Walkthrough

Here is how SIDERIS looks and works in practice.

### 1. The SOC Dashboard
This is the security operations center interface. It tracks active sessions, lists cumulative risk scores, breakdowns attack categories, and allows analysts to manually block or unblock sessions in one click.

![SIDERIS SOC Dashboard](./screenshots/dashboard.png)
*Figure 1: Real-time session risk tracking and telemetry details.*

### 2. The Verification Screen (Adaptive Guard)
Instead of immediately blocking users who trigger minor behavioral flags, SIDERIS intercepts their requests and displays a server-generated CAPTCHA challenge. Solving it immediately restores their access.

![SIDERIS CAPTCHA Overlay](./screenshots/captcha.png)
*Figure 2: The overlay verification modal injected when risk thresholds are crossed.*

---

## Core Capabilities

* **Automated Agent Injection**: Slips a lightweight telemetry script (agent.js) into the head of all HTML responses. It runs on the client side to monitor telemetry, requiring zero changes to your actual web application code.
* **Heuristic Scoring Engine**: Looks beyond basic signature matching. SIDERIS tracks client-side typing speeds, paste behaviors, mouse movements, rapid click bursts, automated form fills, devtools usage, and headless browser signals.
* **Active Guard Escalate Policies**: Scales mitigations dynamically based on live session risk:
  * **Risk score 10**: Rate-limits the session.
  * **Risk score 20**: Injects the CAPTCHA overlay challenge.
  * **Risk score 30**: Soft-blocks the session temporarily.
  * **Risk score 50**: Hard-blocks the IP address until manually reviewed by an analyst.
* **Self-Healing Storage**: Events are processed via a Redis stream and archived to PostgreSQL for auditing. Database schemas are bootstrapped and migrated automatically on startup.

---

## Setup and Deployment

Getting SIDERIS running in front of your website is quick.

1. **Docker Compose**: SIDERIS includes a production Docker setup that starts SIDERIS, Redis, and PostgreSQL.
2. **Native Node.js**: SIDERIS can be built and run directly on your host machine.

For complete, step-by-step setup instructions, please read the **[Deployment and Configuration Guide](./DEPLOYMENT.md)**.

---

## Project Structure

```
SIDERIS 2.0/
├── src/
│   ├── agent/agent.js         # Browser behavior collector (injected automatically)
│   ├── ingest/server.js       # Telemetry event ingestion and guard verification
│   ├── detector/worker.js     # Redis stream event consumer and scoring runner
│   ├── guard/guard.js         # Active guard mitigation coordinator
│   ├── dashboard/
│   │   ├── server.js          # REST API for the SOC dashboard
│   │   └── ui/                # React-based SOC dashboard frontend
│   └── shared/
│       └── config.js          # Central configuration loader
└── scripts/
    ├── start-all.js           # Launcher for all SIDERIS services (native mode)
    └── setup-sideris.js       # Interactive CLI configuration installer
```

---

## License

This project is open-source and free to use under the **[MIT License](./LICENSE)**. Protect your websites.
