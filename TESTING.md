# Sideris 2.0 — Testing Instructions

## Prerequisites
- Docker running with OWASP Juice Shop container
- Redis running on port 6379
- Node.js installed
- `npm install` completed in project root

## Step-by-Step Testing

### 1. Start Juice Shop
```bash
docker start fervent_edison
```
Verify it's running: open http://localhost:3000

### 2. Start Sideris
```bash
npm run start-all
```
You should see:
```
Ingest:    http://localhost:5000/sideris/health
Detector:  Redis Streams consumer started
Guard:     Subscribed to sideris:alerts
Dashboard: http://localhost:6001
```

### 3. Open Juice Shop
Open **http://localhost:3000** in Chrome.

### 4. Inject the Agent
Press `F12` to open the Console and paste:
```javascript
(function(){var s=document.createElement('script');s.src='http://localhost:5000/sideris/agent.js';document.head.appendChild(s)})();
```

### 5. Verify Agent Loaded
In the console, type:
```js
SiderisAgent.getSessionId()
```
Should return a UUID string.

> **Note:** You may see `PHISHSHIELD_CONFIG` errors in the console — these are from Juice Shop itself, not from Sideris. They are harmless.

### 6. Test Each Attack Type

| Attack | Juice Shop Action |
|--------|-------------------|
| **Normal browsing** | Browse products, click around |
| **SQL Injection** | Search for `' OR 1=1--` |
| **XSS** | Paste `<script>alert(1)</script>` in search |
| **Admin access** | Navigate to `/#/administration` |
| **Login brute force** | Wrong password 3 times at `/#/login` |
| **Rapid requests** | Console: `for(let i=0;i<25;i++) fetch('/rest/products/search?q='+i)` |

### 7. Check Dashboard API
```bash
# Sessions with risk scores
curl http://localhost:6001/sessions

# Global metrics
curl http://localhost:6001/metrics

# Active guard actions
curl http://localhost:6001/guards
```

### 8. Run Guard Test (optional)
```bash
node scripts/test-guard.js
```
This sends 5 high-risk events and verifies the session gets blocked.

### 9. Dashboard UI
Start the Vite dev server:
```bash
cd src/dashboard/ui
npm run dev
```
Open http://localhost:5173 to see the Command Center.
