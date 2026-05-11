# SIDERIS 2.0 — Juice Shop Validation Guide

This guide provides a structured methodology to validate the **Detection**, **Scoring**, and **Enforcement** capabilities of your SIDERIS installation using **OWASP Juice Shop** as a target application.

---

## 1. Setup & Agent Injection

Before testing, ensure your Juice Shop container is running at [http://localhost:3000](http://localhost:3000) and all Sideris services are started (`npm run start-all`).

### Console Injection
1. Open Juice Shop in Chrome at `http://localhost:3000`.
2. Press `F12` to open the **Console**.
3. Paste the following loader:
   ```javascript
   (function(){var s=document.createElement('script');s.src='http://localhost:5000/sideris/agent.js';document.head.appendChild(s)})();
   ```
4. You should see: `[Sideris Agent] initialized | session=...`

> [!NOTE]
> You may see `PHISHSHIELD_CONFIG` errors when navigating. These are from Juice Shop's own `config.js` being re-executed during SPA navigation — they are **harmless** and unrelated to Sideris.

---

## 2. Test Scenarios & Simulation Scripts

### Scenario A: Normal User Activity
**Goal**: Verify the system records baseline events without triggering alerts.
- **Action**: Navigate through categories, click a few items slowly, and view the "About Us" page.
- **Expected Observation**:
  - **Dashboard**: `processed` count increases. `risk_score` remains **0-2**.
  - **Guard Action**: None.

### Scenario B: Suspicious Behavior (Rapid Clicking)
**Goal**: Trigger a medium-level risk score.
- **Action**: Open the console and run this "Autoclicker" script:
  ```javascript
  // Simulates 20 clicks in 2 seconds
  let count = 0;
  const clicker = setInterval(() => {
    document.body.click();
    count++;
    if (count >= 20) clearInterval(clicker);
  }, 100);
  ```
- **Expected Observation**:
  - **Dashboard**: Session risk score climbs to **3-6**.
  - **Status**: Session marked as "Suspicious" (Medium Risk).

### Scenario C: Bot Simulation (Aggressive Typing & Form Fill)
**Goal**: Trigger high-risk scoring and active enforcement (Blocking).
- **Action**: Go to the **Login** page and run this "Bot Form Filler":
  ```javascript
  async function simulateBot() {
    const email = document.querySelector('input[name="email"]');
    if (!email) return console.error('Navigate to Login page first!');
    
    // 1. Instant Focus
    email.focus();
    
    // 2. Extremely fast typing (20ms interval)
    const text = 'bot-attacker-admin@juice-sh.op';
    for (let char of text) {
      email.dispatchEvent(new KeyboardEvent('keydown', { key: char, bubbles: true }));
      email.value += char;
      await new Promise(r => setTimeout(r, 20));
    }
    
    // 3. Instant Submit attempt
    const btn = document.querySelector('button[type="submit"]');
    if (btn) btn.click();
  }
  simulateBot();
  ```
- **Expected Observation**:
  - **Dashboard**: Risk score breaches **12+**.
  - **Guard Matrix**: A new `BLOCK` action appears for the session ID.

### Scenario D: Enforcement Validation
**Goal**: Verify the "Shield" is active.
- **Action**: After Scenario C, try to refresh the page or click any button.
- **Expected Observation**:
  - **Network Tab**: Outgoing requests to `/sideris/ingest` return **403 Forbidden**.
  - **Console**: You will see error: `blocked (code: E_GUARD_BLOCK)`.

### Scenario E: Recovery (Pardon System)
**Goal**: Test the feedback loop.
- **Action**: Use the console to "Verify" the challenge:
  ```javascript
  fetch('http://localhost:5000/sideris/challenge/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      session_id: sessionStorage.getItem('sideris_session_id'), 
      token: 'mock-captcha-success-token' 
    })
  }).then(r => r.json()).then(console.log);
  ```
- **Expected Observation**:
  - **Dashboard**: The Block for this session disappears.
  - **Behavior**: Subsequent requests return to **200 OK**.

---

## 3. Debugging Matrix

| Symptom | Check | Potential Fix |
| :--- | :--- | :--- |
| **No events on Dashboard** | Check Ingest Console | Ensure `REDIS_URL` is correct and Ingest is running on port 5000. |
| **Agent not loading** | Browser Console | Check for CORS errors. Ensure Ingest is running and serving agent.js. |
| **Risk score stays 0** | Check Detector Console | Verify the Worker is running (`npm run detect`) and consuming from the stream. |
| **Guard not blocking** | Check Guard Console | Verify Guard is running (`npm run guard`) and subscribed to the `sideris:alerts` channel. |
| **Dashboard empty UI** | API Response | Check `http://localhost:6001/sessions`. If it's `[]`, ensure detector is running. |

> [!IMPORTANT]
> Always **Flush Redis** (`docker exec sideris-redis redis-cli FLUSHDB`) between full test cycles to ensure a clean state and accurate offense counter scaling.
