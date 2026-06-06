# SIDERIS Customization and Rules Tuning Guide

SIDERIS uses a predictable, deterministic heuristic scoring engine instead of machine learning. This makes it auditable, fast, and easy to tune. This guide explains how the scoring equation works, how to adjust detection thresholds, and how to add your own custom WAF rules.

---

## 1. The Threat Scoring Model

SIDERIS evaluates client threat levels by running incoming request events and browser telemetry signals through a scoring engine. Every event produces an `event_score` computed as:

$$\text{Event Score} = \text{Impact} \times \text{Confidence} \times \text{Persistence}$$

### Breakdown of Variables
1. **Impact (1–30)**: Set on a per-rule basis in [eventAnalyzer.js](file:///home/merlin/Codes/SIDERIS%203.0/SIDERIS/src/detector/eventAnalyzer.js#L111-L138). Represents the severity of the attack (e.g., directory traversal is `3`, while SQL injection is `30`).
2. **Confidence (0.5–1.5)**: Measures signal reliability. Can be boosted by:
   - **Repetition**: If a user triggers the same rule multiple times, the confidence floor is raised.
   - **Pivoting**: If the user triggers rules across two or more *different* threat categories (e.g., both `bot` biometrics and `fuzzing` path scanners), they get a **+0.1 multi-category confidence boost**.
3. **Persistence (1.0–2.0)**: Represents the duration and rate of the activity:
   - `ONE_TIME` (1.0): First occurrence.
   - `REPEATED` (1.3): 3+ occurrences in the session (or 5+ auth attempts).
   - `SUSTAINED` (1.6): 5+ occurrences in the session (or 10+ auth attempts).
   - `FLOOD` (2.0): Volumetric traffic (>10 requests per second).

### Score Decay and Auto-Recovery
The total threat score decays exponentially to ensure that temporary anomalies or resolved blocks are automatically cleared over time:
* **Decay Rate**: The session score is multiplied by `0.99` every 30 seconds.
* **Auto-Release**: If a session's score decays below the threshold of `10` (the safe zone), any soft blocks, CAPTCHA challenges, or rate limits for that session are automatically released.

---

## 2. Adjusting Mitigation Thresholds

Thresholds for taking action are defined in two main places:
1. **Verdicts (Decision Engine)**: [src/detector/decisionEngine.js](file:///home/merlin/Codes/SIDERIS%203.0/SIDERIS/src/detector/decisionEngine.js#L17-L23) maps scores to threat levels.
2. **Enforcements (Guard Service)**: [src/guard/guard.js](file:///home/merlin/Codes/SIDERIS%203.0/SIDERIS/src/guard/guard.js#L21-L26) maps those thresholds to active defense actions and initial block TTLs (Time To Live).

### Standard Action Matrix

| Threat Score | Verdict | Enforced Action | Initial Duration (TTL) |
|:---:|:---|:---|:---|
| **< 10** | `normal` | Allow traffic | None (Safe) |
| **>= 10** | `suspicious` | Rate limit (Slow down client) | 5 minutes (300s) |
| **>= 20** | `high` | CAPTCHA Challenge | 10 minutes (600s) |
| **>= 30** | `very_high` | Soft Block (Temporary IP/Session Block) | 30 minutes (1800s) |
| **>= 50** | `critical` | Hard Block (Permanent IP Block) | Infinite (Requires manual unban) |

### Escalating Penalties (Dynamic Scaling)
SIDERIS tracks how many times a session has triggered the Guard. When a client repeatedly triggers a block after being unbanned or solving a CAPTCHA:
* The WAF retrieves the offense counter from Redis (`sideris:offenses:<session_id>`).
* The base block TTL is multiplied by the offense count:
  
$$\text{Scaled TTL} = \text{Base TTL} \times \text{Offenses}$$

*(e.g., if a user gets soft-blocked for the second time, the ban duration is $1800s \times 2 = 3600s$ (1 hour).*

### Changing Thresholds
To adjust sensitivity (for example, if you want to make the CAPTCHA trigger at score 15 instead of 20), update the thresholds in both files:
* In `src/detector/decisionEngine.js`, change the threshold values in the `THRESHOLDS` array.
* In `src/guard/guard.js`, match the `ACTION_THRESHOLDS` array to the same scores.

---

## 3. Writing Custom WAF Rules

WAF rules reside in [src/detector/eventAnalyzer.js](file:///home/merlin/Codes/SIDERIS%203.0/SIDERIS/src/detector/eventAnalyzer.js).

### Step 1: Add a regex or condition
If you want to block requests searching for a specific vulnerable endpoint (e.g. `/wp-content/plugins/wp-file-manager/`), define a pattern near the top of `eventAnalyzer.js`:

```javascript
// Rule regex pattern
const CUSTOM_EXPLOIT_PAT = /\/wp-file-manager|elfinder/i;
```

### Step 2: Map the attack type to a category and impact
Add your attack type key to the `CATEGORY_MAP` and `IMPACT` registries:

```javascript
const CATEGORY_MAP = {
  // ...
  wp_file_manager_exploit: { 
    category: 'injection', 
    signal: 'Exploit attempt targeting WP File Manager' 
  }
};

const IMPACT = {
  // ...
  wp_file_manager_exploit: 30, // Trigger soft block on first attempt
};
```

### Step 3: Integrate into the `analyze` loop
In the `analyze` function under the backend proxy checks, add the condition check:

```javascript
// RULE: WP File Manager Exploit Scanning
if (CUSTOM_EXPLOIT_PAT.test(path) || CUSTOM_EXPLOIT_PAT.test(endpoint)) {
  return result('wp_file_manager_exploit', 5, 1.2); 
  // params: attack_type, default_impact_level, base_confidence
}
```

---

## 4. Setting Up WAF Bypasses (Testing / Development)

If you are running automated security scans (like ZAP, Burp, or Cypress testing) against your development environment and want to prevent SIDERIS from blocking your pipeline:

1. **Exempt specific paths**: In `src/proxy/server.js`, you can bypass the WAF check for trusted routes:
   ```javascript
   // Inside the guard middleware check in src/proxy/server.js
   if (req.path.startsWith('/api/trusted-webhook')) {
     return next();
   }
   ```
2. **Whitelist Header/Token**: Implement a header-based bypass for your pipeline:
   ```javascript
   const bypassToken = process.env.WAF_BYPASS_TOKEN;
   if (bypassToken && req.headers['x-waf-bypass'] === bypassToken) {
     return next();
   }
   ```
