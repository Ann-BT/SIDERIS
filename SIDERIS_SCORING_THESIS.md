# SIDERIS 2.0: Behavioral Detection and Risk Scoring Architecture

## 1. System Overview

SIDERIS 2.0 is an advanced, behavioral-based web attack detection and mitigation system designed to identify malicious activities through both direct payload inspection and long-term behavioral analysis. 

The architecture combines two complementary protection mechanisms:
1. **Synchronous inline detection** for immediate blocking of critical zero-day payloads.
2. **Asynchronous behavioral analysis** for detecting multi-stage, stealthy, or persistent attacks over time.

The system is organized into four primary, decoupled microservices:

### 1.1 Proxy Layer (Synchronous Protection)
The Proxy Layer (`proxy/server.js`) intercepts all incoming HTTP traffic before requests reach the backend application. This layer performs:
* **Inline inspection** of URLs, headers, query parameters, and request POST bodies (via raw buffer capturing).
* **Regex-based detection** for critical attacks such as:
  * SQL Injection (SQLi)
  * Cross-Site Scripting (XSS)
  * Command Injection (CMDi)
  * Server-Side Request Forgery (SSRF)
  * XML External Entity (XXE)
* **Immediate Mitigation:** If a critical payload is detected, the proxy instantly terminates the request with a silent HTTP 403 JSON response (`E_ATTACK_DETECTED`), bypassing the backend entirely.

### 1.2 Ingest Layer (Telemetry Collection)
The Ingest Layer provides an HTTP API endpoint that collects:
* **Backend access logs** (proxied requests, status codes, methods, endpoints).
* **Frontend telemetry** via a JavaScript agent (mouse movements, keystroke bursts, rapid form filling).
* **Client properties** (User Agent, IP Address, Session ID).

All events are standardized into a JSON format and pushed into a highly scalable **Redis Stream** (`sideris_events`) for asynchronous processing.

### 1.3 Detection Worker (Behavior Analysis Engine)
The Detection Worker continuously consumes events from the Redis stream and performs:
* **Event Classification:** Mapping raw requests to attack categories.
* **Session Tracking:** Aggregating requests across the same `session_id`.
* **Behavioral Pattern Analysis:** Looking for multi-request attack signatures (e.g., brute force, fuzzing).
* **Dynamic Risk Score Calculation:** Applying mathematical models to determine risk.

This layer enables the detection of "low and slow" attacks and persistent malicious behavior that would easily bypass traditional, single-request Web Application Firewalls (WAFs).

### 1.4 Decision Engine & Security Operations Dashboard
The Decision Engine evaluates the accumulated session risk score and determines the appropriate mitigation action (Allow, Rate Limit, Challenge, Block). Enforcement directives are stored back into Redis, where the Proxy reads them to enforce the rules on subsequent requests.

The SOC (Security Operations Center) Dashboard provides a real-time, React-based interface for security analysts to monitor threats, view session metrics, and manually override automated blocks.

---

## 2. Event Risk Scoring Model

Each incoming event is individually analyzed using a dynamic scoring equation inside the `eventAnalyzer`.

The Event Risk Score is calculated as:
**`Event Score = Base Impact × Confidence × Persistence Modifier`**

This model enables adaptive scoring based on attack severity, detection certainty, and attacker persistence.

### 2.1 Base Impact Score
The Base Impact value represents the inherent severity of the detected action.

| Impact Level | Category | Attack Type Examples |
| :--- | :--- | :--- |
| **5 — Critical** | Injection | SQL Injection, Command Injection, SSRF, XXE, SSTI |
| **4 — High** | Auth / DoS | Cross-Site Scripting, Credential Stuffing, Password Spraying, DoS Flood |
| **3 — Medium** | Fuzzing | Directory Traversal, CMS Admin Probing, Endpoint Hammering |
| **2 — Low** | Abuse | Authentication Failures, Rapid Navigation, Bot-like Keystroke Bursts |
| **1 — Minimal** | Recon | Reconnaissance activity, repeated 404 errors |
| **0 — Benign** | Normal | Normal browsing behavior |

Higher impact values contribute more heavily to the overall session score.

### 2.2 Confidence Multiplier
The Confidence value reflects how certain the engine is that the event is actually malicious.

| Confidence Range | Interpretation | Examples |
| :--- | :--- | :--- |
| **1.3 – 1.5** | High | Explicit SQLi payload match, confirmed parameter fuzzing |
| **1.0 – 1.2** | Medium | Repeated failed logins, headless browser user-agents |
| **0.5 – 0.8** | Low | Missing mouse telemetry (could be a mobile user or keyboard navigation) |

### 2.3 Persistence Modifier
The Persistence Modifier increases the severity of repeated malicious actions within the same session.

* Initial value starts at **1.0**.
* Increases by `0.2` for every subsequent malicious action.
* Maximum cap is **1.6**.

This mechanism creates an escalating risk curve for persistent attackers. A single directory traversal attempt generates a moderate score, but the 10th repeated traversal attempt significantly amplifies the event score, ensuring the attacker rapidly crosses the blocking threshold.

---

## 3. Session Aggregation and Behavioral Correlation

SIDERIS maintains a persistent session state for each user or client interaction in Redis (`sideris:session:{sid}`). Instead of relying solely on isolated events, the system aggregates behavioral patterns over time to detect advanced attack strategies.

When specific attack patterns are confirmed across multiple requests, the `SessionTracker` applies additional **Behavioral Bonus Scores**.

### 3.1 Behavioral Bonus Rules

| Attack Pattern | Detection Condition | Bonus Score | Category |
| :--- | :--- | :--- | :--- |
| **Credential Stuffing** | $\ge$ 20 rapid login attempts + $\ge$ 15 failures | **+15** | Authentication |
| **Password Spraying** | $\ge$ 3 usernames targeted + $\ge$ 5 logins | **+12** | Authentication |
| **Brute Force Attack** | $\ge$ 15 failed login attempts | **+10** | Authentication |
| **Directory Fuzzing** | $\ge$ 100 HTTP 404 responses | **+12** | Fuzzing |
| **Parameter Fuzzing** | $\ge$ 50 payload variations | **+10** | Fuzzing |
| **DoS Flooding** | $\ge$ 50 non-normal requests within 60 seconds | **+15** | Denial of Service |
| **Endpoint Hammering**| $\ge$ 20 requests to the exact same endpoint in 60s | **+10** | Denial of Service |

These bonuses allow the engine to identify coordinated attack behavior even when individual requests appear relatively harmless (e.g., a single failed login is benign, but 20 failed logins is an attack).

---

## 4. Decision Matrix and Automated Enforcement

The total Session Score is the sum of all individual Event Scores plus any triggered Behavioral Bonuses. The resulting score is passed to the `DecisionEngine` to determine the final threat classification and automated mitigation response.

| Session Score | Threat Level | Enforcement Action | Description |
| :--- | :--- | :--- | :--- |
| **50+** | **CRITICAL** | `hard_block` | Immediate HTTP 403 block. Persistent (no TTL). Requires manual SOC analyst unblock. |
| **30+** | **VERY HIGH** | `soft_block` | Temporary HTTP 403 block with a 30-minute expiration. |
| **20+** | **HIGH** | `challenge` | CAPTCHA verification required (10-minute TTL). |
| **10+** | **SUSPICIOUS**| `rate_limit` | Request throttling applied via reverse proxy. |
| **< 10** | **NORMAL** | `allow` | Request forwarded normally to the application. |

---

## 5. Security Operations Center (SOC) Dashboard

SIDERIS includes a comprehensive, real-time React dashboard for security analysts to monitor the system state and investigate flagged sessions.

### 5.1 Global Metrics Overview
The top of the dashboard displays high-level system health metrics:
* **Total Risk Score:** The aggregate sum of all active session risk scores.
* **Events Analyzed:** The total number of HTTP requests and telemetry events processed by the ingest pipeline.
* **High Risk Sessions:** The count of currently active sessions that have crossed the suspicious threshold.

### 5.2 Session List
A real-time list of all active sessions, sorted by their Risk Score (highest first). Each row displays:
* Session ID (truncated for readability).
* Total Accumulated Risk Score.
* Threat Level Badge (Normal, Suspicious, High, Very High, Critical).
* Enforcement Action Badge (Allow, Blocked).
* Total Event Count and Last Seen timestamp.

### 5.3 Expanded Session Intelligence
When an analyst clicks on a specific session, an expanded forensics view is revealed, containing detailed metadata required for incident response:

#### A. Attack Category Breakdown
A visual bar-chart breakdown showing exactly how many events fall into the 6 core SIDERIS threat categories:
1. **Authentication:** Failed logins, brute force, credential stuffing.
2. **Injection:** SQLi, XSS, CMDi, SSTI, XXE.
3. **Fuzzing:** Directory traversal, parameter fuzzing, 404 probing.
4. **Bot / Automation:** Rapid form fills, missing mouse telemetry, headless browsers.
5. **Denial of Service:** Request floods, endpoint hammering.
6. **Session Abuse:** IP hopping, abnormal navigation flows.

#### B. Session Intelligence Metadata
Detailed counters and flags extracted during behavioral tracking:
* **Login Attempts:** Total authentication requests made.
* **Unique Usernames:** Total distinct accounts targeted (indicates password spraying).
* **404 Hits:** Total non-existent routes accessed (indicates directory scanning).
* **Scanner Detected:** Boolean flag indicating if automated scanning tools (e.g., Nikto, Burp Suite, sqlmap) were identified.
* **Block Type:** Shows if the session is under a `hard` or `soft` block.
* **User Agent:** The raw HTTP User-Agent string provided by the client.

#### C. Triggered Rule Badges
A series of visual tags indicating the specific behavioral bonuses that were applied to the session (e.g., `inline_sql_injection`, `brute_force`, `endpoint_hammer`).

#### D. Behavior Timeline
A chronological audit log of the most recent malicious events in the session. Each entry details:
* The exact endpoint targeted (e.g., `POST /rest/user/login`).
* The classification type (e.g., `auth_failure`).
* The specific risk score delta applied to the session by that exact event (e.g., `+3.6 points`).

#### E. Analyst Actions
Buttons allowing the SOC analyst to manually intervene:
* **Block Session:** Instantly applies a permanent `hard_block` to the session.
* **Unblock Session:** Instantly removes all guard directives and resets the session's risk score to 0, allowing traffic to resume.

### 5.4 Active Defense Matrix
A secondary panel displaying the active `Guards` currently enforced by the proxy. It shows a table of all sessions currently being mitigated, the specific enforcement action applied (`block`, `challenge`, `rate_limit`), the type of block, the final risk score that triggered the action, and the relative time since the block was applied.

---

## 6. Inline Critical Payload Defense (Zero-Day Protection)

Because behavioral scoring operates asynchronously, there exists a potential race-condition delay between an attack's execution and its threat classification by the Detection Worker. 

To eliminate this risk, SIDERIS implements an **Inline Defense Layer** directly within the proxy middleware.

The inline protection process operates as follows:
1. Every request is intercepted before reaching the backend application.
2. The Proxy evaluates the full URL, query parameters, and raw `POST` bodies.
3. Critical attack signatures are matched using a strict set of regex rules.
4. If a match is detected:
   * The request is immediately terminated.
   * A silent HTTP 403 JSON response is returned to the attacker.
   * A `hard_block` directive with a score of `100` is immediately written to Redis.
   * Session state is updated synchronously so the dashboard immediately reflects the Injection attempt.
   * An event is fired to the Ingest layer so the Detection Worker includes the block in the Behavior Timeline.

This hybrid mechanism ensures that high-risk payloads are blocked instantly, while maintaining the deep, longitudinal analysis required to catch stealthy behavioral anomalies.
