# SIDERIS Browser Agent Reference

SIDERIS uses a lightweight browser telemetry agent (`agent.js`) injected dynamically into the `<head>` of HTML responses by the WAF proxy. The agent collects behavioral signals, mouse movements, keyboard cadence, and environment fingerprints, streaming them back to the decision engine.

---

## 1. What Telemetry is Collected?

To protect user privacy, the agent does **not** collect sensitive text inputs, password field content, or personal identifiers. It tracks behavioral biometrics and environment attributes to verify browser legitimacy.

### A. Behavioral Biometrics
* **Mouse Movements**: Movement vectors, speed, and jitter are sampled to check if the mouse is driven by a human arm or simulated via automated coordinates (which often move in straight lines or jump instantly).
* **Keyboard Cadence**: Interval timings (time between keystrokes) are analyzed. Inhuman speeds (e.g., >10 keystrokes in under 500ms) or perfectly consistent gaps suggest robotic input (like clipboard paste emulation).
* **Scroll Dynamics**: Scroll speed and acceleration patterns.
* **Form Submissions**: Measures the time elapsed between form focus and form submission. Automated scripts submitting forms in under 800ms (`instant_form_fill`) are flagged.

### B. Device Environment (Fingerprint)
The agent queries the window browser objects to build a hardware profile:
* **System Metrics**: Screen resolution, color depth, browser language, timezone, device RAM, and hardware concurrency (CPU core count).
* **Feature Detection**: WebGL renderer engine name, touch support, and plugins count.
* **Automated Client Identifiers**: Verifies the presence of `navigator.webdriver` (which is `true` in Selenium, Puppeteer, Playwright, and headless chrome).

---

## 2. Session Synchronization Mechanics

SIDERIS coordinates request tracking across both client-side and server-side interactions:

1. **Proxy Injection**: When a user first hits a page, the WAF proxy resolves or generates a session UUID and sets a client cookie: `sideris_sid`.
2. **Telemetry Handshake**: The browser loads `/sideris/agent.js`, reads the cookie, and initializes the local session tracker.
3. **HTTP Monkey Patching**: The agent interceptor overrides the browser's global `window.fetch` and `XMLHttpRequest` objects. For every outgoing client request, it automatically appends the custom header:
   ```http
   X-Sideris-Session: <session_id>
   ```
4. **Proxy Association**: The WAF proxy matches the `X-Sideris-Session` header (or the `sideris_sid` cookie) to identify the user's active risk score state in Redis before executing guard checks.

---

## 3. Content Security Policy (CSP) Compatibility

If the target web application has a strict Content Security Policy (CSP) header, it might block the SIDERIS agent from executing. 

Because SIDERIS routes all telemetry relative to your own domain, **you do not need to whitelist external endpoints**. Simply ensure your CSP includes the following directives:

```http
Content-Security-Policy: 
  script-src 'self'; 
  connect-src 'self';
```

### Explanation:
* `script-src 'self'`: Allows the browser to load `/sideris/agent.js` which is hosted on the same origin.
* `connect-src 'self'`: Allows the agent to post behavioral logs and alerts back to `/sideris/ingest`.

If your target application's CSP relies on a **nonce** for scripts, you can write a proxy modification rule to inject the nonce into the SIDERIS script tag:
```html
<!-- Proxy will automatically inject the script: -->
<script src="/sideris/agent.js" defer></script>
```

---

## 4. Telemetry Exclusions

To prevent clogging server logs and telemetry streams, the agent automatically ignores request patching for WebSocket traffic and Hot Module Replacement (HMR) patterns:
* `/socket.io/`
* `/__webpack_hmr`
* `/sockjs-node/`

You can extend the `EXCLUDED_URL_PATTERNS` array inside [src/agent/agent.js](file:///home/merlin/Codes/SIDERIS%203.0/SIDERIS/src/agent/agent.js#L28-L34) to add your own APIs that should bypass telemetry reporting.
