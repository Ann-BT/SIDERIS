<p align="center">
  <img src="./screenshots/banner.png" alt="SIDERIS" width="100%" style="border-radius: 12px;"/>
</p>

<div align="center">
<pre>
<a href="#about">ABOUT</a>  •  <a href="#quick-start">QUICK START</a>  •  <a href="#architecture">ARCHITECTURE</a>  •  <a href="#gallery">GALLERY</a>  •  <a href="#configuration">CONFIGURATION</a>  •  <a href="#license">LICENSE</a>
</pre>
</div>

<br>

<div align="center">
  <h3>If SIDERIS helps protect your website, please support the project by leaving a Star!</h3>
</div>

<br>

<a id="about"></a>
<h2 align="center">ABOUT</h2>

SIDERIS (Sidecar Integrated Detection, Event Reporting, and Intelligence System) is a real-time web application firewall (WAF) and client-side behavioral analysis proxy. 

SIDERIS sits in front of your website like a reverse proxy with severe trust issues. It intercepts user traffic, automatically injects a client-side telemetry agent into served HTML, statefully scores user behavior in real time, and dynamically enforces progressive defenses (like rate-limiting, CAPTCHAs, or IP blocks) when risk thresholds are crossed.

Because hoping your users will play nice is not a security strategy.

---

### Why Webmasters Choose SIDERIS

* **Works With Any Stack**: Whether your website is built on WordPress, PHP, Laravel, Node.js, Python, Ruby, or is just static HTML, SIDERIS runs as a standalone sidecar.
* **Zero Application Code Changes**: You do not need to install plugins or rewrite a single line of backend database or application code.
* **Protects Against Zero-Days**: By statefully monitoring behavioral telemetry (such as typing patterns, mouse tracking, and browser environment signals) rather than relying only on signature databases, it stops sophisticated bots and manual attacks that bypass traditional WAFs.

---

> [!IMPORTANT]
> SIDERIS operates transparently. Simply run SIDERIS in front of your website server and point your public traffic to it.

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="quick-start"></a>
<br>
<h2 align="center">60-SECOND QUICK START</h2>

To deploy SIDERIS in front of your website right now:

### 1. Download SIDERIS
```bash
git clone https://github.com/Ann-BT/SIDERIS.git
cd SIDERIS
```

### 2. Configure Environment
Create your config file:
```bash
cp .env.example .env
```
Open `.env` in a text editor and update:
* `TARGET_URL`: Point this to your existing website (e.g., `http://localhost:8080`).
* `PROXY_PORT`: The public port where users will now access your site through SIDERIS (default `4000`).

### 3. Run SIDERIS
```bash
docker compose up -d --build
```

Access your website at `http://your-server-ip:4000`. You are now protected.

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="architecture"></a>
<br>
<h2 align="center">ARCHITECTURE</h2>

SIDERIS acts as a protective shield between public traffic and your real web application server:

```
                      [ Public Internet ]
                              │
                              ▼ (Ports 80/443)
                      [ Reverse Proxy / SSL ]
                      (e.g., Nginx, Cloudflare)
                              │
                              ▼ (Port 4000)
                      ┌───────────────────────┐
                      │    SIDERIS WAF PROXY  │ ◄── [ Injects agent.js ]
                      └──────────┬────────────┘
                                 │
                                 ▼ (Port 8080 / Localhost)
                       [ Your Web Application ]
                       (WordPress, Node.js, PHP)
```

1. **User traffic** hits the WAF Proxy first.
2. SIDERIS intercepts the HTML responses and automatically injects the telemetry agent (`agent.js`) into the browser.
3. The browser agent streams client-side behavior telemetry (typing speeds, mouse tracking, autofill) back to the ingestion endpoint (`:5000`).
4. Telemetry is streamed into **Redis** for real-time scoring.
5. High-risk actions trigger the **Guard Service** to apply mitigations (rate-limiting, challenges) immediately.
6. Persistent logs and security events are archived in **PostgreSQL** for analysis on the React-based **SOC Dashboard** (`:5173`).

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="gallery"></a>
<br>
<h2 align="center">GALLERY</h2>

### 1. Security Operations Center (SOC) Dashboard
This React-based interface lists active sessions, visualizes live risk scores, breaks down threat categories, and allows analysts to manually block or unblock sessions.

<p align="center">
  <img src="./screenshots/dashboard.png" alt="SIDERIS SOC Dashboard" width="100%" style="border-radius: 8px; border: 1px solid #d0d7de;"/>
</p>

### 2. Adaptive Guard Challenge overlay
Suspicious sessions are prompted with a server-generated verification overlay. Successful completion resets active guards and restores access.

<p align="center">
  <img src="./screenshots/captcha.png" alt="SIDERIS CAPTCHA Overlay" width="100%" style="border-radius: 8px; border: 1px solid #d0d7de;"/>
</p>

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="configuration"></a>
<br>
<h2 align="center">CONFIGURATION</h2>

SIDERIS parameters can be customized via `.env` file variables:

| Variable | Default | Description |
|:---|:---|:---|
| `TARGET_URL` | `http://localhost:8080` | The URL of your web application SIDERIS will protect |
| `PROXY_PORT` | `4000` | The public port where users access your site through the proxy |
| `REDIS_URL` | `redis://localhost:6379` | Connection string for your Redis stream database |
| `POSTGRES_URL` | `postgresql://sideris:sideris...` | Connection string for your PostgreSQL SOC database |
| `DASHBOARD_ALLOWED_IPS` | `127.0.0.1,::1` | Access list of IPs authorized to load the SOC dashboard |

For advanced settings and native (non-Docker) setup, check the **[Deployment and Configuration Guide](./DEPLOYMENT.md)**.

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="license"></a>
<br>
<h2 align="center">LICENSE</h2>

SIDERIS is open-source software licensed under the **[MIT License](./LICENSE)**. Free to download, modify, and deploy for personal or commercial websites.
