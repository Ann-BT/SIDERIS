<a id="sideris"></a>
<p align="center">
  <img src="./screenshots/banner.png" alt="SIDERIS" width="100%" style="border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5);"/>
</p>

<p align="center">
  <a href="#about"><img src="https://img.shields.io/badge/ABOUT-black?style=for-the-badge&color=0969da&labelColor=161b22&logo=info&logoColor=white"/></a>&nbsp;
  <a href="#quick-start"><img src="https://img.shields.io/badge/QUICK_START-black?style=for-the-badge&color=1f883d&labelColor=161b22&logo=docker&logoColor=white"/></a>&nbsp;
  <a href="#architecture"><img src="https://img.shields.io/badge/ARCHITECTURE-black?style=for-the-badge&color=e0af68&labelColor=161b22&logo=securityscorecard&logoColor=white"/></a>&nbsp;
  <a href="#gallery"><img src="https://img.shields.io/badge/GALLERY-black?style=for-the-badge&color=bb9af7&labelColor=161b22&logo=react&logoColor=white"/></a>&nbsp;
  <a href="#configuration"><img src="https://img.shields.io/badge/CONFIG-black?style=for-the-badge&color=7aa2f7&labelColor=161b22&logo=dotenv&logoColor=white"/></a>&nbsp;
  <a href="#contact"><img src="https://img.shields.io/badge/CONTACT-black?style=for-the-badge&color=47a2f7&labelColor=161b22&logo=gmail&logoColor=white"/></a>&nbsp;
  <a href="#license"><img src="https://img.shields.io/badge/LICENSE-black?style=for-the-badge&color=57606a&labelColor=161b22&logo=license&logoColor=white"/></a>
</p>

<p align="center">
  <a href="https://github.com/Ann-BT/SIDERIS/stargazers"><img src="https://img.shields.io/github/stars/Ann-BT/SIDERIS?style=for-the-badge&color=9ece6a&labelColor=161b22&logo=github&logoColor=white"/></a>&nbsp;
  <a href="https://github.com/Ann-BT/SIDERIS"><img src="https://img.shields.io/github/repo-size/Ann-BT/SIDERIS?style=for-the-badge&color=e0af68&labelColor=161b22&logo=git&logoColor=white"/></a>
</p>

<div align="center">
<pre>
<a href="#about">ᴀʙᴏᴜᴛ</a>  •  <a href="#quick-start">ǫᴜɪᴄᴋ sᴛᴀʀᴛ</a>  •  <a href="#architecture">ᴀʀᴄʜɪᴛᴇᴄᴛᴜʀᴇ</a>  •  <a href="#gallery">ɢᴀʟʟᴇʀʏ</a>  •  <a href="#configuration">ᴄᴏɴꜰɪɢᴜʀᴀᴛɪᴏɴ</a>  •  <a href="#contact">ᴄᴏɴᴛᴀᴄᴛ</a>  •  <a href="#license">ʟɪᴄᴇɴsᴇ</a>
</pre>
</div>

<br>

<div align="center">
  <h3>🛡️ If SIDERIS helps protect your website, please support the project by leaving a Star! 🛡️</h3>
  <i>💡 Tip: Click any section header badge or the "Back to Top" buttons to return to the top navigation.</i>
</div>

<br>

<a id="about"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-ABOUT%20SIDERIS-0969da?style=for-the-badge&labelColor=161b22&logo=info&logoColor=white" height="60" alt="About SIDERIS"/></a>
</p>
<br>

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
<p align="right"><a href="#sideris"><img src="https://img.shields.io/badge/Back%20To%20Top-161b22?style=flat-square&logo=arrow-up&logoColor=white" alt="Back to Top"/></a></p>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="quick-start"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-60--SECOND%20QUICK%20START-1f883d?style=for-the-badge&labelColor=161b22&logo=docker&logoColor=white" height="60" alt="Quick Start"/></a>
</p>
<br>

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
<p align="right"><a href="#sideris"><img src="https://img.shields.io/badge/Back%20To%20Top-161b22?style=flat-square&logo=arrow-up&logoColor=white" alt="Back to Top"/></a></p>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="architecture"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-ARCHITECTURE-e0af68?style=for-the-badge&labelColor=161b22&logo=nginx&logoColor=white" height="60" alt="Architecture"/></a>
</p>
<br>

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
<p align="right"><a href="#sideris"><img src="https://img.shields.io/badge/Back%20To%20Top-161b22?style=flat-square&logo=arrow-up&logoColor=white" alt="Back to Top"/></a></p>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="gallery"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-VISUAL%20GALLERY-bb9af7?style=for-the-badge&labelColor=161b22&logo=react&logoColor=white" height="60" alt="Gallery"/></a>
</p>
<br>

<table>
  <tr>
    <td width="50%" align="center" valign="top">
      <b>1. Automatic Telemetry Injection</b><br>
      <i>The WAF reverse proxy intercepts traffic and injects <code>agent.js</code> seamlessly without site modifications.</i>
      <br><br>
      <img src="./screenshots/agent_injection.png" alt="Agent Injection" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"/>
    </td>
    <td width="50%" align="center" valign="top">
      <b>2. Adaptive CAPTCHA Challenge</b><br>
      <i>Suspicious sessions trigger a server-generated captcha overlay to verify human presence.</i>
      <br><br>
      <img src="./screenshots/captcha.png" alt="CAPTCHA Challenge" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"/>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center" valign="top">
      <b>3. Hard Block Screen</b><br>
      <i>Malicious request patterns or manual blocks result in an immediate proxy level connection lockout.</i>
      <br><br>
      <img src="./screenshots/blocked_screen.png" alt="Block Screen" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"/>
    </td>
    <td width="50%" align="center" valign="top">
      <b>4. SOC Dashboard Live Streams</b><br>
      <i>The React interface aggregates live sessions, color-coded risk indexes, and active connection metadata.</i>
      <br><br>
      <img src="./screenshots/dashboard.png" alt="SOC Dashboard" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"/>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center" valign="top">
      <b>5. Forensic Session Timeline</b><br>
      <i>Detailed inspection of triggered signature rules, timing heuristics, and analyst block overrides.</i>
      <br><br>
      <img src="./screenshots/session_detail.png" alt="Forensic Timeline" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"/>
    </td>
    <td width="50%" align="center" valign="top">
      <b>6. Active Defense Matrix</b><br>
      <i>Filter, search, and audit all active rate limits, challenges, and blocks currently enforced on Redis.</i>
      <br><br>
      <img src="./screenshots/defense_matrix.png" alt="Defense Matrix" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"/>
    </td>
  </tr>
</table>

<br>

<p align="center">
  <b>7. Dynamic Scoring & Guide Modal</b><br>
  <i>In-dashboard modal displaying scoring formulas, cooling decay metrics, and SIDERIS's 13 correlation rules.</i>
  <br><br>
  <img src="./screenshots/runtime_guide.png" alt="Scoring Guide Modal" width="100%" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

<br>
<p align="right"><a href="#sideris"><img src="https://img.shields.io/badge/Back%20To%20Top-161b22?style=flat-square&logo=arrow-up&logoColor=white" alt="Back to Top"/></a></p>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="configuration"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-CONFIGURATION-7aa2f7?style=for-the-badge&labelColor=161b22&logo=dotenv&logoColor=white" height="60" alt="Configuration"/></a>
</p>
<br>

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
<p align="right"><a href="#sideris"><img src="https://img.shields.io/badge/Back%20To%20Top-161b22?style=flat-square&logo=arrow-up&logoColor=white" alt="Back to Top"/></a></p>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="contact"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-GET%20IN%20TOUCH-47a2f7?style=for-the-badge&labelColor=161b22&logo=gmail&logoColor=white" height="60" alt="Contact"/></a>
</p>
<br>

For inquiries, support, or security discussions:
* **Email**: [anbt.personal@gmail.com](mailto:anbt.personal@gmail.com)
* **Facebook**: [Ann-BT / Merlin the Great Mage](https://www.facebook.com/merlinthegreatmage)

<br>
<p align="right"><a href="#sideris"><img src="https://img.shields.io/badge/Back%20To%20Top-161b22?style=flat-square&logo=arrow-up&logoColor=white" alt="Back to Top"/></a></p>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="license"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-LICENSE-57606a?style=for-the-badge&labelColor=161b22&logo=open-source-initiative&logoColor=white" height="60" alt="License"/></a>
</p>
<br>

SIDERIS is open-source software licensed under the **[MIT License](./LICENSE)**. Free to download, modify, and deploy for personal or commercial websites.

<br>
<p align="right"><a href="#sideris"><img src="https://img.shields.io/badge/Back%20To%20Top-161b22?style=flat-square&logo=arrow-up&logoColor=white" alt="Back to Top"/></a></p>
