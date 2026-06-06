<a id="sideris"></a>

<p align="center">
  <img src="./screenshots/banner.png" alt="SIDERIS" width="100%" style="border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5);"/>
</p>

<p align="center">
  <a href="#about"><img src="https://img.shields.io/badge/WHAT_IS_THIS-black?style=for-the-badge&color=0969da&labelColor=161b22&logo=info&logoColor=white"/></a>&nbsp;
  <a href="#in-action"><img src="https://img.shields.io/badge/SEE_IT_WORK-black?style=for-the-badge&color=bb9af7&labelColor=161b22&logo=react&logoColor=white"/></a>&nbsp;
  <a href="#how-it-works"><img src="https://img.shields.io/badge/HOW_IT_WORKS-black?style=for-the-badge&color=e0af68&labelColor=161b22&logo=securityscorecard&logoColor=white"/></a>&nbsp;
  <a href="#quick-start"><img src="https://img.shields.io/badge/INSTALL_NOW-black?style=for-the-badge&color=1f883d&labelColor=161b22&logo=docker&logoColor=white"/></a>&nbsp;
  <a href="#configuration"><img src="https://img.shields.io/badge/CONFIG-black?style=for-the-badge&color=7aa2f7&labelColor=161b22&logo=dotenv&logoColor=white"/></a>&nbsp;
  <a href="#contact"><img src="https://img.shields.io/badge/CONTACT-black?style=for-the-badge&color=47a2f7&labelColor=161b22&logo=gmail&logoColor=white"/></a>
</p>

<p align="center">
  <a href="https://github.com/Ann-BT/SIDERIS/stargazers"><img src="https://img.shields.io/github/stars/Ann-BT/SIDERIS?style=for-the-badge&color=9ece6a&labelColor=161b22&logo=github&logoColor=white"/></a>
</p>

<div align="center">
  <code>Node.js</code> • <code>React</code> • <code>Redis</code> • <code>PostgreSQL</code> • <code>Docker</code>
</div>


<br>

<div align="center">

### Your website is being probed right now. Bots, scrapers, credential stuffers — they don't knock.
### SIDERIS answers the door for you. With a baseball bat.

*⭐ If SIDERIS saved your server from a bad day, the star button is right up there. I run on dopamine and instant ramen.*

</div>

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="about"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-WHAT_IS_SIDERIS-0969da?style=for-the-badge&labelColor=161b22&logo=info&logoColor=white" height="55"/></a>
</p>
<br>

**The problem:** You built a website. Somewhere between launching it and now, bots started hammering your login page, scrapers are stealing your content, and someone in Eastern Europe is fuzzing your endpoints at 3 AM. Your application has no idea any of this is happening.

**The solution:** SIDERIS — a **real-time WAF (Web Application Firewall) and behavioral analysis proxy** that sits in front of your website like a suspicious bouncer who has seen too much.

It intercepts every visitor, silently watches how they behave (typing speed, mouse movement, browser fingerprint, request patterns), builds a live threat score, and when that score gets ugly — it acts. Rate-limits, CAPTCHA challenges, or a hard block, automatically, before the bad traffic ever touches your actual server.

| Without SIDERIS (Chaos) | With SIDERIS (Order) |
|:---|:---|
| Bot &rarr; `[YOUR SERVER]` | Bot &rarr; `[SIDERIS]` &rarr; ✋ *"I don't think so."* |
| Scraper &rarr; `[YOUR SERVER]` | Scraper &rarr; `[SIDERIS]` &rarr; 🤔 *CAPTCHA challenge* |
| Human &rarr; `[YOUR SERVER]` | Human &rarr; `[SIDERIS]` &rarr; ✅ `[YOUR SERVER]` |
| Attacker &rarr; `[YOUR SERVER]` | Attacker &rarr; `[SIDERIS]` &rarr; 🚫 *Banned* |


**The best part:** You don't change a single line of your application code. SIDERIS is a sidecar — it runs alongside your existing website, whatever stack it's on.

<br>

### What makes SIDERIS different from a normal WAF?

Most WAFs check requests against a list of known bad patterns (signatures). Smart attackers just... don't use those patterns. SIDERIS watches *behavior* instead — how a real human types vs. how a bot fills forms, whether a session looks organic or scripted, whether the browser environment makes sense. You can't fake being human when something is measuring how you move your mouse.

<br>

### Works with literally anything

| Your stack | Does SIDERIS work? |
|:---|:---|
| WordPress | ✅ Yes |
| Laravel / PHP | ✅ Yes |
| Node.js / Express | ✅ Yes |
| Django / Flask | ✅ Yes |
| Static HTML | ✅ Yes |
| Something weird you built in 2011 | ✅ Probably yes |

If it serves HTTP, SIDERIS can protect it. No plugins. No code changes. No rearchitecting anything.

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="in-action"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-SEE_IT_IN_ACTION-bb9af7?style=for-the-badge&labelColor=161b22&logo=react&logoColor=white" height="55"/></a>
</p>
<br>

> These are real screenshots from a running SIDERIS instance. No Figma files, no placeholder text, no lies.

<br>

### SIDERIS in Action: Features

Here is a walkthrough of the SIDERIS interface, starting with the full dashboard overview, followed by its sections ordered from the top of the screen to the bottom, and finally the client-side injection and security intercept screens.

#### 1. Central SOC Dashboard
<p align="center">
  <img src="./screenshots/banner.png" alt="SIDERIS SOC Dashboard" width="800" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

The central cockpit and primary control room of SIDERIS. It aggregates active visitor counts, real-time threat scores, active block percentages, and live telemetry feeds into a single unified workspace—perfect for leaving open on a second monitor to look busy when your boss walks past.

<br>

#### 2. Appearance Theme Selector
<p align="center">
  <img src="./screenshots/theme_picker.png" alt="Theme Selector" width="800" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

Located in the top header. Change color schemes on the fly between Tokyo Night, Catppuccin, Nord, and Dracula. Because defending your database from automated scrapers is serious business, but doing it in an ugly default layout is a tragedy.

<br>

#### 3. Runtime Scoring Guide
<p align="center">
  <img src="./screenshots/runtime_guide.png" alt="Scoring Guide" width="800" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

Accessed from the top header navigation. This is an interactive manual explaining the WAF's threat equations, correlation rules, and decay math—perfect bedtime reading for when you want to study the exact logic of the heuristic engine.

<br>

#### 4. Event Summary Metrics
<p align="center">
  <img src="./screenshots/event_summary_metrics.png" alt="Event Summary Metrics" width="480" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

Sitting in the top row of the dashboard canvas. A high-level KPI widget showing today's deflected attacks and active blocks. It's the ultimate chart to copy-paste into your monthly report to justify your cybersecurity budget and existence.

<br>

#### 5. Top Offenders Leaderboard
<p align="center">
  <img src="./screenshots/top_ips.png" alt="Top Attacking IPs" width="450" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

Positioned in the upper-right dashboard grid. The SIDERIS Hall of Shame. A ranked leaderboard of the most aggressive attacker subnets and scrapers that tried their best, got blocked immediately, and now have their IPs permanently memorialized.

<br>

#### 6. Dashboard Access Log
<p align="center">
  <img src="./screenshots/dashboard_access_log.png" alt="Dashboard Access Log" width="450" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

Placed in the upper metrics row. A strict self-audit panel logging every dashboard log-in attempt. SIDERIS is so paranoid it doesn't even trust you, meaning if you mistype your admin credentials, you will log yourself as a threat.

<br>

#### 7. Live Sessions Monitor
<p align="center">
  <img src="./screenshots/live_sessions.png" alt="Live Sessions Monitor" width="800" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

The main central table of the dashboard. A real-time grid tracking every active visitor. It color-codes sessions by risk level (green is human, red is script) so you can watch scrapers trying to brute-force your pages and giggle as their threat scores spike.

<br>

#### 8. Session Detail Deep Dive
<p align="center">
  <img src="./screenshots/session_expand.png" alt="Session Detail Expansion" width="800" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

Opened by expanding any row in the center grid. The forensic investigator panel. Expand any active user to inspect their triggered correlation rules, keystroke timings, and mouse heatmaps—complete with a massive manual ban button for when automated filtering isn't satisfying enough.

<br>

#### 9. Active Defense Matrix
<p align="center">
  <img src="./screenshots/defense_matrix.png" alt="Active Defense Matrix" width="800" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

Located near the bottom half of the dashboard. A live registry of every active ban, rate-limit, and CAPTCHA challenge currently registered in Redis. If a real user accidentally gets flagged, you can grant them parole with a single click.

<br>

#### 10. Live Multi-Service Logs Console
<p align="center">
  <img src="./screenshots/live_logs.png" alt="Live Logs Console" width="800" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

Embedded at the bottom of the dashboard. An integrated console combining stdout logs from your proxy, ingest, and detector containers. It looks like the Matrix code, except it actually contains useful information instead of green rain.

<br>

#### 11. Transparent Telemetry Injection
<p align="center">
  <img src="./screenshots/storefront.png" alt="Normal Client Storefront" width="600" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

Behind the scenes at the client storefront. SIDERIS intercepts outgoing HTML on the fly to silently inject a tiny tracking agent (`agent.js`) into the page context. It maps mouse movements and keystroke dynamics in the shadows, tracking user behavior without you changing a single line of application code. It's like having a private investigator watch every visitor from the bushes, except it's completely legal and doesn't get tired.

<br>

#### 12. Adaptive CAPTCHA Challenge
<p align="center">
  <img src="./screenshots/captcha.png" alt="Adaptive CAPTCHA Challenge" width="380" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

The security gate served directly to visitors in their browser. Suspected bots get hit with a CAPTCHA mid-session, trapping automated scrapers in an infinite loop of identifying traffic lights while actual humans pass right through.

<br>

#### 13. Hard Block Screen
<p align="center">
  <img src="./screenshots/blocked_screen.png" alt="Hard Block Screen" width="650" style="border-radius: 8px; border: 1px solid #d0d7de; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"/>
</p>

The block page shown to banned visitors. Confirmed threat actors get their TCP connections dropped at the proxy level before they ever touch your actual application server, saving your CPU cycles and database from useless queries.

<br>

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="how-it-works"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-HOW_IT_WORKS-e0af68?style=for-the-badge&labelColor=161b22&logo=securityscorecard&logoColor=white" height="55"/></a>
</p>
<br>

Think of SIDERIS as a bouncer who never sleeps, never gets bribed, and has a perfect memory.

Every visitor to your website goes through SIDERIS first. SIDERIS quietly injects a tiny JavaScript agent into the HTML it serves — invisible to the visitor, invisible to your app. That agent streams behavioral telemetry back in real time: how fast they type, how they move their mouse, whether they're using a real browser or impersonating one.

All of that feeds into a live scoring engine. The score is calculated continuously using `Impact × Confidence × Persistence` across 5 escalating enforcement tiers. When the score crosses a threshold, SIDERIS acts — automatically, without you having to do anything.

```
[ Visitor ]
    │
    ▼ (port 4000 — the only port your users ever see)
┌─────────────────────────────────┐
│         SIDERIS WAF PROXY       │
│  • Intercepts all HTTP traffic  │
│  • Injects agent.js into HTML   │
│  • Enforces active blocks       │
└──────────────┬──────────────────┘
               │                         ┌─────────────────────┐
               │ (forwards clean traffic) │   agent.js running  │
               ▼ (port 8080)             │   in visitor browser │
    [ Your Web Application ]             │   streams telemetry ↓│
    (unchanged, unaware, happy)          └──────────┬──────────┘
                                                    │
                                         (port 5000 — ingest)
                                                    │
                                                    ▼
                                         ┌─────────────────────┐
                                         │   Scoring Engine     │
                                         │   Redis (live state) │
                                         │   Guard Service      │
                                         └──────────┬──────────┘
                                                    │
                                         ┌──────────▼──────────┐
                                         │     PostgreSQL       │
                                         │   (event archive)    │
                                         └──────────┬──────────┘
                                                    │
                                         ┌──────────▼──────────┐
                                         │   SOC Dashboard      │
                                         │   (port 6001)        │
                                         │   your window into   │
                                         │   all of the above   │
                                         └─────────────────────┘
```

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="quick-start"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-INSTALL_IN_60_SECONDS-1f883d?style=for-the-badge&labelColor=161b22&logo=docker&logoColor=white" height="55"/></a>
</p>
<br>

You need: **Docker** and **Docker Compose**. That's it. No Node.js installation. No PostgreSQL setup. No Redis configuration. Docker handles the entire stack.

> [!IMPORTANT]
> SIDERIS runs as a sidecar in front of your existing website. Your website keeps running exactly as it is — you just point traffic through SIDERIS first.

<br>

### Step 1 — Clone

```bash
git clone https://github.com/Ann-BT/SIDERIS.git
cd SIDERIS
```

### Step 2 — Configure (30 seconds)

```bash
cp .env.example .env
```

Open `.env` and set two values:

```env
# Where is your existing website running?
TARGET_URL=http://localhost:8080

# What port should SIDERIS listen on? (your users will hit this)
PROXY_PORT=4000
```

Everything else has sensible defaults. You can tune it later.

### Step 3 — Launch

```bash
docker compose up -d --build
```

That's it. Your website is now at `http://your-server-ip:4000` and SIDERIS is watching.

The SOC dashboard comes up at `http://localhost:6001` — accessible from your machine only by default (see [Configuration](#configuration) to add more IPs).

<br>

### What just started?

```
sideris-proxy      → port 4000   (the WAF, faces the internet)
sideris-ingest     → port 5000   (receives agent.js telemetry)
sideris-dashboard  → port 6001   (your SOC panel)
sideris-redis      → internal    (live session state)
sideris-postgres   → internal    (event archive)
```

All five services talk to each other over an internal Docker network. Nothing except ports 4000, 5000, and 6001 are exposed.

<br>

> [!TIP]
> **Production deployment**: Put Nginx or Cloudflare in front of SIDERIS on ports 80/443 for SSL. SIDERIS handles the security logic; let your reverse proxy handle TLS termination.

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="configuration"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-CONFIGURATION-7aa2f7?style=for-the-badge&labelColor=161b22&logo=dotenv&logoColor=white" height="55"/></a>
</p>
<br>

All configuration lives in `.env`. Here's what every variable does:

| Variable | Default | What it does |
|:---|:---|:---|
| `TARGET_URL` | `http://localhost:8080` | Your actual website. SIDERIS forwards clean traffic here. |
| `PROXY_PORT` | `4000` | The public-facing port. This is what your users connect to. |
| `INGEST_PORT` | `5000` | Where `agent.js` sends behavioral telemetry. Keep internal. |
| `DASHBOARD_PORT` | `6001` | SOC dashboard port. Do not expose to the internet. |
| `REDIS_URL` | `redis://redis:6379` | Live session state. Docker handles this automatically. |
| `POSTGRES_URL` | `postgresql://sideris:...` | Event archive. Docker handles this automatically. |
| `DASHBOARD_ALLOWED_IPS` | `127.0.0.1,::1` | Comma-separated list of IPs that can open the SOC dashboard. Add your own IP here. |

<br>

**To allow your IP on the dashboard:**
```env
DASHBOARD_ALLOWED_IPS=127.0.0.1,::1,YOUR.IP.ADDRESS.HERE
```

**To protect a remote server:**
```env
TARGET_URL=http://localhost:8080   # your app still runs locally on the server
PROXY_PORT=80                      # SIDERIS takes port 80 directly
```

For advanced configuration, native (non-Docker) setup, and scoring threshold tuning, see the **[Deployment and Configuration Guide](./DEPLOYMENT.md)**.

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="contact"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-GET_IN_TOUCH-47a2f7?style=for-the-badge&labelColor=161b22&logo=gmail&logoColor=white" height="55"/></a>
</p>
<br>

Found a bug? Have a feature idea? Want to tell me SIDERIS saved your server? Want to tell me SIDERIS broke your server? Either way, reach out:

- **Email**: [anbt.personal@gmail.com](mailto:anbt.personal@gmail.com)
- **Facebook**: [Ann-BT / Merlin the Great Mage](https://www.facebook.com/merlinthegreatmage)
- **GitHub Issues**: For bugs and feature requests, open an issue — that's what they're for.

<br>
<p align="center">━━━━━━━ ❖ ━━━━━━━</p>

<a id="license"></a>
<br>
<p align="center">
  <a href="#sideris"><img src="https://img.shields.io/badge/-LICENSE-57606a?style=for-the-badge&labelColor=161b22&logo=open-source-initiative&logoColor=white" height="55"/></a>
</p>
<br>

SIDERIS is open-source software licensed under the **[MIT License](./LICENSE)**.

Free to use, modify, and deploy — personal projects, commercial websites, whatever. The only thing you can't do is sue me if a sufficiently determined attacker gets through anyway. Security is a process, not a product. SIDERIS just makes the process considerably less painful.

<br>

---

<div align="center">
  <br>
  <i>Built with too much coffee and genuine paranoia about web security.</i>
  <br><br>
  <a href="https://github.com/Ann-BT/SIDERIS/stargazers"><img src="https://img.shields.io/github/stars/Ann-BT/SIDERIS?style=for-the-badge&color=9ece6a&labelColor=161b22&logo=github&logoColor=white"/></a>
  <br><br>
  <i>⭐ Stars are free and they make me unreasonably happy. Just saying.</i>
</div>
