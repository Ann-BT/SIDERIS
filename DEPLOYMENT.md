# SIDERIS Deployment and Configuration Guide

SIDERIS is a real-time web attack detection and behavioral analysis system that runs as an intelligent Web Application Firewall (WAF) Proxy in front of your web application.

This guide explains how to install, configure, and run SIDERIS to protect your existing website.

---

## Architecture and Traffic Flow

SIDERIS acts as a reverse proxy. It sits between the public internet and your real website server:

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

1. **User traffic** hits SIDERIS WAF Proxy first.
2. SIDERIS intercepts the HTML responses and **automatically injects the telemetry agent (`agent.js`)** into the user's browser.
3. The browser agent streams client-side behavior telemetry back to the **SIDERIS Ingestion Endpoint** (`:5000`).
4. Telemetry is streamed into **Redis** for real-time scoring.
5. High-risk actions trigger the **Guard Service** to block/challenge malicious users.
6. Persistent logs and security events are archived in **PostgreSQL** for analysis on the **SOC Dashboard** (`:5173`).

---

## Prerequisites

Ensure your host system has the following installed:
* **Option A (Docker - Recommended)**: Docker and Docker Compose v2.
* **Option B (Native Node.js)**:
  * Node.js v20 or higher
  * PostgreSQL v16 or higher (with pgvector installed)
  * Redis v7 or higher

---

## Deployment Option A: Docker Compose (Recommended)

This is the fastest way to deploy SIDERIS. It starts SIDERIS alongside preconfigured Redis and PostgreSQL containers.

### Step 1: Copy the Environment Template
```bash
cp .env.example .env
```

### Step 2: Configure `.env`
Open `.env` in your favorite editor and configure your site settings:
```ini
# The URL of your existing website SIDERIS will protect
TARGET_URL=http://localhost:8080
STOREFRONT_URL=http://localhost:8080

# The port where public traffic will access your site through SIDERIS
PROXY_PORT=4000

# Dashboard access control (restricted to secure IPs only)
DASHBOARD_ALLOWED_IPS=127.0.0.1,your.office.ip.here
```

### Step 3: Run SIDERIS
Run the following command to build the SIDERIS image and start all services in the background:
```bash
docker compose up -d --build
```
SIDERIS will automatically:
1. Initialize the PostgreSQL schema and indexes.
2. Obfuscate the client-side telemetry agent (`agent.js`) to prevent reverse-engineering.
3. Start the WAF Proxy, Ingestion Server, Guard Service, Detector Worker, and SOC Dashboard.

---

## Deployment Option B: Native Node.js Setup

If you prefer to run SIDERIS directly on your host operating system:

### Step 1: Install Dependencies
```bash
# Install root backend dependencies
npm install

# Install dashboard UI dependencies
cd src/dashboard/ui && npm install
cd ../../../
```

### Step 2: Run the Interactive Installer
SIDERIS includes an interactive command-line utility to generate your `.env` config:
```bash
npm run setup
```
Follow the prompts to specify your site's target URL, proxy port, Redis URL, and PostgreSQL connection string.

### Step 3: Start All Services
```bash
npm run start-all
```

---

## Integrating with Your Production Web Stack

To put SIDERIS in front of your live site, you should place a production web server (like Nginx) in front of SIDERIS to handle SSL (HTTPS).

### Nginx Configuration Example

Add this configuration block to your Nginx site configuration (`/etc/nginx/sites-available/yourdomain.com`). It forwards standard traffic to SIDERIS, and preserves the real client IP (which SIDERIS needs to score and block attackers):

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL Certificates Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        # Forward traffic to the SIDERIS WAF Proxy
        proxy_pass http://127.0.0.1:4000;
        
        # Crucial: Forward real client IP headers for risk analysis
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSockets support (needed for dashboard real-time streams)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## Security Configuration Recommendations

### 1. Restricting Dashboard Access
The SOC Dashboard contains raw behavioral and alert logs. Never expose the dashboard publicly.
Configure the allowed IP addresses or CIDR ranges in your `.env` file:
```ini
DASHBOARD_ALLOWED_IPS=127.0.0.1,192.168.1.0/24,10.0.0.0/8
```

### 2. Guard Policy
The Guard service automatically blocks or challenges clients whose session scores exceed specific threat levels. You can customize mitigation behaviors under src/guard/guard.js.

---

## Verification and Troubleshooting

1. **Verify Proxy**: Visit http://yourdomain.com (or http://localhost:4000). Your website should load normally.
2. **Verify Telemetry Agent**: Open your browser's Developer Tools (F12) Console and run:
   ```javascript
   SiderisAgent.getSessionId()
   ```
   If it returns a session string, the agent is injected and communicating successfully.
3. **Verify Dashboard**: Navigate to the dashboard UI port (default http://localhost:5173). You should see active sessions, event metrics, and attack events being populated in real time.

