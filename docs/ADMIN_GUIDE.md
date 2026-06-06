# SIDERIS Operations and Administration Guide

This guide is for system administrators, devops engineers, and security operations center (SOC) personnel running SIDERIS in production. It explains how to manage active blocks, diagnose configuration issues, resolve user lockouts, and perform database maintenance.

---

## 1. Managing Blocks and Handling Lockouts

Since SIDERIS performs real-time automated blocking, there is a possibility that a legitimate user or administrator is flagged as a threat (false positive) and gets blocked. 

If this happens, you can manually inspect, whitelist, or unban them directly from the host system using the CLI and `redis-cli`.

### Listing Active Blocks

All active blocks, rate-limits, and CAPTCHAs are stored in Redis as hash keys. You can query these keys to see who is currently restricted:

```bash
# List all active session-based guards
redis-cli KEYS "sideris:guard:*"

# List all active IP-based blocks
redis-cli KEYS "sideris:guard:ip:*"
```

To view the details of a specific block (such as why they were blocked, the risk score, and when it was enforced):

```bash
# Replace <id> with the session ID or IP address
redis-cli HGETALL "sideris:guard:<session_id>"
redis-cli HGETALL "sideris:guard:ip:<ip_address>"
```

### Unbanning a Session or IP Address

If a user gets locked out, you can lift their ban immediately by deleting their keys from Redis:

```bash
# 1. Delete the session-based guard key
redis-cli DEL "sideris:guard:<session_id>"

# 2. Delete the IP-based block key (if applicable)
redis-cli DEL "sideris:guard:ip:<ip_address>"

# 3. Decrement the dashboard's active block metrics to keep statistics accurate
redis-cli DECR "sideris:metrics:guard:block"
```

*Note: If the user was only rate-limited or challenged with a CAPTCHA, use the corresponding metric key to decrement:*
* `sideris:metrics:guard:challenge`
* `sideris:metrics:guard:rate_limit`

### Whitelisting IPs via Dashboard Configuration

To prevent yourself or your office network from ever getting locked out of the SOC Dashboard, ensure your IP address is configured in the `DASHBOARD_ALLOWED_IPS` environment variable inside your `.env` file:

```ini
# Multiple IPs can be comma-separated. Supports CIDR blocks.
DASHBOARD_ALLOWED_IPS=127.0.0.1,::1,203.0.113.50,192.168.1.0/24
```

> [!WARNING]
> The `DASHBOARD_ALLOWED_IPS` protects the SOC Dashboard administration portal. It does **not** exempt clients from WAF rules on the main web application proxy. To bypass WAF rule enforcement for testing, see the `CUSTOMIZATION.md` guide.

---

## 2. Troubleshooting Connection & Proxy Configuration

### Issue: WAF Proxy starts but my website won't load
SIDERIS intercepts traffic on `PROXY_PORT` and forwards it to `TARGET_URL`.
* **Check `.env` parameters**: Ensure `TARGET_URL` matches the internal address of your target application (e.g. `http://localhost:8080` or `http://172.17.0.1:8080`).
* **Port conflicts**: Make sure the target application is not trying to bind to the same port as `PROXY_PORT`.
* **Loopback constraints**: If SIDERIS is in Docker and your app is running natively on the host, `localhost` in Docker refers to the container itself. Use `http://host.docker.internal:8080` (or your host's local IP address) instead.

### Issue: Allowed IPs block valid admins (Express Proxy Trust)
If you configure `DASHBOARD_ALLOWED_IPS` but get blocked when accessing the dashboard from a configured IP, SIDERIS is likely resolving the IP of your upstream load balancer (e.g., Nginx, Cloudflare) instead of your actual client IP.
* **Express trust proxy configuration**: SIDERIS has `app.set('trust proxy', true)` enabled. However, this requires your upstream proxy to correctly set the standard headers.
* **Nginx Configuration**: Ensure your Nginx block forwards headers correctly:
  ```nginx
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  ```
* **Verify Resolved IP**: Inspect the SIDERIS container logs to see what IP is being checked:
  ```bash
  docker compose logs -f sideris-app
  ```

### Issue: Telemetry is not being received
If the dashboard shows active sessions but zero behavioral signals:
* **Verify `agent.js` injection**: View the source of your website in your browser. Look for `<script src="/sideris/agent.js" defer></script>` in the `<head>`.
* **Check browser console**: Press F12 and look for network errors. The agent attempts to post telemetry back to `/sideris/ingest`. If this endpoint returns a `404` or `502`, the proxy configuration is broken.
* **Content Security Policy (CSP)**: If your target web application sets a strict Content Security Policy header, it might block the loading of `/sideris/agent.js` or the connection to `/sideris/ingest`. See `docs/AGENT_DETAILS.md` for how to configure CSP.

---

## 3. Database Maintenance & Log Pruning

SIDERIS logs every access event and behavioral signal. On high-traffic sites, PostgreSQL can accumulate millions of rows, consuming storage and slowing down dashboard queries.

### Postgres Schema Reference

SIDERIS uses two primary tables in PostgreSQL:
1. `attack_sessions`: Aggregated statistics for each visitor session (indexed on `updated_at`).
2. `attack_events`: Individual telemetry and backend proxy log entries (referenced to `attack_sessions` via `session_id ON DELETE CASCADE`, indexed on `timestamp`).

### Automated Log Pruning Queries

To keep database sizes under control, you should configure a cron job or scheduled task to prune old logs.

#### Prune All Events Older Than 30 Days:
```sql
-- This will delete old events.
-- Cascading delete will automatically preserve the sessions but remove their event history.
DELETE FROM attack_events 
WHERE timestamp < NOW() - INTERVAL '30 days';
```

#### Clean Orphaned/Old Sessions:
```sql
-- Delete sessions that have had no activity in 30 days
DELETE FROM attack_sessions 
WHERE updated_at < NOW() - INTERVAL '30 days';
```

### Scripted DB Cleanup

You can run a cleanup command directly inside your docker container or host PostgreSQL system. Example cron-ready shell script:

```bash
#!/bin/bash
# prune_sideris.sh
DB_USER="sideris"
DB_NAME="sideris"

docker exec -t sideris-postgres psql -U $DB_USER -d $DB_NAME -c "
  BEGIN;
  DELETE FROM attack_events WHERE timestamp < NOW() - INTERVAL '14 days';
  DELETE FROM attack_sessions WHERE updated_at < NOW() - INTERVAL '14 days';
  COMMIT;
  VACUUM ANALYZE attack_events;
  VACUUM ANALYZE attack_sessions;
"
```

---

## 4. Monitoring Services

To view the live status and resource usage of the WAF containers:

```bash
# Check CPU/RAM footprint
docker stats sideris-app sideris-redis sideris-postgres

# View container logs dynamically
docker compose logs -f --tail=100
```
