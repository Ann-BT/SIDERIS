#!/usr/bin/env python3
"""
SIDERIS Detection Showcase Script (urllib-based)
-------------------------------------------------
Runs a series of independent "sessions" against your local SIDERIS WAF proxy,
each one demonstrating a specific detection/mitigation tier. Intended for
thesis-defense demos against your own local instance (e.g. Juice Shop behind
the proxy on :4000).

Features:
  - No external dependencies (uses standard urllib.request and concurrent.futures)
  - Automatically resets database/Redis state before execution via docker exec
  - Spoofs distinct "client" IPs via X-Forwarded-For
  - Simulates bulk background traffic to populate the "Events Processed" dashboard
  - Covers all 8 Client-Side User Heuristics (agent-side bot/telemetry events)
  - Covers all 13 Behavioral Correlation Rules (brute force, password spray,
    credential stuffing, 404 storm, multi-vector, combo attacks, DoS, session hijacking)
  - Queries the live SIDERIS dashboard API (:6001) to fetch actual scores,
    verdicts, and active guard rules.
"""

import json
import random
import string
import time
import urllib.request
import urllib.error
import urllib.parse
import uuid
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# CONFIG — matches SIDERIS deployment
# ---------------------------------------------------------------------------
TARGET_URL = "http://localhost:4000"
INGEST_URL = "http://localhost:5000"
DASHBOARD_URL = "http://localhost:6001"
SESSION_HEADER = "X-Sideris-Session"
NORMAL_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# User-Agents that explicitly match SCANNER_UA_PAT in SIDERIS (eventAnalyzer.js)
SCANNER_UAS = [
    "sqlmap/1.7.11#stable",
    "Nikto/2.5.0",
    "nmap/7.92",
    "nuclei/v2.9.0",
    "zaproxy/2.11.0"
]

def clear_waf_state():
    """Resets the Redis and PostgreSQL database state using the container script."""
    print("🧹 Cleaning SIDERIS database and cache state...")
    try:
        res = subprocess.run(
            ["docker", "exec", "sideris-app", "node", "scripts/clear-dashboard.js"],
            capture_output=True,
            text=True,
            check=True
        )
        print(res.stdout)
    except Exception as e:
        print(f"⚠️ Failed to reset SIDERIS state inside container: {e}")
        print("Continuing anyway...")

def random_public_ip() -> str:
    """Generate a plausible public-looking IPv4."""
    first = random.choice([n for n in range(1, 224) if n not in (10, 127, 172, 192, 0)])
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_session_name() -> str:
    words = ["orbit", "falcon", "cobalt", "ember", "quartz", "nimbus", "vale", "atlas"]
    return f"{random.choice(words)}-{uuid.uuid4().hex[:8]}"

def send_request(session_id: str, ip: str, path: str, method: str = "GET", params: dict = None, body: dict = None, ua: str = NORMAL_UA) -> tuple:
    """Sends a request using urllib and returns (status_code, headers, body_content_or_error)."""
    url = TARGET_URL + path
    if params:
        url += "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", ua)
    req.add_header("X-Forwarded-For", ip)
    req.add_header(SESSION_HEADER, session_id)

    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode("utf-8")

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.getcode(), resp.info(), resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return 0, {}, str(e)

def send_agent_events(session_id: str, ip: str, events: list) -> tuple:
    """Sends agent telemetry events to the ingest server."""
    url = f"{TARGET_URL}/sideris/ingest"
    body = []
    for item in events:
        if len(item) == 3:
            ev_type, ev_data, ev_ts = item
        else:
            ev_type, ev_data = item
            ev_ts = int(time.time() * 1000)
        body.append({
            "sessionId": session_id,
            "type": ev_type,
            "ts": ev_ts,
            "data": ev_data
        })
    req = urllib.request.Request(url, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", ip)
    req.data = json.dumps(body).encode("utf-8")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.getcode(), resp.info(), resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return 0, {}, str(e)

def simulate_background_traffic(session_count=20, events_per_session=150):
    """Spins up a thread pool to generate mock background events to populate the dashboard metrics."""
    print(f"🚀 Simulating {session_count} normal sessions with {events_per_session} events each (total {session_count * events_per_session} events)...")
    start_time = time.time()
    
    # Create normal sessions
    sessions = []
    for _ in range(session_count):
        sessions.append({
            "id": f"normal-{uuid.uuid4().hex[:8]}",
            "ip": random_public_ip(),
            "ua": NORMAL_UA
        })
        
    def send_session_batch(s):
        events = []
        base_ts = int(time.time() * 1000) - events_per_session * 1000
        for i in range(events_per_session):
            # Send normal clicking/scrolling events (0 points)
            ev_type = random.choice(["click", "scroll", "keypress", "focus", "blur"])
            events.append({
                "sessionId": s["id"],
                "type": ev_type,
                "ts": base_ts + i * 1000,
                "data": {"path": random.choice(["/", "/products", "/products/3", "/search", "/cart"])}
            })
            
        url = f"{INGEST_URL}/sideris/ingest"
        req = urllib.request.Request(url, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Forwarded-For", s["ip"])
        req.add_header("User-Agent", s["ua"])
        req.data = json.dumps(events).encode("utf-8")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except Exception as e:
            print(f"Error sending batch for session {s['id']}: {e}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(send_session_batch, sessions))
        
    elapsed = time.time() - start_time
    print(f"✅ Generated {session_count * events_per_session} background events across {session_count} sessions in {elapsed:.2f} seconds.")
    print("⏳ Sleeping 8.0 seconds to let the WAF worker finish processing the background stream...")
    time.sleep(8.0)

def get_session_scoring(session_id: str) -> dict:
    """Queries SIDERIS Dashboard API for real-time scoring data."""
    try:
        req = urllib.request.Request(f"{DASHBOARD_URL}/sessions")
        with urllib.request.urlopen(req, timeout=2) as resp:
            sessions = json.loads(resp.read().decode("utf-8"))
            for s in sessions:
                if s.get("session_id") == session_id:
                    return s
    except Exception:
        pass
    return None

def show(label: str, status: int, headers: dict, session_id: str, error_msg: str = None):
    """Formats and prints response details, fetching live backend score."""
    if status == 0:
        print(f"  -> [ERR] {label} | Reason: {error_msg}")
        return

    print(f"  -> [{status}] {label}")
    # Wait briefly for the async worker processing
    time.sleep(0.5)
    info = get_session_scoring(session_id)
    if info:
        score = info.get("session_score", 0)
        verdict = info.get("verdict", "allow")
        # Fetch active mitigation/guard action
        guard_act = info.get("guard_action") or info.get("active_mitigation") or "none"
        print(f"     [LIVE WAF] Score: {score} | Verdict: {verdict} | Guard Action: {guard_act.upper()}")
        if info.get("bonus_applied"):
            print(f"     [Bonuses]  {', '.join(info.get('bonus_applied'))}")
    else:
        print("     [LIVE WAF] Session not yet tracked or no score recorded")

def scenario(title: str):
    def deco(fn):
        def wrapper(*a, **k):
            print(f"\n=== {title} ===")
            fn(*a, **k)
        return wrapper
    return deco

# ---------------------------------------------------------------------------
# SCENARIOS
# ---------------------------------------------------------------------------

@scenario("Scenario 1: Normal Browsing Traffic")
def normal_user():
    session_id = random_session_name()
    ip = random_public_ip()
    paths = [
        ("/", None),
        ("/products", None),
        ("/products/3", None),
        ("/search", {"q": "laptop"}),
        ("/cart", None)
    ]
    for path, params in paths:
        status, headers, body = send_request(session_id, ip, path, params=params)
        show(f"GET {path}" + (f"?{urllib.parse.urlencode(params)}" if params else ""), status, headers, session_id, body)
        time.sleep(0.2)

@scenario("Scenario 2: Client-Side User Heuristics & Bot Detection")
def client_side_heuristics():
    session_id = random_session_name()
    ip = random_public_ip()
    print("  Sending client-side user heuristics and bot events one-by-one...")
    
    # Send 14 click events to build event history
    for _ in range(14):
        send_agent_events(session_id, ip, [("click", {"rps": 12, "mouseMoves": 5})])
        time.sleep(0.05)
        
    heuristics = [
        "headless_browser",
        "no_mouse",
        "fast_typing",
        "rapid_click",
        "rapid_navigation",
        "instant_form_fill",
        "keystroke_burst",
        "suspicious_url"
    ]
    
    for h in heuristics:
        status, headers, body = send_agent_events(session_id, ip, [(h, {"rps": 12, "mouseMoves": 5})])
        show(f"POST agent event: {h}", status, headers, session_id, body)
        time.sleep(0.05)

@scenario("Scenario 3: Behavioral Correlation: Credential Stuffing & Brute Force")
def credential_stuffing_brute_force():
    session_id = random_session_name()
    ip = random_public_ip()
    print("  Performing 20 failed login attempts with the same username...")
    for i in range(20):
        # POST login parameters
        body = {"email": "target-admin@site.com", "password": "wrongpassword123"}
        status, headers, resp_body = send_request(session_id, ip, "/rest/user/login", method="POST", body=body)
        if i in (0, 9, 14, 19) or status != 401:
            show(f"Failed Login attempt #{i+1}", status, headers, session_id, resp_body)
        time.sleep(0.05)

@scenario("Scenario 4: Behavioral Correlation: Password Spray")
def password_spray():
    session_id = random_session_name()
    ip = random_public_ip()
    print("  Performing 5 login attempts with 5 different usernames (same password)...")
    for i in range(5):
        body = {"email": f"sprayed-user-{i+1}@site.com", "password": "CommonPassword123!"}
        status, headers, resp_body = send_request(session_id, ip, "/rest/user/login", method="POST", body=body)
        show(f"Failed Login spray #{i+1} (user: sprayed-user-{i+1}@site.com)", status, headers, session_id, resp_body)
        time.sleep(0.05)

@scenario("Scenario 5: Behavioral Correlation: 404 Storm & Path Fuzzing")
def storm_404():
    session_id = random_session_name()
    ip = random_public_ip()
    print("  Performing 15 fuzzing requests to non-existent endpoints...")
    for i in range(15):
        path = f"/wp-admin/missing-plugin-{i+1}"
        status, headers, body = send_request(session_id, ip, path)
        if i in (0, 7, 14) or status != 404:
            show(f"Fuzzing probe #{i+1} ({path})", status, headers, session_id, body)
        time.sleep(0.05)

@scenario("Scenario 6: Behavioral Correlation: Multi-Vector Attack & Combo Detection")
def multi_vector_attack():
    session_id = random_session_name()
    ip = random_public_ip()
    print("  Pivoting across multiple vectors: fuzzing, bot agent events, and file exploit...")
    
    # 1. Fuzzing category: GET /wp-admin
    status, headers, body = send_request(session_id, ip, "/wp-admin")
    show("GET /wp-admin (fuzzing vector)", status, headers, session_id, body)
    time.sleep(0.2)
    
    # 2. Bot category: Agent headless_browser event
    status, headers, body = send_agent_events(session_id, ip, [("headless_browser", {"rps": 1, "mouseMoves": 0})])
    show("POST agent event: headless_browser (bot vector)", status, headers, session_id, body)
    time.sleep(0.2)
    
    # 3. Injection category: File upload exploit
    status, headers, body = send_request(session_id, ip, "/upload", method="POST", body={"filename": "exploit.php"})
    show("POST /upload (filename: exploit.php) (injection vector)", status, headers, session_id, body)
    
    # 4. Follow-up request showing escalations to blocker
    time.sleep(0.2)
    status, headers, body = send_request(session_id, ip, "/")
    show("Follow-up GET / (expected block)", status, headers, session_id, body)

@scenario("Scenario 7: Behavioral Correlation: DoS Flood & Endpoint Hammering")
def dos_flood_endpoint_hammer():
    session_id = random_session_name()
    ip = random_public_ip()
    print("  Sending DoS requests to /wp-admin one-by-one to show live blocking...")
    
    for i in range(55):
        status, headers, body = send_request(session_id, ip, "/wp-admin")
        if i in (0, 1, 2, 3, 10, 20, 30, 40, 50, 54) or status == 200:
            show(f"DoS request #{i+1} to /wp-admin", status, headers, session_id, body)
        time.sleep(0.02)

@scenario("Scenario 8: Behavioral Correlation: Session IP Switch (Hijacking)")
def session_ip_switch():
    session_id = random_session_name()
    ip1 = "100.100.100.100"
    ip2 = "200.200.200.200"
    
    # Request from IP 1
    print(f"  Sending request from client IP: {ip1}")
    status, headers, body = send_request(session_id, ip1, "/products")
    show("GET /products (IP 1)", status, headers, session_id, body)
    time.sleep(0.2)
    
    # Request from IP 2 (hijacking attempt)
    print(f"  Sending request from client IP: {ip2} (with same Session ID)")
    status, headers, body = send_request(session_id, ip2, "/products")
    show("GET /products (IP 2 - IP switch)", status, headers, session_id, body)

@scenario("Scenario 9: Rate Limiting: Suspicious Fuzzing Burst")
def rate_limiting_fuzzing():
    session_id = random_session_name()
    ip = random_public_ip()
    print("  Sending 3 fuzzing requests to show rate limiting tier...")
    
    status, headers, body = send_request(session_id, ip, "/wp-admin/config.bak")
    show("Fuzzing request #1", status, headers, session_id, body)
    time.sleep(0.05)
    
    status, headers, body = send_request(session_id, ip, "/wp-admin/config.bak")
    show("Fuzzing request #2", status, headers, session_id, body)
    time.sleep(0.8) # Wait for WAF worker to apply the rate limit guard
    
    start_time = time.time()
    status, headers, body = send_request(session_id, ip, "/wp-admin/config.bak")
    elapsed = time.time() - start_time
    show(f"Fuzzing request #3 (expected delay, elapsed: {elapsed:.2f}s)", status, headers, session_id, body)

def main():
    print(f"Target WAF Proxy: {TARGET_URL}")
    print(f"Dashboard Service: {DASHBOARD_URL}")
    
    clear_waf_state()
    simulate_background_traffic(session_count=20, events_per_session=150)
    
    scenarios = [
        normal_user,
        client_side_heuristics,
        credential_stuffing_brute_force,
        password_spray,
        storm_404,
        multi_vector_attack,
        dos_flood_endpoint_hammer,
        session_ip_switch,
        rate_limiting_fuzzing,
    ]
    
    for fn in scenarios:
        fn()
        time.sleep(1.0) # Pause between scenarios to let metrics settle
        
    print("\nDone. Check the SIDERIS dashboard (:6001) for the detailed active matrix, MITRE ATT&CK mapping, and timelines.")

if __name__ == "__main__":
    main()
