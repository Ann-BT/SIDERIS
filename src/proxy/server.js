// src/proxy/server.js
// Sideris 2.0 — Backend Access Log Proxy + Agent Injector
//
// Runs on PROXY_PORT (default 4000).
// Forwards ALL requests transparently to Juice Shop on
// TARGET_URL (default http://localhost:3000).
//
// Session resolution priority (per request):
//   1. Cookie: sideris_sid         (set by agent.js on page load)
//   2. Header: X-Sideris-Session   (set by agent's patched XHR/fetch)
//   3. Fallback: proxy-generated temp ID (prefix: prx-)
//
// This ensures EVERY request — including native browser
// navigation that bypasses XHR patching — carries a session ID
// and is correlated with the correct agent session.

'use strict';

const express      = require('express');
const cookieParser = require('cookie-parser');
const Redis        = require('ioredis');
const path         = require('path');
const fs           = require('fs');
const dotenv       = require('dotenv');
const pool         = require('../shared/pgPool');
const CAPTCHA_PATH = path.resolve(__dirname, 'captcha.html');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');
const analyzer     = require('../detector/eventAnalyzer');

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const PROXY_PORT = parseInt(process.env.PROXY_PORT  || '4000', 10);
const TARGET_URL = process.env.TARGET_URL            || 'http://localhost:3000';
const INGEST_HOST = process.env.INGEST_HOST          || `http://localhost:${process.env.INGEST_PORT || '5000'}`;
const INGEST_URL = INGEST_HOST + '/api/events';

// agent.js is served from our own source tree
const AGENT_PATH = path.resolve(__dirname, '../agent/agent.js');

// Snippet injected into every HTML <head>
// Points the agent at the relative endpoint /sideris/ingest.
// This routes telemetry traffic through the proxy itself, avoiding exposing
// the ingest port (5000) to the public internet and avoiding CORS issues.
const AGENT_VERSION = '2.0.2';
const AGENT_SNIPPET = `<script src="/sideris/agent.js?v=${AGENT_VERSION}" defer></script>`;

// Lightweight unique ID for fallback sessions
// Uses a UUID v4 format (same as agent) so there is no visual
// difference between proxy-seeded sessions and agent sessions.
function generateProxyId() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}

// Detect browser vs server-side requests
// Next.js SSR, Node.js fetch, curl, crawlers, etc. have no browser
// cookie and will always generate a new session per request.
// We only create tracked sessions for real browser clients.
function isBrowserRequest(req) {
  const ua = req.headers['user-agent'] || '';
  // All real browsers send Mozilla/5.0
  if (!ua.includes('Mozilla/')) return false;
  // Exclude headless/bot patterns even if they spoof Mozilla
  const botPattern = /bot|crawl|spider|headless|phantom|slurp|wget|curl|python|java|go-http|okhttp|axios|node-fetch/i;
  return !botPattern.test(ua);
}

const SESSION_ID_REGEX = /^[a-zA-Z0-9_\-]+$/;

function isValidSessionId(id) {
  return typeof id === 'string' && id.length <= 128 && SESSION_ID_REGEX.test(id);
}

// Session ID resolver
// Priority: cookie → header → generated (browser only)
function resolveSessionId(req) {
  // 1. Cookie (set by proxy on HTML response + refreshed by agent.js)
  if (req.cookies && req.cookies.sideris_sid) {
    const id = req.cookies.sideris_sid;
    if (isValidSessionId(id)) {
      return { id, source: 'cookie', tracked: true };
    }
  }
  // 2. Header (set by agent's patched XHR / fetch)
  const header = req.headers['x-sideris-session'] || req.headers['x-session-id'];
  if (header && isValidSessionId(header)) {
    return { id: header, source: 'header', tracked: true };
  }
  // 3. Non-browser (SSR, Node.js, curl, etc.) — group under a stable
  //    per-IP ID so they don't create hundreds of phantom sessions.
  if (!isBrowserRequest(req)) {
    const ip = (req.ip || '::1').replace(/[:.]/g, '-');
    return { id: `ssr-${ip}`, source: 'server', tracked: false };
  }
  // 4. Browser first load — before agent.js has run.
  //    Proxy sets Set-Cookie so future requests reuse this ID.
  return { id: generateProxyId(), source: 'generated', tracked: true };
}

const app = express();
app.set('trust proxy', true);

// Guard Redis client — declared early so it’s available to all routes
// including /sideris/captcha-image which runs before the guard middleware.
const guardRedis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
guardRedis.on('error', err => console.error('[proxy] Guard Redis error:', err.message));

// Parse cookies before any middleware uses them
app.use(cookieParser());

// Helper to check for authentication failures in JSON responses from endpoints
function checkAuthFailure(responseBuffer, proxyRes, req) {
  const contentType = proxyRes.headers['content-type'] || '';
  if (req.method === 'POST' && analyzer.AUTH_ENDPOINT_PAT.test(req.path) && contentType.includes('application/json')) {
    try {
      const json = JSON.parse(responseBuffer.toString('utf8'));
      if (json && (json.error || json.errors || json.failed || json.success === false)) {
        req._sideris_auth_failed = true;
      }
    } catch (e) {
      // Ignore JSON parsing errors
    }
  }
}

// Disable caching for HTML requests to prevent stale CAPTCHA template rendering
app.use((req, res, next) => {
  const accept = req.headers['accept'] || '';
  if (accept.includes('text/html')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

// Capture request body for injection scanning WITHOUT consuming the stream.
// We buffer the raw body then re-attach it so http-proxy-middleware can forward it.
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks);
      // Store raw buffer for the proxy to re-send
      req.rawBody = rawBody;
      // Parse for our logging
      try {
        req.body = JSON.parse(rawBody.toString('utf8'));
      } catch {
        const contentType = req.headers['content-type'] || '';
        if (contentType.includes('application/x-www-form-urlencoded')) {
          const querystring = require('querystring');
          req.body = querystring.parse(rawBody.toString('utf8'));
        } else {
          req.body = rawBody.toString('utf8');
        }
      }
      next();
    });
  } else {
    next();
  }
});

// ROUTE: /sideris/agent.js — serve agent script directly
// Must be registered BEFORE the proxy middleware so it is
// handled locally and not forwarded to Juice Shop.

app.get('/sideris/agent.js', (req, res) => {
  if (!fs.existsSync(AGENT_PATH)) {
    return res.status(404).send('/* Sideris agent.js not found */');
  }
  res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(AGENT_PATH);
});

// Route: Serve the Sideris Demo Storefront page directly for testing
app.get('/storefront.html', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'storefront.html'));
});

// SERVER-SIDE CAPTCHA GENERATION
// Generates a 6-char code, stores it in Redis with a 5-min TTL,
// and returns a distorted SVG image. The client NEVER sees the
// code — only the rendered image.
const CAPTCHA_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function generateCaptchaCode() {
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += CAPTCHA_CHARS[Math.floor(Math.random() * CAPTCHA_CHARS.length)];
  }
  return code;
}

function generateCaptchaSvg(code) {
  const W = 200, H = 64;
  const palettes = [
    ['#2d1a0e', '#5a3a1a', '#8b5e3c'],
    ['#1a2d3a', '#1d4d72', '#1565c0'],
    ['#1a3a1a', '#2d6a2d', '#2e7d32'],
  ];
  const pal = palettes[Math.floor(Math.random() * palettes.length)];

  let svgParts = [];
  svgParts.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`);

  // Background
  svgParts.push(`<rect width="${W}" height="${H}" fill="#f8f6f2"/>`);

  // Grid noise
  const gridColor = 'rgba(180,140,110,0.15)';
  for (let x = 0; x < W; x += 18) {
    svgParts.push(`<line x1="${x}" y1="0" x2="${x}" y2="${H}" stroke="${gridColor}" stroke-width="0.5"/>`);
  }
  for (let y = 0; y < H; y += 18) {
    svgParts.push(`<line x1="0" y1="${y}" x2="${W}" y2="${y}" stroke="${gridColor}" stroke-width="0.5"/>`);
  }

  // Interference bezier curves
  for (let i = 0; i < 4; i++) {
    const r = () => Math.floor(Math.random() * 100);
    const x1 = Math.floor(Math.random() * W * 0.3);
    const y1 = Math.floor(Math.random() * H);
    const cx1 = Math.floor(W * 0.25 + Math.random() * W * 0.25);
    const cy1 = Math.floor(Math.random() * H);
    const cx2 = Math.floor(W * 0.5 + Math.random() * W * 0.25);
    const cy2 = Math.floor(Math.random() * H);
    const x2 = W;
    const y2 = Math.floor(Math.random() * H);
    const op = (0.07 + Math.random() * 0.07).toFixed(2);
    svgParts.push(`<path d="M${x1} ${y1} C${cx1} ${cy1} ${cx2} ${cy2} ${x2} ${y2}" stroke="rgba(111,78,55,${op})" stroke-width="${(1 + Math.random() * 1.5).toFixed(1)}" fill="none"/>`);
  }

  // Random dots
  for (let i = 0; i < 40; i++) {
    const dx = Math.floor(Math.random() * W);
    const dy = Math.floor(Math.random() * H);
    const dr = (0.5 + Math.random() * 1.5).toFixed(1);
    const op = (0.08 + Math.random() * 0.12).toFixed(2);
    svgParts.push(`<circle cx="${dx}" cy="${dy}" r="${dr}" fill="rgba(111,78,55,${op})"/>`);
  }

  // Characters
  const charW = W / code.length;
  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    const x = charW * i + charW / 2;
    const y = H / 2 + 8;
    const angle = ((Math.random() - 0.5) * 22).toFixed(1);
    const size = 22 + Math.floor(Math.random() * 8);
    const weight = Math.random() > 0.5 ? '700' : '600';
    const color = pal[Math.floor(Math.random() * pal.length)];
    svgParts.push(`<text x="${x}" y="${y}" transform="rotate(${angle} ${x} ${y})" font-family="monospace" font-size="${size}" font-weight="${weight}" fill="${color}" text-anchor="middle" dominant-baseline="middle">${ch}</text>`);
  }

  svgParts.push('</svg>');
  return svgParts.join('');
}

// ROUTE: GET /sideris/captcha-image — serve CAPTCHA as server-generated SVG
// Stores the code in Redis; only the SVG is returned to the client.
app.get('/sideris/captcha-image', async (req, res) => {
  const sid = req.query.sid || (req.cookies && req.cookies.sideris_sid);
  if (!sid) {
    return res.status(400).send('Missing session id');
  }
  const code = generateCaptchaCode();
  try {
    await guardRedis.set(`sideris:captcha:${sid}`, code.toUpperCase(), 'EX', 300);
  } catch (err) {
    console.error('[proxy] captcha-image redis error:', err.message);
    // Still serve an image even if Redis is flaky — just won't verify correctly
  }
  const svg = generateCaptchaSvg(code);
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.send(svg);
});

// CAPTCHA OVERLAY — injected into HTML responses for challenged
// sessions. Full-screen modal; no redirect required.
function getCaptchaOverlay(sid, cspNonce = '') {
  const nonceAttr = cspNonce ? ` nonce="${cspNonce}"` : '';
  return `
<div id="sideris-captcha-container"></div>
<script${nonceAttr}>
(function() {
  const container = document.getElementById('sideris-captcha-container');
  if (!container) return;
  const shadow = container.attachShadow({ mode: 'open' });

  const html = \`
  <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap');
    
    #sideris-captcha-overlay {
      position: fixed; inset: 0; z-index: 2147483647;
      display: flex; align-items: center; justify-content: center;
      padding: 1.5rem;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
      background: rgba(246, 248, 250, 0.85);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      animation: sdrFadeIn 0.35s ease forwards;
    }
    @keyframes sdrFadeIn { from { opacity: 0; } to { opacity: 1; } }
    
    #sideris-captcha-overlay * {
      box-sizing: border-box;
    }
    
    .sdr-card {
      background: #ffffff;
      border-radius: 12px;
      border: 1px solid #d0d7de;
      box-shadow: 0 8px 24px rgba(140, 149, 159, 0.2), 0 1px 3px rgba(0, 0, 0, 0.05);
      width: 100%;
      max-width: 440px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      animation: sdrSlideUp 0.45s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }
    @keyframes sdrSlideUp {
      from { opacity: 0; transform: translateY(30px) scale(0.97); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    
    .sdr-head {
      background: #f6f8fa;
      border-bottom: 1px solid #d0d7de;
      padding: 1.25rem 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    
    .sdr-brand {
      font-size: 0.72rem;
      font-weight: 600;
      color: #57606a;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .sdr-title {
      font-size: 1.1rem;
      font-weight: 600;
      color: #24292f;
      line-height: 1.3;
    }
    
    .sdr-sub {
      font-size: 0.78rem;
      color: #57606a;
    }
    
    .sdr-body {
      padding: 1.5rem;
      background: #ffffff;
    }
    
    .sdr-warn {
      background: #fff8c5;
      border: 1px solid rgba(191, 135, 0, 0.35);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      margin-bottom: 1.25rem;
    }
    
    .sdr-warn-text {
      font-size: 0.78rem;
      color: #24292f;
      line-height: 1.5;
    }
    .sdr-warn-text strong {
      color: #9a6700;
      font-weight: 600;
    }
    
    .sdr-sid-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: #f6f8fa;
      border: 1px solid #d0d7de;
      border-radius: 6px;
      padding: 0.5rem 0.75rem;
      margin-bottom: 1.25rem;
    }
    
    .sdr-sid-lbl {
      font-size: 0.72rem;
      font-weight: 500;
      color: #57606a;
    }
    
    .sdr-sid-val {
      font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
      font-size: 0.78rem;
      color: #24292f;
      font-weight: 600;
    }
    
    .sdr-cap-lbl {
      font-size: 0.78rem;
      font-weight: 600;
      color: #24292f;
      margin-bottom: 0.5rem;
    }
    
    .sdr-cap-row {
      display: flex;
      gap: 12px;
      align-items: center;
      margin-bottom: 1.25rem;
    }
    
    .sdr-canvas-wrap {
      flex: 1;
      border-radius: 6px;
      overflow: hidden;
      border: 1px solid #d0d7de;
      background: #ffffff;
      position: relative;
      user-select: none;
      height: 48px;
      display: flex;
      align-items: center;
    }
    
    #sdrCanvas {
      display: block;
      width: 100%;
      height: 100%;
    }
    
    .sdr-noise {
      position: absolute;
      inset: 0;
      pointer-events: none;
      background: repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(140, 149, 159, 0.02) 3px, rgba(140, 149, 159, 0.02) 4px);
    }
    
    .sdr-refresh {
      height: 48px;
      padding: 0 16px;
      border-radius: 6px;
      flex-shrink: 0;
      border: 1px solid #d0d7de;
      background: #f6f8fa;
      color: #24292f;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.82rem;
      font-weight: 600;
      transition: all 0.2s ease;
    }
    
    .sdr-refresh:hover {
      background: #eaeef2;
      border-color: #8c959f;
    }
    
    .sdr-inp-lbl {
      display: block;
      font-size: 0.78rem;
      font-weight: 600;
      color: #24292f;
      margin-bottom: 0.5rem;
    }
    
    .sdr-input {
      width: 100%;
      padding: 0.5rem 0.75rem;
      border: 1px solid #d0d7de;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
      font-size: 1.1rem;
      font-weight: 600;
      letter-spacing: 4px;
      color: #24292f;
      background: #ffffff;
      outline: none;
      transition: all 0.2s ease;
      box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.075);
    }
    
    .sdr-input::placeholder {
      letter-spacing: 1px;
      font-size: 0.85rem;
      color: #8c959f;
      font-family: -apple-system, sans-serif;
      font-weight: 400;
    }
    
    .sdr-input:focus {
      border-color: #0969da;
      box-shadow: 0 0 0 3px rgba(9, 105, 218, 0.3), inset 0 1px 2px rgba(0, 0, 0, 0.075);
    }
    
    .sdr-input.sdr-err {
      border-color: #cf222e;
      box-shadow: 0 0 0 3px rgba(207, 34, 46, 0.3);
      animation: sdrShake 0.4s ease;
    }
    
    .sdr-input.sdr-ok {
      border-color: #1f883d;
      box-shadow: 0 0 0 3px rgba(31, 136, 61, 0.3);
    }
    
    @keyframes sdrShake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-6px); }
      40%, 80% { transform: translateX(6px); }
    }
    
    .sdr-meta-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-top: 0.5rem;
      margin-bottom: 1.25rem;
    }
    
    .sdr-hint {
      font-size: 0.72rem;
      color: #57606a;
    }
    
    .sdr-hint.sdr-h-err {
      color: #cf222e;
      font-weight: 500;
    }
    
    .sdr-hint.sdr-h-ok {
      color: #1f883d;
      font-weight: 500;
    }
    
    .sdr-dots {
      display: flex;
      gap: 6px;
    }
    
    .sdr-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #eaeef2;
      border: 1px solid #d0d7de;
      transition: all 0.25s ease;
    }
    
    .sdr-dot.sdr-dot-used {
      background: #cf222e;
      border-color: #cf222e;
    }
    
    .sdr-btn {
      width: 100%;
      padding: 0.6rem 1rem;
      background-color: #1f883d;
      color: #ffffff;
      border: 1px solid rgba(27, 31, 36, 0.15);
      border-radius: 6px;
      font-family: inherit;
      font-size: 0.88rem;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.2s ease;
      box-shadow: 0 1px 0 rgba(27, 31, 36, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.03);
    }
    
    .sdr-btn:hover:not(:disabled) {
      background-color: #1a7f37;
    }
    
    .sdr-btn:active:not(:disabled) {
      background-color: #187733;
    }
    
    .sdr-btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
      box-shadow: none;
    }
    
    .sdr-success {
      display: none;
      flex-direction: column;
      align-items: center;
      text-align: center;
      padding: 1.5rem 0;
    }
    
    .sdr-success.sdr-vis {
      display: flex;
      animation: sdrFadeIn 0.3s ease forwards;
    }
    
    .sdr-ok-title {
      font-size: 1.1rem;
      font-weight: 600;
      color: #1f883d;
      margin-bottom: 0.25rem;
    }
    
    .sdr-ok-sub {
      font-size: 0.78rem;
      color: #57606a;
      margin-bottom: 1rem;
    }
    
    .sdr-prog-wrap {
      width: 100%;
      background: #f6f8fa;
      border-radius: 3px;
      height: 4px;
      overflow: hidden;
      border: 1px solid #d0d7de;
    }
    
    .sdr-prog-fill {
      height: 100%;
      width: 0%;
      background: #1f883d;
      border-radius: 3px;
      transition: width 3s linear;
    }
    
    .sdr-foot {
      border-top: 1px solid #d0d7de;
      padding: 0.75rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: #f6f8fa;
    }
    
    .sdr-foot-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 0.68rem;
      font-weight: 500;
      color: #57606a;
    }
    
    .sdr-live-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #0969da;
      box-shadow: 0 0 4px rgba(9, 105, 218, 0.4);
      animation: sdrBlink 2s infinite;
    }
    @keyframes sdrBlink {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.3; }
    }
    
    .sdr-foot-ts {
      font-size: 0.65rem;
      color: #57606a;
      font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
    }
  </style>
  
  <div id="sideris-captcha-overlay">
    <div class="sdr-card">
      <div class="sdr-head">
        <div class="sdr-brand">SIDERIS Security</div>
        <h1 class="sdr-title">Verification Required</h1>
        <div class="sdr-sub">Unusual activity detected on your session</div>
      </div>
      <div class="sdr-body">
        <div class="sdr-warn">
          <span class="sdr-warn-text">Our system flagged suspicious behavior patterns. Complete this verification to continue. Repeated failures will temporary block access.</span>
        </div>
        <div class="sdr-sid-row">
          <span class="sdr-sid-lbl">Session</span>
          <span class="sdr-sid-val" id="sdrSid"></span>
        </div>
        <div id="sdrForm">
          <div class="sdr-cap-lbl">Enter the code shown below</div>
          <div class="sdr-cap-row">
            <div class="sdr-canvas-wrap">
              <img id="sdrImg" src="/sideris/captcha-image?sid=${encodeURIComponent(sid || '')}&t=" style="display:block;width:100%;height:100%;object-fit:contain;" alt="CAPTCHA image" draggable="false" />
              <div class="sdr-noise"></div>
            </div>
            <button class="sdr-refresh" id="sdrRefresh" title="New code">Refresh</button>
          </div>
          <label class="sdr-inp-lbl" for="sdrInput">Your answer</label>
          <input id="sdrInput" class="sdr-input" type="text" maxlength="6" autocomplete="off" autocorrect="off" spellcheck="false" placeholder="Type code…" />
          <div class="sdr-meta-row">
            <span class="sdr-hint" id="sdrHint">Case-insensitive · 6 characters</span>
            <div class="sdr-dots" id="sdrDots"></div>
          </div>
          <button class="sdr-btn" id="sdrBtn">Verify My Identity</button>
        </div>
        <div class="sdr-success" id="sdrSuccess">
          <div class="sdr-ok-title">Verification Successful</div>
          <div class="sdr-ok-sub">Resuming your session…</div>
          <div class="sdr-prog-wrap"><div class="sdr-prog-fill" id="sdrProg"></div></div>
        </div>
      </div>
      <div class="sdr-foot">
        <div class="sdr-foot-badge"><span class="sdr-live-dot"></span>SIDERIS Adaptive Guard · Active</div>
        <span class="sdr-foot-ts" id="sdrTs"></span>
      </div>
    </div>
  </div>
  \`;

  shadow.innerHTML = html;

  var MAX=4, tries=0, locked=false;
  var img=shadow.getElementById('sdrImg');
  var inp=shadow.getElementById('sdrInput');
  var hint=shadow.getElementById('sdrHint');
  var btn=shadow.getElementById('sdrBtn');
  var ref=shadow.getElementById('sdrRefresh');
  var dots=shadow.getElementById('sdrDots');
  var ts=shadow.getElementById('sdrTs');
  
  // Set session display
  var fullSid = "${sid || ''}";
  shadow.getElementById('sdrSid').textContent = fullSid ? fullSid.substring(0, 20) + '…' : '—';

  // Load fresh CAPTCHA image (new code generated server-side)
  function freshImage(){
    img.src='/sideris/captcha-image?sid='+encodeURIComponent(fullSid)+'&t='+Date.now();
  }
  freshImage();

  function renderDots(){
    dots.innerHTML='';
    for(var i=0;i<MAX;i++){
      var d=document.createElement('span');
      d.className='sdr-dot'+(i<tries?' sdr-dot-used':'');
      dots.appendChild(d);
    }
  }
  function updateTs(){ts.textContent=new Date().toLocaleTimeString('en-GB',{hour12:false});}
  function verify(){
    if(locked)return;
    var v=inp.value.trim();
    if(!v)return;
    btn.disabled=true;
    hint.textContent='Verifying…';
    hint.className='sdr-hint';
    fetch('/sideris/captcha-verify',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({session_id:fullSid,answer:v})
    }).then(function(r){return r.json();})
    .then(function(data){
      if(data.ok){
        inp.classList.add('sdr-ok');
        hint.textContent='✓ Correct!';
        hint.className='sdr-hint sdr-h-ok';
        showSuccess();
      } else {
        btn.disabled=false;
        tries++; renderDots();
        inp.classList.add('sdr-err');
        inp.value='';
        setTimeout(function(){inp.classList.remove('sdr-err');},600);
        if(tries>=MAX){
          locked=true;
          btn.disabled=true;inp.disabled=true;
          hint.className='sdr-hint sdr-h-err';
          var sec=15;
          hint.textContent='Too many attempts. Retry in '+sec+'s…';
          var tid=setInterval(function(){
            sec--; hint.textContent='Too many attempts. Retry in '+sec+'s…';
            if(sec<=0){
              clearInterval(tid);
              tries=0;locked=false;
              btn.disabled=false;inp.disabled=false;
              inp.value='';hint.textContent='Case-insensitive · 6 characters';
              hint.className='sdr-hint';
              renderDots();freshImage();
            }
          },1000);
        } else {
          var left=MAX-tries;
          hint.textContent='Incorrect — '+left+' attempt'+(left!==1?'s':'')+' remaining';
          hint.className='sdr-hint sdr-h-err';
          freshImage();
        }
      }
    }).catch(function(){
      btn.disabled=false;
      hint.textContent='Network error — try again';
      hint.className='sdr-hint sdr-h-err';
    });
  }
  function showSuccess(){
    shadow.getElementById('sdrForm').style.display='none';
    var s=shadow.getElementById('sdrSuccess');
    s.classList.add('sdr-vis');
    requestAnimationFrame(function(){shadow.getElementById('sdrProg').style.width='100%';});
    setTimeout(function(){
      window.location.reload();
    },3200);
  }
  ref.addEventListener('click',function(){
    if(locked)return;
    ref.classList.add('sdr-spin');
    setTimeout(function(){ref.classList.remove('sdr-spin');},440);
    freshImage();
    inp.value='';
    inp.className='sdr-input';
    hint.textContent='Case-insensitive · 6 characters';
    hint.className='sdr-hint';
  });
  btn.addEventListener('click',verify);
  inp.addEventListener('keydown',function(e){if(e.key==='Enter')verify();});
  updateTs();setInterval(updateTs,1000);
  renderDots();
})();
</script>
`;
}

// ROUTE: POST /sideris/captcha-verify — clear challenge guard
// Called by the CAPTCHA page JS after successful verification.
app.post('/sideris/captcha-verify', async (req, res) => {
  const sid = req.body?.session_id ||
    (req.cookies && req.cookies.sideris_sid) ||
    req.headers['x-sideris-session'];
  const answer = (req.body?.answer || '').trim().toUpperCase();

  if (!sid) {
    return res.status(400).json({ ok: false, error: 'Missing session id' });
  }
  if (!answer) {
    return res.status(400).json({ ok: false, error: 'Missing answer' });
  }

  try {
    // 1. Retrieve the server-generated code from Redis
    const captchaKey = `sideris:captcha:${sid}`;
    const storedCode = await guardRedis.get(captchaKey);

    if (!storedCode) {
      // Code expired or never generated — force a new image fetch
      return res.status(400).json({ ok: false, error: 'CAPTCHA expired — please refresh the image' });
    }

    if (answer !== storedCode.toUpperCase()) {
      // Wrong answer — delete the key to prevent brute-forcing
      await guardRedis.del(captchaKey);
      console.log(`[proxy] CAPTCHA wrong answer for session ${sid} — key deleted to prevent brute-force`);
      return res.json({ ok: false, error: 'Incorrect answer' });
    }

    // 2. Answer is correct — delete the captcha key (single-use)
    await guardRedis.del(captchaKey);
    console.log(`[proxy] CAPTCHA verified — challenge cleared for session ${sid}`);

    // 3. Fetch guard action to decrement dashboard metrics before deletion
    const guardData = await guardRedis.hgetall(`sideris:guard:${sid}`);
    if (guardData && guardData.action) {
      if (guardData.action === 'block') {
        await guardRedis.decr('sideris:metrics:guard:block');
      } else if (guardData.action === 'challenge') {
        await guardRedis.decr('sideris:metrics:guard:challenge');
      } else if (guardData.action === 'rate_limit') {
        await guardRedis.decr('sideris:metrics:guard:rate_limit');
      }
    }

    // 4. Delete the Redis guard key
    await guardRedis.del(`sideris:guard:${sid}`);

    // 5. Mark the CAPTCHA as solved and set last mitigation to allow in Redis
    const sessionKey = `sideris:session:${sid}`;
    await guardRedis.hset(sessionKey,
      'captcha_solved', '1',
      'last_mitigation', 'allow'
    );

    // 6. Publish unblock synchronization message to worker threads (clears L1 cache)
    await guardRedis.publish('sideris:commands', JSON.stringify({
      action: 'unblock',
      session_id: sid
    }));

    // 7. Sync unblock to Postgres
    try {
      await pool.query(`
        UPDATE attack_sessions SET
          last_mitigation = 'allow'
        WHERE session_id = $1
      `, [sid]);
    } catch (pgErr) {
      console.error('[proxy] PG unblock sync error:', pgErr.message);
    }
  } catch (err) {
    console.error('[proxy] CAPTCHA verify redis error:', err.message);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }

  res.json({ ok: true });
});

// GUARD ENFORCEMENT + INLINE ATTACK BLOCKING
// Phase 1: Check existing Redis guard (from previous blocks)
// Phase 2: Scan URL + body for critical attack patterns

const BLOCK_PAGE = `<!DOCTYPE html>
<html><head><title>Access Denied — SIDERIS</title>
<style>
  body { background: #0a0a12; color: #e2e8f0; font-family: system-ui; display: flex;
         justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
  .box { text-align: center; max-width: 500px; padding: 3rem;
         border: 1px solid rgba(248,113,113,0.3); border-radius: 12px;
         background: rgba(20,20,35,0.9); }
  h1 { color: #f87171; font-size: 2rem; margin: 0 0 1rem; }
  p { color: #94a3b8; line-height: 1.6; }
  .code { font-family: monospace; color: #f59e0b; }
</style></head>
<body><div class="box">
  <h1>Access Denied</h1>
  <p>Your session has been blocked by <strong>SIDERIS</strong> due to detected malicious activity.</p>
  <p class="code">ERR_GUARD_BLOCK</p>
  <p>If you believe this is an error, contact the security team.</p>
</div></body></html>`;

// Critical attack patterns for inline detection

const CRITICAL_PATTERNS = [
  { name: 'sql_injection', re: /(UNION[\s\/\*]+SELECT|'\s*OR\s*['"\d]|OR\s+1\s*=\s*1|[\s'"]+--\s*$|DROP\s+TABLE|INSERT\s+INTO|EXEC\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\(|LOAD_FILE\s*\(|INTO\s+OUTFILE)/i },
  { name: 'xss',           re: /(<script[\s>]|javascript\s*:|on(error|load|click|mouseover)\s*=|<iframe[\s>]|<svg[^>]+onload|document\.cookie|eval\s*\()/i },
  { name: 'cmd_injection',  re: /([;&|`]|\$\()\s*(ls|id|cat|wget|curl|whoami|uname|bash|sh|python|nc|ping)\s/i },
  { name: 'ssti',           re: /\{\{[\s\S]{0,50}\}\}|\$\{[\s\S]{0,50}\}|<%=[\s\S]{0,50}%>/  },
  { name: 'xxe',            re: /<!DOCTYPE[^>]*\[|<!ENTITY\s/i },
  { name: 'ssrf',           re: /(https?:\/\/(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|0\.0\.0\.0)|file:\/\/|gopher:\/\/)/i },
  { name: 'path_traversal', re: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%2e%2e%5c)/i },
];

function scanPayload(url, body) {
  const bodyStr = typeof body === 'string' ? body
    : (body && typeof body === 'object') ? JSON.stringify(body)
    : '';
  const combined = url + ' ' + bodyStr;
  for (const pat of CRITICAL_PATTERNS) {
    if (pat.re.test(combined)) return pat.name;
  }
  return null;
}

function isStaticAsset(urlPath) {
  const ext = urlPath.split('?')[0].split('.').pop().toLowerCase();
  const staticExtensions = ['js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'map', 'json'];
  return staticExtensions.includes(ext) || urlPath.includes('/assets/');
}

app.use(async (req, res, next) => {
  // Skip guard check for Sideris internal, dashboard, and dashboard-api routes
  if (req.path.startsWith('/sideris/') || req.path.startsWith('/dashboard') || req.path.startsWith('/dashboard-api')) {
    return next();
  }

  // Skip guard check and inline scan for socket.io requests to avoid false positives on heartbeat parameters
  if (req.path.includes('/socket.io')) {
    return next();
  }

  const session = resolveSessionId(req);
  const sid = session.id;
  const clientIp = req.ip || '::1';

  // Attach session to req so the responseInterceptor can set the cookie
  // on the HTML response — this prevents the double-session problem where
  // the first HTML load (before agent.js runs) gets a different ID.
  req._sideris_session_id = sid;
  req._sideris_no_cookie   = !req.cookies?.sideris_sid;

  // Phase 1: Check existing guard
  try {
    // 1. IP Block Guard Check
    const ipAction = await guardRedis.hget(`sideris:guard:ip:${clientIp}`, 'action');
    if (ipAction === 'block') {
      delete req.headers['if-none-match'];
      delete req.headers['if-modified-since'];

      const accept = req.headers['accept'] || '';
      const isApi = req.path.startsWith('/api/') || req.path.startsWith('/rest/');
      if (accept.includes('text/html') && !isApi) {
        return res.status(403).send(BLOCK_PAGE);
      } else if (isStaticAsset(req.path)) {
        return next();
      } else {
        res.type('text/plain');
        return res.status(403).send('Your IP address has been blocked due to detected malicious activity. Please contact support.');
      }
    }

    // 2. Session Guard Check
    if (sid && !sid.startsWith('prx-') && !sid.startsWith('ssr-')) {
      const action = await guardRedis.hget(`sideris:guard:${sid}`, 'action');
      if (action === 'block') {
        delete req.headers['if-none-match'];
        delete req.headers['if-modified-since'];

        const accept = req.headers['accept'] || '';
        const isApi = req.path.startsWith('/api/') || req.path.startsWith('/rest/');
        if (accept.includes('text/html') && !isApi) {
          return res.status(403).send(BLOCK_PAGE);
        } else if (isStaticAsset(req.path)) {
          // Allow static assets so they can load/render for the block page
          return next();
        } else {
          res.type('text/plain');
          return res.status(403).send('Your session has been blocked due to detected malicious activity. Please reload the page.');
        }
      }
      if (action === 'challenge') {
        delete req.headers['if-none-match'];
        delete req.headers['if-modified-since'];

        const accept = req.headers['accept'] || '';
        const isApi = req.path.startsWith('/api/') || req.path.startsWith('/rest/');
        if (accept.includes('text/html') && !isApi) {
          // Tag the request — the responseInterceptor will inject the overlay.
          req._sideris_challenge_sid = sid;
        } else if (isStaticAsset(req.path)) {
          // Allow static assets so the page and CAPTCHA overlay can load/render
          return next();
        } else {
          // Block non-HTML (API/XHR) requests with 429 CAPTCHA Required
          res.type('text/plain');
          return res.status(429).send('CAPTCHA verification required. Please reload the page.');
        }
      }
      if (action === 'rate_limit') {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }
  } catch (err) {
    console.error('[proxy] Guard check error:', err.message);
  }

  // Phase 2: Inline critical payload scan
  // Detect injection attacks in real-time and block BEFORE
  // the request reaches Juice Shop. No async pipeline delay.
  const detected = scanPayload(req.originalUrl, req.body);
  if (detected) {
    const effectiveSid = sid || 'unknown';
    console.log(`[PROXY] ⚡ INSTANT BLOCK: ${detected} detected in ${req.method} ${req.originalUrl} (session=${effectiveSid})`);

    if (effectiveSid !== 'unknown') {
      try {
        // 2. Update session state so the dashboard shows the attack
        const sessionKey = `sideris:session:${effectiveSid}`;
        const categoryMap = {
          sql_injection: 'injection', xss: 'injection',
          cmd_injection: 'injection', ssti: 'injection',
          xxe: 'injection', ssrf: 'injection', path_traversal: 'fuzzing',
        };
        const cat = categoryMap[detected] || 'injection';

        // Read existing category_counts or create new
        const existing = await guardRedis.hget(sessionKey, 'category_counts');
        const catCounts = existing ? JSON.parse(existing) : {authentication:0,injection:0,fuzzing:0,bot:0,dos:0,session_abuse:0};
        catCounts[cat] = (catCounts[cat] || 0) + 1;

        const existingUrlCounts = await guardRedis.hget(sessionKey, 'url_counts');
        const urlCounts = existingUrlCounts ? JSON.parse(existingUrlCounts) : {};
        urlCounts[detected] = (urlCounts[detected] || 0) + 1;

        // Fetch existing session score and highest score
        const existingScoreStr = await guardRedis.hget(sessionKey, 'session_score');
        const existingScore = parseFloat(existingScoreStr || '0');
        const newScore = Math.max(existingScore + 50, 50);

        const existingHighestStr = await guardRedis.hget(sessionKey, 'highest_score');
        const existingHighest = parseFloat(existingHighestStr || '0');
        const newHighest = Math.max(existingHighest, newScore);

        // Fetch existing timeline timestamps
        const existingSuspStr = await guardRedis.hget(sessionKey, 'first_suspicious_at');
        const existingSusp = parseInt(existingSuspStr || '0', 10);
        const newSusp = existingSusp || Date.now();

        const existingMitStr = await guardRedis.hget(sessionKey, 'first_mitigated_at');
        const existingMit = parseInt(existingMitStr || '0', 10);
        const newMit = existingMit || Date.now();

        const existingHighestTimeStr = await guardRedis.hget(sessionKey, 'highest_score_at');
        let newHighestTime = parseInt(existingHighestTimeStr || '0', 10);
        if (newScore > existingHighest || !newHighestTime) {
          newHighestTime = Date.now();
        }

        // 1. Set hard_block guard for Session and IP
        await guardRedis.hset(`sideris:guard:${effectiveSid}`,
          'action',     'block',
          'block_type', 'hard',
          'risk_score', String(newScore),
          'reason',     `Inline detection: ${detected}`,
          'updated_at', String(Date.now())
        );
        const clientIpAddress = req.ip || '::1';
        await guardRedis.hset(`sideris:guard:ip:${clientIpAddress}`,
          'action',     'block',
          'block_type', 'hard',
          'risk_score', String(newScore),
          'reason',     `Inline detection: ${detected}`,
          'updated_at', String(Date.now())
        );
        await guardRedis.incr('sideris:metrics:guard:block');

        // Write session state for dashboard
        await guardRedis.hset(sessionKey,
          'session_id',      effectiveSid,
          'session_score',   String(newScore),
          'highest_score',   String(newHighest),
          'event_count',     String(parseInt(await guardRedis.hget(sessionKey, 'event_count') || '0', 10) + 1),
          'ip_address',      req.ip || '::1',
          'user_agent',      req.headers['user-agent'] || 'unknown',
          'last_seen',       String(Date.now()),
          'verdict',         'critical',
          'category_counts', JSON.stringify(catCounts),
          'url_counts',      JSON.stringify(urlCounts),
          'bonus_applied',   JSON.stringify([`inline_${detected}`]),
          'login_attempts',  await guardRedis.hget(sessionKey, 'login_attempts') || '0',
          'failed_login_count', await guardRedis.hget(sessionKey, 'failed_login_count') || '0',
          'unique_usernames', await guardRedis.hget(sessionKey, 'unique_usernames') || '[]',
          'scanner_detected', await guardRedis.hget(sessionKey, 'scanner_detected') || '0',
          'scan_detected',   '1',
          'exploit_detected', '1',
          'count_404',       await guardRedis.hget(sessionKey, 'count_404') || '0',
          'first_suspicious_at', String(newSusp),
          'highest_score_at',   String(newHighestTime),
          'first_mitigated_at',  String(newMit),
          'highest_threat_level', 'hard_block',
          'highest_block_type',   'hard',
          'last_mitigation',      'block',
          'mitigation_reason',    `Inline detection: ${detected}`
        );
        await guardRedis.expire(sessionKey, 86400);

        // Push the inline detection event directly to the risk_reasons list to ensure the timeline shows it immediately
        const catObj = analyzer.CATEGORY_MAP[detected] || { category: 'injection', signal: 'Inline detection: ' + detected };
        const signalBase = catObj.signal;

        const parts = [];
        if (req.query) {
          const qStr = typeof req.query === 'object' ? JSON.stringify(req.query) : String(req.query);
          parts.push(`query: ${qStr.substring(0, 150)}${qStr.length > 150 ? '...' : ''}`);
        }
        if (req.body) {
          const bStr = typeof req.body === 'object' ? JSON.stringify(req.body) : String(req.body);
          parts.push(`body: ${bStr.substring(0, 150)}${bStr.length > 150 ? '...' : ''}`);
        }
        let customSignal = signalBase;
        if (parts.length > 0) {
          customSignal = `${customSignal} [${parts.join(', ')}]`;
        }

        const reasonEntry = JSON.stringify({
          rule: detected,
          category: cat,
          signal: customSignal,
          score: '+50.0',
          total: newScore,
          timestamp: Date.now(),
          time: new Date().toISOString(),
        });
        const reasonKey = `sideris:session:${effectiveSid}:risk_reasons`;
        await guardRedis.lpush(reasonKey, reasonEntry);
        await guardRedis.ltrim(reasonKey, 0, 99);
        await guardRedis.expire(reasonKey, 86400);

        // Publish cache clearance message to worker threads to invalidate L1 cache
        await guardRedis.publish('sideris:commands', JSON.stringify({
          action: 'clear_cache',
          session_id: effectiveSid
        }));

        // 3. Also fire the event to ingest so it shows in the timeline
        fetch(INGEST_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'backend_log', sessionId: effectiveSid,
            timestamp: Date.now(), ip: req.ip, method: req.method,
            endpoint: req.originalUrl, status: 403,
            userAgent: req.headers['user-agent'] || 'unknown',
            duration: 0,
            body: req.body, query: req.query,
            inline_blocked: true,
          })
        }).catch(() => {});
      } catch (err) {
        console.error('[proxy] Inline block write error:', err.message);
      }
    }

    const accept = req.headers['accept'] || '';
    const isApi = req.path.startsWith('/api/') || req.path.startsWith('/rest/');
    if (accept.includes('text/html') && !isApi) {
      return res.status(403).send(BLOCK_PAGE);
    }
    return res.status(403).json({ error: 'blocked', code: 'E_ATTACK_DETECTED', attack: detected });
  }

  next();
});

// LOGGING MIDDLEWARE
// Records start time and attaches res.on("finish") listener.
// All logging and event sending happens ONLY inside finish.

app.use((req, res, next) => {
  const start = Date.now();

  // Skip logging for Sideris internal, dashboard, and dashboard-api routes, socket.io polling, and static assets
  const isInternal = req.path.startsWith('/sideris/') || req.path.startsWith('/dashboard') || req.path.startsWith('/dashboard-api');
  const isSocketIo = req.path.includes('/socket.io');
  const isStatic   = req.path.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/i);
  // Skip Next.js internals (image optimizer, webpack chunks, locale files)
  const isNextInternal = req.path.startsWith('/_next/') || req.path.match(/\/store\/locales\//);

  if (!isInternal && !isSocketIo && !isStatic && !isNextInternal) {
    const session = resolveSessionId(req);

    // Skip ingest for server-side (SSR/Node) requests — they have no
    // browser cookie and would create phantom sessions on every render.
    if (!session.tracked) {
      return next();
    }

    res.on('finish', () => {
      // Safely extract body (may be string, object, or undefined)
      let bodyData = null;
      if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
        bodyData = req.body;
      } else if (typeof req.body === 'string' && req.body.length > 0) {
        try { bodyData = JSON.parse(req.body); } catch { bodyData = req.body; }
      }

      const event = {
        type:      'backend_log',
        sessionId: session.id,
        sessionSource: session.source,   // cookie | header | generated
        timestamp: Date.now(),
        ip:        req.ip,
        method:    req.method,
        endpoint:  req.originalUrl,
        status:    res.statusCode,
        userAgent: req.headers['user-agent'] || 'unknown',
        duration:  Date.now() - start,
        body:      bodyData,
        query:     Object.keys(req.query || {}).length > 0 ? req.query : null,
        auth_failed: req._sideris_auth_failed || false,
      };

      console.log(
        `[PROXY] ${event.method} ${event.endpoint} → ${event.status}` +
        ` (session=${event.sessionId} via ${session.source})`
      );

      // Fire-and-forget — do NOT await, do NOT block response
      fetch(INGEST_URL, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(event)
      }).catch(() => {});
    });
  }

  next();
});

// PROXY — created ONCE at top-level.
// Uses responseInterceptor to inject the agent snippet into
// HTML responses. All other responses are passed through
// unchanged (binary-safe buffer return).

const proxy = createProxyMiddleware({
  target:      TARGET_URL,
  changeOrigin: true,
  logLevel:    'silent',
  ws:          true,
  selfHandleResponse: true,

  on: {
    // Re-write the body we consumed in our raw-body middleware
    proxyReq: (proxyReq, req) => {
      if (req.rawBody && req.rawBody.length > 0) {
        proxyReq.setHeader('Content-Length', req.rawBody.length);
        proxyReq.write(req.rawBody);
        proxyReq.end();
      }
    },
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      checkAuthFailure(responseBuffer, proxyRes, req);
      const contentType = proxyRes.headers['content-type'] || '';
      const accept = req.headers['accept'] || '';

      if (contentType.includes('text/html') && accept.includes('text/html')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
      }

      // Only modify text/html responses when the client actually accepts/expects HTML
      if (!contentType.includes('text/html') || !accept.includes('text/html')) {
        return responseBuffer; // pass binary/JSON/etc. unchanged
      }

      let html = responseBuffer.toString('utf8');

      // Seed the sideris_sid cookie via inline script
      // Injected as an inline (non-deferred) script so it runs BEFORE
      // agent.js (which is defer'd). This ensures the very first page
      // load already has a persistent session cookie set, eliminating
      // the double-session-per-load race condition. Agent.js will read
      // this cookie and reuse the same session ID the proxy assigned.
      if (req._sideris_session_id) {
        const cookieScript = `<script data-sideris-seed>(function(){` +
          `var m=document.cookie.match(/(?:^|;\\s*)sideris_sid=([^;]+)/);` +
          `if(!m){` +
            `var e=new Date(Date.now()+1800000).toUTCString();` +
            `document.cookie='sideris_sid=${req._sideris_session_id}; path=/; expires='+e+'; SameSite=Lax';` +
          `}` +
        `})();<\/script>`;
        if (html.includes('<head>')) {
          html = html.replace('<head>', '<head>\n' + cookieScript);
        } else if (html.includes('<HEAD>')) {
          html = html.replace('<HEAD>', '<HEAD>\n' + cookieScript);
        } else {
          html = cookieScript + '\n' + html;
        }
      }

      // Inject agent snippet right before </head>
      if (html.includes('</head>')) {
        html = html.replace('</head>', `${AGENT_SNIPPET}\n</head>`);
      } else {
        html = AGENT_SNIPPET + '\n' + html;
      }

      // CAPTCHA overlay injection
      // If this session is under challenge, inject the full-screen
      // CAPTCHA modal before </body>. The overlay freezes the page
      // until the user solves it. Non-HTML bot requests are still
      // hard-blocked by the Redis guard on each API call.
      if (req._sideris_challenge_sid) {
        const overlay = getCaptchaOverlay(req._sideris_challenge_sid);
        if (html.includes('</body>')) {
          html = html.replace('</body>', `${overlay}\n</body>`);
        } else {
          html = html + '\n' + overlay;
        }
      }

      return html;
    })
  }
});

const medusaProxy = proxy;
const STOREFRONT_URL = process.env.STOREFRONT_URL || 'http://host.docker.internal:8000';

const storefrontProxy = createProxyMiddleware({
  target:      STOREFRONT_URL,
  changeOrigin: true,
  logLevel:    'silent',
  ws:          true,
  selfHandleResponse: true,
  on: {
    proxyReq: (proxyReq, req) => {
      if (req.rawBody && req.rawBody.length > 0) {
        proxyReq.setHeader('Content-Length', req.rawBody.length);
        proxyReq.write(req.rawBody);
        proxyReq.end();
      }
    },
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      checkAuthFailure(responseBuffer, proxyRes, req);
      const contentType = proxyRes.headers['content-type'] || '';
      const accept = req.headers['accept'] || '';

      if (contentType.includes('text/html') && accept.includes('text/html')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        // Server-side session cookie (bypasses CSP entirely)
        // res.append adds to existing Set-Cookie headers from upstream
        // rather than replacing them, so Discourse's own session cookies
        // (like _t, _forum_session) are preserved alongside ours.
        if (req._sideris_session_id) {
          const expires = new Date(Date.now() + 30 * 60 * 1000).toUTCString();
          res.append(
            'Set-Cookie',
            `sideris_sid=${req._sideris_session_id}; Path=/; Expires=${expires}; SameSite=Lax`
          );
        }
      }

      if (!contentType.includes('text/html') || !accept.includes('text/html')) {
        return responseBuffer;
      }

      let html = responseBuffer.toString('utf8');

      // Extract CSP nonce from upstream headers
      // Discourse uses 'strict-dynamic' + per-request nonce, which blocks
      // any inline or external script that doesn't carry the same nonce.
      // We extract it so we can add it to our injected scripts.
      const cspHeader = proxyRes.headers['content-security-policy'] || '';
      const nonceMatch = cspHeader.match(/'nonce-([^']+)'/);
      const cspNonce = nonceMatch ? nonceMatch[1] : '';
      const nonceAttr = cspNonce ? ` nonce="${cspNonce}"` : '';

      // Inline cookie seed script (belt-and-suspenders backup)
      // Server-side Set-Cookie above is the primary mechanism.
      // This JS fallback handles edge cases (e.g. if headers get dropped).
      if (req._sideris_session_id) {
        const cookieScript =
          `<script${nonceAttr} data-sideris-seed>(function(){` +
          `var m=document.cookie.match(/(?:^|;\\s*)sideris_sid=([^;]+)/);` +
          `if(!m){` +
            `var e=new Date(Date.now()+1800000).toUTCString();` +
            `document.cookie='sideris_sid=${req._sideris_session_id}; path=/; expires='+e+'; SameSite=Lax';` +
          `}` +
          `})();<\/script>`;
        if (html.includes('<head>')) {
          html = html.replace('<head>', '<head>\n' + cookieScript);
        } else if (html.includes('<HEAD>')) {
          html = html.replace('<HEAD>', '<HEAD>\n' + cookieScript);
        } else {
          html = cookieScript + '\n' + html;
        }
      }

      // Agent.js injection with CSP nonce
      // Add the nonce so agent.js is allowed under 'strict-dynamic' CSP.
      const agentSnippet = cspNonce
        ? `<script src="/sideris/agent.js?v=${AGENT_VERSION}" nonce="${cspNonce}" defer></script>`
        : AGENT_SNIPPET;

      if (!html.includes('/sideris/agent.js')) {
        if (html.includes('</head>')) {
          html = html.replace('</head>', `${agentSnippet}\n</head>`);
        } else {
          html = agentSnippet + '\n' + html;
        }
      }

      // CAPTCHA overlay injection for storefront
      if (req._sideris_challenge_sid) {
        const overlay = getCaptchaOverlay(req._sideris_challenge_sid, cspNonce);
        if (html.includes('</body>')) {
          html = html.replace('</body>', `${overlay}\n</body>`);
        } else {
          html = html + '\n' + overlay;
        }
      }

      return html;
    })
  }
});

// ROUTE: /sideris/ingest — proxy agent telemetry to ingest server internally
app.use('/sideris/ingest', createProxyMiddleware({
  target: INGEST_HOST,
  changeOrigin: true,
  logLevel: 'silent',
  pathRewrite: (path, req) => {
    return path.startsWith('/sideris/ingest') ? path : ('/sideris/ingest' + path).replace(/\/$/, '');
  },
  on: {
    proxyReq: (proxyReq, req) => {
      // Re-write the body if parsed by our raw-body middleware
      if (req.rawBody && req.rawBody.length > 0) {
        proxyReq.setHeader('Content-Length', req.rawBody.length);
        proxyReq.write(req.rawBody);
        proxyReq.end();
      }
    }
  }
}));

// Route: /dashboard-api/ -> Dashboard API (port 6001)
app.use('/dashboard-api', createProxyMiddleware({
  target: 'http://localhost:6001',
  pathRewrite: { '^/dashboard-api': '' },
  changeOrigin: true,
  logLevel: 'silent',
  on: {
    proxyReq: (proxyReq, req) => {
      // Re-write the body if parsed by our raw-body middleware
      if (req.rawBody && req.rawBody.length > 0) {
        proxyReq.setHeader('Content-Length', req.rawBody.length);
        proxyReq.write(req.rawBody);
        proxyReq.end();
      }
    }
  }
}));

// Route: /dashboard/ -> Dashboard UI (port 5173)
app.use('/dashboard', createProxyMiddleware({
  target: 'http://localhost:5173',
  pathRewrite: (path, req) => {
    return path.startsWith('/dashboard') ? path : '/dashboard' + path;
  },
  changeOrigin: true,
  logLevel: 'silent',
}));

// Route: Medusa API and Admin backend endpoints (routed without prefix stripping)
app.use((req, res, next) => {
  const isMedusa = ['/store', '/admin', '/app', '/auth'].some(prefix => req.path.startsWith(prefix));
  if (isMedusa) {
    medusaProxy(req, res, next);
  } else {
    next();
  }
});

// Route: Direct WebSocket and SockJS connections (bypasses selfHandleResponse HTML buffering)
const sockjsProxy = createProxyMiddleware({
  target: STOREFRONT_URL,
  changeOrigin: true,
  ws: true,
  logLevel: 'silent'
});
app.use(['/sockjs', '/websocket'], sockjsProxy);

// Route: Storefront default fallback for HTML and static assets
app.use('/', storefrontProxy);

// STARTUP

const server = app.listen(PROXY_PORT, () => {
  console.log(`[proxy] Sideris Proxy running on    http://localhost:${PROXY_PORT}`);
  console.log(`[proxy] Forwarding traffic to       ${TARGET_URL}`);
  console.log(`[proxy] Agent injected into HTML    /sideris/agent.js`);
  console.log(`[proxy] Backend logs sent to        ${INGEST_URL}`);
  console.log(`[proxy] Session resolution order    cookie → header → generated`);
});

server.on('upgrade', (req, socket, head) => {
  const isMedusa = ['/store', '/admin', '/app', '/auth'].some(prefix => req.url.startsWith(prefix));
  if (isMedusa) {
    medusaProxy.upgrade(req, socket, head);
  } else if (req.url.startsWith('/sockjs') || req.url.startsWith('/websocket')) {
    sockjsProxy.upgrade(req, socket, head);
  } else {
    storefrontProxy.upgrade(req, socket, head);
  }
});
