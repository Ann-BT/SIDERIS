// ──────────────────────────────────────────────────────────
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
// ──────────────────────────────────────────────────────────

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

// ── Snippet injected into every HTML <head> ───────────────
// Points the agent at the relative endpoint /sideris/ingest.
// This routes telemetry traffic through the proxy itself, avoiding exposing 
// the ingest port (5000) to the public internet and avoiding CORS issues.
const AGENT_SNIPPET = `
<script>
  window.SIDERIS_INGEST_URL = '/sideris/ingest';
</script>
<script src="/sideris/agent.js" defer></script>`.trim();

// ── Lightweight unique ID for fallback sessions ────────────
function generateProxyId() {
  return 'prx-' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

// ── Session ID resolver ────────────────────────────────────
// Priority: cookie → header → generated temp ID
function resolveSessionId(req) {
  // 1. Cookie (set by agent.js on EVERY page — covers all navigation)
  if (req.cookies && req.cookies.sideris_sid) {
    return { id: req.cookies.sideris_sid, source: 'cookie' };
  }
  // 2. Header (set by agent's patched XHR / fetch)
  const header = req.headers['x-sideris-session'] || req.headers['x-session-id'];
  if (header) {
    return { id: header, source: 'header' };
  }
  // 3. Fallback — pre-agent requests (first HTML load before agent runs)
  return { id: generateProxyId(), source: 'generated' };
}

const app = express();
app.set('trust proxy', true);

// Parse cookies before any middleware uses them
app.use(cookieParser());

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
        req.body = rawBody.toString('utf8');
      }
      next();
    });
  } else {
    next();
  }
});

// ══════════════════════════════════════════════════════════
// ROUTE: /sideris/agent.js — serve agent script directly
// Must be registered BEFORE the proxy middleware so it is
// handled locally and not forwarded to Juice Shop.
// ══════════════════════════════════════════════════════════

app.get('/sideris/agent.js', (req, res) => {
  if (!fs.existsSync(AGENT_PATH)) {
    return res.status(404).send('/* Sideris agent.js not found */');
  }
  res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(AGENT_PATH);
});

// ══════════════════════════════════════════════════════════
// CAPTCHA OVERLAY — injected into HTML responses for challenged
// sessions. Full-screen modal; no redirect required.
// ══════════════════════════════════════════════════════════
function getCaptchaOverlay(sid) {
  return `
<div id="sideris-captcha-container"></div>
<script>
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
      margin: 0;
      padding: 0;
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
      align-items: center;
      gap: 1rem;
    }
    
    .sdr-shield {
      width: 42px; height: 42px; border-radius: 6px; flex-shrink: 0;
      background: #24292f;
      display: flex; align-items: center; justify-content: center;
      border: 1px solid #d0d7de;
    }
    
    .sdr-head-text {
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
      display: flex;
      gap: 10px;
      align-items: flex-start;
      background: #fff8c5;
      border: 1px solid rgba(191, 135, 0, 0.35);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      margin-bottom: 1.25rem;
    }
    
    .sdr-warn-icon {
      flex-shrink: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-top: 2px;
      color: #9a6700;
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
      height: 70px;
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
      width: 40px;
      height: 40px;
      border-radius: 6px;
      flex-shrink: 0;
      border: 1px solid #d0d7de;
      background: #f6f8fa;
      color: #24292f;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s ease;
    }
    
    .sdr-refresh:hover {
      background: #eaeef2;
      border-color: #8c959f;
    }
    
    .sdr-refresh.sdr-spin svg {
      animation: sdrSpin 0.5s ease;
    }
    @keyframes sdrSpin { to { transform: rotate(360deg); } }
    
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
      padding: 1rem 0 0.5rem;
    }
    
    .sdr-success.sdr-vis {
      display: flex;
      animation: sdrFadeIn 0.3s ease forwards;
    }
    
    .sdr-ok-ring {
      width: 48px;
      height: 48px;
      border-radius: 50%;
      background: rgba(31, 136, 61, 0.1);
      border: 2px solid rgba(31, 136, 61, 0.25);
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 0.75rem;
      animation: sdrPop 0.45s cubic-bezier(.34, 1.56, .64, 1) forwards;
    }
    @keyframes sdrPop {
      from { transform: scale(0.5); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
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
        <div class="sdr-shield">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div class="sdr-head-text">
          <div class="sdr-brand">SIDERIS Security</div>
          <div class="sdr-title">Verification Required</div>
          <div class="sdr-sub">Unusual activity detected on your session</div>
        </div>
      </div>
      <div class="sdr-body">
        <div class="sdr-warn">
          <span class="sdr-warn-icon">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </span>
          <span class="sdr-warn-text">Our system flagged <strong>suspicious behavior patterns</strong>. Complete this verification to continue. Repeated failures will temporary block access.</span>
        </div>
        <div class="sdr-sid-row">
          <span class="sdr-sid-lbl">Session</span>
          <span class="sdr-sid-val" id="sdrSid"></span>
        </div>
        <div id="sdrForm">
          <div class="sdr-cap-lbl">Enter the code shown below</div>
          <div class="sdr-cap-row">
            <div class="sdr-canvas-wrap">
              <canvas id="sdrCanvas"></canvas>
              <div class="sdr-noise"></div>
            </div>
            <button class="sdr-refresh" id="sdrRefresh" title="New code">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            </button>
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
          <div class="sdr-ok-ring">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#1f883d" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
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

  var MAX=4, code='', tries=0, locked=false;
  var canvas=shadow.getElementById('sdrCanvas');
  var ctx=canvas.getContext('2d');
  var inp=shadow.getElementById('sdrInput');
  var hint=shadow.getElementById('sdrHint');
  var btn=shadow.getElementById('sdrBtn');
  var ref=shadow.getElementById('sdrRefresh');
  var dots=shadow.getElementById('sdrDots');
  var ts=shadow.getElementById('sdrTs');
  
  // Set session display
  var fullSid = "${sid || ''}";
  shadow.getElementById('sdrSid').textContent = fullSid ? fullSid.substring(0, 20) + '…' : '—';

  var CHARS='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  function rc(){return CHARS[Math.floor(Math.random()*CHARS.length)];}
  function gen(){return Array.from({length:6},rc).join('');}
  function hsl(h,s,l){return 'hsl('+h+','+s+'%,'+l+'%)';}
  function draw(c){
    // Match drawing buffer size to actual rendered CSS size to avoid any blurriness or distortion
    canvas.width = canvas.offsetWidth || 320;
    canvas.height = canvas.offsetHeight || 70;
    var W=canvas.width,H=canvas.height;
    ctx.fillStyle='#ffffff';ctx.fillRect(0,0,W,H);
    ctx.strokeStyle='rgba(140,149,159,0.12)';ctx.lineWidth=0.5;
    for(var x=0;x<W;x+=16){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
    for(var y=0;y<H;y+=16){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
    for(var i=0;i<5;i++){
      ctx.beginPath();
      ctx.strokeStyle='rgba('+(36+i*15)+','+(41+i*20)+','+(47+i*25)+','+(0.06+Math.random()*0.06)+')';
      ctx.lineWidth=1+Math.random()*1.5;
      ctx.moveTo(0,H*Math.random());
      ctx.bezierCurveTo(W*0.25,H*Math.random(),W*0.75,H*Math.random(),W,H*Math.random());
      ctx.stroke();
    }
    for(var d=0;d<45;d++){
      ctx.beginPath();
      ctx.arc(Math.random()*W,Math.random()*H,Math.random()*1.4,0,Math.PI*2);
      ctx.fillStyle='rgba(87,96,106,'+(0.06+Math.random()*0.1)+')';
      ctx.fill();
    }
    var cw=W/c.length;
    c.split('').forEach(function(ch,i){
      var x=cw*i+cw/2, y=H/2+9;
      var angle=(Math.random()-0.5)*0.38;
      var size=24+Math.floor(Math.random()*5);
      var pals=[[212,12,18],[212,92,25],[354,70,30],[144,60,25]];
      var p=pals[Math.floor(Math.random()*pals.length)];
      ctx.save();
      ctx.translate(x,y);ctx.rotate(angle);
      ctx.shadowColor='rgba(140,149,159,0.2)';ctx.shadowBlur=2;ctx.shadowOffsetX=1;ctx.shadowOffsetY=1;
      ctx.font=(Math.random()>.5?'700 ':'600 ')+size+"px ui-monospace,SFMono-Regular,SF Mono,Menlo,monospace";
      ctx.fillStyle=hsl(p[0],p[1],p[2]);
      ctx.textAlign='center';ctx.textBaseline='middle';
      ctx.fillText(ch,0,0);
      ctx.shadowColor='transparent';
      ctx.restore();
    });
  }
  function fresh(){code=gen();draw(code);}
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
    var v=inp.value.trim().toUpperCase();
    if(!v)return;
    if(v===code){
      inp.classList.add('sdr-ok');
      hint.textContent='✓ Correct!';
      hint.className='sdr-hint sdr-h-ok';
      showSuccess();
    } else {
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
            renderDots();fresh();
          }
        },1000);
      } else {
        var left=MAX-tries;
        hint.textContent='Incorrect — '+left+' attempt'+(left!==1?'s':'')+' remaining';
        hint.className='sdr-hint sdr-h-err';
        fresh();
      }
    }
  }
  function showSuccess(){
    shadow.getElementById('sdrForm').style.display='none';
    var s=shadow.getElementById('sdrSuccess');
    s.classList.add('sdr-vis');
    requestAnimationFrame(function(){shadow.getElementById('sdrProg').style.width='100%';});
    fetch('/sideris/captcha-verify',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({verified:true,session_id:fullSid})
    }).catch(function(){}).finally(function(){
      setTimeout(function(){
        window.location.reload();
      },3200);
    });
  }
  ref.addEventListener('click',function(){
    if(locked)return;
    ref.classList.add('sdr-spin');
    setTimeout(function(){ref.classList.remove('sdr-spin');},440);
    fresh();inp.value='';
    inp.className='sdr-input';
    hint.textContent='Case-insensitive · 6 characters';
    hint.className='sdr-hint';
  });
  btn.addEventListener('click',verify);
  inp.addEventListener('keydown',function(e){if(e.key==='Enter')verify();});
  updateTs();setInterval(updateTs,1000);
  renderDots();fresh();
})();
</script>
`;
}

// ══════════════════════════════════════════════════════════
// ROUTE: POST /sideris/captcha-verify — clear challenge guard
// Called by the CAPTCHA page JS after successful verification.
// ══════════════════════════════════════════════════════════
app.post('/sideris/captcha-verify', async (req, res) => {
  const sid = req.body?.session_id ||
    (req.cookies && req.cookies.sideris_sid) ||
    req.headers['x-sideris-session'];

  if (sid) {
    try {
      // 1. Fetch guard action to decrement dashboard metrics before deletion
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

      // 2. Delete the Redis guard key
      await guardRedis.del(`sideris:guard:${sid}`);
      console.log(`[proxy] CAPTCHA verified — challenge cleared for session ${sid}`);

      // 3. Mark the CAPTCHA as solved and set last mitigation to allow in Redis
      const sessionKey = `sideris:session:${sid}`;
      await guardRedis.hset(sessionKey,
        'captcha_solved', '1',
        'last_mitigation', 'allow'
      );

      // 4. Publish unblock synchronization message to worker threads (clears L1 cache)
      await guardRedis.publish('sideris:commands', JSON.stringify({
        action: 'unblock',
        session_id: sid
      }));

      // 5. Sync unblock to Postgres
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
    }
  }
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════
// GUARD ENFORCEMENT + INLINE ATTACK BLOCKING
// Phase 1: Check existing Redis guard (from previous blocks)
// Phase 2: Scan URL + body for critical attack patterns
// ══════════════════════════════════════════════════════════

const guardRedis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
guardRedis.on('error', err => console.error('[proxy] Guard Redis error:', err.message));

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

// ── Critical attack patterns for inline detection ─────────

const CRITICAL_PATTERNS = [
  { name: 'sql_injection', re: /(UNION[\s\/\*]+SELECT|'\s*OR\s*['"\d]|OR\s+1\s*=\s*1|--\s*$|DROP\s+TABLE|INSERT\s+INTO|EXEC\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\(|LOAD_FILE\s*\(|INTO\s+OUTFILE)/i },
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
  if (
    req.path.startsWith('/sideris/') ||
    req.path.startsWith('/dashboard') ||
    req.path.startsWith('/dashboard-api')
  ) {
    return next();
  }

  const session = resolveSessionId(req);
  const sid = session.id;
  const clientIp = req.ip || '::1';

  // ── Phase 1: Check existing guard ───────────────────────
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
    if (sid && !sid.startsWith('prx-')) {
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

  // ── Phase 2: Inline critical payload scan ───────────────
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

// ══════════════════════════════════════════════════════════
// LOGGING MIDDLEWARE
// Records start time and attaches res.on("finish") listener.
// All logging and event sending happens ONLY inside finish.
// ══════════════════════════════════════════════════════════

app.use((req, res, next) => {
  const start = Date.now();

  // Skip logging for Sideris internal, dashboard, and dashboard-api routes, socket.io polling, and static assets
  const isInternal =
    req.path.startsWith('/sideris/') ||
    req.path.startsWith('/dashboard') ||
    req.path.startsWith('/dashboard-api');
  const isSocketIo = req.path.includes('/socket.io');
  const isStatic   = req.path.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/i);

  if (!isInternal && !isSocketIo && !isStatic) {
    const session = resolveSessionId(req);

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

// ══════════════════════════════════════════════════════════
// PROXY — created ONCE at top-level.
// Uses responseInterceptor to inject the agent snippet into
// HTML responses. All other responses are passed through
// unchanged (binary-safe buffer return).
// ══════════════════════════════════════════════════════════

const proxy = createProxyMiddleware({
  target:      TARGET_URL,
  changeOrigin: true,
  logLevel:    'silent',

  // selfHandleResponse is required when using responseInterceptor
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

      // Inject agent snippet right before </head>
      if (html.includes('</head>')) {
        html = html.replace('</head>', `${AGENT_SNIPPET}\n</head>`);
      } else {
        html = AGENT_SNIPPET + '\n' + html;
      }

      // ── CAPTCHA overlay injection ────────────────────────
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

// ══════════════════════════════════════════════════════════
// ROUTE: /sideris/ingest — proxy agent telemetry to ingest server internally
// ══════════════════════════════════════════════════════════
app.use('/sideris/ingest', createProxyMiddleware({
  target: INGEST_HOST,
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

app.use('/', proxy);

// ══════════════════════════════════════════════════════════
// STARTUP
// ══════════════════════════════════════════════════════════

app.listen(PROXY_PORT, () => {
  console.log(`[proxy] Sideris Proxy running on    http://localhost:${PROXY_PORT}`);
  console.log(`[proxy] Forwarding traffic to       ${TARGET_URL}`);
  console.log(`[proxy] Agent injected into HTML    /sideris/agent.js`);
  console.log(`[proxy] Backend logs sent to        ${INGEST_URL}`);
  console.log(`[proxy] Session resolution order    cookie → header → generated`);
});
