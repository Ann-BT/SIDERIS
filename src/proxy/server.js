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
const CAPTCHA_PATH = path.resolve(__dirname, 'captcha.html');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const PROXY_PORT = parseInt(process.env.PROXY_PORT  || '4000', 10);
const TARGET_URL = process.env.TARGET_URL            || 'http://localhost:3000';
const INGEST_URL = (process.env.INGEST_URL           || 'http://localhost:5000') + '/api/events';

// agent.js is served from our own source tree
const AGENT_PATH = path.resolve(__dirname, '../agent/agent.js');

// ── Snippet injected into every HTML <head> ───────────────
// Points the agent at the ingest server (port 5000, not the proxy).
const AGENT_SNIPPET = `
<script>
  window.SIDERIS_INGEST_URL = 'http://localhost:5000/sideris/ingest';
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

// Parse cookies before any middleware uses them
app.use(cookieParser());

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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
#sideris-captcha-overlay {
  position:fixed;inset:0;z-index:2147483647;
  display:flex;align-items:center;justify-content:center;
  padding:1.5rem;
  font-family:'IBM Plex Sans',system-ui,sans-serif;
  background:rgba(61,35,20,0.72);
  backdrop-filter:blur(10px);
  -webkit-backdrop-filter:blur(10px);
  animation:sdrFadeIn 0.35s ease;
}
@keyframes sdrFadeIn{from{opacity:0}to{opacity:1}}
#sideris-captcha-overlay *{box-sizing:border-box;margin:0;padding:0}
.sdr-card{
  background:#FFFFFF;border-radius:18px;
  border:1px solid #DDD0C4;
  box-shadow:0 20px 60px rgba(61,35,20,0.35);
  width:100%;max-width:460px;overflow:hidden;
  animation:sdrSlideUp 0.4s cubic-bezier(0.16,1,0.3,1);
}
@keyframes sdrSlideUp{from{opacity:0;transform:translateY(28px) scale(0.96)}to{opacity:1;transform:translateY(0) scale(1)}}
.sdr-head{
  background:#F2EBE0;border-bottom:1px solid #EDE4D8;
  padding:1.4rem 1.75rem 1.2rem;
  display:flex;align-items:center;gap:1rem;
}
.sdr-shield{
  width:46px;height:46px;border-radius:12px;flex-shrink:0;
  background:linear-gradient(135deg,#C8773A,#6F4E37);
  display:flex;align-items:center;justify-content:center;
  font-size:1.35rem;
  box-shadow:0 3px 10px rgba(200,119,58,0.35);
}
.sdr-brand{font-size:0.6rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#C8773A;margin-bottom:3px}
.sdr-title{font-size:1.15rem;font-weight:700;color:#3D2314;letter-spacing:-0.3px;line-height:1.2}
.sdr-sub{font-size:0.73rem;color:#9A7B6A;margin-top:2px}
.sdr-body{padding:1.6rem 1.75rem}
.sdr-warn{
  display:flex;gap:10px;align-items:flex-start;
  background:rgba(184,134,11,0.08);border:1px solid rgba(184,134,11,0.28);
  border-radius:8px;padding:.75rem .95rem;margin-bottom:1.4rem;
}
.sdr-warn-icon{font-size:.95rem;flex-shrink:0;margin-top:1px}
.sdr-warn-text{font-size:.78rem;color:#6B5344;line-height:1.55}
.sdr-warn-text strong{color:#B8860B}
.sdr-sid-row{
  display:flex;align-items:center;justify-content:space-between;
  background:#F2EBE0;border:1px solid #EDE4D8;
  border-radius:7px;padding:.5rem .85rem;margin-bottom:1.4rem;
}
.sdr-sid-lbl{font-size:.6rem;text-transform:uppercase;letter-spacing:1.2px;color:#B8A090}
.sdr-sid-val{font-family:'IBM Plex Mono',monospace;font-size:.73rem;color:#6F4E37}
.sdr-cap-lbl{font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:1.2px;color:#9A7B6A;margin-bottom:.5rem}
.sdr-cap-row{display:flex;gap:10px;align-items:center;margin-bottom:1.25rem}
.sdr-canvas-wrap{
  flex:1;border-radius:8px;overflow:hidden;
  border:1px solid #DDD0C4;background:#F6EFE6;
  position:relative;user-select:none;
}
#sdrCanvas{display:block;width:100%;height:68px}
.sdr-noise{
  position:absolute;inset:0;pointer-events:none;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(61,35,20,.018) 3px,rgba(61,35,20,.018) 4px);
}
.sdr-refresh{
  width:38px;height:38px;border-radius:8px;flex-shrink:0;
  border:1px solid #DDD0C4;background:#FFFFFF;
  color:#6F4E37;font-size:1rem;cursor:pointer;
  display:flex;align-items:center;justify-content:center;
  transition:all .18s;
}
.sdr-refresh:hover{background:#F2EBE0;border-color:rgba(200,119,58,.3);color:#C8773A}
.sdr-refresh.sdr-spin{animation:sdrSpin .42s ease}
@keyframes sdrSpin{to{transform:rotate(360deg)}}
.sdr-inp-lbl{display:block;font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:1.2px;color:#9A7B6A;margin-bottom:.45rem}
.sdr-input{
  width:100%;padding:.62rem .9rem;
  border:1.5px solid #DDD0C4;border-radius:8px;
  font-family:'IBM Plex Mono',monospace;font-size:1rem;font-weight:500;
  letter-spacing:4px;color:#3D2314;background:#FFFFFF;
  outline:none;transition:border-color .18s,box-shadow .18s;
}
.sdr-input::placeholder{letter-spacing:1px;font-size:.82rem;color:#B8A090;font-family:'IBM Plex Sans',sans-serif}
.sdr-input:focus{border-color:#C8773A;box-shadow:0 0 0 3px rgba(200,119,58,.12)}
.sdr-input.sdr-err{border-color:#C0392B;box-shadow:0 0 0 3px rgba(192,57,43,.1);animation:sdrShake .35s}
.sdr-input.sdr-ok {border-color:#2A7D46;box-shadow:0 0 0 3px rgba(42,125,70,.1)}
@keyframes sdrShake{0%,100%{transform:translateX(0)}20%{transform:translateX(-6px)}40%{transform:translateX(6px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}}
.sdr-meta-row{display:flex;align-items:center;justify-content:space-between;margin-top:.5rem;margin-bottom:1.3rem}
.sdr-hint{font-size:.67rem;color:#B8A090}
.sdr-hint.sdr-h-err{color:#C0392B}
.sdr-hint.sdr-h-ok{color:#2A7D46}
.sdr-dots{display:flex;gap:5px}
.sdr-dot{width:8px;height:8px;border-radius:50%;background:#E8DDD0;border:1px solid #DDD0C4;transition:all .2s}
.sdr-dot.sdr-dot-used{background:#C0392B;border-color:rgba(192,57,43,.3)}
.sdr-btn{
  width:100%;padding:.78rem 1rem;
  background:linear-gradient(135deg,#C8773A 0%,#6F4E37 100%);
  color:#fff;border:none;border-radius:9px;
  font-family:'IBM Plex Sans',sans-serif;font-size:.88rem;font-weight:600;
  cursor:pointer;letter-spacing:.3px;
  box-shadow:0 3px 14px rgba(200,119,58,.38);
  transition:opacity .18s,transform .18s,box-shadow .18s;
}
.sdr-btn:hover:not(:disabled){opacity:.93;transform:translateY(-1px);box-shadow:0 6px 22px rgba(200,119,58,.44)}
.sdr-btn:active:not(:disabled){transform:translateY(0)}
.sdr-btn:disabled{opacity:.5;cursor:not-allowed}
.sdr-success{display:none;flex-direction:column;align-items:center;text-align:center;padding:1.5rem 0 .5rem}
.sdr-success.sdr-vis{display:flex;animation:sdrFadeIn .3s ease}
.sdr-ok-ring{
  width:58px;height:58px;border-radius:50%;
  background:rgba(42,125,70,.1);border:2px solid rgba(42,125,70,.25);
  display:flex;align-items:center;justify-content:center;
  font-size:1.6rem;margin-bottom:.85rem;
  animation:sdrPop .4s cubic-bezier(.34,1.56,.64,1);
}
@keyframes sdrPop{from{transform:scale(.4);opacity:0}to{transform:scale(1);opacity:1}}
.sdr-ok-title{font-size:1.05rem;font-weight:700;color:#2A7D46;margin-bottom:.3rem}
.sdr-ok-sub{font-size:.78rem;color:#9A7B6A;margin-bottom:1.1rem}
.sdr-prog-wrap{width:100%;background:#F2EBE0;border-radius:4px;height:4px;overflow:hidden}
.sdr-prog-fill{height:100%;width:0%;background:linear-gradient(90deg,#2A7D46,#3DAA60);border-radius:4px;transition:width 3s linear}
.sdr-foot{
  border-top:1px solid #EDE4D8;padding:.85rem 1.75rem;
  display:flex;align-items:center;justify-content:space-between;
  background:#F2EBE0;
}
.sdr-foot-badge{display:flex;align-items:center;gap:6px;font-size:.65rem;font-weight:600;color:#9A7B6A;letter-spacing:.3px}
.sdr-live-dot{width:6px;height:6px;border-radius:50%;background:#1D6FA4;box-shadow:0 0 5px rgba(29,111,164,.5);animation:sdrBlink 2s infinite}
@keyframes sdrBlink{0%,100%{opacity:1}50%{opacity:.25}}
.sdr-foot-ts{font-size:.63rem;color:#B8A090;font-family:'IBM Plex Mono',monospace}
</style>
<div id="sideris-captcha-overlay">
  <div class="sdr-card">
    <div class="sdr-head">
      <div class="sdr-shield"></div>
      <div>
        <div class="sdr-brand">SIDERIS Security</div>
        <div class="sdr-title">Human Verification Required</div>
        <div class="sdr-sub">Unusual activity detected on your session</div>
      </div>
    </div>
    <div class="sdr-body">
      <div class="sdr-warn">
        <span class="sdr-warn-icon"></span>
        <span class="sdr-warn-text">Our system has flagged <strong>suspicious behavior patterns</strong> from your session. Complete the verification to continue. Repeated failures will result in a temporary block.</span>
      </div>
      <div class="sdr-sid-row">
        <span class="sdr-sid-lbl">Session</span>
        <span class="sdr-sid-val" id="sdrSid">${sid ? sid.substring(0,20) + '…' : '—'}</span>
      </div>
      <div id="sdrForm">
        <div class="sdr-cap-lbl">Enter the code shown below</div>
        <div class="sdr-cap-row">
          <div class="sdr-canvas-wrap">
            <canvas id="sdrCanvas" width="320" height="68"></canvas>
            <div class="sdr-noise"></div>
          </div>
          <button class="sdr-refresh" id="sdrRefresh" title="New code">New</button>
        </div>
        <label class="sdr-inp-lbl" for="sdrInput">Your answer</label>
        <input id="sdrInput" class="sdr-input" type="text" maxlength="6" autocomplete="off" autocorrect="off" spellcheck="false" placeholder="Type here…" />
        <div class="sdr-meta-row">
          <span class="sdr-hint" id="sdrHint">Case-insensitive · 6 characters</span>
          <div class="sdr-dots" id="sdrDots"></div>
        </div>
        <button class="sdr-btn" id="sdrBtn">Verify My Identity</button>
      </div>
      <div class="sdr-success" id="sdrSuccess">
        <div class="sdr-ok-ring">OK</div>
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
<script>
(function(){
  'use strict';
  var MAX=4, code='', tries=0, locked=false;
  var canvas=document.getElementById('sdrCanvas');
  var ctx=canvas.getContext('2d');
  var inp=document.getElementById('sdrInput');
  var hint=document.getElementById('sdrHint');
  var btn=document.getElementById('sdrBtn');
  var ref=document.getElementById('sdrRefresh');
  var dots=document.getElementById('sdrDots');
  var ts=document.getElementById('sdrTs');
  var CHARS='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  function rc(){return CHARS[Math.floor(Math.random()*CHARS.length)];}
  function gen(){return Array.from({length:6},rc).join('');}
  function hsl(h,s,l){return 'hsl('+h+','+s+'%,'+l+'%)';}
  function draw(c){
    var W=canvas.width,H=canvas.height;
    ctx.fillStyle='#F6EFE6';ctx.fillRect(0,0,W,H);
    ctx.strokeStyle='rgba(180,140,110,0.13)';ctx.lineWidth=0.5;
    for(var x=0;x<W;x+=16){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
    for(var y=0;y<H;y+=16){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
    for(var i=0;i<5;i++){
      ctx.beginPath();
      ctx.strokeStyle='rgba('+(111+i*8)+','+(78+i*5)+',55,'+(0.07+Math.random()*0.07)+')';
      ctx.lineWidth=1+Math.random()*1.5;
      ctx.moveTo(0,H*Math.random());
      ctx.bezierCurveTo(W*0.25,H*Math.random(),W*0.75,H*Math.random(),W,H*Math.random());
      ctx.stroke();
    }
    for(var d=0;d<55;d++){
      ctx.beginPath();
      ctx.arc(Math.random()*W,Math.random()*H,Math.random()*1.4,0,Math.PI*2);
      ctx.fillStyle='rgba(111,78,55,'+(0.07+Math.random()*0.12)+')';
      ctx.fill();
    }
    var cw=W/c.length;
    c.split('').forEach(function(ch,i){
      var x=cw*i+cw/2, y=H/2+9;
      var angle=(Math.random()-0.5)*0.38;
      var size=24+Math.floor(Math.random()*7);
      var pals=[[22,55,18],[22,40,30],[26,55,38]];
      var p=pals[Math.floor(Math.random()*pals.length)];
      ctx.save();
      ctx.translate(x,y);ctx.rotate(angle);
      ctx.shadowColor='rgba(61,35,20,0.2)';ctx.shadowBlur=3;ctx.shadowOffsetX=1;ctx.shadowOffsetY=1;
      ctx.font=(Math.random()>.5?'700 ':'600 ')+size+"px 'IBM Plex Mono',monospace";
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
    document.getElementById('sdrForm').style.display='none';
    var s=document.getElementById('sdrSuccess');
    s.classList.add('sdr-vis');
    requestAnimationFrame(function(){document.getElementById('sdrProg').style.width='100%';});
    fetch('/sideris/captcha-verify',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({verified:true,session_id:"${sid || ''}"})
    }).catch(function(){}).finally(function(){
      setTimeout(function(){
        var overlay=document.getElementById('sideris-captcha-overlay');
        if(overlay){overlay.style.transition='opacity .4s';overlay.style.opacity='0';setTimeout(function(){overlay.remove();},420);}
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
</script>`;
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
      await guardRedis.del(`sideris:guard:${sid}`);
      console.log(`[proxy] CAPTCHA verified — challenge cleared for session ${sid}`);
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

app.use(async (req, res, next) => {
  // Skip guard check for sideris internal routes
  if (req.path.startsWith('/sideris/')) return next();

  const session = resolveSessionId(req);
  const sid = session.id;

  // ── Phase 1: Check existing guard ───────────────────────
  if (sid && !sid.startsWith('prx-')) {
    try {
      const action = await guardRedis.hget(`sideris:guard:${sid}`, 'action');
      if (action === 'block') {
        return res.status(403).send(BLOCK_PAGE);
      }
      if (action === 'challenge') {
        // Tag the request — the responseInterceptor will inject the overlay.
        // Non-HTML requests (XHR/API) from a challenged session are rate-limited
        // at the response level; the guard key stays until verified.
        req._sideris_challenge_sid = sid;
      }
      if (action === 'rate_limit') {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    } catch (err) {
      console.error('[proxy] Guard check error:', err.message);
    }
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
        // 1. Set hard_block guard
        await guardRedis.hset(`sideris:guard:${effectiveSid}`,
          'action',     'block',
          'block_type', 'hard',
          'risk_score', '100',
          'reason',     `Inline detection: ${detected}`,
          'updated_at', String(Date.now())
        );
        await guardRedis.incr('sideris:metrics:guard:block');

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

        // Fetch existing highest_score to ensure it is at least 100
        const existingHighestStr = await guardRedis.hget(sessionKey, 'highest_score');
        const existingHighest = parseFloat(existingHighestStr || '0');
        const newHighest = Math.max(existingHighest, 100);

        // Fetch existing timeline timestamps
        const existingSuspStr = await guardRedis.hget(sessionKey, 'first_suspicious_at');
        const existingSusp = parseInt(existingSuspStr || '0', 10);
        const newSusp = existingSusp || Date.now();

        const existingMitStr = await guardRedis.hget(sessionKey, 'first_mitigated_at');
        const existingMit = parseInt(existingMitStr || '0', 10);
        const newMit = existingMit || Date.now();

        const existingHighestTimeStr = await guardRedis.hget(sessionKey, 'highest_score_at');
        let newHighestTime = parseInt(existingHighestTimeStr || '0', 10);
        if (100 > existingHighest || !newHighestTime) {
          newHighestTime = Date.now();
        }

        // Write session state for dashboard
        await guardRedis.hset(sessionKey,
          'session_id',      effectiveSid,
          'session_score',   '100',
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
        const reasonEntry = JSON.stringify({
          rule: detected,
          category: cat,
          signal: `Inline detection: ${detected} in ${req.method} ${req.originalUrl}`,
          score: '+100.0',
          total: 100,
          timestamp: Date.now(),
          time: new Date().toISOString(),
        });
        const reasonKey = `sideris:session:${effectiveSid}:risk_reasons`;
        await guardRedis.lpush(reasonKey, reasonEntry);
        await guardRedis.ltrim(reasonKey, 0, 99);
        await guardRedis.expire(reasonKey, 86400);

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
          })
        }).catch(() => {});
      } catch (err) {
        console.error('[proxy] Inline block write error:', err.message);
      }
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

  // Skip logging for internal sideris routes, socket.io polling, and static assets
  const isInternal = req.path.startsWith('/sideris/');
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
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req) => {
      const contentType = proxyRes.headers['content-type'] || '';

      // Only modify text/html responses
      if (!contentType.includes('text/html')) {
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
