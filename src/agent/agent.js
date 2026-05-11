// ──────────────────────────────────────────────────────────
// src/agent/agent.js
// Sideris 2.0 — Client-Side Behavior Collector
//
// Self-contained vanilla JS that collects behavioral events
// from the browser, detects suspicious patterns, normalizes
// events, and beacons them to the Sideris Ingest server.
//
// Injected into every Juice Shop page by the proxy server.
// Exposes window.SiderisAgent public API.
// ──────────────────────────────────────────────────────────

(function () {
  'use strict';

  // Prevent double-initialization
  if (window.__sideris_initialized) return;
  window.__sideris_initialized = true;

  // ══════════════════════════════════════════════════════════
  // §1 — CONFIGURATION
  // ══════════════════════════════════════════════════════════

  var INGEST_URL = window.SIDERIS_INGEST_URL || 'http://localhost:5000/sideris/ingest';
  var FLUSH_INTERVAL_MS = 5000;
  var MAX_QUEUE_SIZE = 50;
  var SESSION_IDLE_MS = 30 * 60 * 1000; // 30 minutes
  var LOCALSTORAGE_KEY = 'sideris_pending';
  var MAX_RETRY_ATTEMPTS = 3;
  var MAX_BUFFER_SIZE = 100;

  // URL patterns to exclude from monkey-patch instrumentation
  var EXCLUDED_URL_PATTERNS = [
    /\/socket\.io\//,
    /\/__webpack_hmr/,
    /\/sockjs-node\//
  ];

  // ══════════════════════════════════════════════════════════
  // §2 — THRESHOLDS (baked in from normalizer.js)
  // ══════════════════════════════════════════════════════════

  var FAST_MOUSE_PX_PER_MS = 800;
  var RAPID_CLICK_COUNT = 10;
  var RAPID_CLICK_WINDOW_MS = 5000;
  var FAST_TYPING_INTERVAL_MS = 50;
  var INSTANT_FORM_FILL_MS = 800;
  var RAPID_SCROLL_PX_PER_SEC = 5000;
  var RAPID_NAV_COUNT = 10;
  var RAPID_NAV_WINDOW_MS = 5000;
  var MOUSE_JITTER_GUARD_MS = 5;
  var RAPID_REQUESTS_COUNT = 20;
  var RAPID_REQUESTS_WINDOW_MS = 10000;

  // ══════════════════════════════════════════════════════════
  // §3 — SUSPICIOUS PATTERN REGEXES
  // ══════════════════════════════════════════════════════════

  var PATTERNS = {
    sqlInjection: /(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b|OR\s+1\s*=\s*1|'\s*(OR|AND)\s+'|--\s*$|;\s*(DROP|SELECT|INSERT)|\/\*.*\*\/|WAITFOR\s+DELAY|BENCHMARK\s*\(|CHAR\s*\(|CONCAT\s*\()/i,
    xss: /(<script[\s>]|javascript\s*:|on(error|load|click|mouseover|focus|blur|submit|change)\s*=|<iframe[\s>]|<img[^>]+onerror|<svg[^>]+onload|document\.cookie|eval\s*\(|alert\s*\(|prompt\s*\(|String\.fromCharCode)/i,
    directoryTraversal: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%2e%2e%5c|\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/windows\/system32)/i,
    adminEndpoint: /\/(admin|administrator|wp-admin|wp-login|phpmyadmin|cpanel|manager|console|dashboard\/admin|_admin|administration)/i
  };

  // ══════════════════════════════════════════════════════════
  // §4 — SESSION MANAGEMENT
  // ══════════════════════════════════════════════════════════

  var seq = 0;
  var lastActivityTs = Date.now();

  function generateId() {
    // Crypto-grade UUID v4
    if (crypto && crypto.randomUUID) return crypto.randomUUID();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  // ── Cookie helper ─────────────────────────────────────
  function writeSiderisCookie(sid) {
    // Expires in 30 minutes (same as session idle timeout)
    var expires = new Date(Date.now() + SESSION_IDLE_MS).toUTCString();
    document.cookie = 'sideris_sid=' + sid
      + '; path=/'
      + '; expires=' + expires
      + '; SameSite=Lax';
    // NOT httpOnly — must be readable by JS to refresh expiry
  }

  function getSessionId() {
    var now = Date.now();
    var sid = sessionStorage.getItem('sideris_session_id');
    var lastActive = parseInt(sessionStorage.getItem('sideris_last_active') || '0', 10);

    // Regenerate if missing or idle > 30min
    if (!sid || (lastActive > 0 && now - lastActive > SESSION_IDLE_MS)) {
      sid = generateId();
      seq = 0;
      sessionStorage.setItem('sideris_session_id', sid);
    }

    sessionStorage.setItem('sideris_last_active', String(now));
    lastActivityTs = now;

    // ── Write / refresh sideris_sid cookie ──────────────
    // This is the key step: the cookie is sent on EVERY browser request
    // (including native page navigation), so the proxy can always read it.
    writeSiderisCookie(sid);

    return sid;
  }

  // Initialize session on load
  var sessionId = getSessionId();

  // ══════════════════════════════════════════════════════════
  // §5 — DEVICE FINGERPRINT
  // ══════════════════════════════════════════════════════════

  function getFingerprint() {
    var fp = {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
      screenWidth: screen.width,
      screenHeight: screen.height,
      screenColorDepth: screen.colorDepth,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      touchSupport: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
      deviceMemory: navigator.deviceMemory || null,
      hardwareConcurrency: navigator.hardwareConcurrency || null,
      pluginsCount: navigator.plugins ? navigator.plugins.length : 0,
      mimeTypesCount: navigator.mimeTypes ? navigator.mimeTypes.length : 0,
      webglRenderer: getWebGLRenderer(),
      chromeExists: !!window.chrome,
      connectionType: getConnectionType(),
      webdriver: !!navigator.webdriver
    };
    return fp;
  }

  function getWebGLRenderer() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return null;
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (!ext) return null;
      return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
    } catch (e) {
      return null;
    }
  }

  function getConnectionType() {
    try {
      if (navigator.connection && navigator.connection.type) {
        return navigator.connection.type;
      }
      if (navigator.connection && navigator.connection.effectiveType) {
        return navigator.connection.effectiveType;
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  var fingerprint = getFingerprint();

  // ══════════════════════════════════════════════════════════
  // §6 — PATTERN DETECTION HELPERS
  // ══════════════════════════════════════════════════════════

  function detectPatterns(text) {
    if (!text || typeof text !== 'string') return [];
    var found = [];
    for (var name in PATTERNS) {
      if (PATTERNS.hasOwnProperty(name) && PATTERNS[name].test(text)) {
        found.push(name);
      }
    }
    return found;
  }

  function checkSuspiciousUrl(url) {
    return detectPatterns(decodeURIComponent(url || ''));
  }

  // ══════════════════════════════════════════════════════════
  // §7 — NORMALIZATION (baked-in from normalizer.js)
  // ══════════════════════════════════════════════════════════

  function normalizeBehavior(raw) {
    if (!raw || !raw.type) return null;
    var normalized = {
      sessionId: raw.sessionId || null,
      ip: null, // stamped server-side
      ts: raw.clientTs || Date.now(),
      source: 'client',
      event_type: raw.type,
      value: null,
      raw: raw
    };

    switch (raw.type) {
      case 'fast_mouse':        normalized.value = raw.data && raw.data.speed; break;
      case 'rapid_click':       normalized.value = raw.data && raw.data.clickCount; break;
      case 'fast_typing':       normalized.value = raw.data && raw.data.avgInterval; break;
      case 'instant_form_fill': normalized.value = raw.data && raw.data.elapsed; break;
      case 'rapid_scroll':      normalized.value = raw.data && raw.data.scrollSpeed; break;
      case 'headless_browser':
      case 'no_plugins':        normalized.value = raw.data && raw.data.reason; break;
      case 'rapid_navigation':  normalized.value = raw.data && raw.data.pageCount; break;
      case 'login_failed':
      case 'login_success':     normalized.value = raw.data && raw.data.statusCode; break;
      case 'form_submit':       normalized.value = raw.data && raw.data.fieldCount; break;
      case 'paste':             normalized.value = raw.data && raw.data.textLength; break;
      case 'keystroke_burst':   normalized.value = raw.data && raw.data.keyCount; break;
      case 'suspicious_url':    normalized.value = raw.data && raw.data.pattern; break;
      case 'page_view':
      case 'session_start':     normalized.value = raw.path || raw.url; break;
      default:                  normalized.value = raw.data || null; break;
    }

    return normalized;
  }

  // ══════════════════════════════════════════════════════════
  // §8 — EVENT QUEUE & DELIVERY
  // ══════════════════════════════════════════════════════════

  var eventQueue = [];
  var flushTimer = null;

  function buildEnvelope(type, data, extraFields) {
    sessionId = getSessionId(); // refresh + idle check
    var envelope = {
      sessionId: sessionId,
      seq: seq++,
      clientTs: Date.now(),
      type: type,
      url: location.href,
      path: location.pathname,
      referrer: document.referrer,
      data: data,
      device: fingerprint
    };
    if (extraFields) {
      for (var key in extraFields) {
        if (extraFields.hasOwnProperty(key)) {
          envelope[key] = extraFields[key];
        }
      }
    }
    return envelope;
  }

  function enqueue(type, data, extraFields) {
    var envelope = buildEnvelope(type, data, extraFields);
    eventQueue.push(envelope);
    if (eventQueue.length >= MAX_QUEUE_SIZE) {
      flush();
    }
  }

  function flush(useBeaconFirst) {
    if (eventQueue.length === 0) {
      // Try to flush pending localStorage buffer
      retryPending();
      return;
    }

    var batch = eventQueue.slice();
    eventQueue = [];

    var payload = JSON.stringify(batch);

    // During page unload, prefer sendBeacon (fire-and-forget)
    if (useBeaconFirst && navigator.sendBeacon) {
      try {
        var sent = navigator.sendBeacon(INGEST_URL, new Blob([payload], { type: 'application/json' }));
        if (sent) return;
      } catch (e) {
        // Fall through to fetch
      }
    }

    // Primary delivery: fetch with explicit Content-Type
    try {
      fetch(INGEST_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        keepalive: true,
        mode: 'cors'
      }).then(function (resp) {
        if (!resp.ok) {
          console.warn('[Sideris Agent] Ingest returned ' + resp.status);
          bufferToLocalStorage(batch);
        }
      }).catch(function () {
        // Network failure — try sendBeacon as last resort
        var rescued = false;
        if (navigator.sendBeacon) {
          try {
            rescued = navigator.sendBeacon(INGEST_URL, new Blob([payload], { type: 'application/json' }));
          } catch (e) { /* ignore */ }
        }
        if (!rescued) {
          bufferToLocalStorage(batch);
        }
      });
    } catch (e) {
      bufferToLocalStorage(batch);
    }
  }

  // ── localStorage retry buffer ──────────────────────────

  function bufferToLocalStorage(events) {
    try {
      var existing = JSON.parse(localStorage.getItem(LOCALSTORAGE_KEY) || '[]');
      // Mark each event with retry metadata
      for (var i = 0; i < events.length; i++) {
        if (existing.length >= MAX_BUFFER_SIZE) break;
        events[i]._retryCount = (events[i]._retryCount || 0);
        events[i].buffered = true;
        existing.push(events[i]);
      }
      localStorage.setItem(LOCALSTORAGE_KEY, JSON.stringify(existing));
    } catch (e) {
      // localStorage unavailable or full — discard
    }
  }

  function retryPending() {
    try {
      var pending = JSON.parse(localStorage.getItem(LOCALSTORAGE_KEY) || '[]');
      if (pending.length === 0) return;

      // Filter out events with exhausted retries or stale sessionIds
      var currentSid = getSessionId();
      var retryable = [];
      for (var i = 0; i < pending.length; i++) {
        var evt = pending[i];
        evt._retryCount = (evt._retryCount || 0) + 1;
        // Discard if max retries exceeded
        if (evt._retryCount > MAX_RETRY_ATTEMPTS) continue;
        // Discard stale sessionIds to avoid corruption
        if (evt.sessionId !== currentSid) continue;
        retryable.push(evt);
      }

      if (retryable.length === 0) {
        localStorage.removeItem(LOCALSTORAGE_KEY);
        return;
      }

      // Mark as buffered
      for (var j = 0; j < retryable.length; j++) {
        retryable[j].buffered = true;
      }

      var payload = JSON.stringify(retryable);
      var sent = false;

      if (navigator.sendBeacon) {
        try {
          sent = navigator.sendBeacon(INGEST_URL, new Blob([payload], { type: 'application/json' }));
        } catch (e) {
          sent = false;
        }
      }

      if (sent) {
        localStorage.removeItem(LOCALSTORAGE_KEY);
      } else {
        // Update retry counts in storage
        localStorage.setItem(LOCALSTORAGE_KEY, JSON.stringify(retryable));
      }
    } catch (e) {
      // Ignore localStorage errors
    }
  }

  // Start flush timer
  flushTimer = setInterval(flush, FLUSH_INTERVAL_MS);

  // Flush on page unload events (use sendBeacon for reliability during close)
  function onUnload() { flush(true); }
  window.addEventListener('pagehide', onUnload);
  window.addEventListener('beforeunload', onUnload);
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') flush(true);
  });

  // ══════════════════════════════════════════════════════════
  // §9 — XHR / FETCH MONKEY-PATCH
  // ══════════════════════════════════════════════════════════

  function isExcludedUrl(url) {
    for (var i = 0; i < EXCLUDED_URL_PATTERNS.length; i++) {
      if (EXCLUDED_URL_PATTERNS[i].test(url)) return true;
    }
    return false;
  }

  function isSameOrigin(url) {
    if (!url) return false;
    if (url.startsWith('/')) return true;
    if (url.startsWith(window.location.origin)) return true;
    return false;
  }

  function shouldInstrument(url) {
    return isSameOrigin(url) && !isExcludedUrl(url);
  }

  // ── Request timestamp tracker for rapid_requests ───────
  var requestTimestamps = [];

  function trackRequest(url) {
    var now = Date.now();
    requestTimestamps.push(now);
    // Trim to 10s window
    var cutoff = now - RAPID_REQUESTS_WINDOW_MS;
    while (requestTimestamps.length > 0 && requestTimestamps[0] < cutoff) {
      requestTimestamps.shift();
    }
    if (requestTimestamps.length > RAPID_REQUESTS_COUNT) {
      enqueue('rapid_requests', {
        count: requestTimestamps.length,
        windowMs: RAPID_REQUESTS_WINDOW_MS,
        triggerUrl: url
      });
    }
  }

  // ── Patch XMLHttpRequest ───────────────────────────────
  var OriginalXHR = window.XMLHttpRequest;
  function PatchedXHR() {
    var xhr = new OriginalXHR();
    var _open = xhr.open;
    var _url = '';

    xhr.open = function (method, url) {
      _url = url;
      _open.apply(xhr, arguments);
      // Inject session header on same-origin, non-excluded requests
      if (shouldInstrument(url)) {
        try {
          xhr.setRequestHeader('X-Sideris-Session', getSessionId());
        } catch (e) {
          // Header may not be settable before open — set after
        }
      }
    };

    var _send = xhr.send;
    xhr.send = function () {
      // Re-set header after open (some implementations require this order)
      if (shouldInstrument(_url)) {
        try {
          xhr.setRequestHeader('X-Sideris-Session', getSessionId());
        } catch (e) { /* already set */ }
        trackRequest(_url);
      }

      // Intercept login responses
      xhr.addEventListener('load', function () {
        if (shouldInstrument(_url)) {
          detectLoginResponse(_url, xhr.status);
        }
      });

      _send.apply(xhr, arguments);
    };

    return xhr;
  }

  // Copy static properties
  PatchedXHR.prototype = OriginalXHR.prototype;
  PatchedXHR.UNSENT = 0;
  PatchedXHR.OPENED = 1;
  PatchedXHR.HEADERS_RECEIVED = 2;
  PatchedXHR.LOADING = 3;
  PatchedXHR.DONE = 4;
  window.XMLHttpRequest = PatchedXHR;

  // ── Patch fetch ────────────────────────────────────────
  var originalFetch = window.fetch;
  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : (input && input.url ? input.url : '');

    if (shouldInstrument(url)) {
      var isRequest = typeof Request !== 'undefined' && input instanceof Request;
      init = init || {};
      
      // If no init headers but input is a Request, copy its headers to preserve them
      if (!init.headers && isRequest && input.headers) {
         init.headers = new Headers(input.headers);
      } else {
         init.headers = init.headers || {};
      }

      if (typeof Headers !== 'undefined' && init.headers instanceof Headers) {
        init.headers.set('X-Sideris-Session', getSessionId());
      } else if (Array.isArray(init.headers)) {
        init.headers.push(['X-Sideris-Session', getSessionId()]);
      } else {
        init.headers['X-Sideris-Session'] = getSessionId();
      }
      trackRequest(url);
    }

    var promise = originalFetch.call(window, input, init);

    // Intercept login responses
    if (shouldInstrument(url)) {
      promise.then(function (resp) {
        detectLoginResponse(url, resp.status);
        return resp;
      }).catch(function () { /* ignore */ });
    }

    return promise;
  };

  // ══════════════════════════════════════════════════════════
  // §10 — LOGIN DETECTION
  // ══════════════════════════════════════════════════════════

  var LOGIN_URL_PATTERN = /\/(login|auth|signin|rest\/user\/login)/i;

  function detectLoginResponse(url, statusCode) {
    if (!LOGIN_URL_PATTERN.test(url)) return;
    if (statusCode >= 200 && statusCode < 300) {
      enqueue('login_success', { url: url, statusCode: statusCode });
    } else if (statusCode >= 400) {
      enqueue('login_failed', { url: url, statusCode: statusCode });
    }
  }

  // ══════════════════════════════════════════════════════════
  // §11 — EVENT COLLECTORS
  // ══════════════════════════════════════════════════════════

  // ── session_start ──────────────────────────────────────
  enqueue('session_start', {
    entryUrl: location.href,
    referrer: document.referrer,
    sessionId: sessionId
  });

  // ── page_view ──────────────────────────────────────────
  var pageViewTimestamps = [];

  function emitPageView() {
    var now = Date.now();
    var urlStr = location.href;
    var suspicious = checkSuspiciousUrl(urlStr);

    pageViewTimestamps.push(now);
    // Trim to rapid_nav window
    var cutoff = now - RAPID_NAV_WINDOW_MS;
    while (pageViewTimestamps.length > 0 && pageViewTimestamps[0] < cutoff) {
      pageViewTimestamps.shift();
    }

    enqueue('page_view', {
      url: urlStr,
      path: location.pathname,
      query: location.search,
      hash: location.hash,
      suspiciousFlags: suspicious
    });

    // Check for suspicious URL patterns
    if (suspicious.length > 0) {
      for (var i = 0; i < suspicious.length; i++) {
        enqueue('suspicious_url', { pattern: suspicious[i], url: urlStr });
      }
    }

    // Check for rapid navigation
    if (pageViewTimestamps.length > RAPID_NAV_COUNT) {
      enqueue('rapid_navigation', {
        pageCount: pageViewTimestamps.length,
        windowMs: RAPID_NAV_WINDOW_MS
      });
    }
  }

  // Emit initial page_view
  emitPageView();

  // Listen for SPA-style navigation (hashchange, popstate)
  window.addEventListener('hashchange', emitPageView);
  window.addEventListener('popstate', emitPageView);

  // ── page_timing ────────────────────────────────────────
  window.addEventListener('load', function () {
    setTimeout(function () {
      try {
        var timing = performance.getEntriesByType('navigation')[0];
        if (!timing) return;
        enqueue('page_timing', {
          dns: Math.round(timing.domainLookupEnd - timing.domainLookupStart),
          tcp: Math.round(timing.connectEnd - timing.connectStart),
          ttfb: Math.round(timing.responseStart - timing.requestStart),
          domLoad: Math.round(timing.domContentLoadedEventEnd - timing.startTime),
          fullLoad: Math.round(timing.loadEventEnd - timing.startTime)
        });
      } catch (e) { /* timing API unavailable */ }
    }, 100); // Slight delay to ensure timing data is populated
  });

  // ── form_submit ────────────────────────────────────────
  var formSessions = new Map(); // Track firstFocusTs per form

  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!form || form.tagName !== 'FORM') return;

    var fields = form.querySelectorAll('input, textarea, select');
    var fieldNames = [];
    var fieldTypes = [];
    var isLoginForm = false;
    var suspicious = [];

    for (var i = 0; i < fields.length; i++) {
      var field = fields[i];
      fieldNames.push(field.name || field.id || '');
      fieldTypes.push(field.type || 'text');
      if (field.type === 'password') isLoginForm = true;

      // Check for suspicious values (never log passwords)
      if (field.type !== 'password' && field.value) {
        var flags = detectPatterns(field.value);
        if (flags.length > 0) {
          suspicious = suspicious.concat(flags);
        }
      }
    }

    // Check for instant_form_fill
    var formKey = form.id || form.action || 'form_' + Array.from(document.forms).indexOf(form);
    var formSession = formSessions.get(formKey);
    if (formSession && formSession.firstFocusTs) {
      var elapsed = Date.now() - formSession.firstFocusTs;
      if (elapsed < INSTANT_FORM_FILL_MS) {
        enqueue('instant_form_fill', {
          elapsed: elapsed,
          formKey: formKey,
          threshold: INSTANT_FORM_FILL_MS
        });
      }
    }
    formSessions.delete(formKey);

    enqueue('form_submit', {
      fieldNames: fieldNames,
      fieldTypes: fieldTypes,
      fieldCount: fields.length,
      isLoginForm: isLoginForm,
      suspiciousFlags: suspicious,
      action: form.action || ''
    });
  }, true);

  // ── field_change ───────────────────────────────────────
  document.addEventListener('change', function (e) {
    var field = e.target;
    if (!field || !field.tagName) return;
    var tag = field.tagName.toLowerCase();
    if (tag !== 'input' && tag !== 'textarea' && tag !== 'select') return;

    var suspicious = [];
    // Never log password values
    if (field.type !== 'password' && field.value) {
      suspicious = detectPatterns(field.value);
    }

    enqueue('field_change', {
      fieldName: field.name || field.id || '',
      fieldType: field.type || 'text',
      valueLength: field.value ? field.value.length : 0,
      suspiciousFlags: suspicious
    });
  }, true);

  // ── field focus tracking for instant_form_fill ─────────
  document.addEventListener('focus', function (e) {
    var field = e.target;
    if (!field || !field.tagName) return;
    var tag = field.tagName.toLowerCase();
    if (tag !== 'input' && tag !== 'textarea' && tag !== 'select') return;

    var form = field.closest('form');
    if (!form) return;

    var formKey = form.id || form.action || 'form_' + Array.from(document.forms).indexOf(form);
    if (!formSessions.has(formKey)) {
      formSessions.set(formKey, { firstFocusTs: Date.now() });
    }
  }, true);

  // ── paste ──────────────────────────────────────────────
  document.addEventListener('paste', function (e) {
    var textLength = 0;
    var suspicious = [];
    try {
      var pastedText = (e.clipboardData || window.clipboardData).getData('text');
      textLength = pastedText.length;
      suspicious = detectPatterns(pastedText);
    } catch (err) { /* clipboard access denied */ }

    enqueue('paste', {
      textLength: textLength,
      suspiciousFlags: suspicious
    });
  }, true);

  // ── keystroke_burst + fast_typing ──────────────────────
  var keystrokeTimestamps = [];
  var keystrokeBurstWindow = 500; // ms
  var keystrokeBurstThreshold = 10;

  document.addEventListener('keydown', function (e) {
    var target = e.target;
    if (!target || !target.tagName) return;
    var tag = target.tagName.toLowerCase();
    if (tag !== 'input' && tag !== 'textarea') return;

    var now = Date.now();
    keystrokeTimestamps.push(now);

    // Trim to burst window
    var cutoff = now - keystrokeBurstWindow;
    while (keystrokeTimestamps.length > 0 && keystrokeTimestamps[0] < cutoff) {
      keystrokeTimestamps.shift();
    }

    // Check keystroke_burst: >10 keystrokes in 500ms
    if (keystrokeTimestamps.length > keystrokeBurstThreshold) {
      enqueue('keystroke_burst', {
        keyCount: keystrokeTimestamps.length,
        windowMs: keystrokeBurstWindow
      });
      keystrokeTimestamps = []; // Reset after detection
    }

    // Check fast_typing: avg interval < 50ms (need at least 5 keystrokes)
    if (keystrokeTimestamps.length >= 5) {
      var intervals = [];
      for (var i = 1; i < keystrokeTimestamps.length; i++) {
        intervals.push(keystrokeTimestamps[i] - keystrokeTimestamps[i - 1]);
      }
      var avgInterval = intervals.reduce(function (a, b) { return a + b; }, 0) / intervals.length;
      if (avgInterval < FAST_TYPING_INTERVAL_MS) {
        enqueue('fast_typing', {
          avgInterval: Math.round(avgInterval),
          keyCount: keystrokeTimestamps.length,
          threshold: FAST_TYPING_INTERVAL_MS
        });
        keystrokeTimestamps = []; // Reset after detection
      }
    }
  }, true);

  // ── mouse tracking (speed + liveness) ──────────────────
  var lastMouseX = null;
  var lastMouseY = null;
  var lastMouseTs = null;
  var mouseMoveCount = 0;
  var lastMouseMoveTime = 0;

  document.addEventListener('mousemove', function (e) {
    var now = Date.now();
    mouseMoveCount++;
    lastMouseMoveTime = now;

    if (lastMouseX !== null && lastMouseTs !== null) {
      var dx = e.clientX - lastMouseX;
      var dy = e.clientY - lastMouseY;
      var distance = Math.sqrt(dx * dx + dy * dy);
      var interval = now - lastMouseTs;

      // Jitter guard: only compute speed if interval > 5ms
      if (interval > MOUSE_JITTER_GUARD_MS) {
        var speed = distance / interval; // px/ms
        if (speed > FAST_MOUSE_PX_PER_MS) {
          enqueue('fast_mouse', {
            speed: Math.round(speed * 100) / 100,
            distance: Math.round(distance),
            interval: interval,
            threshold: FAST_MOUSE_PX_PER_MS
          });
        }
      }
    }

    lastMouseX = e.clientX;
    lastMouseY = e.clientY;
    lastMouseTs = now;
  });

  // ── rapid_click ────────────────────────────────────────
  var clickTimestamps = [];

  document.addEventListener('click', function () {
    var now = Date.now();
    clickTimestamps.push(now);

    // Trim to 5s window
    var cutoff = now - RAPID_CLICK_WINDOW_MS;
    while (clickTimestamps.length > 0 && clickTimestamps[0] < cutoff) {
      clickTimestamps.shift();
    }

    if (clickTimestamps.length > RAPID_CLICK_COUNT) {
      enqueue('rapid_click', {
        clickCount: clickTimestamps.length,
        windowMs: RAPID_CLICK_WINDOW_MS
      });
      clickTimestamps = []; // Reset after detection
    }
  }, true);

  // ── rapid_scroll ───────────────────────────────────────
  var scrollCount = 0;
  var lastScrollTs = null;
  var scrollAccumulator = 0;

  window.addEventListener('scroll', function () {
    var now = Date.now();
    scrollCount++;

    if (lastScrollTs !== null) {
      var interval = now - lastScrollTs;
      if (interval > 0) {
        // Estimate scroll speed using scroll event frequency
        var scrollSpeed = Math.abs(window.scrollY || 0) / (interval / 1000);
        scrollAccumulator = scrollSpeed;

        if (scrollSpeed > RAPID_SCROLL_PX_PER_SEC) {
          enqueue('rapid_scroll', {
            scrollSpeed: Math.round(scrollSpeed),
            threshold: RAPID_SCROLL_PX_PER_SEC
          });
        }
      }
    }

    lastScrollTs = now;
  });

  // ── liveness_snapshot ──────────────────────────────────
  // Emit every 30 seconds
  setInterval(function () {
    enqueue('liveness_snapshot', {
      mouseMoveCount: mouseMoveCount,
      scrollCount: scrollCount,
      lastMouseMoveTime: lastMouseMoveTime
    });
  }, 30000);

  // ── devtools_change ────────────────────────────────────
  var devtoolsOpen = false;

  function checkDevtools() {
    var threshold = 160;
    var widthDiff = window.outerWidth - window.innerWidth > threshold;
    var heightDiff = window.outerHeight - window.innerHeight > threshold;
    var isOpen = widthDiff || heightDiff;

    if (isOpen !== devtoolsOpen) {
      devtoolsOpen = isOpen;
      enqueue('devtools_change', {
        opened: isOpen
      });
    }
  }

  setInterval(checkDevtools, 2000);

  // ── headless_browser + no_plugins detection ────────────
  // Run once on init
  (function detectHeadless() {
    // Check navigator.webdriver
    if (navigator.webdriver === true) {
      enqueue('headless_browser', {
        reason: 'navigator.webdriver is true'
      });
    }

    // Check user agent for headless patterns
    var ua = navigator.userAgent || '';
    var headlessPattern = /(HeadlessChrome|PhantomJS|Puppeteer|Selenium|webdriver)/i;
    if (headlessPattern.test(ua)) {
      enqueue('headless_browser', {
        reason: 'User agent contains headless pattern: ' + ua.match(headlessPattern)[0]
      });
    }

    // Check plugins
    if (navigator.plugins && navigator.plugins.length === 0) {
      enqueue('no_plugins', {
        reason: 'navigator.plugins.length is 0',
        pluginsCount: 0
      });
    }
  })();

  // ══════════════════════════════════════════════════════════
  // §12 — PUBLIC API
  // ══════════════════════════════════════════════════════════

  window.SiderisAgent = {
    /**
     * Manually track a custom event.
     * @param {string} type — event type name
     * @param {object} data — event-specific payload
     */
    track: function (type, data) {
      enqueue(type, data || {});
    },

    /**
     * Immediately flush the event queue.
     */
    flush: function () {
      flush();
    },

    /**
     * Returns the current session ID.
     * @returns {string}
     */
    getSessionId: function () {
      return getSessionId();
    },

    /**
     * Returns queue length (for debugging).
     * @returns {number}
     */
    getQueueLength: function () {
      return eventQueue.length;
    }
  };

  // ══════════════════════════════════════════════════════════
  // §13 — STARTUP LOG
  // ══════════════════════════════════════════════════════════

  console.log(
    '%c[Sideris Agent]%c initialized | session=' + sessionId.substring(0, 8) + '...',
    'color: #00ff88; font-weight: bold;',
    'color: #888;'
  );

})();
