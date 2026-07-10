// src/detector/eventAnalyzer.js
// Sideris 2.0 — Event Analyzer (Category-Aware Edition)
//
// Input : raw event from Redis stream (agent or backend)
// Output: { attack_type, category, behavior_signal, impact, base_confidence }
//
// 6 attack categories:
//   authentication — credential attacks (brute force, spray, stuffing)
//   injection      — payload-based (SQLi, XSS, CMDi, SSTI, XXE, SSRF)
//   fuzzing        — scanning & discovery (404 storm, dir brute, tool UA)
//   bot            — automation signals (headless, instant fill, bursts)
//   dos            — volumetric abuse (flood, repeated endpoint)
//   session_abuse  — session/privilege manipulation
//
// 18+ detection rules, each with:
//   rule_name, condition, category, impact (1-5), confidence (0–1.5)
'use strict';

// §1 — PAYLOAD ATTACK PATTERNS

// SQL Injection
const SQL_PAT = /(UNION[\s\/\*]+SELECT|'\s*OR\s*'|OR\s+1\s*=\s*1|[\s'"]+--\s*$|#\s*$|DROP\s+TABLE|INSERT\s+INTO|EXEC\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|CHAR\s*\(|CONCAT\s*\(|SLEEP\s*\(|LOAD_FILE\s*\(|INTO\s+OUTFILE)/i;

// Cross-Site Scripting
const XSS_PAT = /(<script[\s>]|javascript\s*:|on(error|load|click|mouseover|focus|blur|submit)\s*=|<iframe[\s>]|<svg[^>]+onload|document\.cookie|eval\s*\(|alert\s*\(|prompt\s*\(|confirm\s*\(|String\.fromCharCode|<img[^>]+onerror)/i;

// Command Injection
const _CMD_CMDS = 'ls|id|cat|wget|curl|whoami|uname|pwd|echo|bash|sh|python3?|perl|ruby|nc|netcat|ncat|ping|nslookup|dig|env|printenv|ifconfig|ipconfig|type';
const CMD_PAT = new RegExp(
  `([;&|\`]|\\$\\()\\s*(${_CMD_CMDS})(\\s|;|\\)|$)` +
  `|(?:^|[\\s&;|=?])(cmd|command|exec|execute|run|shell|system|passthru|popen|proc_open)\\s*=\\s*(${_CMD_CMDS})` +
  `|(\\|\\||&&)\\s*(${_CMD_CMDS})`,
  'im'
);

// Server-Side Template Injection
const SSTI_PAT = /\{\{[\s\S]{0,50}\}\}|\$\{[\s\S]{0,50}\}|<%=[\s\S]{0,50}%>|#\{[\s\S]{0,50}\}|\{%[\s\S]{0,50}%\}|\[#[\s\S]{0,50}\]|#set\s*\(|#foreach\s*\(|\$context\.class|T\(java\.lang/;

// XML External Entity
const XXE_PAT = /<!DOCTYPE[^>]*\[|<!ENTITY\s|SYSTEM\s+["'](file|http|https|gopher|ftp|php|expect):\/\//i;

// Server-Side Request Forgery
const SSRF_PAT = /(https?:\/\/(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|localhost|0\.0\.0\.0)|file:\/\/|gopher:\/\/|dict:\/\/|sftp:\/\/)/i;

// Path / Directory Traversal
const DIR_PAT = /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%2e%2e%5c|\.\.%2f|\.\.%5c)/i;

// §2 — TOOL & BEHAVIORAL FINGERPRINTS

// Known attack tool User-Agents
const SCANNER_UA_PAT = /(sqlmap|nikto|nessus|openvas|nmap|masscan|burpsuite|burp\s*suite|zaproxy|owasp[\s-]?zap|w3af|acunetix|appscan|netsparker|vega|webscarab|wfuzz|dirb|gobuster|dirbuster|feroxbuster|ffuf|nuclei|metasploit|havij|pangolin|arachni|skipfish|grabber|wapiti|commix|droopescan|joomscan|wpscan|shodan|censys|xsser|beef)/i;

// Sensitive files + PHP LFI wrappers
const SENSITIVE_FILE_PAT = /(php:\/\/(filter|input|stdin|fd)|phar:\/\/|data:\/\/text\/|zip:\/\/|compress\.(zlib|bzip2):\/\/|\.git\/(config|HEAD|COMMIT_EDITMSG|packed-refs)|\.env(\.|$)|\.env\.(local|prod|production|dev|development|test)|web\.config|app\.config|database\.yml|secrets\.yml|config\.php|wp-config\.php|settings\.py|\.htpasswd|\.htaccess|phpinfo\.php|php_info\.php|info\.php|test\.php|shell\.php|cmd\.php|webshell\.|\.(bak|backup|old|sql|db|dump|tar|zip)|backup\.|dump\.|db\.|\.(DS_Store)|Thumbs\.db|\.svn\/entries|\.idea\/|crossdomain\.xml|clientaccesspolicy\.xml|\/server-status|\/server-info|\/actuator\/|\/metrics|\/health\/|\/trace$|\/heapdump|\/threaddump)/i;

// CMS / framework admin paths
const CMS_ADMIN_PAT = /\/(wp-admin|wp-login\.php|phpmyadmin|pma\/|adminer\.php|cpanel|webmin|plesk|directadmin|roundcube|squirrelmail|joomla\/administrator|drupal\/admin|typo3\/|ajaxplorer|filemanager\.php|fckeditor|ckeditor\/samples|tiny_mce\/utils\/moxiemanager|ckfinder\/|elrte\/|spaw2\/)(\/|$|\?)/i;

// HTTP methods that should never appear in normal web traffic
const ABUSED_METHODS = new Set(['TRACE', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'SEARCH', 'PATCH_TRACE']);

// Auth-related endpoints (generic patterns)
const AUTH_ENDPOINT_PAT = /\/(login|signin|sign-in|auth|authenticate|token|oauth|api\/login|rest\/user\/login|api\/auth|session)/i;

// §3 — ATTACK CATEGORY MAP
// Maps each attack_type → category + human behavior_signal

const CATEGORY_MAP = {
  // injection
  sql_injection:       { category: 'injection',       signal: 'SQL payload in parameter (UNION/OR/SLEEP)' },
  xss:                 { category: 'injection',       signal: 'XSS payload (<script>, onerror=, eval)' },
  cmd_injection:       { category: 'injection',       signal: 'Shell metachar + command in input' },
  ssti:                { category: 'injection',       signal: 'Template syntax {{…}} in input' },
  xxe:                 { category: 'injection',       signal: '<!DOCTYPE> + SYSTEM entity in body' },
  ssrf:                { category: 'injection',       signal: 'Internal IP or file:// in parameter' },
  file_upload_exploit: { category: 'injection',       signal: 'Shell-extension file upload (.php, .jsp)' },

  // authentication
  auth_failure:        { category: 'authentication',  signal: 'Failed login (401/403 on auth endpoint)' },
  credential_stuffing: { category: 'authentication',  signal: 'Rapid login attempts (same IP, varied users)' },
  password_spray:      { category: 'authentication',  signal: 'Same password across multiple usernames' },

  // fuzzing
  scanner_tool:        { category: 'fuzzing',         signal: 'Attack tool User-Agent detected' },
  recon_404:           { category: 'fuzzing',         signal: 'Non-existent path accessed (404)' },
  file_exposure:       { category: 'fuzzing',         signal: 'Sensitive file access (.env, .git, .bak)' },
  cms_admin_probe:     { category: 'fuzzing',         signal: 'CMS/admin path probe (/wp-admin, /phpmyadmin)' },
  directory_traversal: { category: 'fuzzing',         signal: 'Path traversal (../ sequences)' },
  http_method_abuse:   { category: 'fuzzing',         signal: 'Unusual HTTP method (TRACE, PROPFIND)' },

  // bot
  headless_browser:    { category: 'bot',             signal: 'navigator.webdriver = true (headless)' },
  rapid_navigation:    { category: 'bot',             signal: '10+ pages loaded in 5 seconds' },
  instant_form_fill:   { category: 'bot',             signal: 'Form submitted < 800ms from focus' },
  keystroke_burst:     { category: 'bot',             signal: '>10 keystrokes in 500ms (inhuman speed)' },
  no_mouse_activity:   { category: 'bot',             signal: 'No mouse movement detected (bot)' },
  rapid_click:         { category: 'bot',             signal: 'Rapid click burst detected' },
  fast_typing:         { category: 'bot',             signal: 'Inhumanly fast typing speed' },

  // dos
  request_flood:       { category: 'dos',             signal: 'Extremely high request rate (>50/min)' },
  endpoint_hammer:     { category: 'dos',             signal: 'Same endpoint hit >20 times in 60s' },

  // session_abuse
  session_ip_change:   { category: 'session_abuse',   signal: 'Session used from different IP' },
  abnormal_navigation: { category: 'session_abuse',   signal: 'Jumped to privileged page without auth flow' },

  // benign
  normal_browsing:     { category: 'normal',          signal: 'Normal user activity' },
};

// §4 — IMPACT TABLE (1-5 scale)
const IMPACT = {
  normal_browsing:     0,
  recon_404:           1,
  http_method_abuse:   3,
  no_mouse_activity:   2,
  auth_failure:        3,
  rapid_navigation:    2,
  instant_form_fill:   2,
  keystroke_burst:     2,
  rapid_click:         2,
  fast_typing:         2,
  directory_traversal: 3,
  scanner_tool:        4,
  file_exposure:       6,
  cms_admin_probe:     8,
  xss:                 30,
  credential_stuffing: 4,
  password_spray:      4,
  endpoint_hammer:     3,
  request_flood:       4,
  session_ip_change:   3,
  abnormal_navigation: 3,
  cmd_injection:       30,
  sql_injection:       30,
  ssti:                30,
  xxe:                 30,
  ssrf:                30,
  file_upload_exploit: 30,
  headless_browser:    6,
};

// §5 — AGENT EVENT MAP
// Maps client-side behavioral event_types → attack_types
const AGENT_MAP = {
  headless_browser:  { type: 'headless_browser',    confidence: 1.3 },
  rapid_navigation:  { type: 'rapid_navigation',    confidence: 0.9 },
  suspicious_url:    { type: 'directory_traversal',  confidence: 1.0 },
  instant_form_fill: { type: 'instant_form_fill',   confidence: 0.8 },
  keystroke_burst:   { type: 'keystroke_burst',      confidence: 0.7 },
  no_mouse:          { type: 'no_mouse_activity',    confidence: 0.6 },
  rapid_click:       { type: 'rapid_click',          confidence: 0.8 },
  fast_typing:       { type: 'fast_typing',          confidence: 0.7 },
};

// §6 — MAIN ANALYSIS FUNCTION
function analyze(event) {
  const source    = event.source     || 'unknown';
  const eventType = event.event_type || '';
  const data      = event.data       || {};

  // Agent (client-side behavioral) events
  if (source === 'agent') {
    const mapped = AGENT_MAP[eventType];
    if (mapped) {
      const cat = CATEGORY_MAP[mapped.type] || { category: 'bot', signal: 'Unknown agent signal' };
      return {
        attack_type:     mapped.type,
        category:        cat.category,
        behavior_signal: cat.signal,
        impact:          IMPACT[mapped.type] || 2,
        base_confidence: mapped.confidence,
      };
    }
    // All other agent events → 0 pts
    return {
      attack_type:     'normal_browsing',
      category:        'normal',
      behavior_signal: 'Normal user activity',
      impact:          0,
      base_confidence: 0.5,
    };
  }

  // Backend (proxy access log) events
  if (source === 'backend' && eventType === 'backend_log') {
    const endpoint  = data.endpoint  || '';
    const path      = endpoint.split('?')[0].toLowerCase();
    const status    = parseInt(data.status  || '200', 10);
    const method    = (data.method  || 'GET').toUpperCase();
    const userAgent = (data.userAgent || '').toLowerCase();

    // Build full payload string for pattern scanning
    const queryStr  = typeof data.query === 'string' ? data.query : JSON.stringify(data.query  || '');
    const bodyStr   = typeof data.body  === 'string' ? data.body  : JSON.stringify(data.body   || '');
    const payload   = queryStr + ' ' + bodyStr + ' ' + endpoint;

    // RULE 1: sql_injection
    // IF: SQL keywords (UNION SELECT, OR 1=1, SLEEP, BENCHMARK) in query/body/URL
    // category=injection, impact=5, confidence=1.3
    if (SQL_PAT.test(payload)) {
      return result('sql_injection', 5, 1.3);
    }

    // RULE 2: xss
    // IF: <script>, onerror=, javascript:, eval() in query/body/URL
    // category=injection, impact=4, confidence=1.2
    if (XSS_PAT.test(payload)) {
      return result('xss', 4, 1.2);
    }

    // RULE 3: cmd_injection
    // IF: Shell metachar (;|`$()) followed by system command in input
    // category=injection, impact=5, confidence=1.2
    if (CMD_PAT.test(payload) || CMD_PAT.test(decodeURIComponent(payload).replace(/\+/g, ' '))) {
      return result('cmd_injection', 5, 1.2);
    }

    // RULE 4: ssti
    // IF: Template syntax {{7*7}}, ${…}, <%=…%> in input
    // category=injection, impact=5, confidence=1.0
    if (SSTI_PAT.test(payload)) {
      return result('ssti', 5, 1.0);
    }

    // RULE 5: xxe
    // IF: <!DOCTYPE with nested entity or SYSTEM file:// in body
    // category=injection, impact=5, confidence=1.0
    if (XXE_PAT.test(payload)) {
      return result('xxe', 5, 1.0);
    }

    // RULE 6: ssrf
    // IF: Internal IP (127.x, 10.x, 192.168.x) or file:// in parameter
    // category=injection, impact=5, confidence=1.0
    if (SSRF_PAT.test(payload)) {
      return result('ssrf', 5, 1.0);
    }

    // RULE 7: directory_traversal
    // IF: ../ or ..\\ or %2e%2e%2f sequences in endpoint
    // category=fuzzing, impact=3, confidence=1.0
    if (DIR_PAT.test(endpoint)) {
      return result('directory_traversal', 3, 1.0);
    }

    // RULE 8: scanner_tool
    // IF: User-Agent matches known tool (sqlmap, nikto, ffuf, nuclei…)
    // category=fuzzing, impact=3, confidence=1.3
    if (SCANNER_UA_PAT.test(userAgent)) {
      return result('scanner_tool', 3, 1.3);
    }

    // RULE 9: file_exposure
    // IF: Request to .env, .git/config, wp-config.php, phpinfo, .bak, etc.
    // category=fuzzing, impact=4, confidence=1.0
    if (SENSITIVE_FILE_PAT.test(path) || SENSITIVE_FILE_PAT.test(endpoint)) {
      return result('file_exposure', 4, 1.0);
    }

    // RULE 10: file_upload_exploit
    // IF: POST with filename containing .php, .jsp, .sh, .py, .cgi extension
    // category=injection, impact=5, confidence=1.2
    if (method === 'POST') {
      const combined = (data.filename || '') + path + bodyStr;
      if (/\.(php\d*|asp|aspx|jsp|jspx|sh|py|pl|cgi|cfm|shtml)((\?|$)|["'])/i.test(combined)) {
        return result('file_upload_exploit', 5, 1.2);
      }
    }

    // RULE 11: cms_admin_probe
    // IF: Request to /wp-admin, /phpmyadmin, /cpanel, /adminer on non-CMS app
    // category=fuzzing, impact=3, confidence=1.0
    if (CMS_ADMIN_PAT.test(path)) {
      return result('cms_admin_probe', 3, 1.0);
    }

    // RULE 12: http_method_abuse
    // IF: method IN (TRACE, CONNECT, PROPFIND, PROPPATCH, MKCOL…)
    // category=fuzzing, impact=2, confidence=1.0
    if (ABUSED_METHODS.has(method)) {
      return result('http_method_abuse', 2, 1.0);
    }

    // RULE 13: auth_failure
    // IF: status IN (401, 403) AND endpoint matches auth pattern
    // OR: status IN (401, 403) on any endpoint
    // category=authentication, impact=3, confidence depends on endpoint match
    if (status === 401 || status === 403) {
      const isAuthEndpoint = AUTH_ENDPOINT_PAT.test(path);
      return result('auth_failure', 3, isAuthEndpoint ? 1.2 : 0.8);
    }

    // RULE 14: recon_404
    // IF: status == 404
    // category=fuzzing, impact=1 (individual), scored via bonus accumulation
    if (status === 404) {
      return result('recon_404', 1, 0.5);
    }
  }

  // Default — normal browsing, no score
  return result('normal_browsing', 0, 0.5);
}

// Helper: build result object
function result(attackType, impact, confidence) {
  const cat = CATEGORY_MAP[attackType] || { category: 'normal', signal: 'Unknown' };
  const actualImpact = IMPACT[attackType] !== undefined ? IMPACT[attackType] : impact;
  return {
    attack_type:     attackType,
    category:        cat.category,
    behavior_signal: cat.signal,
    impact:          actualImpact,
    base_confidence: confidence,
  };
}

module.exports = { analyze, IMPACT, CATEGORY_MAP };
