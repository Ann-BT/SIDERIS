import { useState, useEffect, useCallback, useRef, useLayoutEffect } from 'react'
import './index.css'

const API = import.meta.env.VITE_API_URL || (window.location.pathname.startsWith('/dashboard')
  ? `${window.location.protocol}//${window.location.host}/dashboard-api`
  : `${window.location.protocol}//${window.location.hostname}:6001`)

const CATEGORIES = [
  { key: 'authentication',  label: 'Authentication',  color: '#f59e0b' },
  { key: 'injection',       label: 'Injection',       color: '#ef4444' },
  { key: 'fuzzing',         label: 'Fuzzing',         color: '#8b5cf6' },
  { key: 'bot',             label: 'Bot / Automation', color: '#06b6d4' },
  { key: 'dos',             label: 'Denial of Service',color: '#ec4899' },
  { key: 'session_abuse',   label: 'Session Abuse',   color: '#14b8a6' },
]



// ── Main App ─────────────────────────────────────────────────────────────────
function App() {
  const [metrics, setMetrics] = useState({ blocks: 0, challenges: 0, rate_limits: 0, processed: 0 })
  const [sessions, setSessions] = useState([])
  const [guards, setGuards] = useState([])
  const [dashboardUsers, setDashboardUsers] = useState([])
  const [errorStatus, setErrorStatus] = useState(false)
  const [expandedSession, setExpandedSession] = useState(null)
  const [unblockConfirm, setUnblockConfirm] = useState(null)
  const [blockConfirm, setBlockConfirm] = useState(null)
  const [toast, setToast] = useState(null)
  const [logs, setLogs] = useState([])
  const [logsPaused, setLogsPaused] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const [activeTab, setActiveTab] = useState('lifecycle')
  const [theme, setTheme] = useState(() => localStorage.getItem('sideris-theme') || 'catppuccin')
  const [themePickerOpen, setThemePickerOpen] = useState(false)
  const [refreshTrigger, setRefreshTrigger] = useState(0)

  useEffect(() => {
    const classes = document.body.className.split(' ').filter(c => c && !c.startsWith('theme-'));
    classes.push(`theme-${theme}`);
    document.body.className = classes.join(' ');
    localStorage.setItem('sideris-theme', theme);
  }, [theme]);

  // Sorting state for Live Threat Sessions
  const [sortBy, setSortBy]   = useState('score')   // 'score' | 'critical' | 'very_high' | 'high' | 'suspicious' | 'normal'
  const [sessionSortField, setSessionSortField] = useState('score') // 'score' | 'ip' | 'last_seen'
  const [sortDir, setSortDir] = useState('desc')     // 'asc' | 'desc'

  // Sorting & search state for Active Defense Matrix (guards)
  const [guardSortBy, setGuardSortBy]   = useState('score')       // 'score' | 'action' | 'updated_at'
  const [guardSortDir, setGuardSortDir] = useState('desc')        // 'asc' | 'desc'
  const [guardSearch, setGuardSearch]   = useState('')
  const [guardActionFilter, setGuardActionFilter] = useState('all') // 'all' | 'block' | 'challenge' | 'rate_limit'

  const ITEMS_PER_PAGE = 30
  const GUARDS_PER_PAGE = 30
  const [sessionPage, setSessionPage] = useState(1)
  const [guardPage, setGuardPage] = useState(1)

  // Reset session page when sort or filter changes
  useEffect(() => {
    setSessionPage(1)
  }, [sortBy, sessionSortField, sortDir])

  // Reset guard page when sort, search, action filter, or direction changes
  useEffect(() => {
    setGuardPage(1)
  }, [guardSearch, guardSortBy, guardSortDir, guardActionFilter])

  // Escape key listener for guide modal
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setShowGuide(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  const logsEndRef = useRef(null)
  const logsBoxRef = useRef(null)

  const showToast = useCallback((message, type = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 4000)
  }, [])

  const formatRelativeTime = (epochMs) => {
    if (!epochMs) return 'Unknown'
    const diff = Math.floor((Date.now() - epochMs) / 1000)
    if (diff < 5) return 'just now'
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    return `${Math.floor(diff / 3600)}h ago`
  }

  const formatLocalLogTime = (isoString) => {
    if (!isoString) return ''
    try {
      const d = new Date(isoString)
      if (isNaN(d.getTime())) return isoString.replace('T', ' ').slice(0, 23)
      const pad = n => String(n).padStart(2, '0')
      const pad3 = n => String(n).padStart(3, '0')
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad3(d.getMilliseconds())}`
    } catch {
      return isoString.replace('T', ' ').slice(0, 23)
    }
  }

  const getRiskClass = (score) => {
    if (score >= 50) return 'critical-risk'
    if (score >= 30) return 'very-high-risk'
    if (score >= 20) return 'high-risk'
    if (score >= 10) return 'medium-risk'
    return 'low-risk'
  }

  const getVerdictClass = (verdict) => {
    const v = (verdict || '').toLowerCase()
    if (v === 'critical' || v === 'hard_block')  return 'verdict-critical'
    if (v === 'very_high' || v === 'soft_block') return 'verdict-very-high'
    if (v === 'high' || v === 'captcha')      return 'verdict-high'
    if (v === 'suspicious' || v === 'rate_limit') return 'verdict-suspicious'
    return 'verdict-normal'
  }

  const getVerdictLabel = (level) => {
    const map = {
      critical: 'CRITICAL',
      very_high: 'VERY HIGH',
      high: 'HIGH',
      suspicious: 'SUSPICIOUS',
      hard_block: 'HARD BLOCK',
      soft_block: 'SOFT BLOCK',
      captcha: 'CHALLENGE',
      rate_limit: 'RATE LIMIT'
    }
    return map[level] || 'NORMAL'
  }

  const getMitigationLabel = (action, blockType) => {
    const act = (action || '').toLowerCase()
    const bt = (blockType || '').toLowerCase()
    if (act === 'block') {
      if (bt === 'hard') return 'HARD BLOCK'
      return 'BLOCK'
    }
    if (act === 'hard_block') return 'HARD BLOCK'
    if (act === 'soft_block') return 'SOFT BLOCK'
    if (act === 'challenge' || act === 'captcha') return 'CHALLENGE'
    if (act === 'rate_limit') return 'RATE LIMIT'
    return (action || 'ALLOW').toUpperCase()
  }

  // Auto-scroll logs to bottom when new entries arrive (unless user scrolled up)
  useEffect(() => {
    const box = logsBoxRef.current
    if (!box || logsPaused) return
    const isNearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80
    if (isNearBottom) {
      box.scrollTop = box.scrollHeight
    }
  }, [logs, logsPaused])

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [metRes, sesRes, guardRes, userRes] = await Promise.all([
          fetch(`${API}/metrics`),
          fetch(`${API}/sessions`),
          fetch(`${API}/guards`),
          fetch(`${API}/dashboard-users`)
        ])
        if (!metRes.ok || !sesRes.ok || !guardRes.ok || !userRes.ok) throw new Error('API Sync Failed')
        setMetrics(await metRes.json())
        setSessions(await sesRes.json())
        setGuards(await guardRes.json())
        setDashboardUsers(await userRes.json())
        setErrorStatus(false)
      } catch (err) {
        console.error("Dashboard Sync Error:", err)
        setErrorStatus(true)
      }
    }

    const fetchLogs = async () => {
      if (logsPaused) return
      try {
        const res = await fetch(`${API}/logs?limit=100`)
        if (res.ok) setLogs(await res.json())
      } catch { /* silent */ }
    }

    fetchData()
    fetchLogs()
    const interval = setInterval(() => { fetchData(); fetchLogs() }, 3000)
    return () => clearInterval(interval)
  }, [logsPaused, refreshTrigger])

  const handleUnblock = async (sessionId) => {
    try {
      const res = await fetch(`${API}/unblock/${sessionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'SOC analyst manual unblock' }),
      })
      const data = await res.json()
      if (data.success) {
        showToast(`Session ${sessionId.substring(0, 12)}… unblocked`, 'success')
        setUnblockConfirm(null)
        setRefreshTrigger(t => t + 1)
      } else {
        showToast(data.error || 'Unblock failed', 'error')
      }
    } catch {
      showToast('Network error during unblock', 'error')
    }
  }

  const handleBlock = async (sessionId) => {
    try {
      const res = await fetch(`${API}/block/${sessionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'SOC analyst manual block' }),
      })
      const data = await res.json()
      if (data.success) {
        showToast(`Session ${sessionId.substring(0, 12)}… blocked`, 'warning')
        setBlockConfirm(null)
        setRefreshTrigger(t => t + 1)
      } else {
        showToast(data.error || 'Block failed', 'error')
      }
    } catch {
      showToast('Network error during block', 'error')
    }
  }

  const totalCategoryEvents = (cats) => Object.values(cats || {}).reduce((a, b) => a + b, 0)
  const maxCategoryCount = (cats) => Math.max(1, ...Object.values(cats || {}))

  const filteredGuards = guards
    .filter(g => {
      if (guardSearch) {
        const searchLower = guardSearch.toLowerCase()
        const idMatch = (g.session_id || '').toLowerCase().includes(searchLower)
        const resolvedIp = g.ip_address || (sessions.find(s => s.session_id === g.session_id)?.ip_address) || ''
        const ipMatch = resolvedIp.toLowerCase().includes(searchLower)
        if (!idMatch && !ipMatch) return false
      }
      if (guardActionFilter !== 'all') {
        if (g.action !== guardActionFilter) return false
      }
      return true
    })
    .sort((a, b) => {
      let valA, valB
      if (guardSortBy === 'score') {
        valA = parseFloat(a.risk_score || 0)
        valB = parseFloat(b.risk_score || 0)
      } else if (guardSortBy === 'action') {
        valA = (a.action || '').toLowerCase()
        valB = (b.action || '').toLowerCase()
      } else {
        valA = a.updated_at || 0
        valB = b.updated_at || 0
      }
      if (valA < valB) return guardSortDir === 'desc' ? 1 : -1
      if (valA > valB) return guardSortDir === 'desc' ? -1 : 1
      return 0
    })

  const totalGuardPages = Math.ceil(filteredGuards.length / GUARDS_PER_PAGE)
  const currentGuardPage = Math.min(guardPage, Math.max(1, totalGuardPages))
  const paginatedGuards = filteredGuards.slice(
    (currentGuardPage - 1) * GUARDS_PER_PAGE,
    currentGuardPage * GUARDS_PER_PAGE
  )

  const filteredAndSortedSessions = sessions
    .filter(s => sortBy === 'score' || (s.level || 'normal') === sortBy)
    .sort((a, b) => {
      let diff = 0
      if (sessionSortField === 'score') {
        diff = (a.session_score || 0) - (b.session_score || 0)
      } else if (sessionSortField === 'ip') {
        const ipA = (a.ip_address || '').toLowerCase()
        const ipB = (b.ip_address || '').toLowerCase()
        if (ipA < ipB) return sortDir === 'desc' ? 1 : -1
        if (ipA > ipB) return sortDir === 'desc' ? -1 : 1
        return 0
      } else if (sessionSortField === 'last_seen') {
        diff = (a.last_seen || 0) - (b.last_seen || 0)
      }
      return sortDir === 'desc' ? -diff : diff
    })

  const totalSessionPages = Math.ceil(filteredAndSortedSessions.length / ITEMS_PER_PAGE)
  const currentSessionPage = Math.min(sessionPage, Math.max(1, totalSessionPages))
  const paginatedSessions = filteredAndSortedSessions.slice(
    (currentSessionPage - 1) * ITEMS_PER_PAGE,
    currentSessionPage * ITEMS_PER_PAGE
  )

  const getTopAttackerIPs = () => {
    const ipMap = {}
    sessions.forEach(s => {
      if (!s.ip_address) return
      if (!ipMap[s.ip_address]) {
        ipMap[s.ip_address] = { ip: s.ip_address, count: 0, maxScore: 0 }
      }
      ipMap[s.ip_address].count += s.event_count || 0
      const score = parseFloat(s.highest_score || 0)
      if (score > ipMap[s.ip_address].maxScore) {
        ipMap[s.ip_address].maxScore = score
      }
    })
    return Object.values(ipMap)
      .sort((a, b) => b.count - a.count)
      .slice(0, 20)
  }

  return (
    <div className="sideris-dashboard">
      <header className="dash-header">
        <div className="header-left">
          <h1>SIDERIS <span className="highlight">Runtime Defense</span></h1>
          <span className="header-subtitle">protecting : {metrics.targetUrl || '—'}</span>
        </div>
        <div className="header-right">
          {/* Theme picker button + modal */}
          <div style={{ position: 'relative' }}>
            <button className="theme-btn" onClick={() => setThemePickerOpen(o => !o)} title="Change theme">
              <span className="theme-btn-label">Theme</span>
            </button>
            {themePickerOpen && (
              <>
                <div className="theme-modal-backdrop" onClick={() => setThemePickerOpen(false)} />
                <div className="theme-modal" style={{ position: 'fixed', top: '56px', right: '2rem', zIndex: 9001 }}>
                  <div className="theme-modal-title">Choose a Theme</div>

                  {[
                    { label: 'Catppuccin', pairs: [
                      { value: 'catppuccin',       name: 'Mocha',  flavor: 'dark',  dots: ['#1e1e2e','#cba6f7','#fab387','#a6e3a1'] },
                      { value: 'catppuccin-latte', name: 'Latte',  flavor: 'light', dots: ['#eff1f5','#8839ef','#fe640b','#40a02b'] },
                    ]},
                    { label: 'GitHub', pairs: [
                      { value: 'github-dark',  name: 'GitHub', flavor: 'dark',  dots: ['#0d1117','#58a6ff','#bc8cff','#3fb950'] },
                      { value: 'github-light', name: 'GitHub', flavor: 'light', dots: ['#f6f8fa','#0969da','#8250df','#1a7f37'] },
                    ]},
                    { label: 'Gruvbox', pairs: [
                      { value: 'gruvbox-dark',  name: 'Gruvbox', flavor: 'dark',  dots: ['#282828','#fe8019','#fabd2f','#b8bb26'] },
                      { value: 'gruvbox-light', name: 'Gruvbox', flavor: 'light', dots: ['#fbf1c7','#d65d0e','#b57614','#79740e'] },
                    ]},
                    { label: 'Nord', pairs: [
                      { value: 'nord',       name: 'Nord', flavor: 'dark',  dots: ['#2e3440','#88c0d0','#81a1c1','#a3be8c'] },
                      { value: 'nord-light', name: 'Nord', flavor: 'light', dots: ['#eceff4','#5e81ac','#88c0d0','#a3be8c'] },
                    ]},
                    { label: 'Dracula', pairs: [
                      { value: 'dracula',      name: 'Dracula', flavor: 'dark',  dots: ['#282a36','#bd93f9','#ff79c6','#50fa7b'] },
                      { value: 'dracula-dawn', name: 'Dracula', flavor: 'light', dots: ['#f8f8f2','#6272a4','#bd93f9','#ff5555'] },
                    ]},
                    { label: 'One', pairs: [
                      { value: 'one-dark',  name: 'One Dark',  flavor: 'dark',  dots: ['#282c34','#61afef','#c678dd','#98c379'] },
                      { value: 'one-light', name: 'One Light', flavor: 'light', dots: ['#fafafa','#4078f2','#a626a4','#50a14f'] },
                    ]},
                    { label: 'Solarized', pairs: [
                      { value: 'solarized-dark',  name: 'Solarized', flavor: 'dark',  dots: ['#002b36','#268bd2','#cb4b16','#859900'] },
                      { value: 'solarized-light', name: 'Solarized', flavor: 'light', dots: ['#fdf6e3','#cb4b16','#b58900','#2aa198'] },
                    ]},
                    { label: 'Night Owl', pairs: [
                      { value: 'night-owl',       name: 'Night Owl', flavor: 'dark',  dots: ['#011627','#7fdbca','#82aaff','#c792ea'] },
                      { value: 'night-owl-light', name: 'Night Owl', flavor: 'light', dots: ['#fbfbfb','#4876d6','#2aa298','#994cc3'] },
                    ]},
                    { label: 'Coffee', pairs: [
                      { value: 'coffee', name: 'Coffee', flavor: 'warm',  dots: ['#FAF7F2','#C8773A','#6F4E37','#2A7D46'] },
                    ]},
                  ].map(group => (
                    <div key={group.label} className="theme-group">
                      <div className="theme-group-label">{group.label}</div>
                      <div className="theme-pair">
                        {group.pairs.map(t => (
                          <button
                            key={t.value}
                            className={`theme-swatch${theme === t.value ? ' active' : ''}`}
                            onClick={() => { setTheme(t.value); setThemePickerOpen(false); }}
                            title={`${t.name} ${t.flavor}`}
                          >
                            <div className="theme-swatch-dots">
                              {t.dots.map((c, i) => <span key={i} className="theme-dot" style={{ background: c }} />)}
                            </div>
                            <span className="theme-swatch-name">{t.name}</span>
                            <span className="theme-swatch-flavor">{t.flavor}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
          <button className="btn-runtime-guide" onClick={() => setShowGuide(true)}>
            Runtime Defense Guide
          </button>
          <div className={`status-indicator ${errorStatus ? 'offline' : 'online'}`} title={errorStatus ? 'API Disconnected' : 'Systems Online'} />
        </div>
      </header>

      {/* Top Dashboard Section */}
      <section className="top-dashboard-section">
        {/* Left Side: Top IP Addresses */}
        <div className="top-attackers-panel">
          <h3>Top IP Addresses</h3>
          <div className="attacker-list">
            {getTopAttackerIPs().map((item, idx) => (
              <div key={item.ip} className="attacker-row">
                <span className="attacker-rank">#{idx + 1}</span>
                <span className="attacker-ip code-font" title={item.ip}>
                  {item.ip.length > 24 ? item.ip.substring(0, 22) + '…' : item.ip}
                </span>
                <span className="attacker-stats">
                  <span className="badge-events">{item.count} events</span>
                  <span className="badge-score">{item.maxScore.toFixed(1)} score</span>
                </span>
              </div>
            ))}
            {getTopAttackerIPs().length === 0 && (
              <div className="empty-state">No IP data available</div>
            )}
          </div>
        </div>

        {/* Middle Side: Dashboard Access Log */}
        <div className="dashboard-access-panel">
          <h3>Dashboard Access Log</h3>
          <div className="attacker-list">
            {dashboardUsers.map((user, idx) => (
              <div key={user.ip + '_' + idx} className="attacker-row" title={user.user_agent}>
                <span className="attacker-ip code-font" title={user.ip}>
                  {user.ip.length > 24 ? user.ip.substring(0, 22) + '…' : user.ip}
                </span>
                <span className="attacker-stats">
                  <span className={user.allowed === '1' ? 'badge-allowed' : 'badge-blocked'}>
                    {user.allowed === '1' ? 'Allowed' : 'Blocked'}
                  </span>
                  <span className="badge-time">
                    {formatRelativeTime(parseInt(user.last_seen))}
                  </span>
                </span>
              </div>
            ))}
            {dashboardUsers.length === 0 && (
              <div className="empty-state">No access records available</div>
            )}
          </div>
        </div>

        {/* Right Side: 2x2 Metrics Grid */}
        <div className="metrics-2x2-grid">
          <div className="metric-card card-processed">
            <div className="metric-card-header">
              <h3>Events Processed</h3>
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="metric-icon"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
            </div>
            <div className="value">{metrics.processed.toLocaleString()}</div>
          </div>
          <div className="metric-card card-block">
            <div className="metric-card-header">
              <h3>Active Blocks</h3>
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="metric-icon"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
            </div>
            <div className="value red">{metrics.blocks}</div>
          </div>
          <div className="metric-card card-challenge">
            <div className="metric-card-header">
              <h3>Active Challenges</h3>
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="metric-icon"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>
            </div>
            <div className="value yellow">{metrics.challenges}</div>
          </div>
          <div className="metric-card card-ratelimit">
            <div className="metric-card-header">
              <h3>Rate Limits</h3>
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="metric-icon"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
            </div>
            <div className="value blue">{metrics.rate_limits}</div>
          </div>
        </div>
      </section>

      {/* ── Live Logs Panel ── */}
      <section className="logs-panel">
        <div className="logs-header">
          <div className="logs-title">
            <span className="logs-icon">▤</span>
            Live Logs
            <span className="logs-count">{logs.length} entries</span>
          </div>
          <div className="logs-controls">
            {!logsPaused && (
              <span className="live-indicator">
                <span className="live-dot"></span>Live
              </span>
            )}
            <button className="log-btn" onClick={() => setLogsPaused(p => !p)}>
              {logsPaused ? '▶ Resume' : '⏸ Pause'}
            </button>
            <button className="log-btn" onClick={async () => {
              try { const r = await fetch(`${API}/logs?limit=100`); if (r.ok) setLogs(await r.json()) } catch {}
            }}>Reload</button>
          </div>
        </div>
        <div className="logs-body" ref={logsBoxRef}>
          {logs.length === 0
            ? <div className="logs-empty">No backend access log entries yet…</div>
            : logs.map((log, i) => (
              <div key={i} className={`log-entry log-lvl-${log.level.toLowerCase()}`}>
                <span className="log-ts">{formatLocalLogTime(log.timestamp)}</span>
                <span className="log-svc">{log.service}</span>
                <span className="log-msg">{log.message}</span>
              </div>
            ))
          }
          <div ref={logsEndRef} />
        </div>
      </section>

      {/* Sessions Panel */}
      <section className="sessions-panel">
        <div className="sessions-panel-header">
          <h2 className="panel-title">
            Live Threat Sessions
            <span className="session-count">
              {sortBy !== 'score' ? `${filteredAndSortedSessions.length} of ${sessions.length}` : sessions.length} active
            </span>
          </h2>
          <div className="sort-controls">
            {/* Verdict filter pills */}
            <div className="sort-pills" role="group" aria-label="Filter by severity">
              {[
                { key: 'score',      label: 'All' },
                { key: 'critical',   label: 'Critical' },
                { key: 'very_high',  label: 'Very High' },
                { key: 'high',       label: 'High' },
                { key: 'suspicious', label: 'Suspicious' },
                { key: 'normal',     label: 'Normal' },
              ].map(opt => (
                <button
                  key={opt.key}
                  className={`sort-pill sort-pill-${opt.key} ${sortBy === opt.key ? 'active' : ''}`}
                  onClick={() => setSortBy(opt.key)}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            {/* Sort Field Selection */}
            <div className="sort-field-select">
              <span className="sort-label">Sort by:</span>
              <select
                value={sessionSortField}
                onChange={(e) => setSessionSortField(e.target.value)}
                className="sort-dropdown"
              >
                <option value="score">Score</option>
                <option value="ip">IP Address</option>
                <option value="last_seen">Last Seen</option>
              </select>
            </div>
            {/* Direction toggle */}
            <button
              className="sort-dir-btn"
              onClick={() => setSortDir(d => d === 'desc' ? 'asc' : 'desc')}
              title={sortDir === 'desc' ? 'Sort: High → Low' : 'Sort: Low → High'}
            >
              {sortDir === 'desc' ? '↓' : '↑'}
            </button>
          </div>
        </div>

        {sessions.length === 0 ? (
          <div className="empty-state-card">
            <div className="empty-icon"></div>
            <p>No active sessions detected</p>
          </div>
        ) : (
          <>
            <div className="session-list-header">
              <span></span>
              <span>Session ID</span>
              <span>IP Address</span>
              <span>Score (Live / Peak)</span>
              <span>Verdict (Live / Peak)</span>
              <span>Mitigation</span>
              <span>Events</span>
              <span className="header-time">Last Seen</span>
            </div>
            <div className="session-list">
            {paginatedSessions.map(s => {
                const score = parseFloat(s.session_score || 0)
                const isExpanded = expandedSession === s.session_id
                const cats = s.category_counts || {}
                const maxCat = maxCategoryCount(cats)

                return (
                  <div
                    key={s.session_id}
                    className={`session-card ${score >= 50 ? 'card-critical' : score >= 30 ? 'card-very-high' : score >= 20 ? 'card-high' : ''}`}
                  >
                    {/* ── Collapsed Row ── */}
                    <div
                      className="session-summary"
                      onClick={() => setExpandedSession(isExpanded ? null : s.session_id)}
                    >
                      <span className={`expand-chevron ${isExpanded ? 'open' : ''}`}>▶</span>

                      <div className="summary-id">
                        <span className="code-font">{s.session_id.substring(0, 16)}…</span>
                      </div>

                      <div className="summary-ip">
                        <span className="ip-label">IP</span>
                        <span className="ip-value">{s.ip_address || '—'}</span>
                      </div>

                      <div className="summary-score" style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                        <span className={`risk-badge ${getRiskClass(score)}`} title="Live Behavioral Score">
                          {score.toFixed(1)}
                        </span>
                        <span className={`risk-badge ${getRiskClass(s.highest_score)}`} title="Peak Threat Score" style={{ opacity: 0.6 }}>
                          {parseFloat(s.highest_score || 0).toFixed(1)}
                        </span>
                      </div>

                      <div className="summary-verdict" style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                        <span className={`verdict-badge ${getVerdictClass(s.level)}`} title="Live Verdict">
                          {getVerdictLabel(s.level)}
                        </span>
                        <span className={`verdict-badge ${getVerdictClass(s.highest_threat_level)}`} title="Peak Verdict" style={{ opacity: 0.6 }}>
                          {getVerdictLabel(s.highest_threat_level)}
                        </span>
                      </div>

                      <div className="summary-status">
                        {s.active_mitigation === 'block' && (
                          <span className="blocked-badge">
                            {s.highest_block_type === 'hard' ? 'HARD BLOCK' : 'BLOCK'}
                          </span>
                        )}
                        {s.active_mitigation === 'challenge' && <span className="challenge-badge">CHALLENGE</span>}
                        {s.active_mitigation === 'rate_limit' && <span className="ratelimit-badge">RATE LIMITED</span>}
                        {s.active_mitigation === 'allow' && <span className="allow-badge">ALLOW</span>}
                      </div>

                      <div className="summary-events">
                        <span className="event-count-badge">{s.event_count} events</span>
                      </div>

                      <div className="summary-time">
                        {formatRelativeTime(s.last_seen)}
                      </div>
                    </div>

                    {/* ── Expanded Detail ── */}
                    {isExpanded && (
                      <div className="session-detail">
                        {/* Category Breakdown */}
                        <div className="detail-section">
                          <h4 className="detail-heading">Attack Category Breakdown</h4>
                          <div className="category-grid">
                            {CATEGORIES.map(cat => {
                              const count = cats[cat.key] || 0
                              const pct = maxCat > 0 ? (count / maxCat) * 100 : 0
                              return (
                                <div key={cat.key} className={`category-row ${count > 0 ? 'active' : 'inactive'}`}>
                                  <span className="cat-icon" style={{ backgroundColor: cat.color }}></span>
                                  <span className="cat-label">{cat.label}</span>
                                  <div className="cat-bar-track">
                                    <div
                                      className="cat-bar-fill"
                                      style={{ width: `${pct}%`, backgroundColor: cat.color }}
                                    ></div>
                                  </div>
                                  <span className="cat-count" style={{ color: count > 0 ? cat.color : undefined }}>
                                    {count}
                                  </span>
                                </div>
                              )
                            })}
                          </div>
                        </div>

                        {/* Session Metadata Grouped into Categories */}
                        <div className="detail-section">
                          <h4 className="detail-heading">Session Intelligence</h4>
                          
                          {/* Identity & Telemetry Banner */}
                          <div className="intel-banner">
                            <div className="intel-banner-left">
                              <div className="intel-banner-row">
                                <span className="intel-banner-key">Session Name</span>
                                <span className="intel-banner-val">{s.session_id}</span>
                                <button
                                  className="btn-copy-small"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    navigator.clipboard.writeText(s.session_id);
                                    showToast('Copied session ID!', 'success');
                                  }}
                                  title="Copy Session ID to Clipboard"
                                >
                                  Copy
                                </button>
                              </div>
                              <div className="intel-banner-row" style={{ marginTop: '6px' }}>
                                <span className="intel-banner-key">IP Address</span>
                                <span className="intel-banner-val">{s.ip_address || '—'}</span>
                                <span className="intel-banner-sep">|</span>
                                <span className="intel-banner-key">User Agent</span>
                                <span className="intel-banner-val meta-ua" title={s.user_agent || ''}>
                                  {s.user_agent || '—'}
                                </span>
                              </div>
                            </div>
                            <div className="intel-banner-right">
                              <div className="telemetry-pill">
                                <span className="tel-key">Login Attempts</span>
                                <span className="tel-val">{s.login_attempts || 0}</span>
                              </div>
                              <div className="telemetry-pill">
                                <span className="tel-key">Unique Usernames Tried</span>
                                <span className="tel-val">{s.unique_username_count || 0}</span>
                              </div>
                              <div className="telemetry-pill">
                                <span className="tel-key">404 Errors</span>
                                <span className="tel-val">{s.count_404 || 0}</span>
                              </div>
                            </div>
                          </div>

                          {/* Symmetrical 3-Column Grid */}
                          <div className="intel-balanced-grid">
                            {/* Threat Analysis Card */}
                            <div className="intel-category-card">
                              <h5 className="intel-category-title">Threat Analysis</h5>
                              <div className="intel-field-list">
                                <div className="intel-field-row">
                                  <span className="intel-field-label">Peak Score</span>
                                  <span className="intel-field-value">{s.highest_score ? s.highest_score.toFixed(1) : '0.0'}</span>
                                </div>
                                <div className="intel-field-row">
                                  <span className="intel-field-label">Highest Threat</span>
                                  <span className="intel-field-value">{getVerdictLabel(s.highest_threat_level)}</span>
                                </div>
                                <div className="intel-field-row">
                                  <span className="intel-field-label">Scanner Detected</span>
                                  <span className={`intel-field-value ${s.scanner_detected ? 'val-danger' : ''}`}>
                                    {s.scanner_detected ? 'YES' : 'No'}
                                  </span>
                                </div>
                              </div>
                            </div>

                            {/* Enforcement Card */}
                            <div className="intel-category-card">
                              <h5 className="intel-category-title">Enforcement</h5>
                              <div className="intel-field-list">
                                <div className="intel-field-row">
                                  <span className="intel-field-label">Last Mitigation</span>
                                  <span className="intel-field-value">{getMitigationLabel(s.last_mitigation, s.highest_block_type)}</span>
                                </div>
                                <div className="intel-field-row">
                                  <span className="intel-field-label">Mitigation Reason</span>
                                  <span className="intel-field-value text-warning">{s.mitigation_reason || '—'}</span>
                                </div>
                                <div className="intel-field-row">
                                  <span className="intel-field-label">Guard Source</span>
                                  <span className="intel-field-value">{s.guard_source ? s.guard_source.toUpperCase() : '—'}</span>
                                </div>
                              </div>
                            </div>

                            {/* Timeline Card */}
                            <div className="intel-category-card">
                              <h5 className="intel-category-title">Timeline</h5>
                              <div className="intel-field-list">
                                <div className="intel-field-row">
                                  <span className="intel-field-label">First Suspicious</span>
                                  <span className="intel-field-value">{s.first_suspicious_at ? new Date(s.first_suspicious_at).toLocaleTimeString() : '—'}</span>
                                </div>
                                <div className="intel-field-row">
                                  <span className="intel-field-label">Peak Score At</span>
                                  <span className="intel-field-value">{s.highest_score_at ? new Date(s.highest_score_at).toLocaleTimeString() : '—'}</span>
                                </div>
                                <div className="intel-field-row">
                                  <span className="intel-field-label">First Mitigated</span>
                                  <span className="intel-field-value">{s.first_mitigated_at ? new Date(s.first_mitigated_at).toLocaleTimeString() : '—'}</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>

                        {/* Triggered Rules (from url_counts) */}
                        {s.url_counts && Object.keys(s.url_counts).filter(k => k !== 'normal_browsing').length > 0 && (
                          <div className="detail-section">
                            <h4 className="detail-heading">Triggered Rules</h4>
                            <div className="rules-chips">
                              {Object.entries(s.url_counts)
                                .filter(([k]) => k !== 'normal_browsing')
                                .sort((a, b) => b[1] - a[1])
                                .map(([rule, count]) => (
                                  <span key={rule} className="rule-chip">
                                    {rule.replace(/_/g, ' ')} <strong>×{count}</strong>
                                  </span>
                                ))}
                            </div>
                          </div>
                        )}

                        {/* Bonuses Applied */}
                        {s.bonus_applied && s.bonus_applied.length > 0 && (
                          <div className="detail-section">
                            <h4 className="detail-heading">Behavior Bonuses Applied</h4>
                            <div className="bonus-list">
                              {s.bonus_applied.map((b, i) => (
                                <span key={i} className="bonus-chip">⚡ {b.replace(/_/g, ' ')}</span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Behavior Timeline */}
                        <div className="detail-section">
                          <h4 className="detail-heading">Behavior Timeline (Recent)</h4>
                          <div className="timeline">
                            {(!s.risk_reasons || s.risk_reasons.length === 0) ? (
                              <div className="timeline-empty">No risk events recorded yet</div>
                            ) : (
                              s.risk_reasons.map((r, i) => (
                                <div key={i} className="timeline-entry">
                                  <span className="tl-time">{formatRelativeTime(r.timestamp)}</span>
                                  <span className={`tl-category cat-${r.category}`}>{r.category}</span>
                                  <span className="tl-rule">{r.rule?.replace(/_/g, ' ')}</span>
                                  <span className="tl-signal">{r.signal}</span>
                                  <span className="tl-score">{r.score}</span>
                                </div>
                              ))
                            )}
                          </div>
                        </div>

                        {/* SOC Actions */}
                        <div className="detail-section soc-actions">
                          {s.is_blocked ? (
                            // UNBLOCK flow
                            unblockConfirm === s.session_id ? (
                              <div className="confirm-bar">
                                <span className="confirm-text">Confirm unblock this session & IP?</span>
                                <button
                                  className="btn-confirm-yes"
                                  onClick={(e) => { e.stopPropagation(); handleUnblock(s.session_id) }}
                                >
                                  Yes, Unblock
                                </button>
                                <button
                                  className="btn-confirm-no"
                                  onClick={(e) => { e.stopPropagation(); setUnblockConfirm(null) }}
                                >
                                  Cancel
                                </button>
                              </div>
                            ) : (
                              <button
                                className="btn-unblock"
                                onClick={(e) => { e.stopPropagation(); setUnblockConfirm(s.session_id) }}
                              >
                                🔓 Unblock Session & IP
                              </button>
                            )
                          ) : (
                            // BLOCK + CHALLENGE flow
                            <>
                              {blockConfirm === s.session_id ? (
                                <div className="confirm-bar">
                                  <span className="confirm-text">Confirm block this session & IP?</span>
                                  <button
                                    className="btn-confirm-block"
                                    onClick={(e) => { e.stopPropagation(); handleBlock(s.session_id) }}
                                  >
                                    Yes, Block
                                  </button>
                                  <button
                                    className="btn-confirm-no"
                                    onClick={(e) => { e.stopPropagation(); setBlockConfirm(null) }}
                                  >
                                    Cancel
                                  </button>
                                </div>
                              ) : (
                                <button
                                  className="btn-block"
                                  onClick={(e) => { e.stopPropagation(); setBlockConfirm(s.session_id) }}
                                >
                                  🚫 Block Session & IP
                                </button>
                              )}

                              {/* Display CAPTCHA badge if active */}
                              {s.guard_action === 'challenge' && (
                                <span className="challenge-badge" title="CAPTCHA challenge already active">
                                  CAPTCHA Active
                                </span>
                              )}
                            </>
                          )}

                          {/* Export Logs button — always visible */}
                          <a
                            className="btn-export"
                            href={`${API}/session-logs/${s.session_id}`}
                            download
                            onClick={(e) => e.stopPropagation()}
                            title="Download backend access logs for this session as JSON"
                          >
                            Export Logs
                          </a>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
            {totalSessionPages > 1 && (
              <div className="pagination-controls">
                <button
                  className="pagination-btn"
                  onClick={() => setSessionPage(p => Math.max(1, p - 1))}
                  disabled={currentSessionPage === 1}
                >
                  ◀ Prev
                </button>
                <span className="pagination-info">
                  Page {currentSessionPage} of {totalSessionPages} ({filteredAndSortedSessions.length} total)
                </span>
                <button
                  className="pagination-btn"
                  onClick={() => setSessionPage(p => Math.min(totalSessionPages, p + 1))}
                  disabled={currentSessionPage === totalSessionPages}
                >
                  Next ▶
                </button>
              </div>
            )}
          </>
        )}
      </section>

      {/* Guards Panel */}
      <section className="guards-panel">
        <div className="sessions-panel-header">
          <h2 className="panel-title">
            Active Defense Matrix
            <span className="session-count">
              {guardSearch || guardActionFilter !== 'all' ? `${filteredGuards.length} of ${guards.length}` : guards.length} enforced
            </span>
          </h2>
          <div className="sort-controls">
            <input
              type="text"
              placeholder="Search Session ID or IP Address..."
              value={guardSearch}
              onChange={(e) => setGuardSearch(e.target.value)}
              className="search-input"
            />
            <div className="sort-field-select">
              <span className="sort-label">Action:</span>
              <select
                value={guardActionFilter}
                onChange={(e) => setGuardActionFilter(e.target.value)}
                className="sort-dropdown"
              >
                <option value="all">All</option>
                <option value="block">Block</option>
                <option value="challenge">Challenge</option>
                <option value="rate_limit">Rate Limit</option>
              </select>
            </div>
            <div className="sort-pills" role="group" aria-label="Sort guards">
              {[
                { key: 'score', label: 'Score' },
                { key: 'action', label: 'Action' },
                { key: 'updated_at', label: 'Updated' }
              ].map(opt => (
                <button
                  key={opt.key}
                  className={`sort-pill sort-pill-score ${guardSortBy === opt.key ? 'active' : ''}`}
                  onClick={() => setGuardSortBy(opt.key)}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            <button
              className="sort-dir-btn"
              onClick={() => setGuardSortDir(d => d === 'desc' ? 'asc' : 'desc')}
              title={guardSortDir === 'desc' ? 'Sort: Descending' : 'Sort: Ascending'}
            >
              {guardSortDir === 'desc' ? '↓ Desc' : '↑ Asc'}
            </button>
          </div>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Target Session</th>
                <th>IP Address</th>
                <th>Action</th>
                <th>Type</th>
                <th>Score</th>
                <th>Updated</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredGuards.length === 0 ? (
                <tr><td colSpan="7" className="empty-state">No matching guard actions enforced</td></tr>
              ) : (
                paginatedGuards.map(g => (
                  <tr key={g.session_id}>
                    <td className="code-font">{g.session_id.substring(0, 16)}…</td>
                    <td className="code-font">{g.ip_address || (sessions.find(s => s.session_id === g.session_id)?.ip_address) || '—'}</td>
                    <td><span className={`action-badge type-${g.action}`}>{getMitigationLabel(g.action, g.block_type)}</span></td>
                    <td><span className="block-type-badge">{(g.block_type || 'auto').toUpperCase()}</span></td>
                    <td><span className={`risk-badge ${getRiskClass(g.risk_score)}`}>{g.risk_score}</span></td>
                    <td className="time">{formatRelativeTime(g.updated_at)}</td>
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <a
                        className="btn-download-small"
                        href={`${API}/session-logs/${g.session_id}`}
                        download
                        onClick={(e) => e.stopPropagation()}
                        title="Download backend access logs for this session as JSON"
                        style={{ marginRight: '6px' }}
                      >
                        Download
                      </a>
                      {unblockConfirm === g.session_id ? (
                        <div style={{ display: 'inline-flex', gap: '4px', alignItems: 'center' }}>
                          <span style={{ fontSize: '0.68rem', color: 'var(--warning)', marginRight: '2px' }}>Confirm?</span>
                          <button
                            className="btn-confirm-yes-small"
                            onClick={(e) => { e.stopPropagation(); handleUnblock(g.session_id) }}
                          >
                            Yes
                          </button>
                          <button
                            className="btn-confirm-no-small"
                            onClick={(e) => { e.stopPropagation(); setUnblockConfirm(null) }}
                          >
                            No
                          </button>
                        </div>
                      ) : (
                        <button
                          className="btn-unban-small"
                          onClick={(e) => { e.stopPropagation(); setUnblockConfirm(g.session_id) }}
                          title="Unban this session and IP address"
                        >
                          Unban
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        {totalGuardPages > 1 && (
          <div className="pagination-controls">
            <button
              className="pagination-btn"
              onClick={() => setGuardPage(p => Math.max(1, p - 1))}
              disabled={currentGuardPage === 1}
            >
              &lt;
            </button>
            <span className="pagination-info">
              {currentGuardPage} ({filteredGuards.length} total)
            </span>
            <button
              className="pagination-btn"
              onClick={() => setGuardPage(p => Math.min(totalGuardPages, p + 1))}
              disabled={currentGuardPage === totalGuardPages}
            >
              &gt;
            </button>
          </div>
        )}
      </section>




      {/* Runtime Defense Guide Modal */}
      {showGuide && (
        <div className="guide-modal-overlay" onClick={() => setShowGuide(false)}>
          <div className="guide-modal" onClick={(e) => e.stopPropagation()}>
            <header className="guide-modal-header">
              <div className="guide-title-area">
                <h2>SIDERIS Runtime Defense Guide</h2>
              </div>
              <button className="guide-modal-close" onClick={() => setShowGuide(false)} title="Close Guide (Esc)">&times;</button>
            </header>

            <div className="guide-modal-body">
              
              {/* Tab Navigation */}
              <div className="guide-tabs">
                <button 
                  className={`guide-tab-btn ${activeTab === 'lifecycle' ? 'active' : ''}`}
                  onClick={() => setActiveTab('lifecycle')}
                >
                  1. Lifecycle & Decay
                </button>
                <button 
                  className={`guide-tab-btn ${activeTab === 'matrix' ? 'active' : ''}`}
                  onClick={() => setActiveTab('matrix')}
                >
                  2. Mitigation Matrix
                </button>
                <button 
                  className={`guide-tab-btn ${activeTab === 'glossary' ? 'active' : ''}`}
                  onClick={() => setActiveTab('glossary')}
                >
                  3. Telemetry Glossary
                </button>
                <button 
                  className={`guide-tab-btn ${activeTab === 'bonuses' ? 'active' : ''}`}
                  onClick={() => setActiveTab('bonuses')}
                >
                  4. Correlation Heuristics (13)
                </button>
              </div>

              {/* Tab 1: Detection Lifecycle & Decay */}
              {activeTab === 'lifecycle' && (
                <div className="guide-tab-content">
                  {/* Section 1: Threat Escalation Lifecycle (Horizontal Animated Timeline) */}
                  <div className="guide-panel full-width">
                    <h3>Threat Escalation Lifecycle</h3>
                    <p className="panel-intro-text">SIDERIS implements dynamic behavioral defense by statefully observing client events and escalating mitigations based on cumulative threat profiles.</p>
                    <div className="lifecycle-timeline">
                      <div className="timeline-progress-line">
                        <div className="timeline-pulse-glow"></div>
                      </div>
                      
                      <div className="lifecycle-step">
                        <div className="step-number-node">1</div>
                        <div className="step-content">
                          <span className="step-title">Observe</span>
                          <span className="step-desc">Ingests raw client HTTP requests and user interaction telemetry.</span>
                        </div>
                      </div>
                      
                      <div className="lifecycle-step">
                        <div className="step-number-node">2</div>
                        <div className="step-content">
                          <span className="step-title">Correlate</span>
                          <span className="step-desc">Analyzes behavioral logs and logs patterns within the active session scope.</span>
                        </div>
                      </div>
                      
                      <div className="lifecycle-step">
                        <div className="step-number-node">3</div>
                        <div className="step-content">
                          <span className="step-title">Escalate</span>
                          <span className="step-desc">Applies dynamic scoring bonuses when heuristics confirm coordinated attack signatures.</span>
                        </div>
                      </div>
                      
                      <div className="lifecycle-step">
                        <div className="step-number-node">4</div>
                        <div className="step-content">
                          <span className="step-title">Mitigate</span>
                          <span className="step-desc">Enforces appropriate defense directives matching current scoring thresholds.</span>
                        </div>
                      </div>
                      
                      <div className="lifecycle-step">
                        <div className="step-number-node">5</div>
                        <div className="step-content">
                          <span className="step-title">Persist</span>
                          <span className="step-desc">Synchronizes dynamic security guards to fast Redis cache for proxy enforcement.</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="guide-grid-2col" style={{ marginTop: '2rem' }}>
                    <div className="guide-panel">
                      <h3>Dynamic Threat Scoring Engine</h3>
                      <p className="panel-intro-text">To prevent false-positive lockouts while maintaining zero-day protection, SIDERIS calculates real-time event risk using a dynamic confidence-persistence equation:</p>
                      
                      <div className="equation-container">
                        <div className="equation-math">
                          Event Score = Base Impact &times; Confidence &times; Persistence Modifier
                        </div>
                      </div>

                      <div className="equation-breakdown">
                        <div className="eq-element">
                          <span className="eq-label">Base Impact (0.0 to 5.0)</span>
                          <span className="eq-text">The inherent severity of the threat category. SQLi and command injections trigger <strong>5.0 (Critical)</strong>, credential stuffing triggers <strong>4.0 (High)</strong>, endpoint fuzzing triggers <strong>3.0 (Medium)</strong>, while standard authorization failures trigger <strong>2.0 (Low)</strong>.</span>
                        </div>
                        <div className="eq-element">
                          <span className="eq-label">Confidence Refinement floor & Multipliers</span>
                          <span className="eq-text">The base certainty ranges from <strong>0.5 to 1.3</strong>. If an attack is repeated 3+ times, SIDERIS escalates the confidence floor to <strong>0.8 (Unusual)</strong>; at 5+ times, it escalates to <strong>1.0 (Known Signature)</strong>. Additionally, if the attacker pivots across 2+ distinct categories, a <strong>+0.1 multi-vector confidence boost</strong> is applied (max 1.5).</span>
                        </div>
                        <div className="eq-element">
                          <span className="eq-label">Persistence Modifier (1.0 to 2.0)</span>
                          <span className="eq-text">Differentiates one-off probes from heavy scanning. Single attacks use <strong>1.0 (One-Time)</strong>, 3+ matching attacks use <strong>1.3 (Repeated)</strong>, 5+ matching attacks use <strong>1.6 (Sustained)</strong>, and high-frequency real payloads matching &gt;10 requests per second trigger a <strong>2.0 (Flood)</strong> multiplier.</span>
                        </div>
                      </div>
                    </div>

                    <div className="guide-panel">
                      <h3>Temporal Score Decay Heuristics</h3>
                      <p className="panel-text">To prevent transient user connection issues or keyboard errors from locking out legitimate staff permanently, SIDERIS integrates a dynamic cooling decay algorithm. Every <strong>30 seconds</strong>, active session scores are multiplied by a decay factor of <strong>0.95</strong> (S_new = S_old &times; 0.95).</p>
                      <p className="panel-text">This continuous cooling forces the threat score down towards zero over periods of inactivity. A suspicious session that triggered a CAPTCHA will eventually drift back into the normal zone as time passes, unless the score crossed the persistent block threshold (50+ points) or inline signatures triggered an immediate un-expiring lockout.</p>
                      
                      <h3>Session Statefulness & Persistence</h3>
                      <p className="panel-text">SIDERIS maintains behavioral memory across requests within a session. Repeated suspicious activity increases cumulative confidence and escalation probability. Storing state parameters inside memory-cached Redis entries allows the engine to track aggregates (e.g. failed login rates) rather than processing requests in isolation, enabling advanced brute force and spraying heuristics.</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 2: Mitigation Matrix & Override Philosophy */}
              {activeTab === 'matrix' && (
                <div className="guide-tab-content">
                  <div className="guide-grid-2col">
                    <div className="guide-panel">
                      <h3>Mitigation Enforcement Matrix</h3>
                      <p className="panel-intro-text">Enforcement actions are triggered automatically based on the current decayed threat score of the session:</p>
                      <table className="guide-matrix-table">
                        <thead>
                          <tr>
                            <th>Score</th>
                            <th>Threat Level</th>
                            <th>Guard Directive</th>
                            <th>Operational Scope & Expiration</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td><span className="risk-badge low-risk">&lt; 10</span></td>
                            <td><span className="verdict-badge verdict-normal">NORMAL</span></td>
                            <td><code>ALLOW</code></td>
                            <td>Traffic is forwarded to backend with telemetry observation. No TTL.</td>
                          </tr>
                          <tr>
                            <td><span className="risk-badge medium-risk">10+</span></td>
                            <td><span className="verdict-badge verdict-suspicious">SUSPICIOUS</span></td>
                            <td><code>RATE LIMIT</code></td>
                            <td>Reverse proxy applies request rate throttling. Dynamic TTL.</td>
                          </tr>
                          <tr>
                            <td><span className="risk-badge high-risk">20+</span></td>
                            <td><span className="verdict-badge verdict-high">CHALLENGE</span></td>
                            <td><code>CAPTCHA</code></td>
                            <td>Active CAPTCHA verification required. Expires in 10 minutes.</td>
                          </tr>
                          <tr>
                            <td><span className="risk-badge very-high-risk">30+</span></td>
                            <td><span className="verdict-badge verdict-very-high">SOFT BLOCK</span></td>
                            <td><code>TEMP BLOCK</code></td>
                            <td>Session terminated at proxy level. Expires in 30 minutes.</td>
                          </tr>
                          <tr>
                            <td><span className="risk-badge critical-risk">50+</span></td>
                            <td><span className="verdict-badge verdict-critical">CRITICAL</span></td>
                            <td><code>HARD BLOCK</code></td>
                            <td>Immediate, permanent proxy block. Stored without TTL. Requires manual override.</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    <div className="guide-panel">
                      <h3>False Positive Philosophy</h3>
                      <p className="panel-text">SIDERIS prioritizes progressive, adaptive defense layers rather than binary block/allow rules. Legitimate users experiencing connection anomalies, autofill problems, or spelling mistakes might trigger low-level telemetry events, but the system absorbs these in the rate-limit or CAPTCHA levels. Legitimate interactions easily clear CAPTCHAs, resetting active guards without blocking the user.</p>
                      <p className="panel-text">This progressive approach limits permanent lockouts exclusively to verified critical injection payloads or persistent, high-frequency bot scanners. It optimizes the balance between strict protection and zero-friction customer experiences.</p>
                      
                      <h3>SOC Override Controls</h3>
                      <p className="panel-text">For manual intervention, the dashboard provides analysts with immediate override buttons:</p>
                      <ul style={{ margin: '0.5rem 0 0', paddingLeft: '1.25rem', fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                        <li style={{ marginBottom: '6px' }}><strong>Block Session</strong>: Instantly forces an un-expiring <code>hard_block</code> guard onto the session's client IP across the reverse proxy.</li>
                        <li style={{ marginBottom: '6px' }}><strong>Unblock Session</strong>: Deletes all active proxy guard keys from Redis, resets the cumulative session score to 0, and clears telemetry counters to allow immediate traffic recovery.</li>
                        <li><strong>Export Logs</strong>: Downloads the detailed audit trail (in JSON) containing raw headers, IP sequences, and parameters for offline SOC forensic logging.</li>
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 3: Telemetry Glossary */}
              {activeTab === 'glossary' && (
                <div className="guide-tab-content">
                  <div className="guide-grid-2col">
                    
                    {/* User Heuristics */}
                    <div className="guide-panel">
                      <h3>Client-Side User Heuristics</h3>
                      <p className="panel-intro-text">Passive telemetry captured via client-side javascript agent (mouse movements, focus durations, and event timing):</p>
                      
                      <div className="glossary-list">
                        <div className="glossary-item">
                          <span className="glossary-title"><code>headless_browser</code> <small>(Impact 3, Conf 1.3)</small></span>
                          <p className="glossary-text">Triggered when browser checks reveal webdriver execution, automated sandbox environment variables, or headless browser rendering properties. Used by bot scripts to execute headless scraping.</p>
                        </div>
                        
                        <div className="glossary-item">
                          <span className="glossary-title"><code>rapid_navigation</code> <small>(Impact 2, Conf 0.9)</small></span>
                          <p className="glossary-text">Identifies when a client loads &ge; 10 pages within 5 seconds. Inhuman browsing pace indicates automated crawler indexing or vulnerability scanning spiders.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>instant_form_fill</code> <small>(Impact 2, Conf 0.8)</small></span>
                          <p className="glossary-text">Triggers when a form is submitted in &lt; 800ms from focus. Humans require time to read and type; instant completions reveal automated registration spam or stuffing bots.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>keystroke_burst</code> <small>(Impact 2, Conf 0.7)</small></span>
                          <p className="glossary-text">Detects &gt;10 keystrokes in 500ms. Inconsistent with human typing speeds, it flags paste operations, auto-fill macros, or automated script inputs in text areas.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>no_mouse_activity</code> <small>(Impact 2, Conf 0.6)</small></span>
                          <p className="glossary-text">Flags interaction sequences devoid of mouse movement coordinates. Indicates direct API requests (cURL, Python requests) or automation runners bypassing visual cursor emulation.</p>
                        </div>
                      </div>
                    </div>

                    {/* Backend Request Logs */}
                    <div className="guide-panel">
                      <h3>Web & Backend Request Logs</h3>
                      <p className="panel-intro-text">Signatures and HTTP protocol anomalies checked synchronously at the proxy layer or asynchronously in access logs:</p>
                      
                      <div className="glossary-list">
                        <div className="glossary-item">
                          <span className="glossary-title"><code>sql_injection</code> <small>(Impact 5, Conf 1.3)</small></span>
                          <p className="glossary-text">Detects SQL syntax keywords (UNION SELECT, OR 1=1, DROP, SLEEP, etc.) inside headers, query strings, or body buffers. Indicates attempts to access or modify backend databases.</p>
                        </div>
                        
                        <div className="glossary-item">
                          <span className="glossary-title"><code>xss</code> <small>(Impact 4, Conf 1.2)</small></span>
                          <p className="glossary-text">Matches HTML script tags, onerror/onload event handlers, or javascript: payloads. Indicates scripts aiming to execute client-side code in other users' browsers.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>cmd_injection</code> <small>(Impact 5, Conf 1.2)</small></span>
                          <p className="glossary-text">Identifies shell command metacharacters (;, |, `, $()) followed by system executables (id, cat, wget, whoami). Aims to run commands on the server OS.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>ssti</code> / <code>xxe</code> / <code>ssrf</code> <small>(Impact 5, Conf 1.0)</small></span>
                          <p className="glossary-text">Identifies server-side template syntax (e.g. {"${...}"} or {"{{...}}"}), XML DOCTYPE system entities, or internal IP redirects (127.0.0.1, file://). Aims to exploit backend runtimes.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>file_upload_exploit</code> <small>(Impact 5, Conf 1.2)</small></span>
                          <p className="glossary-text">POST request filenames containing executable scripts (.php, .jsp, .asp, .cgi). Aims to upload a web shell for persistent server access.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>file_exposure</code> <small>(Impact 4, Conf 1.0)</small></span>
                          <p className="glossary-text">Probes targeted at backups, repositories, or system configurations (.env, .git/config, wp-config.php). Aims to locate database credentials or code backups.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>cms_admin_probe</code> <small>(Impact 3, Conf 1.0)</small></span>
                          <p className="glossary-text">Scans on administrative portals (/wp-admin, /phpmyadmin) on non-CMS architectures, identifying automated vulnerability scanner mapping.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>directory_traversal</code> <small>(Impact 3, Conf 1.0)</small></span>
                          <p className="glossary-text">Matches file path traversal sequences (../, %2e%2e%2f) aiming to escape the web root and read local system files.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>http_method_abuse</code> <small>(Impact 2, Conf 1.0)</small></span>
                          <p className="glossary-text">Matches unusual HTTP methods like TRACE, CONNECT, or PROPFIND. Standard clients do not use these; they are common in reconnaissance tools.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>auth_failure</code> <small>(Impact 3, Conf 0.8-1.2)</small></span>
                          <p className="glossary-text">HTTP status codes 401 or 403. Scored with 1.2 confidence on dedicated login paths, and 0.8 on other resources.</p>
                        </div>

                        <div className="glossary-item">
                          <span className="glossary-title"><code>recon_404</code> <small>(Impact 1, Conf 0.5)</small></span>
                          <p className="glossary-text">HTTP status code 404 (Not Found). High counts indicate automated directory fuzzers checking for active endpoints.</p>
                        </div>
                      </div>
                    </div>

                  </div>
                </div>
              )}

              {/* Tab 4: Correlation Heuristics */}
              {activeTab === 'bonuses' && (
                <div className="guide-tab-content">
                  <div className="guide-panel full-width">
                    <h3>Behavioral Correlation Heuristic Rules</h3>
                    <p className="panel-intro-text">SIDERIS statefully aggregates events within active session scopes. When behavioral counters cross threshold limits, the correlation engine applies a one-time score boost to accelerate mitigation enforcement:</p>
                    
                    <div className="table-container" style={{ maxHeight: 'none', border: 'none', padding: 0 }}>
                      <table className="guide-matrix-table" style={{ width: '100%' }}>
                        <thead>
                          <tr>
                            <th>Bonus Key</th>
                            <th>Attack Category</th>
                            <th>Triggering Conditions</th>
                            <th>Score Boost</th>
                            <th>Threat Rationale</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td className="code-font"><code>brute_force</code></td>
                            <td>Authentication</td>
                            <td>&ge; 15 failed login responses (401/403 status).</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+10.0</strong></td>
                            <td>Indicates automated attempts to crack user credentials on a single account.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>password_spray</code></td>
                            <td>Authentication</td>
                            <td>&ge; 3 distinct usernames targeted and &ge; 5 total login attempts.</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+12.0</strong></td>
                            <td>Flags attempts to test common credentials across multiple accounts to bypass account lockouts.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>credential_stuffing</code></td>
                            <td>Authentication</td>
                            <td>&ge; 20 login attempts and &ge; 15 failed logins.</td>
                            <td><strong style={{ color: 'var(--danger)' }}>+15.0</strong></td>
                            <td>Identifies takeover bots testing lists of leaked credentials.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>404_storm</code></td>
                            <td>Fuzzing</td>
                            <td>&ge; 15 Page Not Found (404) responses.</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+8.0</strong></td>
                            <td>Detects active endpoint discovery scans mapping the application file tree.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>scanner_detected</code></td>
                            <td>Fuzzing</td>
                            <td>User-Agent strings matching automated scanners (sqlmap, nikto, dirb, etc.).</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+8.0</strong></td>
                            <td>Confirms active automated recon and penetration testing tool execution.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>payload_variation</code></td>
                            <td>Fuzzing</td>
                            <td>&ge; 5 unique payload variants detected in parameters or POST bodies.</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+10.0</strong></td>
                            <td>Identifies automated parameter fuzzing or exploit payload mutations.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>scan_exploit_combo</code></td>
                            <td>Injection</td>
                            <td>Both scan/recon and active exploit (SQLi, XSS) flags triggered in session.</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+12.0</strong></td>
                            <td>Detects the typical transition from mapping vulnerability scanning to active exploitation.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>multi_vector</code></td>
                            <td>Injection</td>
                            <td>Active threat triggers spans &ge; 3 distinct attack categories.</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+10.0</strong></td>
                            <td>Flags an advanced attacker pivoting across methods (e.g. Bot + Fuzzing + Injection).</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>bot_speed</code></td>
                            <td>Bot / Automation</td>
                            <td>Total events &gt; 20, requests per second &gt; 10, and zero cursor movements.</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+8.0</strong></td>
                            <td>Differentiates rapid human browsing from fast automated scraping.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>headless_confirmed</code></td>
                            <td>Bot / Automation</td>
                            <td>&ge; 3 distinct bot events registered and zero cursor movements.</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+10.0</strong></td>
                            <td>High-certainty confirmation of headless scrapers or UI testing runners.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>dos_flood</code></td>
                            <td>Denial of Service</td>
                            <td>&ge; 50 requests within a rolling 60-second window.</td>
                            <td><strong style={{ color: 'var(--danger)' }}>+15.0</strong></td>
                            <td>Flags volumetric application-layer denial of service attempts.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>endpoint_hammer</code></td>
                            <td>Denial of Service</td>
                            <td>&ge; 20 requests hitting the exact same URL path.</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+10.0</strong></td>
                            <td>Detects high-frequency polling abuse or endpoint resource starvation attacks.</td>
                          </tr>
                          <tr>
                            <td className="code-font"><code>session_ip_switch</code></td>
                            <td>Session Abuse</td>
                            <td>Same session ID used across &ge; 2 distinct client IP addresses.</td>
                            <td><strong style={{ color: 'var(--warning)' }}>+8.0</strong></td>
                            <td>Identifies session hijacking, cookie theft, or proxy-hopping attackers.</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

            </div>

            <footer className="guide-modal-footer">
              <button className="btn-close-guide" onClick={() => setShowGuide(false)}>Close Operational Guide</button>
            </footer>
          </div>
        </div>
      )}

      {/* Toast notification */}
      {toast && (
        <div className={`toast toast-${toast.type}`}>
          {toast.message}
        </div>
      )}
    </div>
  )
}

export default App
