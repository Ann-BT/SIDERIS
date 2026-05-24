import { useState, useEffect, useCallback, useRef, useLayoutEffect } from 'react'
import './index.css'

const API = 'http://127.0.0.1:6001'

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
  const [errorStatus, setErrorStatus] = useState(false)
  const [expandedSession, setExpandedSession] = useState(null)
  const [unblockConfirm, setUnblockConfirm] = useState(null)
  const [blockConfirm, setBlockConfirm] = useState(null)
  const [toast, setToast] = useState(null)
  const [logs, setLogs] = useState([])
  const [logsPaused, setLogsPaused] = useState(false)

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
        const [metRes, sesRes, guardRes] = await Promise.all([
          fetch(`${API}/metrics`),
          fetch(`${API}/sessions`),
          fetch(`${API}/guards`)
        ])
        if (!metRes.ok || !sesRes.ok || !guardRes.ok) throw new Error('API Sync Failed')
        setMetrics(await metRes.json())
        setSessions(await sesRes.json())
        setGuards(await guardRes.json())
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
  }, [logsPaused])

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
        <div className={`status-indicator ${errorStatus ? 'offline' : 'online'}`} title={errorStatus ? 'API Disconnected' : 'Systems Online'} />
      </header>

      {/* Top Dashboard Section */}
      <section className="top-dashboard-section">
        {/* Left Side: Top Attacker IPs */}
        <div className="top-attackers-panel">
          <h3>Top Attacker IP Addresses</h3>
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
              <div className="empty-state">No attacker IP data available</div>
            )}
          </div>
        </div>

        {/* Right Side: 2x2 Metrics Grid */}
        <div className="metrics-2x2-grid">
          <div className="metric-card">
             <h3>Events Processed</h3>
             <div className="value">{metrics.processed.toLocaleString()}</div>
          </div>
          <div className="metric-card glass-block">
             <h3>Active Blocks</h3>
             <div className="value red">{metrics.blocks}</div>
          </div>
          <div className="metric-card glass-challenge">
             <h3>Active Challenges</h3>
             <div className="value yellow">{metrics.challenges}</div>
          </div>
          <div className="metric-card glass-ratelimit">
             <h3>Rate Limits</h3>
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
                <span className="log-ts">{log.timestamp.replace('T',' ').slice(0,23)}</span>
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
                                <span className="confirm-text">Confirm unblock this session?</span>
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
                                🔓 Unblock Session
                              </button>
                            )
                          ) : (
                            // BLOCK + CHALLENGE flow
                            <>
                              {blockConfirm === s.session_id ? (
                                <div className="confirm-bar">
                                  <span className="confirm-text">Confirm block this session?</span>
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
                                  🚫 Block Session
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
                <th style={{ textAlign: 'right' }}>Report</th>
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
                    <td style={{ textAlign: 'right' }}>
                      <a
                        className="btn-download-small"
                        href={`${API}/session-logs/${g.session_id}`}
                        download
                        onClick={(e) => e.stopPropagation()}
                        title="Download backend access logs for this session as JSON"
                      >
                        Download
                      </a>
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
