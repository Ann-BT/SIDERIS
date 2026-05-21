import { useState, useEffect, useCallback, useRef } from 'react'
import './index.css'

const API = 'http://127.0.0.1:6001'

const CATEGORIES = [
  { key: 'authentication',  icon: '🔐', label: 'Authentication',  color: '#f59e0b' },
  { key: 'injection',       icon: '💉', label: 'Injection',       color: '#ef4444' },
  { key: 'fuzzing',         icon: '🧪', label: 'Fuzzing',         color: '#8b5cf6' },
  { key: 'bot',             icon: '🕷️', label: 'Bot / Automation', color: '#06b6d4' },
  { key: 'dos',             icon: '🚫', label: 'Denial of Service',color: '#ec4899' },
  { key: 'session_abuse',   icon: '🎭', label: 'Session Abuse',   color: '#14b8a6' },
]

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
  const [sortDir, setSortDir] = useState('desc')     // 'asc' | 'desc'
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
    if (v === 'critical')  return 'verdict-critical'
    if (v === 'very_high') return 'verdict-very-high'
    if (v === 'high')      return 'verdict-high'
    if (v === 'suspicious') return 'verdict-suspicious'
    return 'verdict-normal'
  }

  const getVerdictLabel = (level) => {
    const map = { critical: 'CRITICAL', very_high: 'VERY HIGH', high: 'HIGH', suspicious: 'SUSPICIOUS' }
    return map[level] || 'NORMAL'
  }

  // Auto-scroll logs to bottom when new entries arrive (unless user scrolled up)
  useEffect(() => {
    const box = logsBoxRef.current
    if (!box || logsPaused) return
    const isNearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80
    if (isNearBottom) logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
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

  return (
    <div className="sideris-dashboard">
      <header className="dash-header">
        <div className="header-left">
          <h1>SIDERIS <span className="highlight">Command Center</span></h1>
          <span className="header-subtitle">Security Operations Console</span>
        </div>
        <div className={`status-indicator ${errorStatus ? 'offline' : 'online'}`} title={errorStatus ? 'API Disconnected' : 'Systems Online'} />
      </header>

      {/* Metrics Grid */}
      <section className="metrics-grid">
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
      </section>

      {/* Sessions Panel */}
      <section className="sessions-panel">
        <div className="sessions-panel-header">
          <h2 className="panel-title">
            Live Threat Sessions
            <span className="session-count">{sessions.length} active</span>
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
            {/* Score direction toggle */}
            <button
              className="sort-dir-btn"
              onClick={() => setSortDir(d => d === 'desc' ? 'asc' : 'desc')}
              title={sortDir === 'desc' ? 'Score: High → Low' : 'Score: Low → High'}
            >
              {sortDir === 'desc' ? '↓ Score' : '↑ Score'}
            </button>
          </div>
        </div>

        {sessions.length === 0 ? (
          <div className="empty-state-card">
            <div className="empty-icon">🛡️</div>
            <p>No active sessions detected</p>
          </div>
        ) : (
          <div className="session-list">
            {sessions
              .filter(s => sortBy === 'score' || (s.level || 'normal') === sortBy)
              .sort((a, b) => {
                const diff = (a.session_score || 0) - (b.session_score || 0)
                return sortDir === 'desc' ? -diff : diff
              })
              .map(s => {
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

                      <div className="summary-score">
                        <span className={`risk-badge ${getRiskClass(score)}`}>
                          {score.toFixed(1)}
                        </span>
                      </div>

                      <div className="summary-verdict">
                        <span className={`verdict-badge ${getVerdictClass(s.level)}`}>
                          {getVerdictLabel(s.level)}
                        </span>
                      </div>

                      <div className="summary-status">
                        {s.is_blocked && <span className="blocked-badge">BLOCKED</span>}
                        {s.guard_action === 'challenge' && <span className="challenge-badge">CHALLENGE</span>}
                        {s.guard_action === 'rate_limit' && <span className="ratelimit-badge">RATE LIMITED</span>}
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
                                  <span className="cat-icon">{cat.icon}</span>
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

                        {/* Session Metadata */}
                        <div className="detail-section">
                          <h4 className="detail-heading">Session Intelligence</h4>
                          <div className="meta-grid">
                            <div className="meta-item">
                              <span className="meta-key">Login Attempts</span>
                              <span className="meta-val">{s.login_attempts || 0}</span>
                            </div>
                            <div className="meta-item">
                              <span className="meta-key">Unique Usernames</span>
                              <span className="meta-val">{s.unique_username_count || 0}</span>
                            </div>
                            <div className="meta-item">
                              <span className="meta-key">404 Hits</span>
                              <span className="meta-val">{s.count_404 || 0}</span>
                            </div>
                            <div className="meta-item">
                              <span className="meta-key">Scanner Detected</span>
                              <span className={`meta-val ${s.scanner_detected ? 'val-danger' : ''}`}>
                                {s.scanner_detected ? 'YES' : 'No'}
                              </span>
                            </div>
                            <div className="meta-item">
                              <span className="meta-key">Block Type</span>
                              <span className="meta-val">{s.block_type || '—'}</span>
                            </div>
                            <div className="meta-item">
                              <span className="meta-key">User Agent</span>
                              <span className="meta-val meta-ua" title={s.user_agent || ''}>
                                {s.user_agent ? s.user_agent.substring(0, 50) + '…' : '—'}
                              </span>
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
                              s.risk_reasons.slice(0, 10).map((r, i) => (
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
                                <span className="confirm-text">⚠️ Confirm unblock this session?</span>
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
                            // BLOCK flow
                            blockConfirm === s.session_id ? (
                              <div className="confirm-bar">
                                <span className="confirm-text">⚠️ Confirm block this session?</span>
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
                            )
                          )}

                          {/* Export Logs button — always visible */}
                          <a
                            className="btn-export"
                            href={`${API}/session-logs/${s.session_id}`}
                            download
                            onClick={(e) => e.stopPropagation()}
                            title="Download backend access logs for this session as JSON"
                          >
                            ⬇ Export Logs
                          </a>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
          </div>
        )}
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
            }}>↻</button>
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

      {/* Guards Panel */}
      <section className="guards-panel">
        <h2 className="panel-title">
          Active Defense Matrix
          <span className="session-count">{guards.length} enforced</span>
        </h2>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Target Session</th>
                <th>Action</th>
                <th>Type</th>
                <th>Score</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {guards.length === 0 ? (
                <tr><td colSpan="5" className="empty-state">No guard actions enforced</td></tr>
              ) : (
                guards.map(g => (
                  <tr key={g.session_id}>
                    <td className="code-font">{g.session_id.substring(0, 16)}…</td>
                    <td><span className={`action-badge type-${g.action}`}>{g.action.toUpperCase()}</span></td>
                    <td><span className="block-type-badge">{g.block_type || 'auto'}</span></td>
                    <td><span className={`risk-badge ${getRiskClass(g.risk_score)}`}>{g.risk_score}</span></td>
                    <td className="time">{formatRelativeTime(g.updated_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
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
