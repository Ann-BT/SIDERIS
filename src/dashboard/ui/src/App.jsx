import { useState, useEffect, useCallback } from 'react'
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
    fetchData()
    const interval = setInterval(fetchData, 3000)
    return () => clearInterval(interval)
  }, [])

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
        <div className={`status-indicator ${errorStatus ? 'offline' : 'online'}`}>
          <span className="status-dot"></span>
          {errorStatus ? 'API Disconnected' : 'Systems Online'}
        </div>
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
        <h2 className="panel-title">
          Live Threat Sessions
          <span className="session-count">{sessions.length} active</span>
        </h2>

        {sessions.length === 0 ? (
          <div className="empty-state-card">
            <div className="empty-icon">🛡️</div>
            <p>No active sessions detected</p>
          </div>
        ) : (
          <div className="session-list">
            {sessions
              .sort((a, b) => (b.session_score || 0) - (a.session_score || 0))
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
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
          </div>
        )}
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
