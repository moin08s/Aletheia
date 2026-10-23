import { useState, useEffect } from 'react'
import { useActiveCase } from '../hooks/useActiveCase'
import { useQuery } from '../hooks/useQuery'
import { getTimeline } from '../api/client'
import { AsyncState } from '../components/AsyncState'
import { SeverityBadge } from '../components/SeverityBadge'
import { Clock, Filter, Play, Pause, RotateCcw, AlertTriangle, ShieldCheck } from 'lucide-react'
import { format } from 'date-fns'

function fmt(ts: string) {
  try { return format(new Date(ts), 'yyyy-MM-dd HH:mm:ss') } catch { return ts }
}

export function TimelinePage() {
  const { activeCaseId } = useActiveCase()
  
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [limit, setLimit] = useState(200)
  const [debouncedSearch, setDebouncedSearch] = useState(search)

  // Interactive Incident Replay State
  const [replaying, setReplaying] = useState(false)
  const [replayIndex, setReplayIndex] = useState(0)

  const { data: timeline, isLoading, error, refetch } = useQuery(
    `timeline-${activeCaseId}-${limit}-${severity}-${debouncedSearch}`,
    () => getTimeline(activeCaseId!, { limit, severity: severity || undefined, search: debouncedSearch || undefined }),
    { enabled: !!activeCaseId }
  )

  const events = timeline?.events || []

  // Replay playback ticker
  useEffect(() => {
    let timer: any
    if (replaying && events.length > 0) {
      timer = setInterval(() => {
        setReplayIndex(prev => {
          if (prev >= events.length - 1) {
            setReplaying(false)
            return prev
          }
          return prev + 1
        })
      }, 900)
    }
    return () => clearInterval(timer)
  }, [replaying, events.length])

  const handleSearch = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      setDebouncedSearch(search)
    }
  }

  if (!activeCaseId) {
    return (
      <div className="page-content">
        <div className="state-container">
          <Clock className="state-icon" />
          <div className="state-title">No Case Selected</div>
          <p className="state-message">Please select an active case to view the super timeline.</p>
        </div>
      </div>
    )
  }

  const currentReplayEvent = events[replayIndex]

  return (
    <div className="page-content">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div className="page-title">Super Timeline & Incident Replay</div>
          <div className="page-subtitle">Chronological sequence of all forensic artifacts & automated breach playback</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button 
            className="btn btn-secondary" 
            onClick={() => { setReplayIndex(0); setReplaying(true) }}
            style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <RotateCcw size={13} /> Reset Replay
          </button>
          <button 
            className="btn btn-primary" 
            onClick={() => setReplaying(!replaying)}
            style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            {replaying ? <><Pause size={13} /> Pause Playback</> : <><Play size={13} /> Play Attack Replay</>}
          </button>
        </div>
      </div>

      {/* Interactive Incident Replay Bar */}
      {events.length > 0 && (
        <div className="card" style={{ marginBottom: 16, border: '1px solid #6366f144', background: '#0f172a' }}>
          <div style={{ padding: '12px 18px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ padding: 6, background: '#3b82f622', borderRadius: '50%' }}>
                {currentReplayEvent?.severity === 'CRITICAL' ? (
                  <AlertTriangle size={18} color="#ef4444" />
                ) : (
                  <ShieldCheck size={18} color="#3b82f6" />
                )}
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  BREACH SCRUBBER ({replayIndex + 1} / {events.length})
                </div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#f8fafc' }}>
                  {currentReplayEvent ? currentReplayEvent.action : 'Ready'}
                </div>
              </div>
            </div>

            <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>
              {currentReplayEvent ? fmt(currentReplayEvent.timestamp_utc) : '—'}
            </div>
          </div>

          <div style={{ padding: '0 18px 12px 18px' }}>
            <input 
              type="range" 
              min={0} 
              max={events.length - 1} 
              value={replayIndex} 
              onChange={e => setReplayIndex(Number(e.target.value))}
              style={{ width: '100%', accentColor: '#6366f1', cursor: 'pointer' }}
            />
          </div>
        </div>
      )}

      <div className="filter-bar">
        <Filter size={16} color="var(--text-muted)" />
        <input 
          type="text" 
          className="filter-input" 
          placeholder="Search events... (Enter)" 
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={handleSearch}
          onBlur={() => setDebouncedSearch(search)}
        />
        <select className="filter-select" value={severity} onChange={e => setSeverity(e.target.value)}>
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>
        <select className="filter-select" value={limit} onChange={e => setLimit(Number(e.target.value))}>
          <option value="100">100 events</option>
          <option value="200">200 events</option>
          <option value="500">500 events</option>
        </select>
      </div>

      <div className="card">
        <AsyncState
          isLoading={isLoading}
          error={error}
          isEmpty={!isLoading && events.length === 0}
          emptyTitle="No Events Found"
          emptyMessage="No events match your current filters, or the timeline hasn't been built yet."
          onRetry={refetch}
        >
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Source</th>
                  <th>Action</th>
                  <th>User</th>
                  <th>Object / Path</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev, idx) => {
                  const isCurrent = idx === replayIndex
                  return (
                    <tr 
                      key={ev.event_id} 
                      style={{ 
                        background: isCurrent ? '#3b82f618' : undefined,
                        borderLeft: isCurrent ? '3px solid #3b82f6' : undefined 
                      }}
                    >
                      <td className="td-mono">{fmt(ev.timestamp_utc)}</td>
                      <td className="td-muted">{ev.plugin}</td>
                      <td><span style={{ fontWeight: 600 }}>{ev.action}</span></td>
                      <td className="td-dim">{ev.user || '—'}</td>
                      <td className="td-dim" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ev.object_path || ''}>
                        {ev.object_path || '—'}
                      </td>
                      <td>
                        <SeverityBadge severity={ev.severity} />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </AsyncState>
      </div>
    </div>
  )
}
