import { Web3AttestationPanel } from '../components/Web3AttestationPanel'
import { useState } from 'react'
import { useActiveCase } from '../hooks/useActiveCase'
import { useQuery } from '../hooks/useQuery'
import { getEvidence, verifyCase, analyzeCase, getCaseStatus } from '../api/client'
import { AsyncState } from '../components/AsyncState'
import { SeverityBadge } from '../components/SeverityBadge'
import { Shield, Play, Loader, CheckCircle, Database } from 'lucide-react'
import { format } from 'date-fns'

function fmt(ts: string) {
  try { return format(new Date(ts), 'yyyy-MM-dd HH:mm:ss') } catch { return ts }
}

function fmtBytes(b: number) {
  if (!b) return '—'
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(2)} MB`
}

export function EvidencePage() {
  const { activeCaseId, activeCase } = useActiveCase()
  const [verifying, setVerifying] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [verifyResult, setVerifyResult] = useState<any>(null)
  const [statusMsg, setStatusMsg] = useState('')

  const { data: evidence, isLoading, error, refetch } = useQuery(
    `evidence-${activeCaseId}`,
    () => getEvidence(activeCaseId!),
    { enabled: !!activeCaseId }
  )

  const { data: analysisStatus } = useQuery(
    `status-${activeCaseId}`,
    () => getCaseStatus(activeCaseId!),
    { enabled: !!activeCaseId, refetchInterval: analyzing ? 2000 : 0 }
  )

  const handleVerify = async () => {
    if (!activeCaseId) return
    setVerifying(true)
    setVerifyResult(null)
    setStatusMsg('Verifying cryptographic integrity...')
    try {
      const res = await verifyCase(activeCaseId)
      setVerifyResult(res)
      setStatusMsg(res.overall_status === 'PASS' ? 'Integrity verification passed.' : 'Integrity verification failed.')
    } catch (e: any) {
      setStatusMsg(`Verification error: ${e.message}`)
    } finally {
      setVerifying(false)
    }
  }

  const handleAnalyze = async () => {
    if (!activeCaseId) return
    setAnalyzing(true)
    setStatusMsg('Starting analysis pipeline...')
    try {
      await analyzeCase(activeCaseId)
      setStatusMsg('Analysis pipeline running...')
    } catch (e: any) {
      setStatusMsg(`Analysis error: ${e.message}`)
      setAnalyzing(false)
    }
  }

  if (!activeCaseId) {
    return (
      <div className="page-content">
        <div className="state-container">
          <Database className="state-icon" />
          <div className="state-title">No Case Selected</div>
          <p className="state-message">Please select an active case from the Dashboard or Cases page to view evidence.</p>
        </div>
      </div>
    )
  }

  const isAnalyzed = activeCase?.status === 'analyzed'
  const isRunning = analysisStatus?.status === 'running' || analyzing

  return (
    <div className="page-content">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div className="page-title">Digital Evidence</div>
          <div className="page-subtitle">Acquired sources, cryptographic hashes, and verification</div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-ghost" onClick={handleVerify} disabled={verifying || isRunning}>
            {verifying ? <Loader size={14} className="spinner" style={{ borderWidth: 2 }} /> : <Shield size={14} />}
            Verify Integrity
          </button>
          <button className="btn btn-primary" onClick={handleAnalyze} disabled={isRunning}>
            {isRunning ? <Loader size={14} className="spinner" style={{ borderWidth: 2, borderColor: '#fff', borderTopColor: 'transparent' }} /> : <Play size={14} fill="currentColor" />}
            {isRunning ? 'Analyzing...' : isAnalyzed ? 'Re-Analyze Evidence' : 'Analyze Evidence'}
          </button>
        </div>
      </div>

      {statusMsg && (
        <div className={`alert ${verifyResult?.overall_status === 'FAIL' ? 'alert-error' : 'alert-info'}`} style={{ marginBottom: 16 }}>
          {verifyResult?.overall_status === 'PASS' && <CheckCircle size={16} />}
          {statusMsg}
        </div>
      )}

      {verifyResult && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-header">
            <div className="card-title">Verification Results</div>
            <SeverityBadge severity={verifyResult.overall_status === 'PASS' ? 'VERIFIED' : 'FAILED'} label={verifyResult.overall_status} />
          </div>
          <div className="card-body">
            <div className="kv-list">
              <div className="kv-row">
                <span className="kv-label">Evidence Files</span>
                <span className="kv-value">{verifyResult.checked_items?.evidence_files} checked ({verifyResult.evidence_status})</span>
              </div>
              <div className="kv-row">
                <span className="kv-label">Custody Ledger</span>
                <span className="kv-value">{verifyResult.checked_items?.ledger_entries} entries replayed ({verifyResult.ledger_status})</span>
              </div>
              <div className="kv-row">
                <span className="kv-label">Derived Data</span>
                <span className="kv-value">{verifyResult.checked_items?.derived_files} files checked ({verifyResult.derived_status})</span>
              </div>
            </div>
            {verifyResult.errors?.length > 0 && (
              <div style={{ marginTop: 12, padding: 12, background: 'var(--sev-critical-bg)', border: '1px solid var(--sev-critical-border)', borderRadius: 'var(--radius)', fontSize: 11, color: 'var(--sev-critical)', fontFamily: 'var(--font-mono)' }}>
                {verifyResult.errors.map((e: string, i: number) => <div key={i}>* {e}</div>)}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <div className="card-title">Evidence Manifest</div>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{evidence?.length ?? 0} items</span>
        </div>
        <AsyncState
          isLoading={isLoading}
          error={error}
          isEmpty={!isLoading && evidence?.length === 0}
          emptyTitle="No Evidence Found"
          emptyMessage="No evidence items are associated with this case."
          onRetry={refetch}
        >
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Evidence ID</th>
                  <th>Filename</th>
                  <th>Type</th>
                  <th>Size</th>
                  <th>SHA-256</th>
                  <th>Acquired (UTC)</th>
                  <th>Integrity</th>
                </tr>
              </thead>
              <tbody>
                {evidence?.map((ev) => (
                  <tr key={ev.evidence_id}>
                    <td className="td-mono" style={{ fontWeight: 600 }}>{ev.evidence_id}</td>
                    <td style={{ fontWeight: 500 }}>{ev.filename}</td>
                    <td className="td-dim">{ev.container || 'raw'}</td>
                    <td className="td-mono">{fmtBytes(ev.size_bytes)}</td>
                    <td className="td-mono" style={{ fontSize: 10, maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis' }} title={ev.sha256}>
                      {ev.sha256}
                    </td>
                    <td className="td-mono">{fmt(ev.acquired_utc)}</td>
                    <td>
                      <SeverityBadge
                        severity={ev.verification_status ? 'VERIFIED' : 'FAILED'}
                        label={ev.verification_status ? 'VERIFIED' : 'FAILED'}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </AsyncState>
      </div>

      {activeCaseId && <Web3AttestationPanel caseId={activeCaseId} />}
    </div>
  )
}
