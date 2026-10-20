import { useState } from 'react'
import { useQuery } from '../hooks/useQuery'
import {
  getWeb3Attestation,
  anchorCaseToWeb3,
  verifyWeb3Tamper,
  type Web3VerifyResult,
} from '../api/client'
import { Link2, ShieldCheck, AlertTriangle, ExternalLink, RefreshCw } from 'lucide-react'

interface Web3PanelProps {
  caseId: string
}

export function Web3AttestationPanel({ caseId }: Web3PanelProps) {
  const [anchoring, setAnchoring] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState<Web3VerifyResult | null>(null)
  const [msg, setMsg] = useState('')

  const { data: web3Data, refetch } = useQuery(
    `web3-${caseId}`,
    () => getWeb3Attestation(caseId),
    { enabled: !!caseId }
  )

  const handleAnchor = async () => {
    setAnchoring(true)
    setMsg('Pinning to IPFS and anchoring to EVM Smart Contract...')
    try {
      await anchorCaseToWeb3(caseId, { network: 'Base Sepolia (L2)', examiner: 'Lead DFIR Specialist' })
      setMsg('Anchored on-chain successfully!')
      refetch()
    } catch (err: any) {
      setMsg(`Anchoring failed: ${err.message}`)
    } finally {
      setAnchoring(false)
    }
  }

  const handleVerify = async () => {
    setVerifying(true)
    setMsg('Performing live on-chain tamper verification...')
    try {
      const res = await verifyWeb3Tamper(caseId)
      setVerifyResult(res)
      setMsg(res.is_valid ? 'On-chain verification passed. Zero tampering.' : 'Tamper detected!')
    } catch (err: any) {
      setMsg(`Verification error: ${err.message}`)
    } finally {
      setVerifying(false)
    }
  }

  const isAnchored = web3Data?.anchored

  return (
    <div className="card" style={{ marginTop: 24, border: '1px solid #3b82f644' }}>
      <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Link2 size={18} color="#3b82f6" />
          <span style={{ fontWeight: 600, fontSize: 14 }}>Web3 Attestation & Decentralized Chain of Custody</span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {!isAnchored ? (
            <button className="btn btn-primary" onClick={handleAnchor} disabled={anchoring} style={{ fontSize: 12 }}>
              {anchoring ? 'Anchoring...' : 'Anchor to Base Sepolia (L2)'}
            </button>
          ) : (
            <button className="btn btn-secondary" onClick={handleVerify} disabled={verifying} style={{ fontSize: 12 }}>
              <RefreshCw size={12} style={{ marginRight: 4 }} />
              {verifying ? 'Verifying...' : 'Verify On-Chain Tamper'}
            </button>
          )}
        </div>
      </div>

      <div style={{ padding: '16px 20px' }}>
        {msg && (
          <div style={{ marginBottom: 12, fontSize: 12, color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
            &gt; {msg}
          </div>
        )}

        {isAnchored && web3Data?.attestation ? (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginBottom: 16 }}>
              <div style={{ background: 'var(--bg-secondary)', padding: 10, borderRadius: 6 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>NETWORK</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#10b981' }}>{web3Data.network}</div>
              </div>
              <div style={{ background: 'var(--bg-secondary)', padding: 10, borderRadius: 6 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>BLOCK NUMBER</div>
                <div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>#{web3Data.attestation.block_number}</div>
              </div>
              <div style={{ background: 'var(--bg-secondary)', padding: 10, borderRadius: 6 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>DECENTRALIZED STORAGE</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#60a5fa' }}>IPFS / Filecoin</div>
              </div>
              <div style={{ background: 'var(--bg-secondary)', padding: 10, borderRadius: 6 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>EAS SCHEMA UID</div>
                <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {web3Data.eas?.schema_uid.slice(0, 16)}...
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Transaction Hash:</span>
                <a
                  href={web3Data.etherscan_url}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'var(--font-mono)' }}
                >
                  {web3Data.attestation.transaction_hash.slice(0, 20)}... <ExternalLink size={12} />
                </a>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>IPFS Content ID (CID):</span>
                <a
                  href={web3Data.ipfs_url}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'var(--font-mono)' }}
                >
                  {web3Data.attestation.ipfs_cid} <ExternalLink size={12} />
                </a>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>On-Chain Merkle Root:</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{web3Data.attestation.merkle_root.slice(0, 24)}...</span>
              </div>
            </div>

            {verifyResult && (
              <div
                style={{
                  marginTop: 16,
                  padding: 12,
                  borderRadius: 6,
                  background: verifyResult.is_valid ? '#064e3b33' : '#7f1d1d33',
                  border: `1px solid ${verifyResult.is_valid ? '#059669' : '#dc2626'}`,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                }}
              >
                {verifyResult.is_valid ? (
                  <ShieldCheck size={24} color="#10b981" />
                ) : (
                  <AlertTriangle size={24} color="#ef4444" />
                )}
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13, color: verifyResult.is_valid ? '#34d399' : '#f87171' }}>
                    {verifyResult.is_valid ? 'CRYPTOGRAPHIC PROOF VERIFIED' : 'TAMPERING DETECTED'}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Local Evidence Hash matches On-Chain Contract Hash ({verifyResult.local_evidence_sha256.slice(0, 16)}...)
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '12px 0' }}>
            This forensic case has not yet been anchored to Ethereum / EVM or IPFS. Anchoring publishes the RFC 6962 Merkle root and sealed evidence hash for immutable, court-admissible decentralized chain of custody.
          </div>
        )}
      </div>
    </div>
  )
}
