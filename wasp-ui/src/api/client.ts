import axios from 'axios'

const BASE = '/api/v1'

const api = axios.create({
  baseURL: BASE,
  timeout: 30000,
})

// ----------- Types -----------

export interface HealthStatus {
  status: string
  version: string
  yara_available: boolean
  cases_dir: string
  timestamp: string
}

export interface CaseSummary {
  case_id: string
  case_name: string
  examiner: string
  created_utc: string
  status: 'pending' | 'analyzed'
  evidence_count: number
  timeline_events_count: number
  has_anomalies: boolean
  has_sigma: boolean
  has_reports: boolean
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
}

export interface EvidenceEntry {
  evidence_id: string
  path: string
  filename: string
  size_bytes: number
  sha256: string
  acquired_utc: string
  tsa_status: string
  verification_status: boolean
  container: string
}

export interface CaseDetail {
  case_id: string
  description: string
  examiner: string
  organization: string
  created_utc: string
  authorization_ref: string
  schema_version: string
  tool_version: string
  evidence_count: number
  evidence_entries: EvidenceEntry[]
  has_timeline: boolean
  has_anomalies: boolean
  has_sigma: boolean
  has_lineage: boolean
  merkle_root: string
  status: string
}

export interface TimelineEvent {
  event_id: string
  timestamp_utc: string
  action: string
  action_class: string
  user: string
  host: string
  object_path: string | null
  object_type: string
  artifact: string
  plugin: string
  evidence_id: string
  confidence: number
  rationale: string
  tags: string[]
  warnings: string[]
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
}

export interface TimelineResponse {
  events: TimelineEvent[]
  total: number
  offset: number
  limit: number
}

export interface AnomalyFinding {
  anomaly_id: string
  anomaly_type: string
  severity: string
  title: string
  description: string
  window_start_utc: string
  window_end_utc: string
  metric_value: number
  baseline_value: number
  z_score: number
  affected_users: string[]
  sample_events: string[]
}

export interface SigmaMatch {
  rule_id: string
  title: string
  level: string
  description: string
  mitre_tags: string[]
  event_id: string
  timestamp_utc: string
  matched_fields: Record<string, string>
}

export interface ProcessNode {
  pid: string
  ppid: string
  process_name: string
  command_line: string
  user: string
  timestamp_utc: string
  event_id: string
  parent_name: string | null
  threat_alerts: string[]
  children: ProcessNode[]
}

export interface CorroborationData {
  total_events: number
  corroborated_count: number
  conflict_count: number
  clusters: object[]
  conflicts: {
    entity: string
    conflict_type: string
    description: string
    event_ids: string[]
    severity: string
    evidence_ids: string[]
  }[]
  summary: {
    total_entities_analyzed: number
    corroborated_events: number
    corroborated_clusters: number
    conflicts_detected: number
  }
}

export interface ReportFile {
  filename: string
  format: string
  path_relative: string
  sha256: string | null
  size_bytes: number
  generated_utc: string
}

export interface IntegrityResult {
  case_id: string
  overall_status: string
  ledger_status: string
  evidence_status: string
  derived_status: string
  merkle_status: string
  errors: string[]
  warnings: string[]
  checked_items: {
    ledger_entries: number
    evidence_files: number
    derived_files: number
  }
}

// ----------- API functions -----------

export const getHealth = () => api.get<HealthStatus>('/health').then(r => r.data)

export const listCases = () => api.get<CaseSummary[]>('/cases').then(r => r.data)

export const getCase = (id: string) => api.get<CaseDetail>(`/cases/${id}`).then(r => r.data)

export const createCase = (payload: {
  case_id: string
  examiner: string
  description: string
  organization: string
  authorization_ref: string
}) => api.post<CaseDetail>('/cases', payload).then(r => r.data)

export const getEvidence = (id: string) =>
  api.get<EvidenceEntry[]>(`/cases/${id}/evidence`).then(r => r.data)

export const verifyCase = (id: string) =>
  api.post<IntegrityResult>(`/cases/${id}/verify`).then(r => r.data)

export const getTimeline = (id: string, params?: {
  limit?: number
  offset?: number
  search?: string
  severity?: string
  action?: string
  user?: string
  source?: string
}) => api.get<TimelineResponse>(`/cases/${id}/timeline`, { params }).then(r => r.data)

export const getAnomalies = (id: string) =>
  api.get<AnomalyFinding[]>(`/cases/${id}/anomalies`).then(r => r.data)

export const getSigmaAlerts = (id: string) =>
  api.get<SigmaMatch[]>(`/cases/${id}/sigma`).then(r => r.data)

export const getLineage = (id: string) =>
  api.get<ProcessNode[]>(`/cases/${id}/lineage`).then(r => r.data)

export const getCorroboration = (id: string) =>
  api.get<CorroborationData>(`/cases/${id}/corroboration`).then(r => r.data)

export const getThreatAlerts = (id: string) =>
  api.get<object[]>(`/cases/${id}/threat-alerts`).then(r => r.data)

export const analyzeCase = (id: string) =>
  api.post<{ status: string; case_id: string; message: string }>(
    `/cases/${id}/analyze`
  ).then(r => r.data)

export const getCaseStatus = (id: string) =>
  api.get<{ status: string }>(`/cases/${id}/status`).then(r => r.data)

export const listReports = (id: string) =>
  api.get<ReportFile[]>(`/cases/${id}/reports`).then(r => r.data)

export const generateReports = (id: string, formats: string[]) =>
  api.post<{ generated: Record<string, string> }>(
    `/cases/${id}/reports/generate`,
    { formats }
  ).then(r => r.data)

export const getReportUrl = (caseId: string, filename: string) =>
  `/api/v1/cases/${caseId}/reports/${filename}`

// Web3 / Blockchain Attestation
export interface Web3AttestationResponse {
  anchored: boolean
  case_id?: string
  network?: string
  status?: string
  attestation?: {
    case_id: string
    case_id_bytes32: string
    merkle_root: string
    evidence_sha256: string
    ipfs_cid: string
    network: string
    contract_address: string
    transaction_hash: string
    block_number: number
    investigator_address: string
    timestamp_utc: string
    status: string
  }
  ipfs?: {
    cid: string
    gateway_url: string
    sha256: string
    size_bytes: number
    pinned: boolean
    provider: string
  }
  eas?: {
    uid: string
    schema_uid: string
    time: number
    expiration_time: number
  }
  etherscan_url?: string
  ipfs_url?: string
}

export interface Web3VerifyResult {
  is_valid: boolean
  tamper_detected: boolean
  on_chain_merkle_root: string
  local_merkle_root: string
  merkle_root_match: boolean
  on_chain_evidence_sha256: string
  local_evidence_sha256: string
  evidence_sha256_match: boolean
  transaction_hash: string
  block_number: number
  network: string
}

export const getWeb3Attestation = (id: string) =>
  api.get<Web3AttestationResponse>(`/cases/${id}/web3/attestation`).then(r => r.data)

export const anchorCaseToWeb3 = (id: string, payload?: { network?: string; examiner?: string }) =>
  api.post<Web3AttestationResponse>(`/cases/${id}/web3/anchor`, payload || {}).then(r => r.data)

export const verifyWeb3Tamper = (id: string) =>
  api.post<Web3VerifyResult>(`/cases/${id}/web3/verify`).then(r => r.data)
