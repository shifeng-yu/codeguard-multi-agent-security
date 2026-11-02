export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type Verdict = 'block' | 'waive' | 'defer' | 'pass' | 'human_review' | 'error'

export interface ScanItem {
  scan_id: string
  repo: string
  pr_number: number | null
  head_sha: string
  trigger_type: string
  scan_scope: string
  status: string
  verdict: Verdict | null
  overall_blocking: boolean
  blocker_count: number
  warning_count: number
  cve_count: number
  code_issue_count: number
  llm_degraded: boolean
  degraded_reasons: string[]
  started_at: string
  finished_at: string | null
  duration_ms: number | null
}

export interface ScanList {
  items: ScanItem[]
  total: number
  page: number
  page_size: number
}

export interface Finding {
  id: number
  scan_id: string
  finding_type: 'vulnerability' | 'code_issue'
  finding_id: string
  cve_id: string | null
  rule_id: string | null
  package_name: string | null
  installed_version: string | null
  fixed_version: string | null
  severity: Severity
  cvss_score: number | null
  dependency_type: string | null
  file_path: string | null
  line_number: number | null
  message: string
  evidence_source: string | null
  evidence_url: string | null
  verdict: Verdict | null
  blocking: boolean
  appealable: boolean
}

export interface TimelineEvent {
  seq: number
  agent: string
  stage: string
  status: string
  duration_ms: number | null
  payload: Record<string, unknown>
  created_at: string
  event?: string
  verdict?: string
}

export interface ScanDetail extends ScanItem {
  severity_breakdown: Record<Severity, number>
  timeline: TimelineEvent[]
  findings: Finding[]
}

export interface DashboardSummary {
  window_days: number
  scans: number
  blocked: number
  passed: number
  human_review: number
  cves: number
  blockers: number
  avg_duration_ms: number
  repos: number
}

export interface SeverityBucket {
  severity: Severity
  count: number
}

export interface TrendPoint {
  date: string
  scans: number
  blocked: number
  cves: number
}

export interface PackageRisk {
  package_name: string
  findings: number
  blocked: number
  severity: Severity
}

export interface RepoItem {
  repo_full_name: string
  installation_id: number
  github_repo_id: number | null
  default_branch: string
  enabled: boolean
  authorized_at: string
  last_scan_at: string | null
}

export interface AuditItem {
  id: number
  timestamp: string
  action: string
  operator: string
  detail: Record<string, unknown>
  evidence_link: string
  scan_id: string
  task_id: string
  row_hash: string
}

export interface AuditList {
  items: AuditItem[]
  count: number
  limit: number
  offset: number
}
