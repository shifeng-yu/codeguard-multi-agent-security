import type {
  AuditList,
  DashboardSummary,
  PackageRisk,
  RepoItem,
  ScanDetail,
  ScanList,
  SeverityBucket,
  TrendPoint,
} from './types'

const BASE = import.meta.env.VITE_API_BASE ?? '/api/v1'

function qs(params: Record<string, unknown>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, String(value))
    }
  }
  const text = search.toString()
  return text ? `?${text}` : ''
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  })
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = await response.json()
      detail = body?.detail?.error?.message ?? body?.detail ?? detail
    } catch {
      /* response had no JSON body */
    }
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  return (await response.json()) as T
}

export const api = {
  // scans
  listScans(params: {
    page?: number
    page_size?: number
    repo?: string
    status?: string
    verdict?: string
  } = {}): Promise<ScanList> {
    return request<ScanList>(`/scans${qs(params)}`)
  },
  getScan(scanId: string): Promise<ScanDetail> {
    return request<ScanDetail>(`/scans/${encodeURIComponent(scanId)}`)
  },
  streamUrl(scanId: string, lastEventId = 0): string {
    return `${BASE}/scans/${encodeURIComponent(scanId)}/stream${qs({ last_event_id: lastEventId })}`
  },

  // dashboard
  summary(days = 1): Promise<DashboardSummary> {
    return request<DashboardSummary>(`/dashboard/summary${qs({ days })}`)
  },
  severity(days = 30): Promise<{ items: SeverityBucket[] }> {
    return request<{ items: SeverityBucket[] }>(`/dashboard/severity${qs({ days })}`)
  },
  trend(days = 30): Promise<{ items: TrendPoint[] }> {
    return request<{ items: TrendPoint[] }>(`/dashboard/trend${qs({ days })}`)
  },
  topPackages(days = 30, limit = 8): Promise<{ items: PackageRisk[] }> {
    return request<{ items: PackageRisk[] }>(`/dashboard/top-packages${qs({ days, limit })}`)
  },

  // repos
  listRepos(): Promise<{ items: RepoItem[]; count: number }> {
    return request<{ items: RepoItem[]; count: number }>('/repos')
  },
  authorizeRepo(body: { repo_full_name: string; installation_id?: number }): Promise<RepoItem> {
    return request<RepoItem>('/repos', { method: 'POST', body: JSON.stringify(body) })
  },
  toggleRepo(body: { repo_full_name: string; enabled: boolean }): Promise<RepoItem> {
    return request<RepoItem>('/repos', { method: 'PATCH', body: JSON.stringify(body) })
  },
  installUrl(): Promise<{ url: string; app_slug: string; configured: boolean }> {
    return request('/repos/install/url')
  },

  // audit
  listAudit(params: {
    action?: string
    scan_id?: string
    operator?: string
    limit?: number
    offset?: number
  } = {}): Promise<AuditList> {
    return request<AuditList>(`/audit${qs(params)}`)
  },
  verifyAudit(): Promise<{ valid: boolean; total_rows: number; bad_rows: unknown[] }> {
    return request('/audit/verify')
  },
}
