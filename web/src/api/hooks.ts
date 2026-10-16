import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from './client'
import type {
  AgentsResponse, AuditItem, Recommendation, Scenario, AuthMode, ControlRow, CoverageResponse, Connector, FindingDetail, FindingRow,
  InventoryEntry, ManifestSummary, Me, Overview, Page, PolicyPackInfo, Project, ReportBody,
  ReportList, RunListItem, RunStatus, TaskView,
} from './types'

const qs = (o: Record<string, string | number | string[] | undefined | null>): string => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined || v === null || v === '') continue
    for (const x of Array.isArray(v) ? v : [v]) p.append(k, String(x))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const useAuthMode = () => useQuery({ queryKey: ['auth-mode'], queryFn: () => api<AuthMode>('/auth/mode'), staleTime: Infinity })
export const useMe = (identity: string | null) =>
  useQuery({ queryKey: ['me', identity], queryFn: () => api<Me>('/me'), enabled: !!identity, retry: false, staleTime: 60_000 })
export const useOverview = () => useQuery({ queryKey: ['overview'], queryFn: () => api<Overview>('/overview'), refetchInterval: 15_000 })
export const useProjects = () => useQuery({ queryKey: ['projects'], queryFn: () => api<Project[]>('/projects') })
export const useInventory = (projectId: string | undefined) =>
  useQuery({ queryKey: ['inventory', projectId], queryFn: () => api<InventoryEntry[]>(`/inventory${qs({ project_id: projectId })}`), enabled: !!projectId })
export const useConnectors = () => useQuery({ queryKey: ['connectors'], queryFn: () => api<Connector[]>('/connectors') })
export const usePolicyPacks = () => useQuery({ queryKey: ['policy-packs'], queryFn: () => api<PolicyPackInfo[]>('/policy-packs') })
export const useManifests = (p: { project_id?: string; status?: string }) =>
  useQuery({ queryKey: ['manifests', p], queryFn: () => api<ManifestSummary[]>(`/scope-manifests${qs(p)}`) })
export const useRuns = (p: { project_id?: string; limit?: number; offset?: number }) =>
  useQuery({ queryKey: ['runs', p], queryFn: () => api<Page<RunListItem>>(`/assessments${qs(p)}`), placeholderData: keepPreviousData })
export const useRunStatus = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'status'], queryFn: () => api<RunStatus>(`/assessments/${runId}`) })
export const useTasks = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'tasks'], queryFn: () => api<TaskView[]>(`/assessments/${runId}/tasks`) })
export const useCoverage = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'coverage'], queryFn: () => api<CoverageResponse>(`/assessments/${runId}/coverage`) })
export const useControls = (runId: string | undefined) =>
  useQuery({ queryKey: ['run', runId, 'controls'], queryFn: () => api<ControlRow[]>(`/assessments/${runId}/controls`), enabled: !!runId })
export const useRunFindings = (runId: string, p: { verdict: string[]; severity?: string; limit: number; offset: number }) =>
  useQuery({
    queryKey: ['run', runId, 'findings', p],
    queryFn: () => api<Page<FindingRow & { authoritative: boolean }>>(`/assessments/${runId}/findings${qs({ verdict: p.verdict, severity: p.severity, limit: p.limit, offset: p.offset })}`),
    placeholderData: keepPreviousData,
  })
export const useAllFindings = (p: { verdict: string; severity: string[]; limit: number; offset: number }) =>
  useQuery({ queryKey: ['findings', p], queryFn: () => api<Page<FindingRow>>(`/findings${qs(p)}`), placeholderData: keepPreviousData })
export const useFinding = (runId: string, findingId: string) =>
  useQuery({ queryKey: ['run', runId, 'finding', findingId], queryFn: () => api<FindingDetail>(`/assessments/${runId}/findings/${findingId}`) })
export const useReports = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'reports'], queryFn: () => api<ReportList[]>(`/assessments/${runId}/reports`), retry: false })
export const useReportBody = (reportId: string | undefined) =>
  useQuery({ queryKey: ['report', reportId], queryFn: () => api<ReportBody>(`/reports/${reportId}`), enabled: !!reportId })
export const useAudit = (p: { limit: number; offset: number; result?: string }) =>
  useQuery({ queryKey: ['audit', p], queryFn: () => api<Page<AuditItem>>(`/audit/events${qs(p)}`), placeholderData: keepPreviousData, retry: false })

export const useAgents = () => useQuery({ queryKey: ['agents'], queryFn: () => api<AgentsResponse>('/agents'), staleTime: 60_000 })
export const useRunScenarios = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'scenarios'], queryFn: () => api<Scenario[]>(`/assessments/${runId}/scenarios`) })
export const useRunRecommendations = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'recommendations'], queryFn: () => api<Recommendation[]>(`/assessments/${runId}/recommendations`) })
export const useAllRecommendations = (p: { status?: string; run_id?: string; limit: number; offset: number }) =>
  useQuery({
    queryKey: ['recommendations', p],
    queryFn: () => api<Page<Recommendation & { run_id: string; project_name: string }>>(`/recommendations${qs(p)}`),
    placeholderData: keepPreviousData,
  })
