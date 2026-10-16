import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from './client'
import type {
  AgentsResponse, AiValidations, AssetDetail, AssetList, AssuranceOverview, AuditItem, Disagreement, ModelCallLedger, TriggerPolicyView, Recommendation, Scenario, AuthMode, ControlMatrix, ControlRow, ExceptionList, CoverageResponse, Connector, FindingDetail, FindingRow,
  InventoryEntry, ManifestSummary, Me, Overview, Page, PolicyPackInfo, Project, ReportBody,
  ReportList, Roadmap, RunListItem, RunStatus, TaskView, ItsmTarget, OutboxRow, RenderedTicket,
  AnswerKeyInfo, Scorecard, TrendRow, CoverageLedgerView, ImportFile, ProjectRoleGrant, RetentionPlan, RetentionCheck, RetentionHold,
  RetentionAction,
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
export const useImports = (projectId: string | undefined) =>
  useQuery({ queryKey: ['imports', projectId], queryFn: () => api<ImportFile[]>(`/imports${qs({ project_id: projectId })}`), enabled: !!projectId })
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
export const useControlMatrix = (p: { run_id?: string; policy_version?: string }) =>
  useQuery({ queryKey: ['control-matrix', p], queryFn: () => api<ControlMatrix>(`/control-matrix${qs(p)}`), enabled: !!(p.run_id || p.policy_version), placeholderData: keepPreviousData })
export const useExceptions = (p: { state?: string }) =>
  useQuery({ queryKey: ['exceptions', p], queryFn: () => api<ExceptionList>(`/exceptions${qs(p)}`), placeholderData: keepPreviousData })
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
export const useAssets = (p: { project_id?: string; asset_type?: string; q?: string; confidence?: string; owner?: string; limit: number; offset: number }) =>
  useQuery({ queryKey: ['assets', p], queryFn: () => api<AssetList>(`/assets${qs(p)}`), placeholderData: keepPreviousData })
export const useAsset = (projectId: string, assetId: string) =>
  useQuery({ queryKey: ['asset', projectId, assetId], queryFn: () => api<AssetDetail>(`/assets/${encodeURIComponent(projectId)}/${encodeURIComponent(assetId)}`) })
export const useReports = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'reports'], queryFn: () => api<ReportList[]>(`/assessments/${runId}/reports`), retry: false })
export const useReportBody = (reportId: string | undefined) =>
  useQuery({ queryKey: ['report', reportId], queryFn: () => api<ReportBody>(`/reports/${reportId}`), enabled: !!reportId })
export const useAudit = (p: { limit: number; offset: number; result?: string }) =>
  useQuery({ queryKey: ['audit', p], queryFn: () => api<Page<AuditItem>>(`/audit/events${qs(p)}`), placeholderData: keepPreviousData, retry: false })

export const useAgents = () => useQuery({ queryKey: ['agents'], queryFn: () => api<AgentsResponse>('/agents'), staleTime: 60_000 })
export const useRunScenarios = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'scenarios'], queryFn: () => api<Scenario[]>(`/assessments/${runId}/scenarios`) })
export const useAssuranceOverview = () =>
  useQuery({ queryKey: ['assurance', 'overview'], queryFn: () => api<AssuranceOverview>('/assurance/overview') })
export const useDisagreements = (p: { state: string; limit: number; offset: number }) =>
  useQuery({ queryKey: ['assurance', 'disagreements', p], queryFn: () => api<Page<Disagreement>>(`/assurance/disagreements${qs(p)}`), placeholderData: keepPreviousData })
export const useTriggerPolicy = (runId?: string) =>
  useQuery({ queryKey: ['assurance', 'triggers', runId ?? ''], queryFn: () => api<TriggerPolicyView>(`/assurance/trigger-policy${qs({ run_id: runId })}`) })
export const useModelCalls = (p: { run_id?: string; purpose?: string; status?: string; limit: number; offset: number }) =>
  useQuery({ queryKey: ['model-calls', p], queryFn: () => api<ModelCallLedger>(`/model-calls${qs(p)}`), placeholderData: keepPreviousData, retry: false })
export const useTicketOutbox = (runId?: string) =>
  useQuery({ queryKey: ['tickets', runId ?? ''], queryFn: () => api<OutboxRow[]>(`/tickets/drafts${qs({ run_id: runId })}`) })
export const useRenderedTicket = (outboxId: string, target: ItsmTarget | null) =>
  useQuery({ queryKey: ['tickets', 'render', outboxId, target ?? ''], queryFn: () => api<RenderedTicket>(`/tickets/drafts/${outboxId}/render${qs({ target })}`) })
export const useRoadmap = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'roadmap'], queryFn: () => api<Roadmap>(`/assessments/${runId}/roadmap`), enabled: !!runId })
export const useRunRecommendations = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'recommendations'], queryFn: () => api<Recommendation[]>(`/assessments/${runId}/recommendations`) })
export const useAiValidations = (runId: string) =>
  useQuery({ queryKey: ['run', runId, 'ai-validations'], queryFn: () => api<AiValidations>(`/assessments/${runId}/ai-validations`) })
export const useAllRecommendations = (p: { status?: string; run_id?: string; limit: number; offset: number }) =>
  useQuery({
    queryKey: ['recommendations', p],
    queryFn: () => api<Page<Recommendation & { run_id: string; project_name: string; run_requested_by: string }>>(`/recommendations${qs(p)}`),
    placeholderData: keepPreviousData,
  })
export const useAnswerKeys = () => useQuery({ queryKey: ['evaluation', 'keys'], queryFn: () => api<AnswerKeyInfo[]>('/evaluation/answer-keys'), staleTime: Infinity })
export const useEvaluationTrend = (fixtureSet?: string) =>
  useQuery({ queryKey: ['evaluation', 'trend', fixtureSet ?? ''], queryFn: () => api<TrendRow[]>(`/evaluation/runs${qs({ fixture_set: fixtureSet, limit: 20 })}`) })
export const useScorecard = (runId?: string) =>
  useQuery({ queryKey: ['evaluation', 'card', runId], queryFn: () => api<Scorecard>(`/evaluation/runs/${runId}/scorecard`), enabled: !!runId })
export const useCoverageLedger = (incompleteOnly: boolean) =>
  useQuery({ queryKey: ['coverage-ledger', incompleteOnly], queryFn: () => api<CoverageLedgerView>(`/coverage${qs({ incomplete_only: incompleteOnly ? 'true' : undefined })}`) })
export const useRetentionPlan = (enabled: boolean) =>
  useQuery({ queryKey: ['retention', 'plan'], queryFn: () => api<RetentionPlan>('/retention/plan'), enabled })
export const useRetentionChecks = () => useQuery({ queryKey: ['retention', 'checks'], queryFn: () => api<RetentionCheck[]>('/retention/checks') })
export const useRetentionHolds = () => useQuery({ queryKey: ['retention', 'holds'], queryFn: () => api<RetentionHold[]>('/retention/holds') })
export const useRetentionActions = (enabled: boolean) =>
  useQuery({ queryKey: ['retention', 'actions'], queryFn: () => api<RetentionAction[]>('/retention/actions'), enabled })
export const useProjectRoles = (projectId: string | undefined) =>
  useQuery({ queryKey: ['project-roles', projectId], queryFn: () => api<ProjectRoleGrant[]>(`/projects/${projectId}/roles`), enabled: !!projectId })
