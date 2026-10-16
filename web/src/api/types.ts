// Response shapes of the platform API that are not wire contracts (see contracts.d.ts for those).
import type { CoverageLedger, Finding } from './contracts'

export type { CoverageLedger, Finding }

export interface Me {
  tenant_id: string
  actor_id: string
  roles: string[]
  permissions: string[]
}
export interface AuthMode {
  mode: 'dev_stub' | 'none'
  users: { name: string; tenant_id: string; roles: string[] }[]
}
export interface Project {
  project_id: string
  name: string
  environment: string
  owner: string | null
  created_by: string
}
export interface InventoryEntry {
  kind: string
  selector: string
  resolved_id: string
  expected_assets: string[]
}
export interface Connector {
  adapter_id: string
  version: string
  enabled: boolean
  permission_ok: boolean
  domains: string[]
  target_kinds: string[]
  profiles: { profile_id: string; profile_class: 'READ_ONLY' | 'ACTIVE' }[]
  read_only: boolean
}
export interface PolicyPackInfo {
  key: string
  pack_hash: string
  description: string
  rules: number
  framework: { name: string; version: string }
}
export interface ManifestSummary {
  manifest_id: string
  project_id: string
  project_name: string
  version: number
  status: 'DRAFT' | 'PREFLIGHTED' | 'APPROVED' | 'SUPERSEDED' | 'REVOKED'
  canonical_hash: string
  created_by: string
  approved_by: string[]
  created_at: string
  targets: string[]
  exclusions: string[]
  adapters: string[]
  domains: string[]
  profiles: Record<string, { profile_id: string; profile_class: 'READ_ONLY' | 'ACTIVE' }>
  policy_version: string
  expires_at: string
  quotas: { max_concurrency: number; max_requests: number; max_duration_seconds: number }
  evidence_retention_days: number
  active_profiles: string[]
}
export interface GateIssue {
  code: string
  severity: 'BLOCKING' | 'WARNING'
  detail: string
}
export interface GateResult {
  decision: { decision: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED'; reason_codes: string[]; manifest_hash: string | null }
  issues: GateIssue[]
}
export interface RunListItem {
  run_id: string
  project_id: string
  project_name: string
  state: string
  partial: boolean
  created_at: string
  manifest_hash: string
  policy_version: string
  requested_by: string
  reason: string | null
  tasks_total: number
  tasks_open: number
}
export interface RunStatus {
  run_id: string
  state: string
  last_phase: string | null
  reason: string | null
  partial: boolean
  cancel_requested: boolean
  manifest_hash: string
  policy_version: string
  created_at: string
  tasks: Record<string, number>
  event_cursor: number
  report: { report_id: string; approval_state: string } | null
}
export interface RunEvent {
  seq: number
  event_id: string
  type: string
  payload: Record<string, unknown>
  occurred_at: string
}
export interface TaskView {
  task_id: string
  agent_id: string
  profile: string
  target_kind: string
  target: string
  status: string
  attempts: number
  max_attempts: number
  started_at: string | null
  completed_at: string | null
  warnings: string[]
  errors: string[]
  output_refs: string[]
  tool_version: string | null
  contract_version: string
}
export interface CoverageResponse {
  run_id: string
  segments: CoverageLedger[]
  final: boolean
  complete: boolean
}
export interface ControlRow {
  framework: string
  version: string
  control_id: string
  applicability: string
  outcome: string
  evidence_refs: string[]
  policy_version: string
  final: boolean
}
export interface FindingRow {
  run_id: string
  finding_id: string
  severity: string
  lifecycle: string
  assurance_verdict: string
  title: string
  outcome: string
  affected_assets: string[]
  project_name: string
  authoritative: boolean
}
export interface FindingDetail {
  finding: Finding
  assurance_verdict: string
  authoritative: boolean
  evidence: {
    evidence_ref: string
    content_hash: string
    source: string
    tool_version: string
    collected_at: string
    redacted: boolean
    media_type: string
    size_bytes: number
  }[]
  observation: {
    asset_id: string
    rule_id: string
    observed_value: unknown
    expected_value: unknown
    outcome: string
    observed_at: string
  } | null
  assurance: {
    verdict: string
    defect_codes: string[]
    missing_refs: string[]
    stale_refs: string[]
    validation_version: string
    validated_at: string
  } | null
  risk_explanation: {
    deterministic: { severity: string; severity_source: string; confidence: string; policy_version: string }
    business_risk: string | null
    risk: RiskInfo | null
    scenarios: { scenario_id: string; title: string; tier: string | null; basis: string }[]
    inferred_links: string[]
    assumptions: string[]
    ai_narrative: string | null
  }
}
export interface RiskInfo {
  rubric_version: string
  tier: string | null
  provisional_tier: string
  basis: 'COMPLETE' | 'NEEDS_POLICY_REVIEW'
  factors: { severity: string; criticality: string | null; exposure: string; evidence_fresh: boolean; corroborating_sources: number }
  missing_evidence: string[]
  rationale: string
  assurance_verdict: string | null
}
export interface Narrative {
  summary: string
  claims: { text: string; finding_ids: string[]; asset_ids: string[] }[]
  open_questions: string[]
  model_id: string | null
  prompt_version: string | null
  ai_generated?: boolean
}
export interface Scenario {
  scenario_id: string
  asset_id: string
  title: string
  finding_ids: string[]
  chain: { finding_id: string; evidence_ref: string; basis: string; note: string | null }[]
  tier: string | null
  basis: 'COMPLETE' | 'NEEDS_POLICY_REVIEW'
  confidence: string
  assumptions: string[]
  missing_evidence: string[]
  validation_steps: string[]
  assurance_verdict: string | null
  authoritative: boolean
  narrative: Narrative | null
}
export interface Recommendation {
  recommendation_id: string
  run_id?: string
  project_name?: string
  title: string | null
  catalog_ref: string | null
  target_pattern: string | null
  current_state: string | null
  action: string
  alternatives: string[]
  dependencies: string[]
  effort: { value: string | null; basis: string | null; is_estimate: boolean }
  owner_questions: string[]
  rollback: string | null
  acceptance_test: string | null
  assumptions: string[]
  validation_steps: string[]
  finding_refs: string[]
  affected_assets: string[]
  risk_tier: string | null
  status: 'DRAFT' | 'NEEDS_REVIEW' | 'APPROVED_FOR_PLANNING' | 'REJECTED' | 'IMPLEMENTED_PENDING_VALIDATION'
  assurance_verdict: string | null
  authoritative: boolean
  decided_by: string | null
  decided_at: string | null
  decision_reason: string | null
  narrative: Narrative | null
  executable: false
}
export interface AgentInfo {
  agent_id: number
  name: string
  purpose: string
  kind: string
  adapters: string[]
  outputs: string[]
  read_only: boolean
  ai_capable: boolean
  ai_active: boolean
  ai_validated: boolean
}
export interface AgentsResponse {
  agents: AgentInfo[]
  ai: { enabled: boolean; model_id: string | null; model_license: string | null; provider: 'ollama' | 'astra' | null; endpoint_local_only: boolean; tools_available_to_model: boolean; may_decide: boolean; validation_enabled: boolean; validation_model: string | null }
  ticket_drafts_enabled: boolean
  rubric_version: string
}
export type AiVerdict = 'CONCUR' | 'CONCERN' | 'DISSENT' | 'INSUFFICIENT_EVIDENCE' | 'NO_VERDICT' | 'VALIDATOR_INVALID' | 'UNAVAILABLE'
export interface AiValidationItem {
  target_ref: string
  agent_id: number
  agent_name: string
  verdict: AiVerdict
  effect: 'HOLD_FOR_REVIEW' | 'REVIEW_ITEM' | 'ANNOTATION' | 'NONE'
  issues: { code: string; explanation: string; evidence_refs: string[] }[]
  human_questions: string[]
  validator_confidence: 'LOW' | 'MEDIUM' | 'HIGH' | null
  defects: string[]
  model_id: string | null
  prompt_version: string
  ai_generated: true
  resolution: AiResolution | null
}
export type AiDecision = 'OVERRULE' | 'UPHOLD'
export interface AiResolution { decision: AiDecision; reason: string; decided_by: string; decided_at: string }
export interface AiValidations {
  summary: { total: number; by_verdict: Record<string, number>; by_agent: Record<string, number>; held_for_review: number; unavailable: number; overruled: number; upheld: number; models: string[] }
  items: AiValidationItem[]
}
export interface TicketDraft {
  outbox_id: string
  status: 'DRAFT'
  delivered: false
  payload: { summary: string; description: string; labels: string[]; delivery: string }
}
export interface ReportList {
  report_id: string
  approval_state: string
  report_hash: string
  generated_at: string
  coverage_complete: boolean
  revision: number
  supersedes: string | null
}
/** Agent 8 summary for leadership: AI-written, shown only when Independent Assurance accepted it. */
export interface ExecutiveSummary {
  summary: string
  claims: { text: string; finding_ids: string[]; asset_ids: string[] }[]
  model_id: string | null
  prompt_version: string
  ai_generated: true
}
/** Agent 4 questions for the asset owner about an accepted finding. AI-written; nothing was tested. */
export interface VerificationQuestions {
  questions: string[]
  model_id: string | null
  ai_generated: true
}
export interface ReportBody {
  title: string
  run_id: string
  banner: string | null
  disclaimer: string
  limitations: string[]
  coverage_complete: boolean
  finding_counts: Record<string, number>
  assurance: { accepted: number; needs_review: number; rejected: number }
  pending_review: { finding_id: string; severity: string; title: string }[]
  policy_versions: string[]
  scope_manifest_hash: string
  generated_at: string
  findings: (Finding & { risk?: RiskInfo; verification_questions?: VerificationQuestions })[]
  executive_summary?: ExecutiveSummary
  scenarios?: Scenario[]
  recommendations?: Recommendation[]
  ai?: { mode: string; narratives_total?: number; narratives_accepted?: number; not_shown?: number }
  model_versions?: string[]
}
export interface Overview {
  as_of: string
  runs: { total: number; by_state: Record<string, number> }
  active_runs: { run_id: string; state: string; created_at: string }[]
  partial_runs: { run_id: string; state: string; created_at: string }[]
  coverage: {
    basis: string
    runs_considered: number
    segments_total: number
    segments_incomplete: number
    expected: number
    reconciled: number
    unknown: number
    unsupported: number
  }
  findings: {
    open_critical_high_authoritative: number
    critical: number
    high: number
    pending_review_critical_high: number
  }
  connectors: { adapter_id: string; enabled: boolean; permission_ok: boolean }[]
}
export interface AuditItem {
  seq: number
  actor: string
  action: string
  resource: string
  result: string
  occurred_at: string
  correlation_id: string
}
export interface Page<T> {
  items: T[]
  total: number
}
