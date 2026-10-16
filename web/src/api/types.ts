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
  mode: 'dev_stub' | 'oidc' | 'none'
  users: { name: string; tenant_id: string; roles: string[] }[]
  sso?: boolean
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
  needs_opa: boolean
  runnable: boolean
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
export type MappingStatus = 'APPROVED' | 'NEEDS_REVIEW' | 'REJECTED'
export interface FrameworkMapping {
  key: string
  framework: string
  version: string
  control_id: string
  title: string
  status: MappingStatus
  reviewed_by: string | null
  reviewed_at: string | null
  reason: string | null
}
export interface ControlMatrix {
  policy_version: string
  pack_framework: { name: string; version: string }
  run_id: string | null
  final: boolean
  catalog_version: string
  notice: string
  frameworks: { framework: string; version: string; name: string }[]
  controls: { control_id: string; rules: { rule_id: string; title: string; severity: string }[]; outcome: string | null; mappings: FrameworkMapping[] }[]
  summary: Record<MappingStatus, number>
  can_review: boolean
}
export type ReviewAction = 'CONFIRM' | 'REJECT' | 'REOPEN' | 'REQUEST_EXCEPTION'
export interface ReviewEntry { action: string; from: string; to: string; reason: string; actor: string; at: string; exception_id: string | null }
export type ExceptionState = 'PENDING' | 'ACTIVE' | 'EXPIRED' | 'REJECTED' | 'REVOKED'
export interface ExceptionItem {
  exception_id: string
  project_id: string
  project_name?: string
  rule_id: string
  asset_id: string
  title: string
  source_run_id: string
  source_finding_id: string
  reason: string
  requested_by: string
  requested_at: string
  expires_at: string
  status: string
  state: ExceptionState
  days_left: number | null
  decided_by: string | null
  decided_at: string | null
  decision_reason: string | null
  revoked_by: string | null
  revoked_at: string | null
  revoke_reason: string | null
}
export interface ExceptionList { as_of: string; max_days: number; counts: Record<ExceptionState, number>; items: ExceptionItem[]; can_decide: boolean }
export interface FindingDetail {
  finding: Finding
  assurance_verdict: string
  authoritative: boolean
  framework_mappings: FrameworkMapping[]
  lifecycle: string
  review_history: ReviewEntry[]
  review_actions: ReviewAction[]
  exception: ExceptionItem | null
  exception_max_days: number
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
  rubric_signoff?: SignoffStatus
}
export type SignoffStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'UNRECORDED'
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
  chain: { finding_id: string; evidence_ref: string; basis: string; note: string | null; title?: string; severity?: string; category?: string }[]
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
  ticket_delivery: { enabled: boolean; target: 'jira' | 'servicenow' | null }
  rubric_version: string
  signoffs: { rubric: SignoffStatus; catalog: SignoffStatus }
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
export type ItsmTarget = 'jira' | 'servicenow'
export type TicketStatus = 'DRAFT' | 'SENDING' | 'SENT' | 'FAILED'
export interface OutboxRow {
  outbox_id: string
  run_id: string
  recommendation_id: string
  status: TicketStatus
  payload: TicketDraft['payload']
  created_by: string
  created_at: string
  delivered: boolean
  target: ItsmTarget | null
  attempts: number
  external_ref: string | null
  external_url: string | null
  last_error: string | null
  sent_by: string | null
  sent_at: string | null
}
export interface RenderedTicket {
  outbox_id: string
  target: ItsmTarget
  correlation_key: string
  payload: Record<string, unknown>
  delivery_enabled: boolean
  configured_target: ItsmTarget | null
  sent: boolean
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
  exceptions: { pending: number; active: number; expiring_30d: number; expired: number }
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
export interface AssuranceOverview {
  assurance: Record<string, Record<string, number>>
  defects: { code: string; count: number }[]
  ai_validation: Record<string, number>
  open_dissent: number
  triggers: { agent_id: number; agent_name: string; triggered: number; skipped: number }[]
}
export interface Disagreement {
  run_id: string
  project_name: string
  agent_id: number
  agent_name: string
  target_ref: string
  ai_verdict: string
  effect: string
  issues: { code: string; explanation: string }[]
  human_questions: string[]
  validator_confidence: string | null
  model_id: string | null
  prompt_version: string
  created_at: string
  engine_verdict: string | null
  engine_defects: string[]
  run_state: string
  ai_generated: true
  resolution: { decision: 'OVERRULE' | 'UPHOLD'; reason: string; decided_by: string; decided_at: string } | null
  resolvable: boolean
}
export interface TriggerPolicyView {
  version: string
  status: string
  sha256: string
  signoff: string
  priority: { agent_id: number; agent_name: string }[]
  agents: { agent_id: number; agent_name: string; why: string; rules: string[] }[]
  ai_validation_enabled: boolean
  decisions: { agent_id: number; agent_name: string; target_ref: string; triggered: boolean; rule: string; policy_version: string }[]
}
export interface ModelCallRow {
  run_id: string
  project_name: string
  purpose: string
  subject_ref: string
  model_id: string | null
  prompt_version: string
  status: string
  attempts: number
  defects: string[]
  input_tokens: number | null
  output_tokens: number | null
  latency_ms: number | null
  replayed: boolean
  input_hash: string
  output_hash: string | null
  created_at: string
}
export interface ModelCallLedger extends Page<ModelCallRow> {
  totals: { calls: number; input_tokens: number; output_tokens: number; latency_ms: number; replayed: number; unmetered: number; not_validated: number }
}
export interface RoadmapCard {
  recommendation_id: string
  title: string | null
  status: Recommendation['status']
  risk_tier: string | null
  catalog_ref: string | null
  current_state: string | null
  target_pattern: string | null
  affected_assets: string[]
  effort: { value: string | null; is_estimate: boolean }
  depends_on: string[]
  reason: string
}
export interface Roadmap {
  run_id: string
  waves: { wave: number; label: string; items: RoadmapCard[] }[]
  unrated: RoadmapCard[]
  awaiting_validation: RoadmapCard[]
  rejected: RoadmapCard[]
  edges: { from: string; to: string; basis: string; assets: string[] }[]
  not_authoritative: number
  rules: string[]
  catalog_signoff: string
}
export interface AssetRow {
  project_id: string
  project_name: string
  asset_id: string
  asset_type: string
  native_ids: Record<string, unknown>
  attrs: Record<string, unknown>
  environment: string | null
  owner: string | null
  owner_source: string | null
  criticality: string | null
  criticality_source: string | null
  technology: string | null
  match_confidence: 'HIGH' | 'MEDIUM' | 'LOW'
  first_seen: string
  last_seen: string
  last_run_id: string
}
export interface AssetList extends Page<AssetRow> {
  types: { asset_type: string; count: number; owner_unknown: number; low_confidence: number }[]
}
export interface AssetDetail extends AssetRow {
  posture: { rule_id: string; outcome: string; observed: unknown; expected: unknown; observed_at: string; run_id: string; source: string }[]
  runs: { run_id: string; segment: string; status: string; reason: string | null; at: string }[]
  findings: { run_id: string; finding_id: string; severity: string; lifecycle: string; title: string }[]
  findings_visible: boolean
  relationships: null
}
