// Closed vocabularies. Severity, policy outcome, workflow state and task status are DIFFERENT
// attributes with different encodings; every one is conveyed by label + icon + colour token,
// never colour alone (WCAG 2.2 AA).
export const POLICY_OUTCOMES = [
  'PASS',
  'FAIL',
  'NOT_APPLICABLE',
  'NOT_ASSESSED',
  'UNKNOWN',
  'ERROR',
  'EXCEPTION',
] as const
export type PolicyOutcome = (typeof POLICY_OUTCOMES)[number]

export interface Display {
  icon: string
  label: string
  tone: 'ok' | 'bad' | 'warn' | 'info' | 'neutral'
}

export const OUTCOME_DISPLAY: Record<PolicyOutcome, Display> = {
  PASS: { icon: '✓', label: 'Pass', tone: 'ok' },
  FAIL: { icon: '✕', label: 'Fail', tone: 'bad' },
  NOT_APPLICABLE: { icon: '–', label: 'Not applicable', tone: 'neutral' },
  NOT_ASSESSED: { icon: '○', label: 'Not assessed', tone: 'warn' },
  UNKNOWN: { icon: '?', label: 'Unknown', tone: 'warn' },
  ERROR: { icon: '!', label: 'Error', tone: 'bad' },
  EXCEPTION: { icon: '◇', label: 'Exception', tone: 'info' },
}

export const SEVERITY_DISPLAY: Record<string, Display> = {
  CRITICAL: { icon: '◆', label: 'Critical', tone: 'bad' },
  HIGH: { icon: '▲', label: 'High', tone: 'bad' },
  MEDIUM: { icon: '■', label: 'Medium', tone: 'warn' },
  LOW: { icon: '●', label: 'Low', tone: 'info' },
  INFO: { icon: '○', label: 'Info', tone: 'neutral' },
}

export const RUN_STATE_DISPLAY: Record<string, Display> = {
  AUTHORIZED: { icon: '◐', label: 'Authorized', tone: 'info' },
  ASSESSMENT_DISPATCH: { icon: '▶', label: 'Collecting', tone: 'info' },
  NORMALIZATION: { icon: '▶', label: 'Normalizing', tone: 'info' },
  POLICY_EVALUATION: { icon: '▶', label: 'Evaluating policy', tone: 'info' },
  CORRELATION: { icon: '▶', label: 'Risk and correlation', tone: 'info' },
  ARCHITECTURE_ANALYSIS: { icon: '▶', label: 'Architecture analysis', tone: 'info' },
  ASSURANCE: { icon: '▶', label: 'Assurance', tone: 'info' },
  REPORT_READY: { icon: '✓', label: 'Report ready', tone: 'ok' },
  PARTIAL: { icon: '◑', label: 'Partial', tone: 'warn' },
  CLOSED: { icon: '■', label: 'Closed', tone: 'neutral' },
  FAILED: { icon: '✕', label: 'Failed', tone: 'bad' },
  CANCELLED: { icon: '⊘', label: 'Cancelled', tone: 'neutral' },
  EXPIRED: { icon: '⌛', label: 'Expired', tone: 'neutral' },
}

export const TASK_STATUS_DISPLAY: Record<string, Display> = {
  QUEUED: { icon: '…', label: 'Queued', tone: 'neutral' },
  RUNNING: { icon: '▶', label: 'Running', tone: 'info' },
  SUCCEEDED: { icon: '✓', label: 'Succeeded', tone: 'ok' },
  PARTIAL: { icon: '◑', label: 'Partial', tone: 'warn' },
  FAILED: { icon: '✕', label: 'Failed', tone: 'bad' },
  REJECTED: { icon: '⊘', label: 'Rejected by gateway', tone: 'bad' },
  CANCELLED: { icon: '⊘', label: 'Cancelled', tone: 'neutral' },
  TIMED_OUT: { icon: '⌛', label: 'Timed out', tone: 'bad' },
  SKIPPED: { icon: '–', label: 'Skipped', tone: 'neutral' },
  NEEDS_REVIEW: { icon: '?', label: 'Needs review', tone: 'warn' },
}

export const VERDICT_DISPLAY: Record<string, Display> = {
  ACCEPT: { icon: '✓', label: 'Authoritative (assurance accepted)', tone: 'ok' },
  NEEDS_REVIEW: { icon: '?', label: 'Pending review (not authoritative)', tone: 'warn' },
  REJECT: { icon: '✕', label: 'Rejected by assurance', tone: 'bad' },
}

export const RECOMMENDATION_STATUS_DISPLAY: Record<string, Display> = {
  DRAFT: { icon: '…', label: 'Draft: awaiting a human decision', tone: 'neutral' },
  NEEDS_REVIEW: { icon: '?', label: 'Deferred: needs owner input', tone: 'warn' },
  APPROVED_FOR_PLANNING: { icon: '✓', label: 'Accepted for planning (nothing was changed)', tone: 'ok' },
  REJECTED: { icon: '✕', label: 'Rejected', tone: 'bad' },
  IMPLEMENTED_PENDING_VALIDATION: { icon: '◐', label: 'Implemented, pending validation', tone: 'info' },
}

export const TERMINAL_RUN_STATES = new Set(['CLOSED', 'FAILED', 'CANCELLED', 'EXPIRED', 'PARTIAL', 'REPORT_READY'])

export function display(map: Record<string, Display>, key: string): Display {
  return map[key] ?? { icon: '?', label: key, tone: 'neutral' }
}

export const MANIFEST_BADGE: Record<string, Display> = {
  DRAFT: { icon: '…', label: 'Draft', tone: 'neutral' },
  PREFLIGHTED: { icon: '◐', label: 'Awaiting approval', tone: 'warn' },
  APPROVED: { icon: '✓', label: 'Approved', tone: 'ok' },
  SUPERSEDED: { icon: '–', label: 'Superseded', tone: 'neutral' },
  REVOKED: { icon: '✕', label: 'Revoked', tone: 'bad' },
}
