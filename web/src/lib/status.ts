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

// AI validator verdicts (ADR-021): advisory only; a dissent can hold an item, never approve one.
export const AI_VERDICT_DISPLAY: Record<string, Display> = {
  CONCUR: { icon: '✓', label: 'AI concurs', tone: 'ok' },
  CONCERN: { icon: '!', label: 'AI concern (review note)', tone: 'warn' },
  INSUFFICIENT_EVIDENCE: { icon: '?', label: 'AI: insufficient evidence', tone: 'warn' },
  DISSENT: { icon: '✕', label: 'AI dissent: held for review', tone: 'bad' },
  NO_VERDICT: { icon: '–', label: 'No AI verdict', tone: 'neutral' },
  VALIDATOR_INVALID: { icon: '⊘', label: 'AI reply rejected (ungrounded)', tone: 'neutral' },
  UNAVAILABLE: { icon: '○', label: 'AI validation unavailable', tone: 'neutral' },
}

export const RECOMMENDATION_STATUS_DISPLAY: Record<string, Display> = {
  DRAFT: { icon: '…', label: 'Draft: awaiting a human decision', tone: 'neutral' },
  NEEDS_REVIEW: { icon: '?', label: 'Deferred: needs owner input', tone: 'warn' },
  APPROVED_FOR_PLANNING: { icon: '✓', label: 'Accepted for planning (nothing was changed)', tone: 'ok' },
  REJECTED: { icon: '✕', label: 'Rejected', tone: 'bad' },
  IMPLEMENTED_PENDING_VALIDATION: { icon: '◐', label: 'Implemented, pending validation', tone: 'info' },
}

// Framework-mapping review state (ADR-032): a proposal until the policy owner decides.
export const MAPPING_DISPLAY: Record<string, Display> = {
  APPROVED: { icon: '✓', label: 'Approved', tone: 'ok' },
  NEEDS_REVIEW: { icon: '?', label: 'Needs policy-owner review', tone: 'warn' },
  REJECTED: { icon: '✕', label: 'Rejected', tone: 'bad' },
}

// Finding exceptions (ADR-033): a risk acceptance in force for a limited time.
export const EXCEPTION_DISPLAY: Record<string, Display> = {
  PENDING: { icon: '…', label: 'Awaiting approval', tone: 'warn' },
  ACTIVE: { icon: '◇', label: 'In force', tone: 'info' },
  EXPIRED: { icon: '⌛', label: 'Expired: reported again', tone: 'bad' },
  REJECTED: { icon: '✕', label: 'Rejected', tone: 'neutral' },
  REVOKED: { icon: '⊘', label: 'Revoked', tone: 'neutral' },
}

// Ticket outbox (ADR-037): a draft is sent once, by a second approver, and never edited after.
export const TICKET_DISPLAY: Record<string, Display> = {
  DRAFT: { icon: '…', label: 'Draft: not sent', tone: 'neutral' },
  SENDING: { icon: '◐', label: 'Sending', tone: 'info' },
  SENT: { icon: '✓', label: 'Sent', tone: 'ok' },
  FAILED: { icon: '!', label: 'Not sent: last attempt failed', tone: 'warn' },
}

export const LIFECYCLE_LABEL: Record<string, string> = {
  NEW: 'New', TRIAGED: 'Confirmed', FALSE_POSITIVE: 'False positive', REOPENED: 'Reopened',
  EXCEPTION_PENDING: 'Exception requested', ACCEPTED: 'Risk accepted (exception)',
  IN_REMEDIATION: 'In remediation', PENDING_VALIDATION: 'Pending validation', RESOLVED: 'Resolved',
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
