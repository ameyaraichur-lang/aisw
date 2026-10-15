// Policy-outcome vocabulary (blueprint section 3.1). Status is always conveyed by
// label + icon + colour token, never colour alone (WCAG 2.2 AA).
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

export const OUTCOME_DISPLAY: Record<PolicyOutcome, { icon: string; label: string }> = {
  PASS: { icon: '✓', label: 'Pass' },
  FAIL: { icon: '✕', label: 'Fail' },
  NOT_APPLICABLE: { icon: '–', label: 'Not applicable' },
  NOT_ASSESSED: { icon: '○', label: 'Not assessed' },
  UNKNOWN: { icon: '?', label: 'Unknown' },
  ERROR: { icon: '!', label: 'Error' },
  EXCEPTION: { icon: '◇', label: 'Exception' },
}
