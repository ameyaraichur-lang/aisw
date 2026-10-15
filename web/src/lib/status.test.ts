import { describe, expect, it } from 'vitest'
import { OUTCOME_DISPLAY, POLICY_OUTCOMES } from './status'

describe('policy outcome vocabulary', () => {
  it('has a distinct icon and label for every outcome (never colour-only)', () => {
    const icons = new Set<string>()
    for (const o of POLICY_OUTCOMES) {
      const d = OUTCOME_DISPLAY[o]
      expect(d.label.length).toBeGreaterThan(0)
      expect(d.icon.length).toBeGreaterThan(0)
      icons.add(d.icon)
    }
    expect(icons.size).toBe(POLICY_OUTCOMES.length)
  })
})
