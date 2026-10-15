import { OUTCOME_DISPLAY, POLICY_OUTCOMES } from './lib/status'

// M0 placeholder shell. No assessment data exists yet and none is simulated.
export default function App() {
  return (
    <main>
      <h1>Agentic Infrastructure Security Warden</h1>
      <p>
        Milestone M0 skeleton. Read-only platform; no assessment data is available and none is
        simulated.
      </p>
      <h2>Outcome vocabulary</h2>
      <ul>
        {POLICY_OUTCOMES.map((o) => (
          <li key={o}>
            <span aria-hidden="true">{OUTCOME_DISPLAY[o].icon}</span> {OUTCOME_DISPLAY[o].label}
          </li>
        ))}
      </ul>
    </main>
  )
}
