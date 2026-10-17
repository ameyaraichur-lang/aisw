# Manual screen-reader pass

Automated checks (axe WCAG 2.2 AA plus the structural best-practice rules, keyboard and reduced-motion tests in `web/e2e/a11y.spec.ts`) cannot tell whether the console makes sense when heard. This pass is done by a person, ideally one who uses a screen reader daily. It is the artefact of the `accessibility-screen-reader` sign-off.

**Setups:** VoiceOver with Safari on macOS, and NVDA with Firefox or Chrome on Windows. Use the dev stack (`docs/runbooks/local-dev-and-test.md`), never real data. Record the screen-reader and browser versions.

For each task, record PASS or FAIL and, for a FAIL, what was announced instead.

| # | Task | Expected |
|---|---|---|
| 1 | Load the sign-in page and sign in as alice | The page title and the sign-in buttons are announced by name; after sign-in, "Signed in user alice" is reachable |
| 2 | Use the skip link, then list landmarks and headings | Skip link moves to the main content; one main landmark, navigation is named; one level-1 heading per page and no skipped levels |
| 3 | Navigate to Assessments with the navigation list | Current page is announced (aria-current); the table caption is read before its rows |
| 4 | Create an assessment with the wizard, keyboard only | Each step is announced; every field reads its label and any hint; validation errors are announced when they appear and are linked to their field |
| 5 | Start a run and stay on the run page | Phase changes and task progress are announced without moving focus (polite status), and failures as alerts; nothing repeats on every update |
| 6 | Cut the network briefly, then restore it | The stale-connection banner is announced once; recovery is announced |
| 7 | Open a finding, then the evidence list | Severity is spoken as text, not only colour; the evidence hash and the "untrusted content" notices are read |
| 8 | Approve a manifest as bob (Approvals) | The confirmation dialog takes focus, announces its title, traps focus, and returns focus to the trigger on close |
| 9 | Open the Analysis tab of a finished run | Scenario routes ("Route to host-2") and the Reachability table are navigable as list and table |
| 10 | Report tab: preview, then download | The draft watermark notice is read; the download control states its format |
| 11 | Audit page as erin | Chain and anchor banners are read as status messages with their full text |
| 12 | Retention page as alice: place and release a hold | The result of each action is announced; the confirmation dialog behaves as in task 8 |
| 13 | Open a page without permission (pete on Approvals) | "Access denied" is announced with the missing permission |

Results go in `docs/implementation/accessibility-screen-reader-results.md` (date, tester, versions, one row per task). Fix any FAIL before recording the sign-off, or record it as a known issue with an owner.
