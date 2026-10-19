# ADR-047: Mission Control live view and the HUD theme

**Status:** Accepted (2026-10-18, product owner). Built in `dfb1dad`, `ece1b5f` and `ad31c81`.

## Context
The product owner asked for a livelier console: a "Jarvis-style" view where real probes and events can be seen moving through the estate, in 3D. Three earlier decisions constrain this:
- The development plan lists "3D graphs" as deliberately deferred (App. D.3).
- ADR-046 did not adopt the rev 3 APEX visual language or the Estate Map relationship graph.
- The console never shows a fact it cannot back with a record, and every screen passes axe WCAG 2.2 AA.

## Decision
1. **A Mission Control page at `/mission`, first in the navigation.** It has five parts:
   - a 3D estate view;
   - a live event stream of recorded run events across the six newest runs;
   - the pipeline stages of the latest run;
   - vitals (the coverage gauge, critical and high counts, runs, exceptions);
   - the agent roster.

   It reads the existing endpoints (`/overview`, `/agents`, `/assessments`, `/assessments/{id}/events`, `/assets`, `/findings`) and adds no API.
2. **The 3D view is decorative, not a graph.** Each project is an orbit of its tracked assets around a core. An asset's colour is the worst severity among accepted findings naming it. Position, orbit and distance mean nothing, and no edges are drawn between assets. The Estate Map relationship graph stays not adopted (ADR-046), and the reachability edges (ADR-041) are not drawn here.
3. **Motion is honest.** Idle rotation, the radar sweep and the scan line are decoration. Pulses fire only for events the platform recorded after the page loaded:
   - a task starting sends a probe from the core to the asset;
   - stored evidence travels back to the core;
   - a failure pulses red;
   - a phase change or a report sends a ring out from the core.

   Recorded history is not re-animated on load. "Replay last run" replays the newest run's recorded events, and the page says it is a replay.
4. **Accessible by construction.** The canvas is `aria-hidden`. The same facts are in the Tracked assets list (with severity in words), the event log (`role="log"`) and the legend. Under reduced motion the view draws one still frame and offers no replay. Without WebGL a text notice replaces it. `/mission` is in the axe sweep, and `web/e2e/mission.spec.ts` covers live streaming and reduced motion.
5. **three.js 0.186 (MIT) is the one new runtime dependency.** It loads with the page as a lazy chunk (about 145 kB gzipped), so the rest of the console is unchanged in size. It and its MIT transitive packages are in the SBOM and the licence report. The page needs no inline styles, so it works under the web image's Content Security Policy.
6. **The HUD theme is a stylesheet change across the console**: dark glass panels with corner brackets, glowing figures and badges, monospace labels. Selectors, markup and behaviour are unchanged. Text keeps at least 4.5:1 contrast on solid colours, and reduced motion still turns every animation off. This is not the APEX visual language; the console stays generic ("AISW Security Warden").

## Consequences
- The deferred "3D graphs" item is still deferred. This view carries no relationships and no reasoning; it presents existing records.
- Colours need `finding:read`. Without it every asset shows as clear, and the roster says that severity colours need the permission.
- Limits: the page loads at most 200 assets, 200 accepted findings and 500 events per run for the six newest runs. Larger estates are cut off without a notice; paging or a "showing N of M" note is a follow-up.
- While a run is in flight, the page polls its events every 2 s and the run list every 4 s. The live run timeline keeps using the event stream (server-sent events).
