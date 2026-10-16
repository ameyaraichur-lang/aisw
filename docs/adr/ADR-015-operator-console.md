# ADR-015: Operator console (M4)

**Status:** Accepted (M4)

## Decision
1. **React + TypeScript + Vite, hand-written accessible components** (native `<dialog>`, real tables with captions, landmarks, skip link). No UI kit dependency; TanStack Query for server state, React Router for routes. Types for wire contracts are **generated from the backend JSON Schemas** (`npm run check:types` fails CI on drift).
2. **Live updates = fetch-based SSE** (not `EventSource`) so the identity header is sent and no token ever appears in a URL. The persisted log is authoritative: the client resumes from the last cursor (`Last-Event-ID`), dedupes by `event_id`, re-reads the status snapshot after every reconnect, reacts to the browser's offline/online events, and falls back to cursor polling after 3 failed stream attempts. The server rotates a stream every 5 minutes and ends it once the run is in a no-more-work state and the log is drained.
3. **Stage rows are derived purely from persisted events** (`deriveStages`); progress is only ever "n of m tasks finished". Nothing is simulated and no reasoning is displayed.
4. **UI permission checks are courtesy only.** Nav items and route guards reflect the role, but every API call is authorised server-side; e2e tests assert both the UI denial and the direct API 403/404.
5. **Report preview** is a sandboxed iframe (no scripts) of server-generated, fully escaped HTML that also carries its own CSP. Downloads go through authenticated fetches.
6. **Dev identity** token is a seeded, non-secret name kept in `sessionStorage` and exists only when the server runs the dev stub. Production sign-in is OIDC through the BFF with an httpOnly cookie (planned, not built).
7. **E2E** runs Playwright against an embedded-Postgres server with the fixture adapter, using the system Chrome (`channel: chrome`), plus axe (WCAG 2.2 AA tags) on every main screen.

## Known limitations
No silent-stall watchdog on a stream that stays open but receives nothing (relies on TCP/browser errors, offline events and the server's 5-minute rotation); only the fixture adapter exists, so no real connector UI beyond the capability matrix; review actions on findings, exceptions, the asset graph, and architecture workbench are not built (marked Planned in the UI); light theme not provided; mobile layout is functional but only desktop-width was verified.
