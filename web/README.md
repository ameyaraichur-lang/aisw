# AISW web console

React + TypeScript + Vite. It talks only to the platform API (proxied at `/api`), never to scanners, the database or a model.

```bash
npm install
npm run dev          # AISW_API_URL=http://127.0.0.1:8000 by default
npm run lint && npm run check:types && npm run typecheck && npm test && npm run build
npm run e2e          # Playwright + axe; starts an embedded-Postgres test server and Vite; uses system Chrome
npm run gen:types    # regenerate src/api/contracts.d.ts from ../schemas (CI fails on drift)
```

Notes: `src/api/contracts.d.ts` is generated; the dev sign-in picker exists only when the server runs the dev identity stub (never in prod).
