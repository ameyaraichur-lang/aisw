import { defineConfig } from '@playwright/test'

// Uses the system Google Chrome (no browser download). The backend is an embedded-Postgres test
// server with the dev identity stub and a fixture adapter; nothing touches a real network target.
const WEB = 'http://127.0.0.1:5199'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1, // tenants are fixed by the dev identity stub and the task queue is shared
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  use: { baseURL: WEB, channel: 'chrome', headless: true, trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  webServer: [
    {
      command: 'cd ../backend && exec .venv/bin/python e2e/server.py',  // exec: SIGTERM reaches Python
      gracefulShutdown: { signal: 'SIGTERM', timeout: 15_000 },
      url: 'http://127.0.0.1:8099/healthz',
      timeout: 180_000,
      reuseExistingServer: false,
      stdout: 'ignore',
    },
    {
      command: 'npm run dev -- --port 5199 --strictPort --host 127.0.0.1',
      url: WEB,
      timeout: 60_000,
      reuseExistingServer: false,
      env: { AISW_API_URL: 'http://127.0.0.1:8099', VITE_STREAM_BACKOFF_MS: '300', VITE_POLL_MS: '600' },
    },
  ],
})
