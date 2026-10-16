import { defineConfig } from '@playwright/test'
import base from './playwright.config.ts'

// Captures the README screenshots from a seeded, synthetic run. Not part of the test suite:
//   cd web && npx playwright test -c playwright.docs.config.ts
export default defineConfig({
  ...base,
  testDir: './docs',
  testMatch: '*.shots.ts',
  timeout: 240_000,
  use: { ...base.use, viewport: { width: 1360, height: 860 }, trace: 'off', screenshot: 'off' },
})
