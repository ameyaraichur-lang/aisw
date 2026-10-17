import { expect, test } from '@playwright/test'
import { json, signIn } from './helpers.ts'

const E2E = 'http://127.0.0.1:8099/__e2e'

test('an auditor sees that the audit chain is signed and confirmed by the external witness', async ({ page, request }) => {
  await signIn(page, 'erin')
  await json(await request.post(`${E2E}/anchor`))
  await page.goto('/audit')
  await expect(page.getByRole('status').filter({ hasText: 'Audit chain verified' })).toBeVisible()
  const anchored = page.getByRole('status').filter({ hasText: 'Audit chain anchored' })
  await expect(anchored).toContainText('confirmed by witness')
  await expect(anchored).toContainText('local-file-witness')
})
