import { expect, test } from '@playwright/test'
import { approvedManifest, launch, seedProject, signIn, untilState } from './helpers.ts'

test('the Coverage Ledger names every gap and lists projects never assessed', async ({ page, request }) => {
  test.setTimeout(120_000)
  const idle = await seedProject(request, ['host-1'])
  const { projectId, name } = await seedProject(request, ['host-1', 'host-2', 'host-3', 'host-4'])
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-partial')
  await untilState(request, runId, ['PARTIAL'])

  await signIn(page, 'carol')
  await page.getByRole('link', { name: 'Coverage Ledger' }).click()
  await expect(page.getByRole('heading', { name: 'Coverage Ledger' })).toBeVisible()
  await expect(page.getByText(`${idle.name} (test): 1 inventory entry, no finished run`)).toBeVisible()

  const panel = page.getByRole('region', { name: new RegExp(`^${name}`) })
  await expect(panel.getByText('Incomplete').first()).toBeVisible()
  const gaps = panel.getByRole('list', { name: `Coverage gaps for ${name}` })
  await expect(gaps).toContainText('Expected but not found (1): host-4')
  await expect(gaps).toContainText('Unreachable (1): host-2 (connection timed out)')
  await expect(gaps).toContainText('No compatible collector (1): host-3')
  await expect(gaps).toContainText('Found but not in the inventory (owner unknown) (1): host-9')
  await panel.getByRole('link', { name: runId.slice(0, 8) }).click()
  await expect(page).toHaveURL(new RegExp(`/assessments/${runId}/coverage$`))

  await page.goBack()
  await page.getByLabel('Only show incomplete projects').check()
  await expect(page.getByRole('region', { name: new RegExp(`^${name}`) })).toBeVisible()
})
