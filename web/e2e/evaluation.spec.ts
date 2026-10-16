import { expect, test } from '@playwright/test'
import { api, approvedManifest, json, launch, seedProject, signIn, untilState } from './helpers.ts'

test('the Maple Trust estate is scored against its answer key in the Evaluation Lab', async ({ page, request }) => {
  test.setTimeout(120_000)
  const [key] = await json(await api(request, 'carol', 'get', '/evaluation/answer-keys'))
  expect(key.key_id).toBe('maple-trust-1.0.0')
  const { projectId } = await seedProject(request, key.cmdb_expected_assets)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'maple-trust')
  await untilState(request, runId, ['PARTIAL', 'REPORT_READY'])

  await signIn(page, 'carol')
  await page.getByRole('link', { name: 'Evaluation Lab' }).click()
  await expect(page.getByRole('heading', { name: 'Evaluation Lab' })).toBeVisible()
  await expect(page.getByText('18 known issues and 145 known-clean checks over 60 CMDB assets.')).toBeVisible()
  await page.getByLabel('Fixture set').selectOption('maple-trust')
  const trend = page.getByTestId('evaluation-trend')
  await trend.getByRole('button', { name: `Show scorecard for run ${runId.slice(0, 8)}` }).click()
  await expect(page).toHaveURL(new RegExp(`run=${runId}`))

  const card = page.getByTestId('scorecard')
  const row = (name: string) => card.getByRole('row').filter({ has: page.getByRole('rowheader', { name, exact: true }) })
  await expect(row('Asset reconciliation')).toContainText('62 of 62 (100.0%)')
  await expect(row('Asset reconciliation')).toContainText('Target met')
  await expect(row('Known-issue detection: recall')).toContainText('15 of 18 (83.3%)')
  await expect(row('Known-issue detection: recall')).toContainText('mt-legacy-02: ASSET_UNREACHABLE')
  await expect(row('Known-issue detection: precision')).toContainText('False positive: password.min_length on mt-win-07')
  await expect(row('Finding traceability')).toContainText('16 of 16 (100.0%)')
  await expect(row('Unsupported compliance claims')).toContainText('Target met')
  await expect(row('Astra validator catch-rate (seeded bad outcomes)')).toContainText('Not measured')
  await expect(page.getByTestId('scorecard-summary')).toContainText('0 not met')
})
