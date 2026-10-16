import { expect, test, type Page } from '@playwright/test'
import { api, approvedManifest, json, launch, resume, seedProject, signIn, signOut, untilState } from '../e2e/helpers.ts'

const OUT = '../docs/screenshots'
const shot = async (page: Page, name: string, full = false) => {
  await page.waitForTimeout(400) // let focus rings and SSE settle
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: full })
}

test.afterEach(async ({ request }) => { await resume(request) })

test('capture README screenshots', async ({ page, request }) => {
  // synthetic data only: a clean run and a partial run, then one decision and one report approval
  const a = await seedProject(request, ['host-1', 'host-2', 'host-3', 'host-4'])
  const ma = await approvedManifest(request, a.projectId)
  const partial = await launch(request, a.projectId, ma, 'baseline-partial')
  await untilState(request, partial, ['PARTIAL'])
  const b = await seedProject(request, ['host-1', 'host-2', 'host-3'])
  const mb = await approvedManifest(request, b.projectId)
  const ok = await launch(request, b.projectId, mb, 'baseline-ok')
  await untilState(request, ok, ['REPORT_READY'])
  const recs = (await json(await api(request, 'bob', 'get', `/assessments/${ok}/recommendations`))) as { recommendation_id: string; title: string }[]
  await json(await api(request, 'bob', 'post', `/assessments/${ok}/recommendations/${recs[0].recommendation_id}/decision`, { decision: 'ACCEPT', reason: 'Approved for the Q4 hardening plan' }))
  const items = (await json(await api(request, 'alice', 'get', `/findings?run_id=${ok}`))).items as { finding_id: string; severity: string }[]
  const high = items.find((i) => i.severity === 'HIGH')!

  await page.goto('/')
  await shot(page, '01-sign-in')

  await signIn(page, 'alice')
  await page.goto('/')
  await expect(page.locator('main h1')).toBeVisible()
  await shot(page, '02-command-center', true)

  await page.goto('/projects'); await expect(page.locator('main h1')).toBeVisible(); await shot(page, '03-projects')
  await page.goto('/assessments/new'); await expect(page.locator('main h1')).toBeVisible(); await shot(page, '04-new-assessment-wizard')
  await page.goto(`/assessments/${ok}/timeline`); await expect(page.getByText('Architecture analysis', { exact: true }).first()).toBeVisible(); await shot(page, '05-run-timeline', true)
  await page.goto(`/assessments/${partial}/coverage`); await expect(page.locator('main h1')).toBeVisible(); await shot(page, '06-coverage-partial-run', true)
  await page.goto('/findings'); await expect(page.locator('main h1')).toBeVisible(); await shot(page, '07-findings')
  await page.goto(`/findings/${ok}/${high.finding_id}`); await expect(page.getByRole('heading', { name: 'Risk rubric' })).toBeVisible(); await shot(page, '08-finding-detail-risk-not-invented', true)
  await page.goto(`/assessments/${ok}/analysis`); await expect(page.getByRole('heading', { name: 'Correlated scenarios' })).toBeVisible(); await shot(page, '09-scenarios-and-recommendations', true)
  await signOut(page)

  await signIn(page, 'bob')
  await page.goto(`/architecture?run=${ok}`); await expect(page.getByText('2 recommendation(s)')).toBeVisible()
  await shot(page, '10-architecture-workbench', true)
  await page.getByRole('button', { name: 'Defer' }).first().click()
  await page.getByRole('dialog').getByLabel('Reason (required)').fill('Need the identity owner first')
  await shot(page, '11-decision-dialog')
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click()
  await signOut(page)

  await signIn(page, 'rita')
  await page.goto(`/assessments/${ok}/report`); await expect(page.locator('main h1')).toBeVisible(); await shot(page, '12-report-awaiting-review')
  await page.getByRole('button', { name: 'Preview HTML report' }).click()
  await expect(page.frameLocator('iframe').getByText('DRAFT: this report has not been approved')).toBeVisible()
  await shot(page, '13-report-preview-draft-watermark', true)
  await signOut(page)

  await signIn(page, 'erin')
  await page.goto('/audit'); await expect(page.locator('main h1')).toBeVisible(); await shot(page, '14-audit-trail')
})
