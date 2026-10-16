import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { api, approvedManifest, json, launch, resume, seedProject, signIn, signOut, tab, untilState } from './helpers.ts'

test.afterEach(async ({ request }) => { await resume(request) })

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

async function finishedRun(request: Parameters<typeof seedProject>[0]) {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  const runId = await launch(request, projectId, m, 'baseline-ok')
  await untilState(request, runId, ['REPORT_READY'])
  return runId
}

test('risk is never invented, recommendations are drafts, and nothing is executable', async ({ page, request }) => {
  test.setTimeout(120_000)
  const runId = await finishedRun(request)
  const items = (await json(await api(request, 'alice', 'get', `/findings?run_id=${runId}`))).items as { finding_id: string; severity: string }[]
  const high = items.find((i) => i.severity === 'HIGH')!

  await signIn(page, 'alice')
  await page.goto(`/findings/${runId}/${high.finding_id}`)
  await expect(page.getByRole('heading', { name: 'Risk rubric' })).toBeVisible()
  await expect(page.getByText('Not rated: the inputs are incomplete, so no tier is invented.')).toBeVisible()
  await expect(page.getByText('Owner-supplied asset criticality is unknown')).toBeVisible()
  await expect(page.getByRole('complementary', { name: 'AI-written summary' })).toHaveCount(0)

  await page.goto(`/assessments/${runId}/analysis`)
  await expect(page.getByRole('heading', { name: 'Correlated scenarios' })).toBeVisible()
  await expect(page.getByText('Evidence chain (observed only)')).toBeVisible()
  await expect(page.getByText('Not rated').first()).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Draft recommendations' })).toBeVisible()
  await page.getByText('Details, validation and rollback').first().click()
  await expect(page.getByText('Unknown: only the owner can estimate this').first()).toBeVisible()
  await expect(page.getByRole('region', { name: 'Draft recommendations' }).getByRole('button')).toHaveCount(0) // nothing to click: no execute, apply or fix control
  await expect(page.getByRole('heading', { name: 'AI validation of agent outcomes' })).toBeVisible()
  await expect(page.getByText('No AI validation for this run')).toBeVisible() // AI is off in e2e: nothing is reviewed or labelled
  await expect(tab(page, 'Analysis')).toBeVisible()
})

test('timeline shows the analysis stages', async ({ page, request }) => {
  const runId = await finishedRun(request)
  await signIn(page, 'alice')
  await page.goto(`/assessments/${runId}/timeline`)
  await expect(page.getByText('Risk and correlation', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Architecture analysis', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Draft recommendations prepared; nothing was changed')).toBeVisible()
})

test('an approver records a decision with a reason; others can only read', async ({ page, request }) => {
  test.setTimeout(150_000)
  const runId = await finishedRun(request)

  await signIn(page, 'alice') // operator: no decision permission
  await page.goto(`/architecture?run=${runId}`)
  await expect(page.getByRole('heading', { name: 'Architecture & Modernization' })).toBeVisible()
  await expect(page.getByText('AI is disabled', { exact: false })).toBeVisible()
  await expect(page.getByText('Showing run')).toBeVisible()
  await expect(page.getByText('2 recommendation(s)')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Accept for planning' })).toHaveCount(0)
  await expect(page.getByText('needs the approver role').first()).toBeVisible()
  await signOut(page)

  await signIn(page, 'bob')
  await page.goto(`/architecture?run=${runId}`)
  const card = page.getByRole('region', { name: 'Harden host configuration to the approved baseline' })
  await expect(card).toBeVisible()
  await card.getByRole('button', { name: 'Accept for planning' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByText('It does not change any system.')).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Accept for planning' })).toBeDisabled() // reason required
  await dialog.getByLabel('Reason (required)').fill('Approved for the Q4 hardening plan')

  const axe = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  expect(axe.violations.map((v) => v.id), 'dialog open').toEqual([])

  await dialog.getByRole('button', { name: 'Accept for planning' }).click()
  await expect(card.getByText('Accepted for planning (nothing was changed)')).toBeVisible()
  await expect(card.getByText('Decided by bob')).toBeVisible()
  await expect(card.getByRole('button', { name: 'Accept for planning' })).toHaveCount(0)
  await expect(card.getByRole('button', { name: 'Create ticket draft' })).toHaveCount(0) // ticket drafts are off

  const recs = (await json(await api(request, 'bob', 'get', `/assessments/${runId}/recommendations`))) as { title: string; status: string; decided_by: string | null }[]
  expect(recs.find((r) => r.status === 'APPROVED_FOR_PLANNING')?.decided_by).toBe('bob')
  expect((await api(request, 'bob', 'post', '/tickets/drafts', { run_id: runId, recommendation_id: 'x' })).status()).toBe(403)

  const other = page.getByRole('region', { name: 'Enforce the identity and credential policy' })
  await other.getByRole('button', { name: 'Defer' }).click()
  await page.getByRole('dialog').getByLabel('Reason (required)').fill('Need the identity owner first')
  await page.getByRole('dialog').getByRole('button', { name: 'Defer' }).click()
  await expect(other.getByText('Deferred: needs owner input')).toBeVisible()
  await expect(other.getByRole('button', { name: 'Reject' })).toBeVisible() // a deferred item can still be decided
})
