import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { approvedManifest, launch, resume, seedProject, signIn, signOut, untilState } from './helpers.ts'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
const reviewer = (request: Parameters<typeof seedProject>[0], mode: 'dissent' | 'off') => request.post(`http://127.0.0.1:8099/__e2e/ai-reviewer/${mode}`)

test.afterEach(async ({ request }) => { await reviewer(request, 'off'); await resume(request) })

test('the assurance console queues an AI dissent beside the engine verdict until a human decides', async ({ page, request }) => {
  test.setTimeout(150_000)
  await reviewer(request, 'dissent')
  const { projectId } = await seedProject(request)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok', true)
  await untilState(request, runId, ['REPORT_READY'])
  await reviewer(request, 'off')
  const short = runId.slice(0, 8)

  await signIn(page, 'rita')
  await page.getByRole('link', { name: 'Assurance Console' }).click()
  await expect(page.getByRole('heading', { name: 'Assurance Console', level: 1 })).toBeVisible()
  const queue = page.getByTestId('disagreements')
  const row = queue.getByRole('row', { name: new RegExp(`run ${short}`) })
  await expect(row).toHaveCount(1)
  await expect(row.getByText('Pending review (not authoritative)')).toBeVisible()
  await expect(row.getByText('AI dissent: held for review')).toBeVisible()
  await expect(page.getByTestId('trigger-rules')).toContainText('severity_at_least=HIGH')
  await expect(page.getByText('Sample policy: awaiting policy-owner approval')).toBeVisible()
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])

  await row.getByRole('button', { name: 'Uphold' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('button', { name: 'Uphold' })).toBeDisabled()
  await dialog.getByLabel('Reason (required, recorded in the audit log)').fill('The observed value is ambiguous; keep it held.')
  await dialog.getByRole('button', { name: 'Uphold' }).click()
  await expect(queue.getByRole('row', { name: new RegExp(`run ${short}`) })).toHaveCount(0)
  await page.getByLabel('Resolved').check()
  await expect(queue.getByRole('row', { name: new RegExp(`run ${short}`) })).toContainText('by rita')
  await signOut(page)

  await signIn(page, 'carol') // report reader: may read the console, not the model-call ledger
  await expect(page.getByRole('link', { name: 'Assurance Console' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Model-call ledger' })).toHaveCount(0)
  await signOut(page)

  await signIn(page, 'erin')
  await page.getByRole('link', { name: 'Model-call ledger' }).click()
  await page.getByLabel('Purpose').selectOption('validation')
  await expect(page.getByTestId('model-calls')).toContainText('validation:agent-')
  await expect(page.getByTestId('model-call-totals')).toContainText('call(s)')
  await expect(page.getByRole('link', { name: 'Model-call ledger' })).toHaveAttribute('aria-current', 'page')
  await expect(page.getByRole('link', { name: 'Policy, Users & Audit' })).not.toHaveAttribute('aria-current', 'page')
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])
})
