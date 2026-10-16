import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { api, approvedManifest, json, launch, resume, seedProject, signIn, signOut, untilState } from './helpers.ts'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
const reviewer = (request: Parameters<typeof seedProject>[0], mode: 'dissent' | 'off') => request.post(`http://127.0.0.1:8099/__e2e/ai-reviewer/${mode}`)

test.afterEach(async ({ request }) => { await reviewer(request, 'off'); await resume(request) })

test('a reviewer overrules an AI dissent with a reason and a new report revision replaces the old one', async ({ page, request }) => {
  test.setTimeout(150_000)
  await reviewer(request, 'dissent')
  const { projectId } = await seedProject(request)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok', true)
  await untilState(request, runId, ['REPORT_READY'])
  await reviewer(request, 'off')

  await signIn(page, 'alice') // operator: may read, may not decide
  await page.goto(`/assessments/${runId}/analysis`)
  const panel = page.getByRole('region', { name: 'AI validation of agent outcomes' })
  await expect(panel.getByText('Held for review', { exact: true })).toBeVisible()
  await expect(panel.getByText('Awaiting a reviewer')).toBeVisible()
  await expect(panel.getByRole('button', { name: 'Overrule' })).toHaveCount(0)
  await signOut(page)

  await signIn(page, 'rita')
  await page.goto(`/assessments/${runId}/analysis`)
  await panel.getByRole('button', { name: 'Overrule' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByText('a new report revision replaces the unapproved one')).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Overrule' })).toBeDisabled() // reason required
  await dialog.getByLabel('Reason (required, recorded in the audit log)').fill('Re-read the evidence: the check result stands.')
  const axe = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  expect(axe.violations.map((v) => v.id), 'dialog open').toEqual([])
  await dialog.getByRole('button', { name: 'Overrule' }).click()
  await expect(panel.getByText('by rita: Re-read the evidence: the check result stands.')).toBeVisible()

  await untilState(request, runId, ['REPORT_READY'])
  const reports = await json<{ revision: number; approval_state: string }[]>(await api(request, 'carol', 'get', `/assessments/${runId}/reports`))
  expect(reports.map((r) => [r.revision, r.approval_state])).toEqual([[2, 'PENDING'], [1, 'SUPERSEDED']])
  await page.goto(`/assessments/${runId}/report`)
  await expect(page.getByTestId('report-revision')).toContainText('Revision 2')
  await expect(page.getByRole('button', { name: 'Approve report' })).toBeVisible()
})
