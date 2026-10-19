import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { api, approvedManifest, json, launch, seedProject, signIn, signOut, untilState } from './helpers.ts'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
const itsm = (request: Parameters<typeof seedProject>[0], mode: 'jira' | 'off') => request.post(`http://127.0.0.1:8099/__e2e/itsm/${mode}`)

test.afterEach(async ({ request }) => { await itsm(request, 'off') })

test('a draft is previewed, refused to its author, and sent once by a second approver', async ({ page, request }) => {
  test.setTimeout(150_000)
  const { projectId } = await seedProject(request)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok')
  await untilState(request, runId, ['REPORT_READY'])
  await itsm(request, 'jira')
  const recs = await json<{ recommendation_id: string }[]>(await api(request, 'bob', 'get', `/assessments/${runId}/recommendations`))
  const rid = recs[0].recommendation_id
  await json(await api(request, 'bob', 'post', `/assessments/${runId}/recommendations/${rid}/decision`, { decision: 'ACCEPT', reason: 'approved for planning' }))
  const draft = await json<{ outbox_id: string }>(await api(request, 'bob', 'post', '/tickets/drafts', { run_id: runId, recommendation_id: rid }), 201)

  await signIn(page, 'bob')
  await page.getByRole('link', { name: 'Ticket Outbox' }).click()
  await expect(page.getByRole('heading', { name: 'Ticket Outbox', level: 1 })).toBeVisible()
  await expect(page.getByText('Delivery to Jira is on')).toBeVisible()
  await page.goto(`/tickets?run=${runId}`)
  await expect(page.getByText('1 draft(s), 0 sent')).toBeVisible()
  await expect(page.getByText('You drafted this ticket, so another approver sends it.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Send to Jira' })).toHaveCount(0)
  await signOut(page)

  await signIn(page, 'vic')
  await page.goto(`/tickets?run=${runId}`)
  await expect(page.getByText('Draft: not sent')).toBeVisible()
  await page.getByText('Ticket payload').click()
  const payload = page.getByTestId('ticket-payload')
  await expect(payload).toContainText(`aisw-${draft.outbox_id}`)
  await expect(payload).toContainText('"key": "SEC"')
  await page.getByLabel('Render for').selectOption('servicenow')
  await expect(payload).toContainText('"correlation_id"')
  await page.getByLabel('Render for').selectOption('')
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])

  await page.getByRole('button', { name: 'Send to Jira' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByText('It does not change any system AISW assessed.')).toBeVisible()
  await dialog.getByRole('button', { name: 'Send ticket' }).click()
  await expect(page.getByText(/Jira ticket SEC-\d+ sent by vic/)).toBeVisible()
  await expect(page.getByText('1 draft(s), 1 sent')).toBeVisible()
  await expect(page.getByRole('button', { name: /Send to Jira|Retry sending/ })).toHaveCount(0)
  await expect(page.getByLabel('Render for')).toBeDisabled() // a sent draft keeps its system
  await signOut(page)

  await signIn(page, 'carol') // report reader: reads the outbox, cannot send
  await page.goto(`/tickets?run=${runId}`)
  await expect(page.getByText(/Jira ticket SEC-\d+ sent by vic/)).toBeVisible()
})
