import { expect, test } from '@playwright/test'
import { approvedManifest, launch, pause, resume, seedProject, signIn } from './helpers.ts'

test.afterEach(async ({ request }) => { await resume(request) })

async function eventSeqs(page: import('@playwright/test').Page): Promise<number[]> {
  const items = await page.getByTestId('event-log').locator('li').allTextContents()
  return items.map((t) => Number(/^#(\d+)/.exec(t)?.[1]))
}

test('reload restores the run from the durable log without duplicates, and live updates resume', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  await pause(request)
  const runId = await launch(request, projectId, m)
  await signIn(page, 'alice')
  await page.goto(`/assessments/${runId}/timeline`)

  await expect(page.getByTestId('stage-collection')).toHaveAttribute('data-status', 'running')
  await expect(page.getByTestId('stage-collection')).toContainText('0 of 1 task(s) finished')
  await expect(page.getByTestId('stage-report')).toHaveAttribute('data-status', 'pending')
  await expect(page.getByTestId('stream-status')).toContainText('Live')
  const before = await eventSeqs(page)
  expect(before.length).toBeGreaterThan(2)

  await page.reload()
  await expect(page.getByTestId('stage-collection')).toHaveAttribute('data-status', 'running')
  await expect(page.getByTestId('stream-status')).toContainText('Live')
  expect(await eventSeqs(page)).toEqual(before) // same events, same order, no duplicates

  await resume(request)
  await expect(page.getByTestId('stage-report')).toHaveAttribute('data-status', 'succeeded', { timeout: 40_000 })
  const after = await eventSeqs(page)
  expect(after.slice(0, before.length)).toEqual(before)
  expect(new Set(after).size).toBe(after.length)
  expect(after).toEqual(after.map((_, i) => i + 1)) // contiguous: nothing missed
})

test('connection loss shows a stale banner and recovery resumes from the cursor', async ({ page, request, context }) => {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  await pause(request)
  const runId = await launch(request, projectId, m)
  await signIn(page, 'alice')
  await page.goto(`/assessments/${runId}/timeline`)
  await expect(page.getByTestId('stream-status')).toContainText('Live')
  const before = await eventSeqs(page)

  await context.setOffline(true)
  await expect(page.getByRole('alert').filter({ hasText: 'Live updates interrupted' })).toBeVisible()
  await expect(page.getByRole('alert').filter({ hasText: 'Live updates interrupted' })).toContainText('Showing the last known state')
  await resume(request) // the server makes progress while the browser is offline
  await expect(page.getByTestId('stage-report')).not.toHaveAttribute('data-status', 'succeeded')

  await context.setOffline(false)
  await expect(page.getByRole('alert').filter({ hasText: 'Live updates interrupted' })).toHaveCount(0, { timeout: 20_000 })
  await expect(page.getByTestId('stage-report')).toHaveAttribute('data-status', 'succeeded', { timeout: 40_000 })
  const after = await eventSeqs(page)
  expect(after.slice(0, before.length)).toEqual(before)
  expect(new Set(after).size).toBe(after.length)
  expect(after).toEqual(after.map((_, i) => i + 1))
})

test('when streaming is blocked the page falls back to polling and still completes', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  await pause(request)
  const runId = await launch(request, projectId, m)
  await page.route('**/events/stream**', (route) => route.abort())
  await signIn(page, 'alice')
  await page.goto(`/assessments/${runId}/timeline`)
  await expect(page.getByText('Live stream unavailable')).toBeVisible({ timeout: 20_000 })
  await resume(request)
  await expect(page.getByTestId('stage-report')).toHaveAttribute('data-status', 'succeeded', { timeout: 40_000 })
  const seqs = await eventSeqs(page)
  expect(seqs).toEqual(seqs.map((_, i) => i + 1))
})

test('cancelling shows the request, then the cancelled state; nothing ran', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  await pause(request)
  const runId = await launch(request, projectId, m)
  await signIn(page, 'alice')
  await page.goto(`/assessments/${runId}/timeline`)
  await page.getByRole('button', { name: 'Cancel run' }).click()
  await page.keyboard.press('Escape') // Esc closes the dialog without cancelling
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByText('Cancellation requested')).toHaveCount(0)
  await page.getByRole('button', { name: 'Cancel run' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel run' }).click()
  await expect(page.getByText('Cancellation requested')).toBeVisible()
  await resume(request)
  await expect(page.getByRole('status').filter({ hasText: 'Run cancelled' })).toBeVisible({ timeout: 30_000 })
  await expect(page.getByTestId('stage-collection')).toHaveAttribute('data-status', 'cancelled')
  await expect(page.getByTestId('event-log')).toContainText('Assessment cancelled')
})
