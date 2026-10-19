import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { approvedManifest, launch, seedProject, signIn, untilState } from './helpers.ts'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

test('Mission Control shows the estate, streams new run events and keeps a text alternative to the 3D view', async ({ page, request }) => {
  test.setTimeout(150_000)
  const { projectId, name } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  const first = await launch(request, projectId, m, 'baseline-ok')
  await untilState(request, first, ['REPORT_READY'])

  await signIn(page, 'alice')
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Mission Control' }).click()
  await expect(page.getByRole('heading', { name: 'Mission Control', level: 1 })).toBeVisible()
  await expect(page.locator('.mc-scene canvas, .mc-scene__fallback:not([hidden])').first()).toBeAttached()
  if (await page.locator('.mc-scene canvas').count()) await expect(page.locator('.mc-scene canvas')).toHaveAttribute('aria-hidden', 'true')

  const log = page.getByRole('log', { name: /Recent run events/ })
  await expect(log.getByRole('link', { name })).not.toHaveCount(0)
  await expect(page.getByRole('heading', { name: new RegExp(`Pipeline.*${name}`) })).toBeVisible()
  await expect(page.locator('.mc-pipe__stage--succeeded').first()).toBeVisible()

  await page.getByText(/^Tracked assets/).click()
  const group = page.locator('.mc-roster > ul > li').filter({ has: page.getByText(name, { exact: true }) })
  await expect(group.locator('.mc-roster__nodes > li')).toHaveCount(3)
  await expect(group).toContainText(/db-01 \(host; High finding/)
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])

  // events of a run started while the page is open arrive in the stream (capped at the newest 60) and are marked as new
  const second = await launch(request, projectId, m, 'baseline-ok')
  await expect(page.locator('.mc-ev--fresh').first()).toBeVisible({ timeout: 30_000 })
  await untilState(request, second, ['REPORT_READY'])
  await expect(log.locator(`a[href="/assessments/${second}/timeline"]`).first()).toBeVisible({ timeout: 15_000 })
  await expect(page.getByRole('link', { name: new RegExp(`run ${second.slice(0, 8)}`) })).toBeVisible({ timeout: 15_000 })
})

test('Mission Control reads a long run to its newest event and says when the estate is larger than it shows', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok')
  await untilState(request, runId, ['REPORT_READY'])

  // Synthetic responses: the fixture adapter cannot produce 1,200 events or a 1,000-asset estate.
  const TOTAL = 1200
  const seen: number[] = []
  await page.route(`**/api/v1/assessments/${runId}/events?*`, (route) => {
    const u = new URL(route.request().url())
    const cursor = Number(u.searchParams.get('cursor') ?? 0)
    const limit = Number(u.searchParams.get('limit') ?? 100)
    seen.push(cursor)
    const events = Array.from({ length: Math.max(0, Math.min(limit, TOTAL - cursor)) }, (_, i) => {
      const seq = cursor + i + 1
      return {
        seq, event_id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`,
        type: seq === TOTAL ? 'report.ready' : 'task.progress', payload: { note: `step ${seq}` },
        occurred_at: new Date(Date.UTC(2030, 0, 1) + seq * 1000).toISOString(),
      }
    })
    return route.fulfill({ json: { events, next_cursor: events.at(-1)?.seq ?? cursor } })
  })
  await page.route('**/api/v1/assets?*', async (route) => {
    const res = await route.fetch()
    const body = await res.json()
    return route.fulfill({ response: res, json: { ...body, total: body.items.length + 1000 } })
  })

  await signIn(page, 'alice')
  await page.goto('/mission')
  const log = page.getByRole('log', { name: /Recent run events/ })
  await expect(log.getByRole('listitem').first()).toContainText('Report ready')
  await expect(log).toContainText('step 1199')
  expect(seen.slice(0, 3)).toEqual([0, 500, 1000])
  await expect(page.getByTestId('mission-truncation')).toContainText(/Showing \d+ of [\d,]+ tracked assets/)
  await expect(page.getByTestId('mission-truncation').getByRole('link', { name: /Asset Explorer/ })).toBeVisible()
})

test('Mission Control under reduced motion offers no replay animation', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const run = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok')
  await untilState(request, run, ['REPORT_READY'])
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await signIn(page, 'alice')
  await page.goto('/mission')
  await expect(page.getByRole('heading', { name: 'Mission Control', level: 1 })).toBeVisible()
  await expect(page.getByRole('log', { name: /Recent run events/ }).getByRole('listitem').first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Replay last run' })).toHaveCount(0)
})
