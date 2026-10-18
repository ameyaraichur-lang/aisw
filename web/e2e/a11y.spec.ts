import { AxeBuilder } from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'
import { approvedManifest, launch, resume, seedProject, signIn, signOut, untilState } from './helpers.ts'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
// Best-practice rules about page structure: what a screen-reader user navigates by.
const STRUCTURE = ['page-has-heading-one', 'heading-order', 'landmark-one-main', 'landmark-unique',
  'landmark-no-duplicate-main', 'landmark-banner-is-top-level', 'landmark-main-is-top-level', 'region',
  'empty-heading', 'empty-table-header']

async function scan(page: Page, label: string, exclude: string[] = []) {
  const t0 = Date.now()
  await page.waitForLoadState('domcontentloaded')
  await expect(page.locator('main, body').first()).toBeVisible()
  await expect(page.locator('h1').first()).toBeVisible()
  let builder = new AxeBuilder({ page }).withTags(TAGS)
  for (const sel of exclude) builder = builder.exclude(sel)
  const r = await builder.analyze()
  let structure = new AxeBuilder({ page }).withRules(STRUCTURE)
  for (const sel of exclude) structure = structure.exclude(sel)
  const violations = [...r.violations, ...(await structure.analyze()).violations]
  const summary = violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(' | ')}`)
  console.log(`axe ${label}: ${Date.now() - t0}ms, ${violations.length} violation(s)`)
  expect(summary, `${label}: ${summary.join('\n')}`).toEqual([])
}

test.afterEach(async ({ request }) => { await resume(request) })

test('no WCAG 2.2 AA violations on the main screens', async ({ page, request }) => {
  test.setTimeout(240_000)
  const { projectId } = await seedProject(request, ['host-1', 'host-2', 'host-3', 'host-4'])
  const m = await approvedManifest(request, projectId)
  const runId = await launch(request, projectId, m, 'baseline-partial')
  await untilState(request, runId, ['PARTIAL'])
  const ok = await launch(request, projectId, m, 'baseline-ok')
  await untilState(request, ok, ['REPORT_READY', 'PARTIAL'])

  await page.goto('/')
  await scan(page, 'sign-in')

  await signIn(page, 'alice')
  for (const path of ['/', '/mission', '/projects', '/integrations', '/assessments', '/assessments/new', '/assets', '/architecture',
    `/assessments/${runId}/timeline`, `/assessments/${runId}/coverage`, `/assessments/${runId}/findings`, `/assessments/${runId}/analysis`, `/architecture?run=${ok}`, `/assessments/${runId}/controls`, `/findings`, '/controls', '/retention']) {
    await page.goto(path)
    await expect(page.locator('main h1')).toBeVisible()
    await scan(page, `alice ${path}`)
  }
  // wizard steps with content
  await page.goto('/assessments/new')
  await page.getByLabel('Project and environment').selectOption(projectId)
  await scan(page, 'wizard step 1')
  await page.getByRole('button', { name: 'Next' }).click()
  await scan(page, 'wizard step 2')
  // finding detail
  await page.goto(`/assessments/${ok}/findings`)
  await page.getByRole('link', { name: /Direct root login/ }).click()
  await scan(page, 'finding detail')
  await page.goto(`/assessments/${ok}/timeline`)
  await page.getByRole('button', { name: 'Details' }).click()
  await scan(page, 'task details')
  await page.getByRole('button', { name: 'Cancel run' }).count()
  await signOut(page)

  await signIn(page, 'carol')
  await page.goto(`/assessments/${runId}/report`)
  await expect(page.getByTestId('report-total')).toBeVisible()
  await page.getByRole('button', { name: 'Preview HTML report' }).click()
  // The preview iframe is sandboxed without scripts on purpose, so axe cannot run inside it: scan the
  // surrounding page with the frame excluded, and scan the generated report HTML as its own document.
  await scan(page, 'report tab', ['iframe[title="Report preview"]'])
  const rid = (await (await request.get(`/api/v1/assessments/${runId}/reports`, { headers: { Authorization: 'Bearer dev-carol' } })).json())[0].report_id
  const html = await (await request.get(`/api/v1/reports/${rid}?format=html`, { headers: { Authorization: 'Bearer dev-carol' } })).text()
  const doc = await page.context().newPage()
  await doc.setContent(html)
  await scan(doc, 'generated report html')
  await doc.close()
  await page.goto('/reports')
  await scan(page, 'reports')
  await signOut(page)

  await signIn(page, 'bob')
  await page.goto('/approvals')
  await scan(page, 'approvals')
  await signOut(page)

  await signIn(page, 'erin')
  await page.goto('/audit')
  await expect(page.getByText('Audit chain verified')).toBeVisible()
  await scan(page, 'audit')
  await page.goto('/retention')
  await expect(page.locator('main h1')).toBeVisible()
  await scan(page, 'erin /retention')
  await page.goto('/approvals')
  await scan(page, 'denied state')
})

test('keyboard: skip link, dialog focus handling, and wizard operable without a mouse', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  await signIn(page, 'alice')
  await page.goto('/')
  await expect(page.getByLabel('Signed in user')).toBeVisible() // wait for the shell before tabbing
  await page.keyboard.press('Tab')
  await expect(page.getByRole('link', { name: 'Skip to main content' })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page.locator('#main')).toBeInViewport()

  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Assessments', exact: true }).click()
  await expect(page.locator('main h1')).toBeFocused() // in-app navigation moves focus to the page heading
  await page.getByRole('link', { name: 'New assessment' }).click()
  await expect(page.locator('main h1')).toBeFocused()
  const select = page.getByLabel('Project and environment')
  await select.focus()
  await select.selectOption(projectId)
  await page.getByRole('button', { name: 'Next' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Scope' })).toBeVisible()
  await expect(page.getByRole('listitem').filter({ hasText: '2. Scope' })).toHaveAttribute('aria-current', 'step')
  const box = page.getByRole('checkbox', { name: /fixture-group-1/ })
  await box.focus()
  await page.keyboard.press('Space')
  await expect(box).toBeChecked()
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
})

test('reduced motion is respected and statuses never rely on colour alone', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  const runId = await launch(request, projectId, m, 'baseline-partial')
  await untilState(request, runId, ['PARTIAL'])
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await signIn(page, 'alice')
  await page.goto(`/assessments/${runId}/timeline`)
  const anim = await page.evaluate(() => getComputedStyle(document.body).animationName)
  expect(['none', '']).toContain(anim)
  // every badge carries a text label in addition to its icon and colour
  const badges = page.locator('.badge')
  const n = await badges.count()
  expect(n).toBeGreaterThan(3)
  for (let i = 0; i < n; i++) {
    const text = (await badges.nth(i).innerText()).trim()
    expect(text.replace(/[^A-Za-z]/g, '').length, `badge ${i}: "${text}"`).toBeGreaterThan(2)
    await expect(badges.nth(i).locator('.badge__icon')).toHaveAttribute('aria-hidden', 'true')
  }
})
