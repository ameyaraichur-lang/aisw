import { readFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'
import { api, json, manifestPayload, seedProject, signIn, tab, untilState } from './helpers.ts'

const golden = (name: string) => readFileSync(new URL(`../../backend/tests/fixtures/golden/${name}`, import.meta.url))
const PROFILES = {
  cmdb_import: { profile_id: 'CMDB_IMPORT', profile_class: 'READ_ONLY' },
  greenbone_import: { profile_id: 'GREENBONE_REPORT_IMPORT', profile_class: 'READ_ONLY' },
  nmap_import: { profile_id: 'NMAP_BOUNDED_IMPORT', profile_class: 'READ_ONLY' },
}

test('a scan declared as run from outside the estate verifies exposure and builds routes to vulnerable hosts', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const body = manifestPayload(projectId, {
    domains: ['host', 'inventory', 'network'], allowed_adapters: Object.keys(PROFILES), policy_version: 'import-baseline:1.0.0', profiles: PROFILES,
  })
  const created = await json(await api(request, 'alice', 'post', '/scope-manifests', body), 201)
  const id = created.manifest.manifest_id as string
  await json(await api(request, 'alice', 'post', `/scope-manifests/${id}/preflight`))
  await json(await api(request, 'bob', 'post', `/scope-manifests/${id}/approve`, {}))

  await signIn(page, 'alice')
  await page.goto(`/assessments/new?manifest=${id}`)
  for (const [adapter, file, mime] of [['cmdb_import', 'cmdb.csv', 'text/csv'], ['greenbone_import', 'greenbone.xml', 'application/xml'], ['nmap_import', 'nmap.xml', 'application/xml']]) {
    const box = page.getByTestId(`import-${adapter}`)
    await box.getByLabel('Upload a new file').setInputFiles({ name: file, mimeType: mime, buffer: golden(file) })
    await expect(box.getByRole('status')).toContainText(`Uploaded ${file}`)
  }
  await expect(page.getByTestId('import-cmdb_import').getByLabel('Where the scan ran from')).toHaveCount(0)
  await page.getByTestId('import-nmap_import').getByLabel('Where the scan ran from').selectOption('untrusted')
  await page.getByRole('button', { name: 'Start Assessment' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Start Assessment' }).click()
  await page.waitForURL((u) => /^\/assessments\/[^/]+/.test(u.pathname) && !u.pathname.endsWith('/new'))
  const runId = new URL(page.url()).pathname.split('/')[2]
  await untilState(request, runId, ['REPORT_READY', 'PARTIAL'])

  const tasks = await json(await api(request, 'alice', 'get', `/assessments/${runId}/tasks`))
  expect(tasks.find((t: any) => t.agent_id === 'nmap_import')).toBeTruthy()

  await tab(page, 'Analysis').click()
  const edges = page.getByRole('table', { name: 'Reachability edges' })
  await expect(edges.getByRole('row').filter({ hasText: 'host-1' })).toContainText('port 22, 443')
  await expect(edges.getByRole('row').filter({ hasText: 'host-1' })).toContainText('exposure verified')
  await expect(edges.getByRole('row').filter({ hasText: 'host-1' })).toContainText('observed')
  const route = page.getByRole('heading', { name: /host-1 is reachable from the internet in 1 hop/ })
  await expect(route).toBeVisible()
  await expect(page.getByRole('list', { name: 'Route to host-1' })).toContainText('scan declared as run from an untrusted network')
})
