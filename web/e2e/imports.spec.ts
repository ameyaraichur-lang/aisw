import { readFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'
import { api, json, manifestPayload, seedProject, signIn, untilState } from './helpers.ts'

const golden = (name: string) => readFileSync(new URL(`../../backend/tests/fixtures/golden/${name}`, import.meta.url))

test('import files are uploaded on the review step, and the CMDB runs before the scanner in one run', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const body = manifestPayload(projectId, {
    domains: ['inventory', 'network'], allowed_adapters: ['nmap_import', 'cmdb_import'], policy_version: 'import-baseline:1.0.0',
    profiles: { nmap_import: { profile_id: 'NMAP_BOUNDED_IMPORT', profile_class: 'READ_ONLY' }, cmdb_import: { profile_id: 'CMDB_IMPORT', profile_class: 'READ_ONLY' } },
  })
  const created = await json(await api(request, 'alice', 'post', '/scope-manifests', body), 201)
  const id = created.manifest.manifest_id as string
  await json(await api(request, 'alice', 'post', `/scope-manifests/${id}/preflight`))
  await json(await api(request, 'bob', 'post', `/scope-manifests/${id}/approve`, {}))

  await signIn(page, 'alice')
  await page.goto(`/assessments/new?manifest=${id}`)
  await expect(page.getByTestId('imports-missing')).toContainText('cmdb_import, nmap_import')
  await expect(page.getByRole('button', { name: 'Start Assessment' })).toBeDisabled()
  await expect(page.getByText('Inventory imports run first in this run')).toBeVisible()

  const cmdb = page.getByTestId('import-cmdb_import')
  await cmdb.getByLabel('Upload a new file').setInputFiles({ name: 'bad.csv', mimeType: 'text/csv', buffer: Buffer.from('a,b\u0000c') })
  await expect(cmdb.getByRole('alert')).toContainText('BINARY_CONTENT')
  await cmdb.getByLabel('Upload a new file').setInputFiles({ name: 'cmdb.csv', mimeType: 'text/csv', buffer: golden('cmdb.csv') })
  await expect(cmdb.getByRole('status')).toContainText('Uploaded cmdb.csv')
  await expect(cmdb.getByLabel('Uploaded file')).not.toHaveValue('')

  const nmap = page.getByTestId('import-nmap_import')
  await nmap.getByLabel('Upload a new file').setInputFiles({ name: 'nmap.xml', mimeType: 'application/xml', buffer: golden('nmap.xml') })
  await expect(nmap.getByRole('status')).toContainText('Uploaded nmap.xml')
  await expect(page.getByTestId('imports-missing')).toHaveCount(0)

  await page.getByRole('button', { name: 'Start Assessment' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Start Assessment' }).click()
  await page.waitForURL((u) => /^\/assessments\/[^/]+/.test(u.pathname) && !u.pathname.endsWith('/new'))
  const runId = new URL(page.url()).pathname.split('/')[2]
  await untilState(request, runId, ['REPORT_READY', 'PARTIAL'])

  const tasks = await json(await api(request, 'alice', 'get', `/assessments/${runId}/tasks`))
  const byAdapter = Object.fromEntries(tasks.map((t: any) => [t.agent_id, t]))
  expect(byAdapter.cmdb_import.status).toBe('SUCCEEDED')
  expect(['SUCCEEDED', 'PARTIAL']).toContain(byAdapter.nmap_import.status)
  const events = await json(await api(request, 'alice', 'get', `/assessments/${runId}/events?limit=500`))
  const started = events.events.filter((e: any) => e.type === 'task.started').map((e: any) => e.payload.agent_id)
  expect(started[0]).toBe('cmdb_import')
  const queued = events.events.find((e: any) => e.type === 'task.queued' && e.payload.agent_id === 'nmap_import')
  expect(queued.payload.dependencies).toEqual([byAdapter.cmdb_import.task_id])
})
