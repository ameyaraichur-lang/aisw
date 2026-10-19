import { lazy, Suspense } from 'react'
import { Route, Routes } from 'react-router-dom'
import { RequirePermission } from './components/Guard'
import { Shell } from './components/Shell'
import { useSession } from './auth/useSession'
import { Assessments } from './pages/Assessments'
import { Approvals } from './pages/Approvals'
import { AssetDetailPage, Assets } from './pages/Assets'
import { AssuranceConsole, ModelCallsPage } from './pages/Assurance'
import { CommandCenter } from './pages/CommandCenter'
import { FindingDetail, Findings } from './pages/Findings'
import { Integrations } from './pages/Integrations'
import { ControlMatrix } from './pages/Controls'
import { Exceptions } from './pages/Exceptions'
import { Login } from './pages/Login'
import { Architecture } from './pages/Architecture'
import { AuditPage, NotImplemented, ReportsPage } from './pages/Misc'
import { RetentionPage } from './pages/Retention'
import { Projects } from './pages/Projects'
import { Roadmap } from './pages/Roadmap'
import { RunPage } from './pages/RunDetail'
import { TicketOutbox } from './pages/Tickets'
import { EvaluationLab } from './pages/Evaluation'
import { CoverageLedgerPage } from './pages/Coverage'
import { Wizard } from './pages/Wizard'

const MissionControl = lazy(() => import('./pages/MissionControl').then((m) => ({ default: m.MissionControl })))

export default function App() {
  const { status } = useSession()
  if (status === 'loading') return <p role="status" style={{ padding: '2rem' }}>Loading session…</p>
  if (status === 'anonymous') return <Login />
  if (status === 'error')
    return <main className="main" id="main"><h1>Cannot reach the platform API</h1><p>Check that the server is running, then reload.</p></main>
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<CommandCenter />} />
        <Route path="mission" element={<Suspense fallback={<p role="status">Loading Mission Control…</p>}><MissionControl /></Suspense>} />
        <Route path="projects" element={<Projects />} />
        <Route path="integrations" element={<Integrations />} />
        <Route path="assessments" element={<Assessments />} />
        <Route path="assessments/new" element={<RequirePermission need={['manifest:create', 'assessment:launch']} title="New assessment"><Wizard /></RequirePermission>} />
        <Route path="assessments/:runId/*" element={<RunPage />} />
        <Route path="approvals" element={<RequirePermission need={['manifest:approve']} title="Pending approvals"><Approvals /></RequirePermission>} />
        <Route path="findings" element={<RequirePermission need={['finding:read']} title="Findings & Exposure"><Findings /></RequirePermission>} />
        <Route path="findings/:runId/:findingId" element={<FindingDetail />} />
        <Route path="controls" element={<ControlMatrix />} />
        <Route path="exceptions" element={<RequirePermission need={['finding:read']} title="Exceptions"><Exceptions /></RequirePermission>} />
        <Route path="reports" element={<RequirePermission need={['report:read']} title="Reports & Evidence"><ReportsPage /></RequirePermission>} />
        <Route path="assurance" element={<RequirePermission need={['finding:read']} title="Assurance Console"><AssuranceConsole /></RequirePermission>} />
        <Route path="audit/model-calls" element={<RequirePermission need={['audit:read']} title="Model-call ledger"><ModelCallsPage /></RequirePermission>} />
        <Route path="retention" element={<RequirePermission need={['retention:manage', 'audit:read']} title="Evidence Retention"><RetentionPage /></RequirePermission>} />
        <Route path="audit" element={<RequirePermission need={['audit:read']} title="Policy, Users & Audit"><AuditPage /></RequirePermission>} />
        <Route path="assets" element={<Assets />} />
        <Route path="assets/:projectId/:assetId" element={<AssetDetailPage />} />
        <Route path="roadmap" element={<RequirePermission need={['finding:read']} title="Modernization Roadmap"><Roadmap /></RequirePermission>} />
        <Route path="tickets" element={<RequirePermission need={['finding:read']} title="Ticket Outbox"><TicketOutbox /></RequirePermission>} />
        <Route path="evaluation" element={<RequirePermission need={['finding:read']} title="Evaluation Lab"><EvaluationLab /></RequirePermission>} />
        <Route path="coverage" element={<CoverageLedgerPage />} />
        <Route path="architecture" element={<RequirePermission need={['finding:read']} title="Architecture & Modernization"><Architecture /></RequirePermission>} />
        <Route path="*" element={<NotImplemented title="Page not found" milestone="n/a" why="This route does not exist." />} />
      </Route>
    </Routes>
  )
}
