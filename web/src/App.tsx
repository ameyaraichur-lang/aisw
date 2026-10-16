import { Route, Routes } from 'react-router-dom'
import { RequirePermission } from './components/Guard'
import { Shell } from './components/Shell'
import { useSession } from './auth/useSession'
import { Assessments } from './pages/Assessments'
import { Approvals } from './pages/Approvals'
import { CommandCenter } from './pages/CommandCenter'
import { ControlCoverage, FindingDetail, Findings } from './pages/Findings'
import { Integrations } from './pages/Integrations'
import { Login } from './pages/Login'
import { AuditPage, NotImplemented, ReportsPage } from './pages/Misc'
import { Projects } from './pages/Projects'
import { RunPage } from './pages/RunDetail'
import { Wizard } from './pages/Wizard'

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
        <Route path="projects" element={<Projects />} />
        <Route path="integrations" element={<Integrations />} />
        <Route path="assessments" element={<Assessments />} />
        <Route path="assessments/new" element={<RequirePermission need={['manifest:create', 'assessment:launch']} title="New assessment"><Wizard /></RequirePermission>} />
        <Route path="assessments/:runId/*" element={<RunPage />} />
        <Route path="approvals" element={<RequirePermission need={['manifest:approve']} title="Pending approvals"><Approvals /></RequirePermission>} />
        <Route path="findings" element={<RequirePermission need={['finding:read']} title="Findings & Exposure"><Findings /></RequirePermission>} />
        <Route path="findings/:runId/:findingId" element={<FindingDetail />} />
        <Route path="controls" element={<ControlCoverage />} />
        <Route path="reports" element={<RequirePermission need={['report:read']} title="Reports & Evidence"><ReportsPage /></RequirePermission>} />
        <Route path="audit" element={<RequirePermission need={['audit:read']} title="Policy, Users & Audit"><AuditPage /></RequirePermission>} />
        <Route path="assets" element={<NotImplemented title="Asset Explorer" milestone="M6" why="Asset reconciliation and the relationship explorer arrive with the discovery and adapter milestone." />} />
        <Route path="architecture" element={<NotImplemented title="Architecture & Modernization" milestone="M7" why="Recommendations require the bounded analysis agents and independent assurance." />} />
        <Route path="*" element={<NotImplemented title="Page not found" milestone="n/a" why="This route does not exist." />} />
      </Route>
    </Routes>
  )
}
