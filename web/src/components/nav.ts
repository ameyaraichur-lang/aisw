export interface Item { to: string; label: string; need?: string; planned?: string }
export const NAV: Item[] = [
  { to: '/', label: 'Command Center' },
  { to: '/projects', label: 'Projects & Environments' },
  { to: '/integrations', label: 'Integrations & Collectors' },
  { to: '/assessments', label: 'Assessments' },
  { to: '/assets', label: 'Asset Explorer' },
  { to: '/findings', label: 'Findings & Exposure', need: 'finding:read' },
  { to: '/architecture', label: 'Architecture & Modernization', need: 'finding:read' },
  { to: '/roadmap', label: 'Modernization Roadmap', need: 'finding:read' },
  { to: '/controls', label: 'Control Matrix' },
  { to: '/exceptions', label: 'Exceptions', need: 'finding:read' },
  { to: '/assurance', label: 'Assurance Console', need: 'finding:read' },
  { to: '/reports', label: 'Reports & Evidence', need: 'report:read' },
  { to: '/audit', label: 'Policy, Users & Audit', need: 'audit:read' },
  { to: '/audit/model-calls', label: 'Model-call ledger', need: 'audit:read' },
]

