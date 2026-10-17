export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z')
}

export const describePorts = (ports: [number, number][] | null) =>
  ports === null ? 'every port' : `port ${ports.map(([lo, hi]) => (lo === hi ? `${lo}` : `${lo}-${hi}`)).join(', ')}`
