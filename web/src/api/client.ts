// Thin fetch wrapper. The UI never talks to anything but the platform API (no scanners, no DB).
// Dev identity token: held in sessionStorage ONLY for the dev stub (a seeded, non-secret name).
// Real sign-in is OIDC through the BFF (ADR-026): the session is an httpOnly cookie the page cannot
// read; the page only echoes the readable CSRF cookie on each request. No IdP token reaches the browser.
const TOKEN_KEY = 'aisw.dev.identity'
const CSRF_COOKIE = 'aisw_csrf'

export class ApiError extends Error {
  status: number
  body: unknown
  constructor(status: number, body: unknown, message: string) {
    super(message)
    this.status = status
    this.body = body
  }
  get reasonCodes(): string[] {
    const b = this.body as { reason_codes?: string[] } | null
    return b?.reason_codes ?? []
  }
  get issues(): { code: string; severity: string; detail: string }[] {
    const b = this.body as { issues?: { code: string; severity: string; detail: string }[] } | null
    return b?.issues ?? []
  }
}

export function getDevIdentity(): string | null {
  return sessionStorage.getItem(TOKEN_KEY)
}
export function setDevIdentity(name: string | null): void {
  if (name) sessionStorage.setItem(TOKEN_KEY, name)
  else sessionStorage.removeItem(TOKEN_KEY)
}
export function csrfToken(): string | null {
  const m = document.cookie.match(new RegExp(`(?:^|;\\s*)${CSRF_COOKIE}=([^;]+)`))
  return m ? decodeURIComponent(m[1]) : null
}
export function authHeaders(): Record<string, string> {
  const id = getDevIdentity()
  if (id) return { Authorization: `Bearer dev-${id}` }
  const csrf = csrfToken()
  return csrf ? { 'X-AISW-CSRF': csrf } : {}
}
export function ssoLoginUrl(returnTo: string): string {
  return `/api/v1/auth/login?return_to=${encodeURIComponent(returnTo)}`
}

export async function api<T>(
  path: string,
  init: { method?: string; body?: unknown; headers?: Record<string, string>; signal?: AbortSignal } = {},
): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    method: init.method ?? 'GET',
    headers: {
      Accept: 'application/json',
      ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...authHeaders(),
      ...init.headers,
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    signal: init.signal,
  })
  const text = await res.text()
  let parsed: unknown = null
  try {
    parsed = text ? JSON.parse(text) : null
  } catch {
    parsed = text
  }
  if (!res.ok) {
    const detail =
      (parsed as { detail?: unknown; error?: string } | null)?.error ??
      (typeof (parsed as { detail?: unknown } | null)?.detail === 'string'
        ? ((parsed as { detail: string }).detail)
        : res.statusText)
    throw new ApiError(res.status, parsed, String(detail))
  }
  return parsed as T
}

export function newIdempotencyKey(): string {
  return crypto.randomUUID()
}

export async function apiText(path: string, accept = 'text/html'): Promise<string> {
  const res = await fetch(`/api/v1${path}`, { headers: { Accept: accept, ...authHeaders() } })
  if (!res.ok) throw new ApiError(res.status, null, res.statusText)
  return res.text()
}
