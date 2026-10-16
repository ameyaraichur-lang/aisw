import { useEffect, useRef } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useSession } from '../auth/useSession'
import { NAV } from './nav'

export function Shell() {
  const { me, logout, can } = useSession()
  const loc = useLocation()
  const prev = useRef(loc.pathname)
  useEffect(() => {
    // Move focus to the page heading on navigation only. Comparing paths (not "first run") keeps
    // this correct under React StrictMode's double effect, and the skip link stays the first tab stop.
    if (prev.current === loc.pathname) return
    prev.current = loc.pathname
    document.querySelector<HTMLElement>('main h1')?.focus()
  }, [loc.pathname])
  return (
    <div className="shell">
      <a className="skip" href="#main">Skip to main content</a>
      <header className="topbar">
        <span className="brand">AISW <span className="muted">Security Warden</span></span>
        <span className="tag" title="The MVP can only read and report">Read-only platform</span>
        <span className="spacer" />
        <span aria-label="Signed in user">{me?.actor_id} <span className="muted">({me?.tenant_id})</span></span>
        <ul className="roles" aria-label="Roles">{me?.roles.map((r) => <li key={r} className="chip">{r}</li>)}</ul>
        <button type="button" className="btn btn--small" onClick={logout}>Sign out</button>
      </header>
      <nav className="sidenav" aria-label="Main">
        <ul>
          {NAV.filter((i) => !i.need || can(i.need)).map((i) => (
            <li key={i.to}>
              <NavLink to={i.to} end={i.to === '/'} className={({ isActive }) => (isActive ? 'active' : '')}>
                {i.label}{i.planned ? <span className="muted"> ({i.planned})</span> : null}
              </NavLink>
            </li>
          ))}
          {can('manifest:approve') ? (
            <li><NavLink to="/approvals" className={({ isActive }) => (isActive ? 'active' : '')}>Pending approvals</NavLink></li>
          ) : null}
        </ul>
      </nav>
      <main id="main" className="main"><Outlet /></main>
    </div>
  )
}
