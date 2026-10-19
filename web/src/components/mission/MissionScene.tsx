import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { STATUS_LABEL, type PulseKind, type SceneGroup } from '../../lib/mission'
import { MissionScene as Scene } from './scene'

export interface SceneHandle { pulse: (kind: PulseKind, projectId: string | null) => void }

const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false
const hasWebGL = () => {
  try {
    const c = document.createElement('canvas')
    return !!(c.getContext('webgl2') ?? c.getContext('webgl'))
  } catch {
    return false
  }
}

/** Decorative 3D view (aria-hidden); the same facts are in the asset list beside it. */
export const MissionScene = forwardRef<SceneHandle, { groups: SceneGroup[] }>(function MissionScene({ groups }, ref) {
  const host = useRef<HTMLDivElement>(null)
  const tip = useRef<HTMLDivElement>(null)
  const scene = useRef<Scene | null>(null)
  const fallback = useRef<HTMLParagraphElement>(null)
  const [failed] = useState(() => !hasWebGL())

  useEffect(() => {
    if (failed || !host.current) return
    try {
      scene.current = new Scene(host.current, {
        reducedMotion: reducedMotion(),
        onHover: (node, x, y) => {
          const el = tip.current
          if (!el) return
          if (!node) { el.hidden = true; return }
          el.hidden = false
          el.style.transform = `translate(${Math.round(x + 14)}px, ${Math.round(y - 10)}px)`
          el.textContent = `${node.label} · ${node.projectName} · ${STATUS_LABEL[node.status]}${node.findings ? ` (${node.findings})` : ''}`
        },
      })
    } catch {
      if (fallback.current) fallback.current.hidden = false
    }
    return () => { scene.current?.dispose(); scene.current = null }
  }, [failed])

  useEffect(() => { scene.current?.setGroups(groups) }, [groups])
  useImperativeHandle(ref, () => ({ pulse: (kind, projectId) => scene.current?.pulse(kind, projectId) }), [])

  return (
    <div className="mc-scene" ref={host}>
      <p className="mc-scene__fallback" ref={fallback} hidden={!failed}>3D view unavailable in this browser (WebGL is off). The asset list and event stream show the same data.</p>
      <div className="mc-tip" ref={tip} hidden aria-hidden="true" />
    </div>
  )
})
