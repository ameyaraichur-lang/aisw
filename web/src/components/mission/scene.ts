// The Mission Control scene: a core (the platform), one orbit per project, one node per asset.
// Pulses are driven only by recorded run events; the idle motion is decoration, never data.
import * as THREE from 'three'
import type { PulseKind, SceneGroup, SceneNode, NodeStatus } from '../../lib/mission'

export const STATUS_COLOR: Record<NodeStatus, number> = {
  critical: 0xff4d6d, high: 0xff9f43, medium: 0xffd166, low: 0x7fd1ff, clear: 0x3ef0b0,
}
const PULSE_COLOR: Record<PulseKind, number> = { probe: 0x5cdcff, return: 0x3ef0b0, fault: 0xff4d6d, core: 0xb48cff }
const CYAN = 0x5cdcff

interface NodeObj { mesh: THREE.Mesh; halo: THREE.Sprite; data: SceneNode; flash: number }
interface Pulse {
  kind: PulseKind
  target: NodeObj | null
  t: number
  head: THREE.Sprite
  trail: THREE.Line
  ring?: THREE.Mesh
}

function glowTexture(): THREE.CanvasTexture {
  const c = document.createElement('canvas')
  c.width = c.height = 128
  const g = c.getContext('2d')
  if (g) {
    const r = g.createRadialGradient(64, 64, 0, 64, 64, 64)
    r.addColorStop(0, 'rgba(255,255,255,1)')
    r.addColorStop(0.25, 'rgba(255,255,255,.55)')
    r.addColorStop(1, 'rgba(255,255,255,0)')
    g.fillStyle = r
    g.fillRect(0, 0, 128, 128)
  }
  return new THREE.CanvasTexture(c)
}

export interface SceneOptions {
  reducedMotion: boolean
  onHover: (node: SceneNode | null, x: number, y: number) => void
}

export class MissionScene {
  private renderer: THREE.WebGLRenderer
  private scene = new THREE.Scene()
  private camera = new THREE.PerspectiveCamera(48, 1, 0.1, 300)
  private clock = new THREE.Timer()
  private glow = glowTexture()
  private core = new THREE.Group()
  private orbits = new THREE.Group()
  private sweep: THREE.Mesh
  private nodes: NodeObj[] = []
  private pulses: Pulse[] = []
  private raycaster = new THREE.Raycaster()
  private pointer = new THREE.Vector2(9, 9)
  private frame = 0
  private running = false
  private resize: ResizeObserver
  private hovered: NodeObj | null = null
  private host: HTMLElement
  private opts: SceneOptions

  constructor(host: HTMLElement, opts: SceneOptions) {
    this.host = host
    this.opts = opts
    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'low-power' })
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    this.renderer.domElement.setAttribute('aria-hidden', 'true')
    host.appendChild(this.renderer.domElement)
    this.scene.fog = new THREE.FogExp2(0x030814, 0.028)
    this.camera.position.set(0, 7.5, 17)
    this.camera.lookAt(0, 0, 0)

    this.scene.add(this.stars(), this.floor(), this.core, this.orbits)
    this.sweep = this.radar()
    this.scene.add(this.sweep)
    this.buildCore()

    this.resize = new ResizeObserver(() => this.fit())
    this.resize.observe(host)
    this.fit()
    host.addEventListener('pointermove', this.onPointer)
    host.addEventListener('pointerleave', this.onLeave)
    document.addEventListener('visibilitychange', this.onVisibility)
    this.start()
  }

  // ---- static dressing ------------------------------------------------------------------------
  private stars(): THREE.Points {
    const n = 1400
    const pos = new Float32Array(n * 3)
    for (let i = 0; i < n; i++) {
      const r = 40 + Math.random() * 60
      const th = Math.random() * Math.PI * 2
      const ph = Math.acos(2 * Math.random() - 1)
      pos.set([r * Math.sin(ph) * Math.cos(th), r * Math.cos(ph), r * Math.sin(ph) * Math.sin(th)], i * 3)
    }
    const g = new THREE.BufferGeometry()
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3))
    return new THREE.Points(g, new THREE.PointsMaterial({ color: 0x8fc8ff, size: 0.18, transparent: true, opacity: 0.65, fog: false }))
  }

  private floor(): THREE.Object3D {
    const grid = new THREE.PolarGridHelper(14, 16, 7, 96, CYAN, CYAN)
    grid.position.y = -3.2
    for (const m of [grid.material].flat()) Object.assign(m, { transparent: true, opacity: 0.16 })
    return grid
  }

  private radar(): THREE.Mesh {
    const m = new THREE.Mesh(
      new THREE.CircleGeometry(14, 48, 0, Math.PI / 5),
      new THREE.MeshBasicMaterial({ color: CYAN, transparent: true, opacity: 0.09, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, depthWrite: false }),
    )
    m.rotation.x = -Math.PI / 2
    m.position.y = -3.18
    return m
  }

  private buildCore(): void {
    const add = (o: THREE.Object3D) => { this.core.add(o); return o }
    add(new THREE.Mesh(new THREE.SphereGeometry(0.85, 32, 32),
      new THREE.MeshBasicMaterial({ color: CYAN, transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending })))
    add(new THREE.Mesh(new THREE.IcosahedronGeometry(1.35, 1),
      new THREE.MeshBasicMaterial({ color: CYAN, wireframe: true, transparent: true, opacity: 0.75 }))).name = 'shell'
    add(new THREE.Mesh(new THREE.IcosahedronGeometry(1.9, 0),
      new THREE.MeshBasicMaterial({ color: 0xb48cff, wireframe: true, transparent: true, opacity: 0.25 }))).name = 'outer'
    for (const [i, tilt] of [[0, 0.4], [1, -0.9]] as const) {
      const ring = add(new THREE.Mesh(new THREE.TorusGeometry(2.5 + i * 0.35, 0.018, 8, 128),
        new THREE.MeshBasicMaterial({ color: i ? 0xb48cff : CYAN, transparent: true, opacity: 0.7 })))
      ring.rotation.x = Math.PI / 2 + tilt
      ring.name = `ring${i}`
    }
    const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: this.glow, color: CYAN, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false }))
    halo.scale.setScalar(6.5)
    add(halo).name = 'halo'
  }

  // ---- data -----------------------------------------------------------------------------------
  setGroups(groups: SceneGroup[]): void {
    this.clearObject(this.orbits)
    this.nodes = []
    groups.forEach((g, i) => {
      const orbit = new THREE.Group()
      orbit.rotation.set(0.35 + (i % 3) * 0.32, 0, (i % 2 ? -1 : 1) * (0.18 + i * 0.12))
      orbit.userData = { speed: (i % 2 ? -1 : 1) * (0.06 + 0.025 * (groups.length - i)), projectId: g.projectId }
      const radius = 4.3 + i * 1.75
      const curve = new THREE.EllipseCurve(0, 0, radius, radius, 0, Math.PI * 2, false, 0)
      const ring = new THREE.LineLoop(
        new THREE.BufferGeometry().setFromPoints(curve.getPoints(160).map((p) => new THREE.Vector3(p.x, 0, p.y))),
        new THREE.LineBasicMaterial({ color: CYAN, transparent: true, opacity: 0.28 }),
      )
      orbit.add(ring)
      g.nodes.forEach((n, j) => {
        const a = (j / Math.max(g.nodes.length, 1)) * Math.PI * 2 + i * 0.7
        const p = new THREE.Vector3(Math.cos(a) * radius, 0, Math.sin(a) * radius)
        const color = STATUS_COLOR[n.status]
        const mesh = new THREE.Mesh(new THREE.SphereGeometry(n.status === 'clear' ? 0.17 : 0.24, 20, 20), new THREE.MeshBasicMaterial({ color }))
        mesh.position.copy(p)
        const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: this.glow, color, transparent: true, opacity: 0.8, blending: THREE.AdditiveBlending, depthWrite: false }))
        halo.position.copy(p)
        halo.scale.setScalar(n.status === 'clear' ? 0.9 : 1.4)
        const beam = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(), p]),
          new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.1 }))
        orbit.add(beam, mesh, halo)
        const obj: NodeObj = { mesh, halo, data: n, flash: 0 }
        mesh.userData.node = obj
        this.nodes.push(obj)
      })
      this.orbits.add(orbit)
    })
    this.renderOnce()
  }

  /** Animate one recorded event: probes fly to a node of the run's project, returns fly back. */
  pulse(kind: PulseKind, projectId: string | null): void {
    if (this.opts.reducedMotion) return
    const pool = this.nodes.filter((n) => !projectId || n.data.projectId === projectId)
    const target = kind === 'core' ? null : (pool.length ? pool : this.nodes)[Math.floor(Math.random() * Math.max(pool.length || this.nodes.length, 1))] ?? null
    const color = PULSE_COLOR[kind]
    const head = new THREE.Sprite(new THREE.SpriteMaterial({ map: this.glow, color, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }))
    head.scale.setScalar(0.9)
    const trail = new THREE.Line(new THREE.BufferGeometry().setFromPoints(Array.from({ length: 24 }, () => new THREE.Vector3())),
      new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending }))
    const p: Pulse = { kind, target, t: 0, head, trail }
    if (kind === 'core' || !target) {
      p.ring = new THREE.Mesh(new THREE.RingGeometry(0.96, 1, 96),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }))
      p.ring.rotation.x = -Math.PI / 2
      this.scene.add(p.ring)
    } else {
      this.scene.add(head, trail)
    }
    this.pulses.push(p)
    if (this.pulses.length > 40) this.dropPulse(this.pulses[0])
  }

  // ---- loop -----------------------------------------------------------------------------------
  private start(): void {
    if (this.running) return
    this.running = true
    this.clock.update()
    const tick = () => {
      if (!this.running) return
      this.frame = requestAnimationFrame(tick)
      this.clock.update()
      this.step(Math.min(this.clock.getDelta(), 0.05))
    }
    if (this.opts.reducedMotion) { this.running = false; this.renderOnce() } else tick()
  }

  private step(dt: number): void {
    const t = this.clock.getElapsed()
    this.core.rotation.y += dt * 0.25
    this.core.getObjectByName('shell')?.rotateX(dt * 0.3)
    this.core.getObjectByName('outer')?.rotateY(-dt * 0.4)
    this.core.getObjectByName('ring0')?.rotateZ(dt * 0.6)
    this.core.getObjectByName('ring1')?.rotateZ(-dt * 0.45)
    const halo = this.core.getObjectByName('halo')
    if (halo) halo.scale.setScalar(6.2 + Math.sin(t * 2) * 0.4)
    this.sweep.rotation.z -= dt * 0.9
    for (const o of this.orbits.children) o.rotation.y += dt * (o.userData.speed as number)
    for (const n of this.nodes) {
      const base = n.data.status === 'clear' ? 0.9 : 1.4
      const throb = n.data.status === 'critical' || n.data.status === 'high' ? Math.sin(t * 4 + n.mesh.id) * 0.25 : 0
      n.flash = Math.max(0, n.flash - dt * 1.5)
      n.halo.scale.setScalar(base + throb + n.flash * 2.2)
      n.mesh.scale.setScalar(n === this.hovered ? 1.7 : 1)
    }
    this.camera.position.x = Math.sin(t * 0.05) * 3
    this.camera.lookAt(0, 0, 0)
    this.stepPulses(dt)
    this.pick()
    this.renderer.render(this.scene, this.camera)
  }

  private stepPulses(dt: number): void {
    const node = new THREE.Vector3()
    const origin = new THREE.Vector3()
    for (const p of [...this.pulses]) {
      p.t += dt / (p.ring ? 1.6 : 1.3)
      if (p.ring) {
        p.ring.scale.setScalar(1 + p.t * 13)
        ;(p.ring.material as THREE.MeshBasicMaterial).opacity = Math.max(0, 0.9 * (1 - p.t))
      } else if (p.target) {
        p.target.mesh.getWorldPosition(node)
        const [from, to] = p.kind === 'return' ? [node, origin] : [origin, node]
        const mid = from.clone().add(to).multiplyScalar(0.5).add(new THREE.Vector3(0, 2.4, 0))
        const curve = new THREE.QuadraticBezierCurve3(from, mid, to)
        const head = Math.min(p.t, 1)
        p.head.position.copy(curve.getPoint(head))
        const pts = Array.from({ length: 24 }, (_, i) => curve.getPoint(Math.max(0, head - 0.22 * (1 - i / 23))))
        p.trail.geometry.setFromPoints(pts)
        ;(p.trail.material as THREE.LineBasicMaterial).opacity = p.t > 1 ? Math.max(0, 1 - (p.t - 1) * 3) : 0.85
        if (p.t >= 1 && p.kind !== 'return' && p.target.flash === 0) p.target.flash = 1
      }
      if (p.t > 1.35) this.dropPulse(p)
    }
  }

  private dropPulse(p: Pulse): void {
    this.pulses = this.pulses.filter((x) => x !== p)
    for (const o of [p.head, p.trail, p.ring]) {
      if (!o) continue
      this.scene.remove(o)
      this.disposeObject(o)
    }
  }

  private pick(): void {
    if (Math.abs(this.pointer.x) > 1) return
    this.raycaster.setFromCamera(this.pointer, this.camera)
    const hit = this.raycaster.intersectObjects(this.nodes.map((n) => n.mesh), false)[0]
    const node = (hit?.object.userData.node as NodeObj | undefined) ?? null
    const changed = node !== this.hovered
    if (changed) {
      this.hovered = node
      this.host.style.cursor = node ? 'pointer' : ''
    }
    if (!node && !changed) return
    if (node) {
      const v = node.mesh.getWorldPosition(new THREE.Vector3()).project(this.camera)
      const r = this.renderer.domElement.getBoundingClientRect()
      this.opts.onHover(node.data, ((v.x + 1) / 2) * r.width, ((1 - v.y) / 2) * r.height)
    } else this.opts.onHover(null, 0, 0)
  }

  private onPointer = (e: PointerEvent) => {
    const r = this.renderer.domElement.getBoundingClientRect()
    this.pointer.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1)
    if (!this.running) { this.pick(); this.renderOnce() }
  }
  private onLeave = () => { this.pointer.set(9, 9); this.hovered = null; this.opts.onHover(null, 0, 0) }
  private onVisibility = () => {
    if (document.hidden) { this.running = false; cancelAnimationFrame(this.frame) } else this.start()
  }

  private fit(): void {
    const w = this.host.clientWidth || 1
    const h = this.host.clientHeight || 1
    this.renderer.setSize(w, h, false)
    this.camera.aspect = w / h
    this.camera.position.z = w / h < 1.2 ? 22 : 17
    this.camera.updateProjectionMatrix()
    this.renderOnce()
  }

  private renderOnce(): void { this.renderer.render(this.scene, this.camera) }

  // ---- teardown -------------------------------------------------------------------------------
  private disposeObject(o: THREE.Object3D): void {
    o.traverse((x) => {
      const m = x as THREE.Mesh
      m.geometry?.dispose()
      for (const mat of [m.material].flat()) (mat as THREE.Material | undefined)?.dispose()
    })
  }
  private clearObject(o: THREE.Object3D): void {
    for (const c of [...o.children]) { o.remove(c); this.disposeObject(c) }
  }

  dispose(): void {
    this.running = false
    cancelAnimationFrame(this.frame)
    this.resize.disconnect()
    this.host.removeEventListener('pointermove', this.onPointer)
    this.host.removeEventListener('pointerleave', this.onLeave)
    document.removeEventListener('visibilitychange', this.onVisibility)
    this.disposeObject(this.scene)
    this.glow.dispose()
    this.renderer.dispose()
    this.renderer.domElement.remove()
  }
}
