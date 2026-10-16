// Live run events with durable-state semantics: the persisted log is authoritative, so after any
// interruption we resume from the last cursor, dedupe by event_id, and re-read the status snapshot.
import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { api, authHeaders } from '../api/client'
import type { RunEvent } from '../api/types'
import { applyEvents, emptyEvents, parseSse, type EventState } from './events'

export type StreamStatus = 'connecting' | 'live' | 'reconnecting' | 'polling' | 'ended' | 'denied'

export interface RunStream {
  events: RunEvent[]
  status: StreamStatus
  lastEventAt: number | null
  staleSince: number | null
  reconnects: number
}

const BASE_BACKOFF_MS = Number(import.meta.env.VITE_STREAM_BACKOFF_MS ?? 1000)
const POLL_MS = Number(import.meta.env.VITE_POLL_MS ?? 3000)
const MAX_STREAM_FAILURES = 3

const sleep = (ms: number, signal: AbortSignal, onWake?: (w: () => void) => void) =>
  new Promise<void>((resolve) => {
    const t = setTimeout(resolve, ms)
    const done = () => { clearTimeout(t); resolve() }
    onWake?.(done)
    signal.addEventListener('abort', done, { once: true })
  })

export function useRunStream(runId: string): RunStream {
  const qc = useQueryClient()
  const [state, setState] = useState<EventState>(emptyEvents)
  const [status, setStatus] = useState<StreamStatus>('connecting')
  const [lastEventAt, setLastEventAt] = useState<number | null>(null)
  const [staleSince, setStaleSince] = useState<number | null>(null)
  const [reconnects, setReconnects] = useState(0)
  const cursor = useRef(0)

  useEffect(() => {
    const ctl = new AbortController()
    cursor.current = 0 // state resets because the page remounts per run (see RunPage)
    // The browser tells us when connectivity changes; an open stream would otherwise sit silently.
    let conn: AbortController | null = null
    let wake: (() => void) | null = null
    let resetFailures = false
    const onOffline = () => {
      setStatus((st) => (st === 'ended' || st === 'denied' ? st : 'reconnecting'))
      setStaleSince((t) => t ?? Date.now())
      conn?.abort()
    }
    const onOnline = () => { resetFailures = true; wake?.() }
    window.addEventListener('offline', onOffline)
    window.addEventListener('online', onOnline)
    let invalidateTimer: ReturnType<typeof setTimeout> | null = null
    const refresh = () => {
      if (invalidateTimer) return
      invalidateTimer = setTimeout(() => {
        invalidateTimer = null
        void qc.invalidateQueries({ queryKey: ['run', runId] })
        void qc.invalidateQueries({ queryKey: ['overview'] })
        void qc.invalidateQueries({ queryKey: ['runs'] })
      }, 250)
    }
    const take = (events: RunEvent[]) => {
      if (events.length === 0) return
      setState((s) => applyEvents(s, events))
      cursor.current = Math.max(cursor.current, ...events.map((e) => e.seq))
      setLastEventAt(Date.now())
      refresh()
    }
    const markLive = (wasDown: boolean) => {
      setStatus('live')
      setStaleSince(null)
      if (wasDown) {
        setReconnects((n) => n + 1)
        void qc.invalidateQueries({ queryKey: ['run', runId] }) // recover from the snapshot
      }
    }

    async function readStream(wasDown: boolean): Promise<'end' | 'closed'> {
      conn = new AbortController()
      const onAbort = () => conn?.abort()
      ctl.signal.addEventListener('abort', onAbort, { once: true })
      const res = await fetch(`/api/v1/assessments/${runId}/events/stream?cursor=${cursor.current}`, {
        headers: { Accept: 'text/event-stream', ...authHeaders(), ...(cursor.current ? { 'Last-Event-ID': String(cursor.current) } : {}) },
        signal: conn.signal,
      })
      if ([401, 403, 404].includes(res.status)) throw Object.assign(new Error('denied'), { denied: true })
      if (!res.ok || !res.body) throw new Error(`stream failed: ${res.status}`)
      markLive(wasDown)
      const reader = res.body.getReader()
      const dec = new TextDecoder()
      let buf = ''
      for (;;) {
        const { done, value } = await reader.read()
        if (done) return 'closed'
        const parsed = parseSse(buf + dec.decode(value, { stream: true }))
        buf = parsed.rest
        const batch: RunEvent[] = []
        for (const m of parsed.messages) {
          if (m.event === 'end') { take(batch); return 'end' }
          if (m.event === 'reconnect') { take(batch); return 'closed' }
          try { batch.push(JSON.parse(m.data) as RunEvent) } catch { /* ignore a corrupt frame; the log is re-read on reconnect */ }
        }
        take(batch)
      }
    }

    async function pollOnce(): Promise<boolean> {
      const r = await api<{ events: RunEvent[]; next_cursor: number }>(`/assessments/${runId}/events?cursor=${cursor.current}&limit=200`, { signal: ctl.signal })
      take(r.events)
      const st = await api<{ state: string; event_cursor: number }>(`/assessments/${runId}`, { signal: ctl.signal })
      return ['CLOSED', 'FAILED', 'CANCELLED', 'EXPIRED', 'PARTIAL', 'REPORT_READY'].includes(st.state) && cursor.current >= st.event_cursor
    }

    async function loop() {
      let failures = 0
      let down = false
      while (!ctl.signal.aborted) {
        try {
          if (failures >= MAX_STREAM_FAILURES) {
            setStatus((s) => (s === 'ended' ? s : 'polling'))
            if (await pollOnce()) { setStatus('ended'); setStaleSince(null); return }
            down = false
            await sleep(POLL_MS, ctl.signal, (w) => { wake = w })
            if (resetFailures) { failures = 0; resetFailures = false }
            continue
          }
          const how = await readStream(down)
          failures = 0
          down = false
          if (how === 'end') { setStatus('ended'); setStaleSince(null); refresh(); return }
        } catch (e) {
          if (ctl.signal.aborted) return
          if ((e as { denied?: boolean }).denied) { setStatus('denied'); return }
          failures += 1
          down = true
          setStatus((s) => (s === 'polling' ? s : 'reconnecting'))
          setStaleSince((t) => t ?? Date.now())
          await sleep(Math.min(BASE_BACKOFF_MS * 2 ** (failures - 1), 8000), ctl.signal, (w) => { wake = w })
          if (resetFailures) { failures = 0; resetFailures = false }
        }
      }
    }
    void loop()
    return () => {
      ctl.abort()
      window.removeEventListener('offline', onOffline)
      window.removeEventListener('online', onOnline)
      if (invalidateTimer) clearTimeout(invalidateTimer)
    }
  }, [runId, qc])

  return { events: state.events, status, lastEventAt, staleSince, reconnects }
}
