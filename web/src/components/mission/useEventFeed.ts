import { useQueries, useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import { useCallback } from 'react'
import { api } from '../../api/client'
import type { RunEvent, RunListItem } from '../../api/types'
import { mergeFeed, type FeedItem } from '../../lib/mission'
import { TERMINAL_RUN_STATES } from '../../lib/status'

const POLL_MS = Number(import.meta.env.VITE_POLL_MS ?? 2000)
const PAGE = 500
const PAGES_PER_FETCH = 20

interface RunEvents { events: RunEvent[]; more: boolean }
export interface EventFeed { feed: FeedItem[]; byRun: Map<string, RunEvent[]>; live: boolean }

/** Persisted events of the most recent runs, read forward from the last seen cursor until caught up. */
export function useEventFeed(runs: RunListItem[]): EventFeed {
  const qc = useQueryClient()
  const combine = useCallback((results: UseQueryResult<RunEvents>[]): EventFeed => {
    const perRun = runs.map((run, i) => ({ run, events: results[i]?.data?.events ?? [] }))
    return {
      feed: mergeFeed(perRun),
      byRun: new Map(perRun.map((p) => [p.run.run_id, p.events])),
      live: runs.some((r) => !TERMINAL_RUN_STATES.has(r.state)),
    }
  }, [runs])
  return useQueries({
    queries: runs.map((run) => {
      const queryKey = ['run', run.run_id, 'event-feed']
      return {
        queryKey,
        queryFn: async (): Promise<RunEvents> => {
          let events = qc.getQueryData<RunEvents>(queryKey)?.events ?? []
          let cursor = events.at(-1)?.seq ?? 0
          for (let i = 0; i < PAGES_PER_FETCH; i++) {
            const page = await api<{ events: RunEvent[]; next_cursor: number }>(
              `/assessments/${run.run_id}/events?cursor=${cursor}&limit=${PAGE}`)
            events = events.concat(page.events.filter((e) => e.seq > cursor))
            if (page.events.length < PAGE) return { events, more: false }
            cursor = page.next_cursor
          }
          return { events, more: true }
        },
        refetchInterval: (q: { state: { data?: RunEvents } }) =>
          q.state.data?.more || !TERMINAL_RUN_STATES.has(run.state) ? POLL_MS : (false as const),
      }
    }),
    combine,
  })
}
