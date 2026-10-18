import { useQueries, type UseQueryResult } from '@tanstack/react-query'
import { useCallback } from 'react'
import { api } from '../../api/client'
import type { RunEvent, RunListItem } from '../../api/types'
import { mergeFeed, type FeedItem } from '../../lib/mission'
import { TERMINAL_RUN_STATES } from '../../lib/status'

const POLL_MS = Number(import.meta.env.VITE_POLL_MS ?? 2000)

export interface EventFeed { feed: FeedItem[]; byRun: Map<string, RunEvent[]>; live: boolean }

/** Persisted events of the most recent runs; runs still in flight are re-read every few seconds. */
export function useEventFeed(runs: RunListItem[]): EventFeed {
  const combine = useCallback((results: UseQueryResult<{ events: RunEvent[] }>[]): EventFeed => {
    const perRun = runs.map((run, i) => ({ run, events: results[i]?.data?.events ?? [] }))
    return {
      feed: mergeFeed(perRun),
      byRun: new Map(perRun.map((p) => [p.run.run_id, p.events])),
      live: runs.some((r) => !TERMINAL_RUN_STATES.has(r.state)),
    }
  }, [runs])
  return useQueries({
    queries: runs.map((run) => ({
      queryKey: ['run', run.run_id, 'event-feed'],
      queryFn: () => api<{ events: RunEvent[] }>(`/assessments/${run.run_id}/events?limit=500`),
      refetchInterval: TERMINAL_RUN_STATES.has(run.state) ? (false as const) : POLL_MS,
    })),
    combine,
  })
}
