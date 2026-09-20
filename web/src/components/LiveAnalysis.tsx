import { lazy, Suspense, useEffect, useMemo, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { motion, useReducedMotion } from "motion/react"
import { api, invalidateBinary, jobsQuery, eventsQuery } from "@/lib/api"
import { ErrorNotice, LoadingRows } from "@/components/Feedback"
import { Badge } from "@/components/ui/badge"
import CallGraph2D from "@/components/CallGraph2D"
import { useGraphLayout } from "@/lib/use-graph-layout"
import { dateTime } from "@/lib/format"

import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"

const CallGraph3D = lazy(() => import("@/components/CallGraph3D"))

export function useLiveAnalysis(binaryId: string) {
  const [connected, setConnected] = useState(false)
  useEffect(() => {
    const source = new EventSource(`/events/${encodeURIComponent(binaryId)}`)
    let refresh: ReturnType<typeof setTimeout> | undefined
    source.onopen = () => setConnected(true)
    source.onerror = () => setConnected(false)
    source.onmessage = () => {
      if (refresh === undefined)
        refresh = setTimeout(() => {
          refresh = undefined
          void invalidateBinary(binaryId)
        }, 250)
    }
    return () => {
      source.close()
      if (refresh) clearTimeout(refresh)
    }
  }, [binaryId])
  return connected
}
export function LiveAnalysis({
  binaryId,
  onSelect,
}: {
  binaryId: string
  onSelect: (id: string) => void
}) {
  const graph = useQuery({
    queryKey: ["binary", binaryId, "graph"],
    queryFn: ({ signal }) => api.getGraph({ binaryId }, { signal }),
    refetchInterval: 5000,
  })
  const jobs = useQuery(jobsQuery(binaryId))
  const events = useQuery(eventsQuery(binaryId))
  const reduced = useReducedMotion()
  const layout = useGraphLayout(graph.data)
  const running = useMemo(
    () =>
      new Set(
        jobs.data?.jobs
          .filter((job) => job.status === "running")
          .map((job) => job.functionId)
      ),
    [jobs.data]
  )
  return (
    <section className="flex flex-col gap-5">
      <div className="section-heading">
        <h2>Live analysis</h2>
        <Badge variant="outline">{running.size} active requests</Badge>
      </div>
      <p>
        Call relationships for {graph.data?.nodes.length ?? 0} of{" "}
        {graph.data?.total ?? 0} functions. Select a node to inspect its
        evidence and assessments.
      </p>
      <ErrorNotice
        error={graph.error ?? jobs.error ?? events.error ?? layout.error}
      />
      {layout.isLoading ? (
        <p role="status">Arranging call relationships…</p>
      ) : null}
      <Tabs defaultValue="3d">
        <TabsList variant="line" aria-label="Graph view">
          <TabsTrigger value="3d">3D graph</TabsTrigger>
          <TabsTrigger value="2d">2D graph</TabsTrigger>
        </TabsList>
        <TabsContent
          value="3d"
          className="motion-safe:animate-in motion-safe:duration-200 motion-safe:fade-in-0"
        >
          {graph.data && layout.data ? (
            <Suspense fallback={<LoadingRows />}>
              <CallGraph3D
                graph={graph.data}
                layout={layout.data.space}
                running={running}
                onSelect={onSelect}
              />
            </Suspense>
          ) : (
            <LoadingRows />
          )}
        </TabsContent>
        <TabsContent value="2d">
          {graph.data && layout.data ? (
            <CallGraph2D
              key={layout.dataUpdatedAt}
              graph={graph.data}
              layout={layout.data.plane}
              running={running}
              onSelect={onSelect}
            />
          ) : (
            <LoadingRows />
          )}
        </TabsContent>
      </Tabs>
      <h3>Activity log</h3>
      <ol className="event-list">
        {events.data?.events.slice(0, 40).map((event) => (
          <motion.li
            key={event.id.toString()}
            initial={reduced ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <time>{dateTime(event.createdAt)}</time>
            <Badge
              variant={event.level === "error" ? "destructive" : "outline"}
            >
              {event.level}
            </Badge>
            <p>{event.message}</p>
          </motion.li>
        ))}
      </ol>
    </section>
  )
}
