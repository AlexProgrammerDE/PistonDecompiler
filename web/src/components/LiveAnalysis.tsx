import { useEffect, useMemo, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { motion, useReducedMotion } from "motion/react"
import { api, invalidateBinary, jobsQuery, eventsQuery } from "@/lib/api"
import { ErrorNotice } from "@/components/Feedback"
import { Badge } from "@/components/ui/badge"
import { dateTime } from "@/lib/format"

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
  const positions = useMemo(
    () =>
      new Map(
        graph.data?.nodes.map((node, i) => [
          node.id,
          { x: 35 + (i % 10) * 90, y: 35 + Math.floor(i / 10) * 65 },
        ])
      ),
    [graph.data]
  )
  const running = new Set(
    jobs.data?.jobs
      .filter((job) => job.status === "running")
      .map((job) => job.functionId)
  )
  const height = Math.max(
    150,
    Math.ceil((graph.data?.nodes.length ?? 0) / 10) * 65 + 20
  )
  return (
    <section className="flex flex-col gap-5">
      <div className="section-heading">
        <h2>Live analysis</h2>
        <Badge variant="outline">{running.size} active requests</Badge>
      </div>
      <p>
        Call relationships for {graph.data?.nodes.length ?? 0} of{" "}
        {graph.data?.total ?? 0} functions. Select a node to inspect it. Pulses
        indicate active requests; outlined nodes need reconsideration.
      </p>
      <ErrorNotice error={graph.error ?? jobs.error ?? events.error} />
      <div className="graph-scroll">
        <svg
          viewBox={`0 0 900 ${height}`}
          role="group"
          aria-label="Live function call graph"
          className="function-graph"
        >
          {graph.data?.edges.map((edge) => {
            const from = positions.get(edge.caller)
            const to = positions.get(edge.callee)
            return from && to ? (
              <path
                key={`${edge.caller}:${edge.callee}`}
                d={`M${from.x},${from.y} Q${from.x},${to.y} ${to.x},${to.y}`}
                fill="none"
                stroke="var(--muted-foreground)"
                strokeOpacity={0.45}
              />
            ) : null
          })}
          {graph.data?.nodes.map((node) => {
            const pos = positions.get(node.id)!
            const active = running.has(node.id)
            return (
              <g
                key={node.id}
                role="button"
                tabIndex={0}
                aria-label={`${node.proposedName || node.name}${active ? ", analyzing" : ""}`}
                onClick={() => onSelect(node.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault()
                    onSelect(node.id)
                  }
                }}
                className="graph-node"
              >
                <title>{node.proposedName || node.name}</title>
                <motion.circle
                  cx={pos.x}
                  cy={pos.y}
                  r={8}
                  fill={
                    node.resultId ? "var(--primary)" : "var(--muted-foreground)"
                  }
                  stroke={node.stale ? "var(--foreground)" : "none"}
                  strokeWidth={3}
                  animate={{ opacity: active && !reduced ? [1, 0.35, 1] : 1 }}
                  transition={{
                    duration: 1.4,
                    repeat: active && !reduced ? Infinity : 0,
                  }}
                />
                <text
                  x={pos.x}
                  y={pos.y + 22}
                  textAnchor="middle"
                  fill="var(--muted-foreground)"
                  fontSize={9}
                >
                  {node.address.slice(-8)}
                </text>
              </g>
            )
          })}
        </svg>
      </div>
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
