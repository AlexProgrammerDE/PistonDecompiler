import {
  useEffect,
  useEffectEvent,
  useId,
  useMemo,
  useRef,
  useState,
} from "react"
import type { Graph } from "@/gen/piston/v1/piston_pb"
import type { GraphLayout } from "@/lib/graph-layout"
import { Button } from "@/components/ui/button"

export default function CallGraph2D({
  graph,
  layout,
  running,
  onSelect,
}: {
  graph: Graph
  layout: GraphLayout
  running: Set<string>
  onSelect: (id: string) => void
}) {
  const svg = useRef<SVGSVGElement>(null)
  const marker = useId()
  const [view, setView] = useState({
    x: 0,
    y: 0,
    width: layout.width,
    height: layout.height,
  })
  const [focused, setFocused] = useState<string | null>(null)
  const drag = useRef<{ x: number; y: number; moved: boolean } | null>(null)
  const adjacent = useMemo(() => {
    const ids = new Set([focused])
    for (const edge of graph.edges) {
      if (edge.caller === focused) ids.add(edge.callee)
      if (edge.callee === focused) ids.add(edge.caller)
    }
    return ids
  }, [graph.edges, focused])
  const fit = () =>
    setView({ x: 0, y: 0, width: layout.width, height: layout.height })
  const zoom = (factor: number) =>
    setView((current) => {
      const width = Math.max(
        layout.width / 12,
        Math.min(layout.width * 3, current.width * factor)
      )
      const height = (current.height * width) / current.width
      return {
        x: current.x + (current.width - width) / 2,
        y: current.y + (current.height - height) / 2,
        width,
        height,
      }
    })
  const wheel = useEffectEvent((event: WheelEvent) => {
    event.preventDefault()
    zoom(Math.exp(Math.max(-0.3, Math.min(0.3, event.deltaY * 0.002))))
  })
  useEffect(() => {
    const element = svg.current
    if (!element) return
    const handler = (event: WheelEvent) => wheel(event)
    element.addEventListener("wheel", handler, { passive: false })
    return () => element.removeEventListener("wheel", handler)
  }, [])
  const selected = graph.nodes.find((node) => node.id === focused)
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-sm text-muted-foreground">
          Drag to pan, scroll to zoom. Hover or focus a function to follow its
          calls.
        </p>
        <Button
          variant="outline"
          onClick={() => zoom(0.75)}
          aria-label="Zoom in"
        >
          +
        </Button>
        <Button
          variant="outline"
          onClick={() => zoom(1.33)}
          aria-label="Zoom out"
        >
          −
        </Button>
        <Button variant="outline" onClick={fit}>
          Fit graph
        </Button>
      </div>
      <svg
        ref={svg}
        viewBox={`${view.x} ${view.y} ${view.width} ${view.height}`}
        role="group"
        aria-label="Two-dimensional function call graph"
        className="h-[32rem] w-full touch-none rounded-md border select-none"
        onPointerDown={(event) => {
          drag.current = { x: event.clientX, y: event.clientY, moved: false }
        }}
        onPointerMove={(event) => {
          const previous = drag.current
          if (!previous || !event.buttons) return
          const dx = event.clientX - previous.x,
            dy = event.clientY - previous.y
          if (!previous.moved && Math.hypot(dx, dy) < 4) return
          const scale = Math.max(
            view.width / event.currentTarget.clientWidth,
            view.height / event.currentTarget.clientHeight
          )
          setView((current) => ({
            ...current,
            x: current.x - dx * scale,
            y: current.y - dy * scale,
          }))
          drag.current = { x: event.clientX, y: event.clientY, moved: true }
        }}
        onPointerLeave={() => {
          drag.current = null
          setFocused(null)
        }}
        onPointerCancel={() => {
          drag.current = null
        }}
      >
        <defs>
          <marker
            id={marker}
            viewBox="0 -4 8 8"
            refX="8"
            refY="0"
            markerWidth="7"
            markerHeight="7"
            orient="auto"
            markerUnits="userSpaceOnUse"
          >
            <path d="M0,-3 L7,0 L0,3" fill="none" stroke="var(--foreground)" />
          </marker>
        </defs>
        {graph.edges.map((edge) => {
          const from = layout.positions[edge.caller],
            to = layout.positions[edge.callee]
          if (!from || !to) return null
          const highlighted = focused === edge.caller || focused === edge.callee
          const distance = Math.hypot(to.x - from.x, to.y - from.y)
          const ratio = distance ? Math.max(0, distance - 10) / distance : 0
          return (
            <path
              key={`${edge.caller}:${edge.callee}`}
              d={
                distance
                  ? `M${from.x},${from.y} L${from.x + (to.x - from.x) * ratio},${from.y + (to.y - from.y) * ratio}`
                  : `M${from.x},${from.y - 7} c-30,-35 30,-35 0,0`
              }
              fill="none"
              stroke={
                highlighted ? "var(--foreground)" : "var(--muted-foreground)"
              }
              strokeOpacity={focused ? (highlighted ? 0.9 : 0.08) : 0.25}
              strokeWidth={highlighted ? 1.8 : 1}
              markerEnd={highlighted ? `url(#${marker})` : undefined}
            />
          )
        })}
        {graph.nodes.map((node) => {
          const position = layout.positions[node.id]
          if (!position) return null
          const active = running.has(node.id)
          return (
            <g
              key={node.id}
              className="graph-node"
              role="button"
              tabIndex={0}
              aria-label={`${node.proposedName || node.name}, ${node.address}${active ? ", analyzing" : ""}${node.stale ? ", needs reconsideration" : ""}`}
              onPointerEnter={() => setFocused(node.id)}
              onPointerLeave={() => setFocused(null)}
              onFocus={(event) => {
                setFocused(node.id)
                if (event.currentTarget.matches(":focus-visible"))
                  setView((current) => ({
                    ...current,
                    x: position.x - current.width / 2,
                    y: position.y - current.height / 2,
                  }))
              }}
              onBlur={() => setFocused(null)}
              onClick={() => {
                if (!drag.current?.moved) onSelect(node.id)
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault()
                  onSelect(node.id)
                }
              }}
              opacity={focused && !adjacent.has(node.id) ? 0.2 : 1}
            >
              <title>
                {node.proposedName || node.name} · {node.address}
              </title>
              <circle
                cx={position.x}
                cy={position.y}
                r={active ? 10 : 7}
                fill={
                  node.resultId ? "var(--primary)" : "var(--muted-foreground)"
                }
                stroke={node.stale ? "var(--foreground)" : "var(--background)"}
                strokeWidth={2}
              />
            </g>
          )
        })}
      </svg>
      <p className="min-h-6 font-mono text-sm break-all">
        {selected
          ? `${selected.proposedName || selected.name} · ${selected.address}`
          : "Larger nodes are active; outlined nodes need reconsideration. Arrows show caller to callee."}
      </p>
    </div>
  )
}
