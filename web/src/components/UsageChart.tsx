import { useMemo } from "react"
import { barY, defineChart } from "@tanstack/charts"
import { scaleBand } from "@tanstack/charts/scales/band"
import { scaleLinear } from "@tanstack/charts/scales/linear"
import { Chart } from "@tanstack/charts/react"
import { tooltip } from "@tanstack/charts/tooltip"
import type { UsagePoint } from "@/gen/piston/v1/piston_pb"
export default function UsageChart({ points }: { points: UsagePoint[] }) {
  const definition = useMemo(
    () =>
      defineChart({
        marks: [
          barY(
            points.map((p) => ({
              hour: p.bucket,
              tokens: Number(p.inputTokens + p.outputTokens),
            })),
            { x: "hour", y: "tokens", fill: "var(--chart-3)" }
          ),
        ],
        scales: {
          x: {
            scale: () => scaleBand().padding(0.25),
            axis: { label: "Hour (UTC)" },
          },
          y: {
            scale: scaleLinear,
            nice: true,
            grid: true,
            axis: { label: "Tokens" },
          },
        },
        tooltip,
      }),
    [points]
  )
  return (
    <Chart
      definition={definition}
      height={280}
      ariaLabel="Provider token usage by hour"
    />
  )
}
