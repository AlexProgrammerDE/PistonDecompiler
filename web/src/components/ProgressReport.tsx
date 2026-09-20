import { useQuery } from "@tanstack/react-query"
import { overviewQuery } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Progress, ProgressLabel } from "@/components/ui/progress"
import { ErrorNotice } from "@/components/Feedback"

function duration(seconds: bigint) {
  const n = Math.max(0, Number(seconds))
  if (n < 60) return `${Math.floor(n)}s`
  if (n < 3600) return `${Math.floor(n / 60)}m ${Math.floor(n % 60)}s`
  return `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m`
}

export function ProgressReport({
  binaryId,
  compact = false,
}: {
  binaryId: string
  compact?: boolean
}) {
  const query = useQuery(overviewQuery(binaryId))
  const reports = query.data?.progress ?? []
  const active = reports.filter(
    (r) =>
      ![
        "completed",
        "ready",
        "indexed",
        "applied",
        "stable",
        "deferred",
        "unchanged",
      ].includes(r.status)
  )
  const shown = compact
    ? (active.length ? active : reports).slice(0, 1)
    : reports
  function download() {
    const blob = new Blob(
      [
        JSON.stringify(
          {
            generatedAt: new Date().toISOString(),
            binaryId,
            scope: query.data?.activeRunId || "All runs",
            reports,
          },
          (_, value) => (typeof value === "bigint" ? value.toString() : value),
          2
        ),
      ],
      { type: "application/json" }
    )
    const url = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = url
    link.download = `piston-status-${binaryId}.json`
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return (
    <section
      aria-label="Progress report"
      className={
        compact
          ? "mt-2 flex flex-col gap-2 text-xs"
          : "flex flex-col gap-3 border-b px-6 py-4"
      }
    >
      {!compact && (
        <div className="flex items-center justify-between gap-3">
          <h2>Progress</h2>
          <Button variant="outline" size="sm" onClick={download}>
            Download status report
          </Button>
        </div>
      )}
      <ErrorNotice error={query.error} />
      {!compact && (
        <p className="text-xs text-muted-foreground">
          {query.data?.activeRunId ? "Current run" : "All runs"} · Refreshes
          every 2 seconds ·{" "}
          {query.dataUpdatedAt
            ? `Updated ${new Date(query.dataUpdatedAt).toLocaleTimeString()}`
            : "Waiting for status"}
        </p>
      )}
      {shown.map((r) => (
        <div key={r.phase} className="flex min-w-0 flex-col gap-2">
          <Progress value={r.total ? (100 * r.completed) / r.total : null}>
            <ProgressLabel>
              {r.phase.replaceAll("_", " ")}{" "}
              {r.total > 0 &&
                `· ${r.completed.toLocaleString()} / ${r.total.toLocaleString()}`}
            </ProgressLabel>
            <Badge
              variant={
                [
                  "failed",
                  "needs attention",
                  "blocked",
                  "uncertain",
                  "interrupted",
                ].includes(r.status)
                  ? "destructive"
                  : "outline"
              }
            >
              {r.status}
            </Badge>
          </Progress>
          <p className="text-xs text-muted-foreground tabular-nums">
            Elapsed {duration(r.elapsedSeconds)} ·{" "}
            {r.etaSeconds >= 0n
              ? `Estimated remaining ${duration(r.etaSeconds)}`
              : [
                    "completed",
                    "ready",
                    "indexed",
                    "applied",
                    "stable",
                    "deferred",
                    "unchanged",
                  ].includes(r.status)
                ? "Finished"
                : "ETA unavailable"}
          </p>
          {!compact && r.detail && (
            <p className="max-h-24 overflow-auto text-xs break-words text-muted-foreground">
              {r.detail}
            </p>
          )}
        </div>
      ))}
      {!reports.length && !compact && (
        <p className="text-sm text-muted-foreground">
          No work started. Progress appears when extraction or analysis begins.
        </p>
      )}
    </section>
  )
}
