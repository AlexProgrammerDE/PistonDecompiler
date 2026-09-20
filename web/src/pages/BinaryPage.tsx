import { Recordings } from "@/components/Recordings"
import { ProgressReport } from "@/components/ProgressReport"
import { InvestigationWorkbench } from "@/components/InvestigationWorkbench"
import { ApplyChanges } from "@/components/ApplyChanges"
import { LiveAnalysis, useLiveAnalysis } from "@/components/LiveAnalysis"
import { lazy, Suspense, useCallback } from "react"
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router"
import { useMutation, useQuery } from "@tanstack/react-query"
import {
  PlayIcon,
  PauseIcon,
  ArrowClockwiseIcon,
  DownloadSimpleIcon,
} from "@phosphor-icons/react"
import {
  api,
  overviewQuery,
  jobsQuery,
  eventsQuery,
  settingsQuery,
  invalidateBinary,
} from "@/lib/api"
import { bytes, count, dateTime, money } from "@/lib/format"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { ErrorNotice, EmptyNotice, LoadingRows } from "@/components/Feedback"
import { FunctionTable } from "@/components/FunctionTable"
import { FunctionDetail } from "@/components/FunctionDetail"
import {
  Table,
  TableHead,
  TableHeader,
  TableRow,
  TableCell,
  TableBody,
} from "@/components/ui/table"
const UsageChart = lazy(() => import("@/components/UsageChart"))
export type BinaryView =
  | "functions"
  | "pipeline"
  | "usage"
  | "events"
  | "investigations"
  | "live"
  | "recordings"
const views: { id: BinaryView; label: string }[] = [
  { id: "functions", label: "Functions" },
  { id: "recordings", label: "Recordings" },
  { id: "investigations", label: "Investigations" },
  { id: "live", label: "Live graph" },
  { id: "pipeline", label: "Pipeline" },
  { id: "usage", label: "Usage & cost" },
  { id: "events", label: "Events" },
]
export function BinaryPage() {
  const { binaryId } = useParams({ from: "/binaries/$binaryId" })
  const { view, functionId: selected = "" } = useSearch({
    from: "/binaries/$binaryId",
  })
  const navigate = useNavigate({ from: "/binaries/$binaryId" })
  const query = useQuery(overviewQuery(binaryId))
  const settings = useQuery(settingsQuery)
  const connected = useLiveAnalysis(binaryId)
  const onSelect = useCallback(
    (id: string) => {
      void navigate({ search: { view: "functions", functionId: id } })
    },
    [navigate]
  )
  const mutation = useMutation({
    mutationFn: (action: string) => api.controlPipeline({ binaryId, action }),
    onSuccess: () => invalidateBinary(binaryId),
  })
  const o = query.data
  const b = o?.binary
  const canExtract =
    b && ["imported", "failed", "interrupted"].includes(b.status)
  return (
    <>
      <header className="page-header">
        <div className="w-full min-w-0 flex-1">
          <div className="flex items-center gap-3">
            <h1 className="min-w-0 truncate" title={b?.name}>
              {b?.name ?? "Binary analysis"}
            </h1>
            {b ? <Badge variant="outline">{b.status}</Badge> : null}
          </div>
          <p>Ghidra desktop: {o?.ghidraDesktop || "Checking connection"}</p>
          <p aria-live="polite">
            {connected
              ? "Live updates connected"
              : "Connecting to live updates…"}
          </p>
          <p>
            {b
              ? `${b.format} · ${b.architecture} · ${bytes(b.size)}`
              : "Inspect indexed functions and analysis results."}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {canExtract ? (
            <Button
              disabled={mutation.isPending || !settings.data?.ghidraConfigured}
              onClick={() => mutation.mutate("extract")}
            >
              <DownloadSimpleIcon data-icon="inline-start" />
              Extract with Ghidra
            </Button>
          ) : null}
          <Button
            variant="outline"
            disabled={
              mutation.isPending ||
              o?.ghidraDesktop === "starting" ||
              !o?.functions ||
              !settings.data?.ghidraConfigured
            }
            onClick={() => mutation.mutate("open_ghidra")}
          >
            {o?.ghidraDesktop === "connected"
              ? "Show Ghidra"
              : "Open in Ghidra"}
          </Button>
          <Button
            variant="outline"
            disabled={
              mutation.isPending ||
              !o ||
              o.functions === 0 ||
              !settings.data?.aiConfigured
            }
            onClick={() => mutation.mutate(o?.paused ? "resume" : "pause")}
          >
            {o?.paused ? (
              <PlayIcon data-icon="inline-start" />
            ) : (
              <PauseIcon data-icon="inline-start" />
            )}
            {o?.paused ? "Run analysis" : "Pause analysis"}
          </Button>
        </div>
      </header>
      {o?.activeRunId ? (
        <div className="page-body">
          <p>
            Analysis is scoped to the latest investigation or selection. Other
            queued work is held.
          </p>
          <Button
            variant="outline"
            disabled={mutation.isPending}
            onClick={() => mutation.mutate("all")}
          >
            Include all queued work
          </Button>
        </div>
      ) : null}
      <ProgressReport binaryId={binaryId} />
      <div className="summary-strip">
        <div>
          <span>Functions</span>
          <strong>
            {o ? count(o.functions) : <Skeleton className="h-6 w-16" />}
          </strong>
        </div>
        <div>
          <span>Analyzed</span>
          <strong>
            {o ? (
              `${count(o.analyzed)} / ${count(o.functions)}`
            ) : (
              <Skeleton className="h-6 w-16" />
            )}
          </strong>
        </div>
        <div>
          <span>Call edges</span>
          <strong>
            {o ? count(o.edges) : <Skeleton className="h-6 w-16" />}
          </strong>
        </div>
        <div>
          <span>Awaiting validation</span>
          <strong>
            {o ? count(o.proposals) : <Skeleton className="h-6 w-16" />}
          </strong>
        </div>
        <div>
          <span>Reported cost</span>
          <strong>
            {o ? money(o.costUsd) : <Skeleton className="h-6 w-24" />}
          </strong>
        </div>
      </div>
      <div className="page-notices">
        <ErrorNotice error={query.error} />
        <ErrorNotice error={mutation.error} />
        {b?.error ? <ErrorNotice error={new Error(b.error)} /> : null}
      </div>
      <nav className="view-tabs" aria-label="Analysis views">
        {views.map((v) => (
          <Link
            key={v.id}
            to="/binaries/$binaryId"
            params={{ binaryId }}
            search={{ view: v.id, functionId: selected }}
            className={view === v.id ? "view-tab selected" : "view-tab"}
            onClick={(e) => {
              e.preventDefault()
              void navigate({ search: { view: v.id, functionId: selected } })
            }}
          >
            {v.label}
          </Link>
        ))}
      </nav>
      {view === "recordings" ? <Recordings binaryId={binaryId} /> : null}
      {view === "functions" ? (
        <div className="workbench">
          <FunctionTable
            key={binaryId}
            binaryId={binaryId}
            selected={selected}
            onSelect={onSelect}
          />
          <FunctionDetail
            id={selected.startsWith(binaryId + ":") ? selected : ""}
            binaryId={binaryId}
            onSelect={onSelect}
          />
        </div>
      ) : null}
      {view === "pipeline" ? (
        <div className="page-body">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2>Persistent job queue</h2>
            <div className="flex gap-2">
              <Button
                variant="outline"
                disabled={mutation.isPending}
                onClick={() => mutation.mutate("retry")}
              >
                <ArrowClockwiseIcon data-icon="inline-start" />
                Retry failed jobs
              </Button>
            </div>
          </div>
          <p className="text-sm text-muted-foreground">
            Pause stops new requests. Active requests finish and save their
            results. Retrying an uncertain request can incur another provider
            charge.
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Pass</TableHead>
                <TableHead>Queued</TableHead>
                <TableHead>Running / batch</TableHead>
                <TableHead>Completed</TableHead>
                <TableHead>Failed / uncertain</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {o?.stages.map((s) => (
                <TableRow key={s.name}>
                  <TableCell>{s.name}</TableCell>
                  <TableCell>{s.queued}</TableCell>
                  <TableCell>{s.running}</TableCell>
                  <TableCell>{s.completed}</TableCell>
                  <TableCell>{s.failed}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Jobs binaryId={binaryId} />
          <ApplyChanges binaryId={binaryId} />
        </div>
      ) : null}
      {view === "usage" ? (
        <div className="page-body">
          <section>
            <h2>Token usage</h2>
            {o?.usage.length ? (
              <Suspense fallback={<Skeleton className="h-72 w-full" />}>
                <UsageChart points={o.usage} />
              </Suspense>
            ) : (
              <EmptyNotice
                title="No provider usage yet"
                description="Recorded token usage appears after AI requests complete."
              />
            )}
          </section>
          <section className="settings-section">
            <h2>Accounting</h2>
            <dl className="property-list">
              <dt>Input tokens</dt>
              <dd>{count(o?.inputTokens ?? 0n)}</dd>
              <dt>Output tokens</dt>
              <dd>{count(o?.outputTokens ?? 0n)}</dd>
              <dt>Provider-reported cost</dt>
              <dd>{money(o?.costUsd)}</dd>
              <dt>Requests without reported cost</dt>
              <dd>{o?.unreportedCostRequests ?? "Loading"}</dd>
              <dt>Graph modules</dt>
              <dd>{o?.modules ?? 0}</dd>
            </dl>
            <p>
              Only charges returned by the provider are included. Requests
              without billing data remain unknown, so the reported subtotal can
              be incomplete. Spending limits are managed by your provider.
            </p>
          </section>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hour (UTC)</TableHead>
                <TableHead>Requests</TableHead>
                <TableHead>Input</TableHead>
                <TableHead>Output</TableHead>
                <TableHead>Reported cost</TableHead>
                <TableHead>Cost unknown</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {o?.usage.map((p) => (
                <TableRow key={p.bucket}>
                  <TableCell>{p.bucket}</TableCell>
                  <TableCell>{p.requests}</TableCell>
                  <TableCell>{count(p.inputTokens)}</TableCell>
                  <TableCell>{count(p.outputTokens)}</TableCell>
                  <TableCell>{money(p.costUsd)}</TableCell>
                  <TableCell>{p.unreportedCostRequests}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <section>
            <h2>Provider breakdown</h2>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Model</TableHead>
                  <TableHead>Pass</TableHead>
                  <TableHead>Requests</TableHead>
                  <TableHead>Average latency</TableHead>
                  <TableHead>Input / output</TableHead>
                  <TableHead>Reported cost</TableHead>
                  <TableHead>Cost unknown</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {o?.providerBreakdowns.map((item) => (
                  <TableRow key={`${item.model}:${item.stage}`}>
                    <TableCell className="font-mono">{item.model}</TableCell>
                    <TableCell>{item.stage}</TableCell>
                    <TableCell>{count(item.requests)}</TableCell>
                    <TableCell>
                      {item.averageLatencyMs === undefined
                        ? "Unknown"
                        : `${Math.round(item.averageLatencyMs).toLocaleString()} ms`}
                    </TableCell>
                    <TableCell>
                      {count(item.inputTokens)} / {count(item.outputTokens)}
                    </TableCell>
                    <TableCell>{money(item.costUsd)}</TableCell>
                    <TableCell>{item.unreportedCostRequests}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {o?.providerBreakdowns.length === 0 ? (
              <EmptyNotice
                title="No provider requests"
                description="Usage appears when the provider returns a response."
              />
            ) : null}
          </section>
        </div>
      ) : null}
      {view === "investigations" ? (
        <div className="page-body">
          <InvestigationWorkbench
            binaryId={binaryId}
            selected={selected}
            onSelect={onSelect}
          />
        </div>
      ) : null}
      {view === "live" ? (
        <div className="page-body">
          <LiveAnalysis binaryId={binaryId} onSelect={onSelect} />
        </div>
      ) : null}
      {view === "events" ? <Events binaryId={binaryId} /> : null}
    </>
  )
}
function Jobs({ binaryId }: { binaryId: string }) {
  const query = useQuery(jobsQuery(binaryId))
  return (
    <section>
      <div className="section-heading">
        <h2>Latest jobs</h2>
        <span>Up to 500 jobs</span>
      </div>
      <ErrorNotice error={query.error} />
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Function</TableHead>
            <TableHead>Pass</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Attempts</TableHead>
            <TableHead>Last attempt</TableHead>
            <TableHead>Details</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {query.data?.jobs.map((job) => (
            <TableRow key={job.id}>
              <TableCell className="font-mono">
                <span className="block max-w-64 truncate" title={job.name}>
                  {job.name}
                </span>
              </TableCell>
              <TableCell>{job.stage}</TableCell>
              <TableCell>{job.status}</TableCell>
              <TableCell>{job.attempts}</TableCell>
              <TableCell>
                {job.startedAt > 0n
                  ? `${Math.max(0, Number((job.finishedAt || (job.status === "running" ? BigInt(Math.floor(query.dataUpdatedAt / 1000)) : job.updatedAt)) - job.startedAt))}s`
                  : "No timing data"}
              </TableCell>
              <TableCell className="max-w-lg whitespace-normal">
                {job.error || ""}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {query.isPending ? <LoadingRows /> : null}
      {query.data?.jobs.length === 0 ? (
        <EmptyNotice
          title="No analysis jobs"
          description="Extract this binary to create the function analysis queue."
        />
      ) : null}
    </section>
  )
}
function Events({ binaryId }: { binaryId: string }) {
  const query = useQuery(eventsQuery(binaryId))
  return (
    <div className="page-body">
      <div className="section-heading">
        <h2>Pipeline events</h2>
        <span>Latest 200</span>
      </div>
      <ErrorNotice error={query.error} />
      {query.isPending ? <LoadingRows /> : null}
      <ol className="event-list">
        {query.data?.events.map((event) => (
          <li key={event.id.toString()}>
            <time>{dateTime(event.createdAt)}</time>
            <Badge
              variant={event.level === "error" ? "destructive" : "outline"}
            >
              {event.level}
            </Badge>
            <p>{event.message}</p>
          </li>
        ))}
      </ol>
    </div>
  )
}
