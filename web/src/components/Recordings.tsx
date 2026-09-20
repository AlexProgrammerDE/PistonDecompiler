import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import { useState } from "react"
import { useMutation, useQuery } from "@tanstack/react-query"
import { api, invalidateBinary } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldDescription,
} from "@/components/ui/field"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from "@/components/ui/table"
import { ErrorNotice, EmptyNotice, LoadingRows } from "@/components/Feedback"
import { dateTime } from "@/lib/format"
import type { Recording } from "@/gen/piston/v1/piston_pb"

type CaptureProgress = {
  skipped_functions?: number
  counts?: Record<string, number>
  events?: number
  elapsed_seconds?: number
  remaining_seconds?: number
  dropped_events?: number
  markers?: number
  last_marker?: string
  shortcut_command?: string
  hotkey?: string
  pid?: number
  state?: string
}
function parse<T>(value: string): T {
  try {
    return JSON.parse(value)
  } catch {
    return {} as T
  }
}
const activeStates = new Set(["starting", "recording", "stopping", "importing"])

export function Recordings({ binaryId }: { binaryId: string }) {
  const [mode, setMode] = useState("explore")
  const [target, setTarget] = useState("launch")
  const [memory, setMemory] = useState(false)
  const [selected, setSelected] = useState<string[]>([])
  const [search, setSearch] = useState("")
  const recordings = useQuery({
    queryKey: ["binary", binaryId, "recordings"],
    queryFn: ({ signal }) => api.listRecordings({ binaryId }, { signal }),
    refetchInterval: 1000,
  })
  const functions = useQuery({
    queryKey: ["binary", binaryId, "capture-functions", search],
    queryFn: ({ signal }) =>
      api.listFunctions({ binaryId, search, limit: 50 }, { signal }),
  })
  const start = useMutation({
    mutationFn: (form: FormData) =>
      api.startRecording({
        binaryId,
        scenario: String(form.get("scenario")),
        executable: String(form.get("executable")),
        mode,
        pid: target === "attach" ? Number(form.get("pid")) : 0,
        seconds: Number(form.get("seconds")),
        arguments: String(form.get("arguments") || "")
          .split("\n")
          .filter(Boolean),
        workingDirectory: String(form.get("cwd") || ""),
        functionIds: selected,
        argumentCount: Number(form.get("argumentCount") || 0),
        snapshotBytes: Number(form.get("snapshotBytes") || 0),
        traceMemory: mode === "investigate" && memory,
      }),
    onSuccess: () => invalidateBinary(binaryId),
  })
  const active = recordings.data?.recordings.find((r) =>
    activeStates.has(r.status)
  )
  return (
    <section
      className="flex flex-col gap-6 px-6 py-4"
      aria-label="Runtime recordings"
    >
      <div>
        <h2>Record an application session</h2>
        <p className="text-muted-foreground">
          Use the application normally. Stop to import its execution evidence,
          then choose Analyze to send the evidence to your model.
        </p>
      </div>
      {active ? (
        <RecordingControls recording={active} binaryId={binaryId} />
      ) : null}
      <form
        onSubmit={(event) => {
          event.preventDefault()
          start.mutate(new FormData(event.currentTarget))
        }}
      >
        <FieldGroup className="max-w-3xl">
          <Field>
            <FieldLabel>Capture level</FieldLabel>
            <ToggleGroup
              value={[mode]}
              onValueChange={(values) => {
                if (values[0]) setMode(values[0])
              }}
            >
              <ToggleGroupItem value="explore">Explore</ToggleGroupItem>
              <ToggleGroupItem value="investigate">Investigate</ToggleGroupItem>
            </ToggleGroup>
            <FieldDescription>
              {mode === "explore"
                ? "Broad function coverage with low-volume samples. No argument snapshots or detailed paths."
                : "Selected functions, ordered calls and blocks, argument slots, and entry/return snapshots."}
            </FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="capture-scenario">Scenario</FieldLabel>
            <Input
              id="capture-scenario"
              name="scenario"
              placeholder="Take damage, open inventory, load a save…"
              required
              maxLength={256}
            />
          </Field>
          <Field>
            <FieldLabel>Target</FieldLabel>
            <ToggleGroup
              value={[target]}
              onValueChange={(values) => {
                if (values[0]) setTarget(values[0])
              }}
            >
              <ToggleGroupItem value="launch">
                Launch and record
              </ToggleGroupItem>
              <ToggleGroupItem value="attach">
                Attach to process
              </ToggleGroupItem>
            </ToggleGroup>
          </Field>
          <Field>
            <FieldLabel htmlFor="capture-executable">
              Original executable path
            </FieldLabel>
            <Input
              id="capture-executable"
              name="executable"
              required
              placeholder="/path/to/application"
            />
            <FieldDescription>
              The executable must match the imported binary. Choose the original
              installation so its resources are available.
            </FieldDescription>
          </Field>
          {target === "attach" ? (
            <Field>
              <FieldLabel htmlFor="capture-pid">Process ID</FieldLabel>
              <Input
                id="capture-pid"
                name="pid"
                type="number"
                min={1}
                required
              />
              <FieldDescription>
                Objects created before attachment have unknown allocation
                lifetimes.
              </FieldDescription>
            </Field>
          ) : (
            <>
              <Field>
                <FieldLabel htmlFor="capture-cwd">
                  Working directory (optional)
                </FieldLabel>
                <Input
                  id="capture-cwd"
                  name="cwd"
                  placeholder="Defaults to the executable directory"
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="capture-arguments">
                  Launch arguments (one per line)
                </FieldLabel>
                <Textarea id="capture-arguments" name="arguments" />
              </Field>
            </>
          )}
          <Field>
            <FieldLabel htmlFor="capture-seconds">
              Maximum duration in seconds
            </FieldLabel>
            <Input
              id="capture-seconds"
              name="seconds"
              type="number"
              min={1}
              max={3600}
              defaultValue={300}
              required
            />
            <FieldDescription>
              You can stop sooner. The application stays open when recording
              ends.
            </FieldDescription>
          </Field>
          <Collapsible>
            <CollapsibleTrigger
              render={<Button type="button" variant="outline" />}
            >
              Capture scope (
              {selected.length
                ? `${selected.length} selected`
                : "all eligible functions"}
              )
            </CollapsibleTrigger>
            <CollapsibleContent className="pt-3">
              <Field>
                <FieldLabel htmlFor="capture-search">
                  Select functions ({selected.length}/200)
                </FieldLabel>
                <Input
                  id="capture-search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search function names or addresses"
                />
                <FieldDescription>
                  Investigate requires a selection. Explore uses all eligible
                  functions when none are selected (up to 10,000). Selection is
                  retained during search.
                </FieldDescription>
                <div className="max-h-64 overflow-auto">
                  <FieldGroup>
                    {functions.data?.functions
                      .filter((f) => !f.skipReason)
                      .map((f) => (
                        <Field key={f.id} orientation="horizontal">
                          <Checkbox
                            id={`capture-${f.id}`}
                            checked={selected.includes(f.id)}
                            onCheckedChange={(checked) =>
                              setSelected((previous) =>
                                checked
                                  ? [...previous, f.id]
                                  : previous.filter((id) => id !== f.id)
                              )
                            }
                            disabled={
                              !selected.includes(f.id) && selected.length >= 200
                            }
                          />
                          <FieldLabel htmlFor={`capture-${f.id}`}>
                            {f.name} · {f.address}
                          </FieldLabel>
                        </Field>
                      ))}
                  </FieldGroup>
                </div>
                <ErrorNotice error={functions.error} />
              </Field>
            </CollapsibleContent>
          </Collapsible>
          {mode === "investigate" ? (
            <>
              <Field>
                <FieldLabel htmlFor="capture-slots">
                  Argument slots per call
                </FieldLabel>
                <Input
                  id="capture-slots"
                  name="argumentCount"
                  type="number"
                  min={0}
                  max={8}
                  defaultValue={4}
                />
                <FieldDescription>
                  Raw ABI slots are candidates, not confirmed parameters.
                  Floating-point and custom calling conventions need dedicated
                  adapters.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="capture-bytes">
                  Snapshot bytes per readable pointer
                </FieldLabel>
                <Input
                  id="capture-bytes"
                  name="snapshotBytes"
                  type="number"
                  min={0}
                  max={4096}
                  defaultValue={128}
                />
              </Field>
              <Field orientation="horizontal">
                <Checkbox
                  id="capture-memory"
                  checked={memory}
                  onCheckedChange={(v) => setMemory(v === true)}
                />
                <FieldLabel htmlFor="capture-memory">
                  Trace x86-64 MOV memory reads and writes
                </FieldLabel>
              </Field>
              <p className="text-sm text-muted-foreground">
                Detailed tracing can slow the application. Memory capture covers
                supported scalar MOV instructions in selected functions, not
                every memory access.
              </p>
            </>
          ) : null}
          <ErrorNotice error={start.error} />
          <Button
            type="submit"
            className="self-start"
            disabled={
              start.isPending ||
              !!active ||
              (mode === "investigate" && selected.length === 0)
            }
          >
            {start.isPending
              ? "Starting recorder…"
              : target === "attach"
                ? "Attach and record"
                : "Launch and record"}
          </Button>
        </FieldGroup>
      </form>
      <div className="flex flex-col gap-3">
        <h2>Saved recordings</h2>
        <ErrorNotice error={recordings.error} />
        {recordings.isPending ? <LoadingRows /> : null}
        {recordings.data?.recordings.length === 0 ? (
          <EmptyNotice
            title="No recordings yet"
            description="Record a scenario to add runtime evidence to this binary."
          />
        ) : null}
        {recordings.data?.recordings
          .filter((r) => r.id !== active?.id)
          .map((r) => (
            <RecordingControls key={r.id} recording={r} binaryId={binaryId} />
          ))}
      </div>
    </section>
  )
}
function RecordingControls({
  recording: r,
  binaryId,
}: {
  recording: Recording
  binaryId: string
}) {
  const [marker, setMarker] = useState("")
  const action = useMutation({
    mutationFn: ({ action, label = "" }: { action: string; label?: string }) =>
      api.controlRecording({ id: r.id, action, label }),
    onSuccess: () => invalidateBinary(binaryId),
  })
  const progress = parse<CaptureProgress>(r.progressJson)
  const coverage = parse<{
    observed_functions?: number
    new_functions?: number
  }>(r.coverageJson)
  const active = activeStates.has(r.status)
  return (
    <article className="flex flex-col gap-3 border-t pt-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3>{r.scenario}</h3>
        <span>
          {r.status} · {r.mode} · {dateTime(r.createdAt)}
        </span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Observations</TableHead>
            <TableHead>Elapsed</TableHead>
            <TableHead>Time limit remaining</TableHead>
            <TableHead>Dropped</TableHead>
            <TableHead>New functions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell>{progress.events ?? 0}</TableCell>
            <TableCell>{progress.elapsed_seconds ?? 0}s</TableCell>
            <TableCell>
              {active ? `${progress.remaining_seconds ?? "?"}s` : "Finished"}
            </TableCell>
            <TableCell>{progress.dropped_events ?? 0}</TableCell>
            <TableCell>{coverage.new_functions ?? "Pending import"}</TableCell>
          </TableRow>
        </TableBody>
      </Table>
      <p className="text-sm text-muted-foreground">
        {progress.markers ?? 0} markers
        {progress.last_marker ? ` · Latest: ${progress.last_marker}` : ""}
        {progress.pid ? ` · Process ${progress.pid}` : ""}
      </p>
      {progress.skipped_functions ? (
        <p>
          {progress.skipped_functions} functions could not be instrumented.
          Their absence is not evidence that they did not execute.
        </p>
      ) : null}
      {progress.counts ? (
        <p className="text-sm text-muted-foreground">
          {Object.entries(progress.counts)
            .map(([kind, count]) => `${count} ${kind}`)
            .join(" · ")}
        </p>
      ) : null}
      {progress.state === "interrupted" ? (
        <p>
          Target exited before a clean stop. Saved observations are partial.
        </p>
      ) : null}
      {active ? (
        <>
          <p className="text-sm text-muted-foreground">
            {progress.hotkey ?? "Preparing recorder…"}
          </p>
          {progress.shortcut_command ? (
            <p className="text-sm text-muted-foreground">
              For a desktop shortcut that follows the active session:{" "}
              <code className="break-all">{progress.shortcut_command}</code>
            </p>
          ) : null}
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              action.mutate({ action: "marker", label: marker })
              setMarker("")
            }}
          >
            <Field className="max-w-sm">
              <FieldLabel htmlFor={`marker-${r.id}`}>
                Scenario marker
              </FieldLabel>
              <Input
                id={`marker-${r.id}`}
                value={marker}
                onChange={(e) => setMarker(e.target.value)}
                maxLength={256}
                placeholder="Before damage"
              />
            </Field>
            <Button
              type="submit"
              variant="outline"
              disabled={action.isPending || r.status !== "recording"}
            >
              Add marker
            </Button>
            <Button
              type="button"
              onClick={() => action.mutate({ action: "stop" })}
              disabled={
                action.isPending ||
                !["starting", "recording"].includes(r.status)
              }
            >
              Stop and import
            </Button>
          </form>
        </>
      ) : (
        <div className="flex flex-wrap gap-2">
          {r.status === "ready" ? (
            <>
              <Button
                onClick={() => action.mutate({ action: "analyze" })}
                disabled={action.isPending}
              >
                {r.analysisRunId
                  ? "Resume analysis"
                  : "Analyze observed functions"}
              </Button>
              <Button
                variant="outline"
                onClick={() => action.mutate({ action: "publish" })}
                disabled={action.isPending}
              >
                Save evidence in Ghidra
              </Button>
            </>
          ) : null}
          {["failed", "interrupted"].includes(r.status) ? (
            <Button
              variant="outline"
              onClick={() => action.mutate({ action: "recover" })}
              disabled={action.isPending}
            >
              Recover saved recording
            </Button>
          ) : null}
        </div>
      )}
      {r.analysisRunId ? (
        <p className="text-sm">
          Analysis queued. Follow its status and ETA in Pipeline.
        </p>
      ) : null}
      <p className="text-sm text-muted-foreground">
        Ghidra evidence: {r.ghidraStatus}
      </p>
      {r.error ? <ErrorNotice error={new Error(r.error)} /> : null}
      <ErrorNotice error={action.error} />
    </article>
  )
}
