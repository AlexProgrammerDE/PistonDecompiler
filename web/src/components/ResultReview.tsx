import { useState } from "react"
import { useMutation, useQuery } from "@tanstack/react-query"
import { api, invalidateBinary } from "@/lib/api"
import type { AnalysisResult } from "@/gen/piston/v1/piston_pb"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { ErrorNotice } from "@/components/Feedback"

type Reference = { artifact_id: string; start_line: number; end_line: number }
type Claim = { text: string; references: Reference[] }
function parseAnalysis(raw: string): {
  claims: Claim[]
  evidence: string[]
  uncertainties: string[]
} {
  try {
    const value = JSON.parse(raw)
    return {
      claims: value.claims ?? [],
      evidence: value.evidence ?? [],
      uncertainties: value.uncertainties ?? [],
    }
  } catch {
    return { claims: [], evidence: [], uncertainties: [] }
  }
}
export function ResultReview({
  result,
  binaryId,
}: {
  result: AnalysisResult
  binaryId: string
}) {
  const [name, setName] = useState(result.proposedName)
  const [summary, setSummary] = useState(result.summary)
  const [reason, setReason] = useState("")
  const [editing, setEditing] = useState(false)
  const [reference, setReference] = useState<Reference>()
  const analysis = parseAnalysis(result.analysisJson)
  const reanalyze = useMutation({
    mutationFn: () =>
      api.reanalyze({ binaryId, functionIds: [result.functionId] }),
    onSuccess: () => invalidateBinary(binaryId),
  })
  const review = useMutation({
    mutationFn: ({ field, decision }: { field: string; decision: string }) =>
      api.reviewProposal({
        resultId: result.id,
        expectedRevision: result.revision,
        field,
        decision,
        reason,
      }),
    onSuccess: () => invalidateBinary(binaryId),
  })
  const correction = useMutation({
    mutationFn: () =>
      api.correctResult({
        resultId: result.id,
        expectedRevision: result.revision,
        proposedName: name,
        summary,
        reason,
      }),
    onSuccess: () => invalidateBinary(binaryId),
  })
  return (
    <section className="proposal flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h4>
          {result.author === "human"
            ? "Reviewed correction"
            : "Analysis proposal"}
        </h4>
        <Badge variant="outline">
          {result.stale ? "Needs reconsideration" : result.author}
        </Badge>
      </div>
      <p>{result.summary}</p>
      <p className="text-xs text-muted-foreground">
        {result.model || "Human-authored"} · {result.stage}
      </p>
      {result.stale ? (
        <p>
          Supporting context changed. This conclusion remains available for
          review and comparison.
        </p>
      ) : null}
      {[
        { field: "name", label: "Name", state: result.nameReview },
        { field: "summary", label: "Summary", state: result.summaryReview },
      ].map((item) => (
        <div className="flex flex-wrap items-center gap-2" key={item.field}>
          <span>
            {item.label}: {item.state}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={
              result.stale || review.isPending || item.state === "accepted"
            }
            onClick={() =>
              review.mutate({ field: item.field, decision: "accepted" })
            }
          >
            Accept {item.field}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={
              result.stale || review.isPending || item.state === "rejected"
            }
            onClick={() =>
              review.mutate({ field: item.field, decision: "rejected" })
            }
          >
            Reject {item.field}
          </Button>
        </div>
      ))}
      {analysis.claims.map((claim) => (
        <div className="flex flex-col gap-2" key={claim.text}>
          <p>{claim.text}</p>
          <div className="flex flex-wrap gap-2">
            {claim.references.map((ref) => (
              <Button
                key={`${ref.artifact_id}:${ref.start_line}:${ref.end_line}`}
                variant="link"
                size="sm"
                onClick={() => setReference(ref)}
              >
                Evidence, lines {ref.start_line}–{ref.end_line}
              </Button>
            ))}
          </div>
        </div>
      ))}
      {analysis.claims.length === 0 && analysis.evidence.length ? (
        <details>
          <summary>Unlinked evidence observations</summary>
          <ul>
            {analysis.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </details>
      ) : null}
      {analysis.uncertainties.length ? (
        <section>
          <h4>Unresolved questions</h4>
          <ul>
            {analysis.uncertainties.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
      ) : null}
      {reference ? <EvidenceViewer reference={reference} /> : null}
      <Button
        variant="outline"
        size="sm"
        disabled={reanalyze.isPending}
        onClick={() => reanalyze.mutate()}
      >
        Queue reanalysis of this function
      </Button>
      {reanalyze.isSuccess ? (
        <p role="status">Queued. Use Run analysis to start requests.</p>
      ) : null}
      <Button variant="outline" size="sm" onClick={() => setEditing(!editing)}>
        Correct this interpretation
      </Button>
      {editing ? (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            correction.mutate()
          }}
          className="flex flex-col gap-3"
        >
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor={`name-${result.id}`}>
                Function name
              </FieldLabel>
              <Input
                id={`name-${result.id}`}
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor={`summary-${result.id}`}>
                Behavior summary
              </FieldLabel>
              <Textarea
                id={`summary-${result.id}`}
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor={`reason-${result.id}`}>
                Reason for correction
              </FieldLabel>
              <Textarea
                id={`reason-${result.id}`}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                required
              />
            </Field>
          </FieldGroup>
          <Button type="submit" disabled={correction.isPending}>
            Save reviewed correction
          </Button>
        </form>
      ) : null}
      <ErrorNotice
        error={review.error ?? correction.error ?? reanalyze.error}
      />
      <details>
        <summary>Exact analysis inputs</summary>
        <pre className="code-view">
          {result.inputJson ||
            "No request recorded for this legacy or human-authored result."}
        </pre>
      </details>
      <details>
        <summary>Request and tool transcript</summary>
        <pre className="code-view">{result.transcriptJson}</pre>
      </details>
    </section>
  )
}
function EvidenceViewer({ reference }: { reference: Reference }) {
  const query = useQuery({
    queryKey: ["artifact", reference.artifact_id],
    queryFn: ({ signal }) =>
      api.getArtifact({ id: reference.artifact_id }, { signal }),
  })
  return (
    <section aria-label="Cited evidence">
      <ErrorNotice error={query.error} />
      <h4>{query.data?.kind ?? "Loading evidence"}</h4>
      <pre className="code-view">
        {query.data?.content
          .split("\n")
          .map(
            (line, index) =>
              `${index + 1 >= reference.start_line && index + 1 <= reference.end_line ? ">" : " "} ${index + 1}: ${line}`
          )
          .join("\n")}
      </pre>
      {query.data ? (
        <details>
          <summary>Extraction provenance</summary>
          <pre className="code-view">{query.data.metadataJson}</pre>
          <p className="break-all">SHA-256: {query.data.sha256}</p>
        </details>
      ) : null}
    </section>
  )
}
export function ResultHistory({
  functionId,
  binaryId,
  currentId,
}: {
  functionId: string
  binaryId: string
  currentId: string
}) {
  const query = useQuery({
    queryKey: ["binary", binaryId, "history", functionId],
    queryFn: ({ signal }) => api.listResults({ id: functionId }, { signal }),
  })
  return (
    <details>
      <summary>Interpretation history</summary>
      <ErrorNotice error={query.error} />
      {query.data?.results.map((result) => (
        <details key={result.id}>
          <summary>
            {result.proposedName} · {result.author} ·{" "}
            {result.id === currentId ? "Current" : "Earlier or alternative"}
          </summary>
          <ResultReview
            key={`${result.id}:${result.revision}`}
            result={result}
            binaryId={binaryId}
          />
        </details>
      ))}
    </details>
  )
}
