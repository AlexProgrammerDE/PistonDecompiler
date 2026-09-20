import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import type { AnalysisResult } from "@/gen/piston/v1/piston_pb"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
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
export function ResultDetails({ result }: { result: AnalysisResult }) {
  const [reference, setReference] = useState<Reference>()
  const analysis = parseAnalysis(result.analysisJson)
  const automation: Record<string, string> = JSON.parse(
    result.automationJson || "{}"
  )
  return (
    <section className="proposal flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h4>
          {result.author === "human" ? "Saved correction" : "Analysis proposal"}
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
          comparison. Automatic recovery reanalyzes affected functions.
        </p>
      ) : null}
      <div className="flex flex-col gap-1 text-sm">
        <p>Name: {automation.name || "Awaiting automatic validation"}</p>
        <p>Summary: {automation.summary || "Awaiting automatic validation"}</p>
        <p>
          Types and signatures:{" "}
          {automation.types || "Awaiting automatic validation"}
        </p>
        {automation.reason ? (
          <p className="text-muted-foreground">{automation.reason}</p>
        ) : null}
      </div>
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
          <summary
            className="truncate"
            title={`${result.proposedName} · ${result.author}`}
          >
            {result.proposedName} · {result.author} ·{" "}
            {result.id === currentId ? "Current" : "Earlier or alternative"}
          </summary>
          <ResultDetails
            key={`${result.id}:${result.revision}`}
            result={result}
          />
        </details>
      ))}
    </details>
  )
}
