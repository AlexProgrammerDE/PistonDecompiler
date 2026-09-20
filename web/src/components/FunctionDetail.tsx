import { motion, useReducedMotion } from "motion/react"
import { ResultReview, ResultHistory } from "@/components/ResultReview"
import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { EmptyNotice, ErrorNotice, LoadingRows } from "@/components/Feedback"

export function FunctionDetail({
  id,
  binaryId,
  onSelect,
}: {
  id: string
  binaryId: string
  onSelect: (id: string) => void
}) {
  const reduced = useReducedMotion()
  const query = useQuery({
    queryKey: ["function", id],
    queryFn: ({ signal }) => api.getFunction({ id }, { signal }),
    enabled: !!id,
    refetchInterval: 3000,
  })
  const detail = query.data
  const f = detail?.function
  return (
    <aside className="detail-pane" aria-label="Function details">
      <div className="section-heading">
        <h2>Function evidence</h2>
        {f ? <code>{f.address}</code> : null}
      </div>
      {!id ? (
        <EmptyNotice
          title="Inspect a function"
          description="Select a function to read its decompiled code, references, and AI proposals."
        />
      ) : null}
      <ErrorNotice error={query.error} />
      {id && query.isPending ? <LoadingRows /> : null}
      {detail && f ? (
        <div className="detail-content">
          <div>
            <h3 className="truncate font-mono" title={f.proposedName || f.name}>
              {f.proposedName || f.name}
            </h3>
            <p className="mt-1 text-muted-foreground">
              {f.module} · {f.callers} callers · {f.callees} callees
            </p>
          </div>
          {detail.result ? (
            <>
              <ResultReview
                key={`${detail.result.id}:${detail.result.revision}`}
                result={detail.result}
                binaryId={binaryId}
              />
              <ResultHistory
                functionId={id}
                binaryId={binaryId}
                currentId={detail.result.id}
              />
            </>
          ) : (
            <p>
              {f.skipReason
                ? `Excluded from background analysis: ${f.skipReason}.`
                : "No analysis result yet. Select this function for an investigation."}
            </p>
          )}
          <Tabs defaultValue="code">
            <TabsList variant="line">
              <TabsTrigger value="code">Pseudocode</TabsTrigger>
              <TabsTrigger value="references">References</TabsTrigger>
              <TabsTrigger value="assembly">Assembly</TabsTrigger>
              <TabsTrigger value="analysis">Analysis</TabsTrigger>
              <TabsTrigger value="decisions">Assessments</TabsTrigger>
            </TabsList>
            <TabsContent value="code">
              <pre className="code-view">
                <code>
                  {detail.pseudocode || "Ghidra did not recover pseudocode."}
                </code>
              </pre>
            </TabsContent>
            <TabsContent value="assembly">
              <h4>Disassembly</h4>
              <pre className="code-view">
                <code>{detail.disassembly || "No disassembly exported."}</code>
              </pre>
              <h4>P-code</h4>
              <pre className="code-view">
                <code>{detail.pcode || "No P-code exported."}</code>
              </pre>
            </TabsContent>
            <TabsContent value="references">
              <div className="flex flex-col gap-4">
                {[
                  { title: "Callers", items: detail.callers },
                  { title: "Callees", items: detail.callees },
                ].map((group) => (
                  <section key={group.title}>
                    <h4>
                      {group.title}{" "}
                      <span className="text-muted-foreground">(up to 100)</span>
                    </h4>
                    {group.items.length ? (
                      <ul className="reference-list">
                        {group.items.map((item) => (
                          <li key={item.id}>
                            <button
                              className="flex w-full min-w-0 items-center gap-2 text-left"
                              title={item.proposedName || item.name}
                              onClick={() => onSelect(item.id)}
                            >
                              <code className="shrink-0">{item.address}</code>
                              <span className="min-w-0 truncate">
                                {item.proposedName || item.name}
                              </span>
                            </button>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-muted-foreground">None</p>
                    )}
                  </section>
                ))}
                <section>
                  <h4>Strings</h4>
                  <pre className="code-view">
                    {detail.strings.join("\n") || "None"}
                  </pre>
                </section>
                <section>
                  <h4>Imports</h4>
                  <pre className="code-view">
                    {detail.imports.join("\n") || "None"}
                  </pre>
                </section>
              </div>
            </TabsContent>
            <TabsContent
              value="decisions"
              className="motion-safe:animate-in motion-safe:duration-200 motion-safe:fade-in-0"
            >
              <div className="flex flex-col gap-4">
                <p className="text-muted-foreground">
                  Model assessments guide analysis. They do not approve changes
                  to Ghidra.
                </p>
                {detail.decisions.length === 0 ? (
                  <p>No assessments yet.</p>
                ) : (
                  detail.decisions.map((decision) => (
                    <motion.section
                      key={decision.id}
                      initial={reduced ? false : { opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ duration: 0.18 }}
                      className="flex flex-col gap-2"
                    >
                      <h4>{decision.stage.replaceAll("_", " ")}</h4>
                      <p>
                        {decision.route === "superseded"
                          ? "The proposal changed or was reviewed. No further work was queued."
                          : decision.route === "defer"
                            ? "Deferred: gather more evidence before reanalysis."
                            : decision.route === "needs_review"
                              ? "Uncertain proposal: review the evidence."
                              : decision.route === "review"
                                ? "Checks passed. Human review is still required."
                                : decision.route === "escalate"
                                  ? "Routed to the escalation model."
                                  : "Routed to the generation model."}
                      </p>
                      <p className="break-all text-muted-foreground">
                        {decision.model}
                      </p>
                      <pre className="code-view">
                        <code>
                          {JSON.stringify(
                            JSON.parse(decision.responseJson).answers,
                            null,
                            2
                          )}
                        </code>
                      </pre>
                    </motion.section>
                  ))
                )}
              </div>
            </TabsContent>
            <TabsContent value="analysis">
              <pre className="code-view">
                <code>
                  {detail.analysisJson
                    ? JSON.stringify(JSON.parse(detail.analysisJson), null, 2)
                    : "No structured analysis yet."}
                </code>
              </pre>
              {detail.promptHash ? (
                <p className="mt-3 break-all text-muted-foreground">
                  Prompt fingerprint: <code>{detail.promptHash}</code>
                </p>
              ) : null}
            </TabsContent>
          </Tabs>
        </div>
      ) : null}
    </aside>
  )
}
