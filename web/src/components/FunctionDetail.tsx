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
            <h3 className="font-mono break-all">{f.proposedName || f.name}</h3>
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
                            <button onClick={() => onSelect(item.id)}>
                              <code>{item.address}</code>{" "}
                              {item.proposedName || item.name}
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
