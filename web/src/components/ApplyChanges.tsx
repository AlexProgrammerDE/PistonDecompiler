import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import type { ApplyOperation } from "@/gen/piston/v1/piston_pb"
import { Button } from "@/components/ui/button"
import { ErrorNotice } from "@/components/Feedback"
export function ApplyChanges({ binaryId }: { binaryId: string }) {
  const [operation, setOperation] = useState<ApplyOperation>()
  const history = useQuery({
    queryKey: ["binary", binaryId, "apply"],
    queryFn: ({ signal }) => api.listApplyOperations({ binaryId }, { signal }),
    refetchInterval: 3000,
  })
  return (
    <section className="settings-section flex flex-col gap-3">
      <h2>Ghidra changes</h2>
      <p>
        AI validation and Ghidra writeback run automatically. These saved change
        sets are available for inspection.
      </p>
      {operation ? (
        <>
          <p>
            {operation.items.length} changes · {operation.status}
          </p>
          {operation.items.map((item) => (
            <article key={item.resultId}>
              <h4>{item.address}</h4>
              <pre className="code-view">{`Name: ${item.expectedName} → ${item.name}\nComment before: ${item.expectedComment || "(empty)"}\nComment after: ${item.summary || "(empty)"}`}</pre>
              <p>
                {item.status}
                {item.error ? `: ${item.error}` : ""}
              </p>
            </article>
          ))}
        </>
      ) : null}
      <details>
        <summary>Recent change sets and recovery</summary>
        {history.data?.operations.map((item) => (
          <p key={item.id}>
            <Button variant="link" onClick={() => setOperation(item)}>
              {item.status} · {item.items.length} changes
            </Button>
            {item.error}
          </p>
        ))}
      </details>
      <ErrorNotice error={history.error} />
    </section>
  )
}
