import { useState } from "react"
import { useMutation, useQuery } from "@tanstack/react-query"
import { api, invalidateBinary } from "@/lib/api"
import type { Investigation } from "@/gen/piston/v1/piston_pb"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { ErrorNotice, EmptyNotice } from "@/components/Feedback"

export function InvestigationWorkbench({
  binaryId,
  selected,
  onSelect,
}: {
  binaryId: string
  selected: string
  onSelect: (id: string) => void
}) {
  const [question, setQuestion] = useState("")
  const [budget, setBudget] = useState("1")
  const query = useQuery({
    queryKey: ["binary", binaryId, "investigations"],
    queryFn: ({ signal }) => api.listInvestigations({ binaryId }, { signal }),
  })
  const create = useMutation({
    mutationFn: async () => {
      const detail = await api.getFunction({ id: selected })
      const functionIds = [
        ...new Set([
          selected,
          ...detail.callees.map((f) => f.id),
          ...detail.callers.map((f) => f.id),
        ]),
      ].slice(0, 200)
      return api.saveInvestigation({
        binaryId,
        question,
        budgetUsd: Number(budget),
        functionIds,
      })
    },
    onSuccess: () => {
      setQuestion("")
      return invalidateBinary(binaryId)
    },
  })
  return (
    <section className="flex flex-col gap-5">
      <h2>Investigations</h2>
      <p>
        Start with a selected function and its direct callers and callees. Save
        a question, then inspect and refine the findings.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          create.mutate()
        }}
        className="flex flex-col gap-3"
      >
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="investigation-question">
              What do you want to understand?
            </FieldLabel>
            <Input
              id="investigation-question"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              required
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="investigation-budget">
              Investigation budget (USD)
            </FieldLabel>
            <Input
              id="investigation-budget"
              type="number"
              min="0.01"
              step="0.01"
              value={budget}
              onChange={(e) => setBudget(e.target.value)}
              required
            />
          </Field>
        </FieldGroup>
        <Button type="submit" disabled={!selected || create.isPending}>
          Create from selected function
        </Button>
        {!selected ? (
          <p>Select a function in the Functions view first.</p>
        ) : null}
      </form>
      <ErrorNotice error={query.error ?? create.error} />
      {query.data?.investigations.map((item) => (
        <InvestigationEditor key={item.id} item={item} onSelect={onSelect} />
      ))}
      {query.data?.investigations.length === 0 ? (
        <EmptyNotice
          title="No saved investigations"
          description="Choose a starting function and a question to keep this work together."
        />
      ) : null}
    </section>
  )
}
function InvestigationEditor({
  item,
  onSelect,
}: {
  item: Investigation
  onSelect: (id: string) => void
}) {
  const [draft, setDraft] = useState(item)
  const [notes, setNotes] = useState(item.notes)
  const [message, setMessage] = useState("")
  const save = useMutation({
    mutationFn: () => api.saveInvestigation({ ...draft, notes }),
    onSuccess: (saved) => {
      setDraft(saved)
      return invalidateBinary(item.binaryId)
    },
  })
  const run = useMutation({
    mutationFn: async ({
      staleOnly,
      stage = "map",
    }: {
      staleOnly: boolean
      stage?: string
    }) => {
      const result = await api.reanalyze({
        binaryId: item.binaryId,
        investigationId: item.id,
        staleOnly,
        stage,
      })
      setMessage(
        `${result.queued} functions queued. Use Run analysis to start requests.`
      )
      return result
    },
    onSuccess: () => invalidateBinary(item.binaryId),
  })
  return (
    <article className="settings-section flex flex-col gap-3">
      <h3>{item.question}</h3>
      <p>
        {item.functionIds.length} functions · ${item.budgetUsd.toFixed(2)}{" "}
        budget
      </p>
      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          disabled={run.isPending}
          onClick={() => run.mutate({ staleOnly: false })}
        >
          Queue this scope
        </Button>
        <Button
          variant="outline"
          disabled={run.isPending}
          onClick={() => run.mutate({ staleOnly: true })}
        >
          Reconsider stale findings
        </Button>
      </div>
      <Button
        variant="outline"
        disabled={run.isPending}
        onClick={() => run.mutate({ staleOnly: false, stage: "escalate" })}
      >
        Queue deeper evidence analysis
      </Button>
      {message ? <p role="status">{message}</p> : null}
      <details>
        <summary>Functions in scope</summary>
        <ul>
          {item.functionIds.map((id) => (
            <li key={id}>
              <Button variant="link" onClick={() => onSelect(id)}>
                {id.split(":").at(-1)}
              </Button>
            </li>
          ))}
        </ul>
      </details>
      <Field>
        <FieldLabel htmlFor={`notes-${item.id}`}>
          Findings and unresolved questions
        </FieldLabel>
        <Textarea
          id={`notes-${item.id}`}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
      </Field>
      <Button
        variant="outline"
        disabled={save.isPending || notes === item.notes}
        onClick={() => save.mutate()}
      >
        Save notes
      </Button>
      <p>
        {item.resultIds.length} result revisions retained with this
        investigation.
      </p>
      {draft.revision !== item.revision ? (
        <Button variant="outline" onClick={() => setDraft(item)}>
          Load updated findings before saving
        </Button>
      ) : null}
      {item.resultIds.map((id) => (
        <SavedFinding key={id} id={id} onSelect={onSelect} />
      ))}
      <ErrorNotice error={save.error ?? run.error} />
    </article>
  )
}

function SavedFinding({
  id,
  onSelect,
}: {
  id: string
  onSelect: (id: string) => void
}) {
  const [open, setOpen] = useState(false)
  const query = useQuery({
    queryKey: ["result", id],
    queryFn: ({ signal }) => api.getResult({ id }, { signal }),
    enabled: open,
  })
  return (
    <details onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary>Saved result {id.slice(0, 8)}</summary>
      <ErrorNotice error={query.error} />
      {query.data ? (
        <>
          <h4 className="truncate" title={query.data.proposedName}>
            {query.data.proposedName}
          </h4>
          <p>{query.data.summary}</p>
          <p>
            {query.data.stale
              ? "Supporting context changed"
              : "Evidence available"}
          </p>
          <Button
            variant="link"
            onClick={() => onSelect(query.data!.functionId)}
          >
            Inspect function and revisions
          </Button>
        </>
      ) : null}
    </details>
  )
}
