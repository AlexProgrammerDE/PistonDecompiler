import { useMemo, useState } from "react"
import { useQuery, keepPreviousData } from "@tanstack/react-query"
import { useDebouncedValue } from "@tanstack/react-pacer"
import {
  createColumnHelper,
  tableFeatures,
  useTable,
} from "@tanstack/react-table"
import { CaretLeftIcon, CaretRightIcon } from "@phosphor-icons/react"
import type { Function as BinaryFunction } from "@/gen/piston/v1/piston_pb"
import { api } from "@/lib/api"
import { count } from "@/lib/format"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableHeader,
  TableHead,
  TableRow,
  TableBody,
  TableCell,
} from "@/components/ui/table"
import { ErrorNotice, EmptyNotice, LoadingRows } from "@/components/Feedback"

const features = tableFeatures({})
const helper = createColumnHelper<typeof features, BinaryFunction>()
const emptyFunctions: BinaryFunction[] = []
export function FunctionTable({
  binaryId,
  selected,
  onSelect,
}: {
  binaryId: string
  selected: string
  onSelect: (id: string) => void
}) {
  const [search, setSearch] = useState("")
  const [debounced] = useDebouncedValue(search, { wait: 250 })
  const [page, setPage] = useState(0)
  const [filter, setFilter] = useState("all")
  const query = useQuery({
    queryKey: ["binary", binaryId, "functions", debounced, filter, page],
    queryFn: ({ signal }) =>
      api.listFunctions(
        { binaryId, search: debounced, filter, offset: page * 50, limit: 50 },
        { signal }
      ),
    placeholderData: keepPreviousData,
    refetchInterval: 3000,
  })
  const columns = useMemo(
    () =>
      helper.columns([
        helper.accessor("address", {
          header: "Address",
          cell: (info) => <code>{info.getValue()}</code>,
        }),
        helper.accessor("name", {
          header: "Function",
          cell: (info) => (
            <button
              className="function-link"
              onClick={() => onSelect(info.row.original.id)}
            >
              <span
                className="block w-full truncate"
                title={info.row.original.proposedName || info.getValue()}
              >
                {info.row.original.proposedName || info.getValue()}
              </span>
              {info.row.original.proposedName ? (
                <span
                  className="block w-full truncate text-xs text-muted-foreground"
                  title={info.getValue()}
                >
                  {info.getValue()}
                </span>
              ) : null}
            </button>
          ),
        }),
        helper.accessor("size", {
          header: "Bytes",
          cell: (info) => count(info.getValue()),
        }),
        helper.accessor("stale", {
          header: "Evidence status",
          cell: (info) =>
            info.getValue()
              ? "Needs reconsideration"
              : info.row.original.resultId
                ? "Available"
                : "Not analyzed",
        }),
        helper.accessor("status", {
          header: "Status",
          cell: (info) =>
            info.row.original.skipReason ||
            info.row.original.review ||
            info.getValue(),
        }),
      ]),
    [onSelect]
  )
  const table = useTable({
    features,
    columns,
    data: query.data?.functions ?? emptyFunctions,
    getRowId: (row) => row.id,
  })
  return (
    <section className="function-index">
      <div className="function-toolbar">
        <Input
          aria-label="Search functions"
          placeholder="Search names, code, or summaries…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setPage(0)
          }}
        />
        <label className="sr-only" htmlFor="function-filter">
          Function filter
        </label>
        <select
          id="function-filter"
          className="native-select"
          value={filter}
          onChange={(e) => {
            setFilter(e.target.value)
            setPage(0)
          }}
        >
          <option value="all">All functions</option>
          <option value="eligible">Eligible</option>
          <option value="review">Awaiting validation</option>
          <option value="accepted">Validated</option>
          <option value="stale">Needs reconsideration</option>
          <option value="skipped">Skipped</option>
        </select>
      </div>
      <ErrorNotice error={query.error} />
      <Table className="min-w-[640px] table-fixed">
        <colgroup>
          <col className="w-24" />
          <col />
          <col className="w-16" />
          <col className="w-36" />
          <col className="w-32" />
        </colgroup>
        <TableHeader>
          {table.getHeaderGroups().map((group) => (
            <TableRow key={group.id}>
              {group.headers.map((header) => (
                <TableHead key={header.id}>
                  <table.FlexRender header={header} />
                </TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.map((row) => (
            <TableRow
              key={row.id}
              data-state={row.id === selected ? "selected" : undefined}
            >
              {row.getAllCells().map((cell) => (
                <TableCell key={cell.id}>
                  <table.FlexRender cell={cell} />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {query.isPending ? (
        <LoadingRows />
      ) : query.data?.functions.length === 0 ? (
        <EmptyNotice
          title="No matching functions"
          description="Extract this binary or change the search and filter."
        />
      ) : null}
      <footer className="table-footer">
        <span>
          {count(query.data?.total ?? 0)} functions
          {query.isFetching ? " · Updating" : ""}
        </span>
        <div className="flex items-center gap-2">
          <Button
            size="icon-sm"
            variant="outline"
            aria-label="Previous page"
            disabled={page === 0 || query.isPlaceholderData}
            onClick={() => setPage((p) => p - 1)}
          >
            <CaretLeftIcon />
          </Button>
          <span>Page {page + 1}</span>
          <Button
            size="icon-sm"
            variant="outline"
            aria-label="Next page"
            disabled={
              !query.data ||
              (page + 1) * 50 >= query.data.total ||
              query.isPlaceholderData
            }
            onClick={() => setPage((p) => p + 1)}
          >
            <CaretRightIcon />
          </Button>
        </div>
      </footer>
    </section>
  )
}
