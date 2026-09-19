import { Link } from "@tanstack/react-router"
import { useQuery } from "@tanstack/react-query"
import { PlusIcon, ArrowRightIcon, FileCodeIcon } from "@phosphor-icons/react"
import { binariesQuery, settingsQuery } from "@/lib/api"
import { setImportOpen } from "@/lib/workspace-store"
import { bytes, dateTime } from "@/lib/format"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableHead,
  TableHeader,
  TableRow,
  TableCell,
} from "@/components/ui/table"
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert"
import { EmptyNotice, ErrorNotice, LoadingRows } from "@/components/Feedback"

export function LibraryPage() {
  const binaries = useQuery(binariesQuery)
  const settings = useQuery(settingsQuery)
  return (
    <>
      <header className="page-header">
        <div>
          <h1>Binaries</h1>
          <p>Index, understand, and review compiled programs.</p>
        </div>
        <Button onClick={() => setImportOpen(true)}>
          <PlusIcon data-icon="inline-start" />
          Import binary
        </Button>
      </header>
      <div className="page-body">
        <ErrorNotice error={binaries.error} />
        {settings.data && !settings.data.ghidraConfigured ? (
          <Alert>
            <AlertTitle>Connect Ghidra to start extraction</AlertTitle>
            <AlertDescription>
              Set GHIDRA_HOME to your Ghidra installation and restart the
              backend. You can import binaries now.
            </AlertDescription>
          </Alert>
        ) : null}
        <section className="rounded-lg border">
          <div className="section-heading">
            <h2>Analysis projects</h2>
            <span>{binaries.data?.binaries.length ?? 0} projects</span>
          </div>
          <Table className="min-w-[760px] table-fixed">
            <colgroup>
              <col />
              <col className="w-32" />
              <col className="w-24" />
              <col className="w-24" />
              <col className="w-44" />
              <col className="w-12" />
            </colgroup>
            <TableHeader>
              <TableRow>
                <TableHead>Binary</TableHead>
                <TableHead>Architecture</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Imported</TableHead>
                <TableHead>
                  <span className="sr-only">Open</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {binaries.data?.binaries.map((binary) => (
                <TableRow key={binary.id}>
                  <TableCell>
                    <Link
                      className="file-link min-w-0"
                      title={binary.name}
                      to="/binaries/$binaryId"
                      params={{ binaryId: binary.id }}
                      search={{ view: "functions" }}
                    >
                      <FileCodeIcon size={18} className="shrink-0" />
                      <span className="min-w-0 truncate">{binary.name}</span>
                    </Link>
                    <div className="mt-1 font-mono text-xs text-muted-foreground">
                      {binary.sha256.slice(0, 16)}
                    </div>
                  </TableCell>
                  <TableCell>
                    {binary.format} / {binary.architecture}
                  </TableCell>
                  <TableCell>{bytes(binary.size)}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{binary.status}</Badge>
                  </TableCell>
                  <TableCell>{dateTime(binary.createdAt)}</TableCell>
                  <TableCell>
                    <Link
                      aria-label={`Open ${binary.name}`}
                      to="/binaries/$binaryId"
                      params={{ binaryId: binary.id }}
                      search={{ view: "functions" }}
                    >
                      <ArrowRightIcon size={18} />
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {binaries.isPending ? (
            <LoadingRows />
          ) : binaries.data?.binaries.length === 0 ? (
            <EmptyNotice
              title="Your first binary starts here"
              description="Import a file to build its function index and call graph. AI analysis starts only when you run the pipeline."
            />
          ) : null}
        </section>
        <div className="workflow-guide">
          <h2>From binary to reviewed evidence</h2>
          <ol>
            <li>
              <strong>Extract</strong>
              <p>
                Ghidra recovers functions, pseudocode, strings, and references.
              </p>
            </li>
            <li>
              <strong>Analyze</strong>
              <p>
                Workers summarize functions, propagate context, and investigate
                uncertain results.
              </p>
            </li>
            <li>
              <strong>Review</strong>
              <p>
                Accept proposals before the single writer changes your Ghidra
                project.
              </p>
            </li>
          </ol>
        </div>
      </div>
    </>
  )
}
