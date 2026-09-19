import { Link, Outlet } from "@tanstack/react-router"
import { useQuery } from "@tanstack/react-query"
import {
  FolderOpenIcon,
  GearSixIcon,
  PlusIcon,
  FileCodeIcon,
} from "@phosphor-icons/react"
import { Button } from "@/components/ui/button"
import { ImportDialog } from "@/components/ImportDialog"
import { ErrorNotice } from "@/components/Feedback"
import { binariesQuery } from "@/lib/api"
import { setImportOpen } from "@/lib/workspace-store"
import { ThemeToggle } from "@/components/ThemeToggle"

export function AppShell() {
  const binaries = useQuery(binariesQuery)
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link to="/" className="brand">
          <img src="/pistondecompiler.svg" alt="" width={28} height={28} />
          <span>PistonDecompiler</span>
        </Link>
        <nav aria-label="Workspace">
          <Link to="/" activeOptions={{ exact: true }} className="nav-link">
            <FolderOpenIcon />
            Binaries
          </Link>
          <Link to="/settings" className="nav-link">
            <GearSixIcon />
            Configuration
          </Link>
        </nav>
        <div className="sidebar-heading">
          <h2>Analysis projects</h2>
          <Button
            size="icon-sm"
            variant="ghost"
            aria-label="Import binary"
            onClick={() => setImportOpen(true)}
          >
            <PlusIcon />
          </Button>
        </div>
        <nav className="project-list" aria-label="Binaries">
          {binaries.data?.binaries.map((binary) => (
            <Link
              key={binary.id}
              to="/binaries/$binaryId"
              params={{ binaryId: binary.id }}
              search={{ view: "functions" }}
              className="nav-link"
              title={binary.name}
            >
              <FileCodeIcon />
              <span className="min-w-0 truncate">{binary.name}</span>
            </Link>
          ))}
        </nav>
        <ErrorNotice error={binaries.error} />
        <div className="sidebar-bottom">
          <span>Local workspace</span>
          <ThemeToggle />
        </div>
      </aside>
      <main className="main-content" id="main">
        <Outlet />
      </main>
      <ImportDialog />
    </div>
  )
}
