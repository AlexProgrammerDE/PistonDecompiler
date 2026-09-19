import { Link, Outlet } from "@tanstack/react-router"
import { useQuery } from "@tanstack/react-query"
import {
  CpuIcon,
  FolderOpenIcon,
  GearSixIcon,
  PlusIcon,
  MoonIcon,
  SunIcon,
  FileCodeIcon,
} from "@phosphor-icons/react"
import { useStore } from "@tanstack/react-store"
import { Button } from "@/components/ui/button"
import { ImportDialog } from "@/components/ImportDialog"
import { ErrorNotice } from "@/components/Feedback"
import { binariesQuery } from "@/lib/api"
import {
  workspaceStore,
  setImportOpen,
  toggleTheme,
} from "@/lib/workspace-store"

export function AppShell() {
  const binaries = useQuery(binariesQuery)
  const dark = useStore(workspaceStore, (s) => s.dark)
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link to="/" className="brand">
          <CpuIcon size={24} weight="duotone" />
          <span>Piston</span>
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
            >
              <FileCodeIcon />
              <span className="truncate">{binary.name}</span>
            </Link>
          ))}
        </nav>
        <ErrorNotice error={binaries.error} />
        <div className="sidebar-bottom">
          <span>Local workspace</span>
          <Button
            size="icon"
            variant="ghost"
            onClick={toggleTheme}
            aria-label={dark ? "Use light theme" : "Use dark theme"}
          >
            {dark ? <SunIcon /> : <MoonIcon />}
          </Button>
        </div>
      </aside>
      <main className="main-content" id="main">
        <Outlet />
      </main>
      <ImportDialog />
    </div>
  )
}
