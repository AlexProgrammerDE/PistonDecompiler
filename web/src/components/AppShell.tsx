import { Link, Outlet, useLocation } from "@tanstack/react-router"
import { useQuery } from "@tanstack/react-query"
import {
  FolderOpenIcon,
  GearSixIcon,
  PlusIcon,
  FileCodeIcon,
} from "@phosphor-icons/react"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupAction,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarSeparator,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { ImportDialog } from "@/components/ImportDialog"
import { ErrorNotice } from "@/components/Feedback"
import { binariesQuery } from "@/lib/api"
import { setImportOpen } from "@/lib/workspace-store"
import { ThemeToggle } from "@/components/ThemeToggle"

export function AppShell() {
  const binaries = useQuery(binariesQuery)
  const pathname = useLocation({ select: (location) => location.pathname })
  const defaultOpen = !document.cookie
    .split("; ")
    .includes("sidebar_state=false")
  return (
    <SidebarProvider defaultOpen={defaultOpen}>
      <Sidebar collapsible="offcanvas">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton size="lg" render={<Link to="/" />}>
                <img
                  src="/pistondecompiler.svg"
                  alt=""
                  width={28}
                  height={28}
                />
                <span>PistonDecompiler</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Workspace</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    isActive={pathname === "/"}
                    render={<Link to="/" />}
                  >
                    <FolderOpenIcon />
                    <span>Binaries</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    isActive={pathname === "/settings"}
                    render={<Link to="/settings" />}
                  >
                    <GearSixIcon />
                    <span>Configuration</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
          <SidebarGroup>
            <SidebarGroupLabel>Analysis projects</SidebarGroupLabel>
            <SidebarGroupAction
              title="Import binary"
              onClick={() => setImportOpen(true)}
            >
              <PlusIcon />
              <span className="sr-only">Import binary</span>
            </SidebarGroupAction>
            <SidebarGroupContent>
              <SidebarMenu>
                {binaries.data?.binaries.map((binary) => (
                  <SidebarMenuItem key={binary.id}>
                    <SidebarMenuButton
                      isActive={pathname === `/binaries/${binary.id}`}
                      title={binary.name}
                      render={
                        <Link
                          to="/binaries/$binaryId"
                          params={{ binaryId: binary.id }}
                          search={{ view: "functions" }}
                        />
                      }
                    >
                      <FileCodeIcon />
                      <span>{binary.name}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
              <ErrorNotice error={binaries.error} />
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
        <SidebarSeparator />
        <SidebarFooter>
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">
              Local workspace
            </span>
            <ThemeToggle />
          </div>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <main className="min-w-0 flex-1" id="main">
        <SidebarTrigger className="m-2 md:hidden" />
        <Outlet />
      </main>
      <ImportDialog />
    </SidebarProvider>
  )
}
