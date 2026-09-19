import {
  createRootRoute,
  createRoute,
  createRouter,
} from "@tanstack/react-router"
import { AppShell } from "@/components/AppShell"
import { LibraryPage } from "@/pages/LibraryPage"
import { BinaryPage, type BinaryView } from "@/pages/BinaryPage"
import { SettingsPage } from "@/pages/SettingsPage"
import { EmptyNotice, ErrorNotice } from "@/components/Feedback"
const rootRoute = createRootRoute({
  component: AppShell,
  notFoundComponent: () => (
    <EmptyNotice
      title="Page not found"
      description="Choose a binary from the workspace navigation."
    />
  ),
  errorComponent: ({ error }) => (
    <ErrorNotice
      error={error instanceof Error ? error : new Error(String(error))}
    />
  ),
})
const library = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: LibraryPage,
})
const binary = createRoute({
  getParentRoute: () => rootRoute,
  path: "/binaries/$binaryId",
  validateSearch: (search: Record<string, unknown>): { view: BinaryView } => ({
    view: ["functions", "pipeline", "usage", "events"].includes(
      String(search.view)
    )
      ? (search.view as BinaryView)
      : "functions",
  }),
  component: BinaryPage,
})
const settings = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
})
export const router = createRouter({
  routeTree: rootRoute.addChildren([library, binary, settings]),
  defaultPreload: "intent",
})
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}
