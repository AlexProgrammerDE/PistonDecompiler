import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
} from "@tanstack/react-router"
import { AppShell } from "@/components/AppShell"
import type { BinaryView } from "@/pages/BinaryPage"
import {
  EmptyNotice,
  ErrorNotice,
  LoadingRows,
} from "@/components/Feedback"

const LibraryPage = lazyRouteComponent(
  () => import("@/pages/LibraryPage"),
  "LibraryPage"
)
const BinaryPage = lazyRouteComponent(
  () => import("@/pages/BinaryPage"),
  "BinaryPage"
)
const SettingsPage = lazyRouteComponent(
  () => import("@/pages/SettingsPage"),
  "SettingsPage"
)
const PendingPage = () => (
  <div className="page-body">
    <LoadingRows />
  </div>
)
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
  pendingComponent: PendingPage,
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
  pendingComponent: PendingPage,
})
const settings = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
  pendingComponent: PendingPage,
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
