import { StrictMode, Suspense, lazy } from "react"
import { createRoot } from "react-dom/client"
import { QueryClientProvider } from "@tanstack/react-query"
import { RouterProvider } from "@tanstack/react-router"
import { router } from "./router"
import { queryClient } from "./lib/api"
import "./styles.css"
const Devtools = import.meta.env.DEV
  ? lazy(() => import("./components/Devtools"))
  : null
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <RouterProvider router={router} />
      {Devtools ? (
        <Suspense>
          <Devtools />
        </Suspense>
      ) : null}
    </QueryClientProvider>
  </StrictMode>
)
