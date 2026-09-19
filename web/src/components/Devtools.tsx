import { TanStackDevtools } from "@tanstack/react-devtools"
import { TanStackRouterDevtoolsPanel } from "@tanstack/react-router-devtools"
import { ReactQueryDevtoolsPanel } from "@tanstack/react-query-devtools"
export default function Devtools() {
  return (
    <TanStackDevtools
      plugins={[
        { name: "Router", render: <TanStackRouterDevtoolsPanel /> },
        { name: "Query", render: <ReactQueryDevtoolsPanel /> },
      ]}
    />
  )
}
