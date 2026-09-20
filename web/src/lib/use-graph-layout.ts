import { useQuery } from "@tanstack/react-query"
import type { Graph } from "@/gen/piston/v1/piston_pb"
import { topologyKey, type GraphLayouts } from "./graph-layout"

export function useGraphLayout(graph: Graph | undefined) {
  const key = graph ? topologyKey(graph) : ""
  return useQuery({
    queryKey: ["graph-layout", key],
    enabled: !!graph,
    staleTime: Infinity,
    retry: false,
    queryFn: ({ signal }) =>
      new Promise<GraphLayouts>((resolve, reject) => {
        const worker = new Worker(
          new URL("./graph-layout.worker.ts", import.meta.url),
          { type: "module" }
        )
        const cleanup = () => {
          worker.terminate()
          signal.removeEventListener("abort", abort)
        }
        const abort = () => {
          cleanup()
          reject(new DOMException("Layout cancelled", "AbortError"))
        }
        signal.addEventListener("abort", abort, { once: true })
        worker.onmessage = (event: MessageEvent<GraphLayouts>) => {
          cleanup()
          resolve(event.data)
        }
        worker.onerror = () => {
          cleanup()
          reject(
            new Error("Could not arrange the call graph. Reload to try again.")
          )
        }
        worker.postMessage(JSON.parse(key))
      }),
  })
}
