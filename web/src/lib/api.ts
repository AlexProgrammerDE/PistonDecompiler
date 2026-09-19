import { createClient } from "@connectrpc/connect"
import { createGrpcWebTransport } from "@connectrpc/connect-web"
import { QueryClient, queryOptions } from "@tanstack/react-query"
import { PistonService } from "@/gen/piston/v1/piston_pb"

export const api = createClient(
  PistonService,
  createGrpcWebTransport({ baseUrl: window.location.origin })
)
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 1500, retry: 1, refetchOnWindowFocus: true },
  },
})
export const binariesQuery = queryOptions({
  queryKey: ["binaries"],
  queryFn: ({ signal }) => api.listBinaries({}, { signal }),
  refetchInterval: 5000,
})
export const settingsQuery = queryOptions({
  queryKey: ["settings"],
  queryFn: ({ signal }) => api.getSettings({}, { signal }),
})
export const overviewQuery = (binaryId: string) =>
  queryOptions({
    queryKey: ["binary", binaryId, "overview"],
    queryFn: ({ signal }) => api.getOverview({ binaryId }, { signal }),
    refetchInterval: 2000,
  })
export const jobsQuery = (binaryId: string) =>
  queryOptions({
    queryKey: ["binary", binaryId, "jobs"],
    queryFn: ({ signal }) => api.listJobs({ binaryId }, { signal }),
    refetchInterval: 3000,
  })
export const eventsQuery = (binaryId: string) =>
  queryOptions({
    queryKey: ["binary", binaryId, "events"],
    queryFn: ({ signal }) => api.listEvents({ binaryId }, { signal }),
    refetchInterval: 3000,
  })
export async function invalidateBinary(binaryId: string) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: ["binary", binaryId] }),
    queryClient.invalidateQueries({ queryKey: ["binaries"] }),
    queryClient.invalidateQueries({ queryKey: ["function"] }),
    queryClient.invalidateQueries({ queryKey: ["result"] }),
  ])
}
