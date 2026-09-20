import {
  layoutGraph,
  type GraphTopology,
  type GraphLayouts,
} from "./graph-layout"

self.onmessage = (event: MessageEvent<GraphTopology>) => {
  const result: GraphLayouts = {
    plane: layoutGraph(event.data, 2),
    space: layoutGraph(event.data, 3),
  }
  self.postMessage(result)
}
