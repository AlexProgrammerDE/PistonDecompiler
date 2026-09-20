import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationNode,
} from "d3-force-3d"

export type GraphTopology = {
  nodes: string[]
  edges: { caller: string; callee: string }[]
}
export type GraphPosition = { x: number; y: number; z: number }
export type GraphLayout = {
  positions: Record<string, GraphPosition>
  width: number
  height: number
}
export type GraphLayouts = { plane: GraphLayout; space: GraphLayout }

// Status, names, and input order do not affect the simulation or its cache key.
export function topologyKey(graph: {
  nodes: { id: string }[]
  edges: GraphTopology["edges"]
}): string {
  const nodes = [...new Set(graph.nodes.map((node) => node.id))].sort()
  const ids = new Set(nodes)
  const edges = [
    ...new Set(
      graph.edges
        .filter(
          (edge) =>
            ids.has(edge.caller) &&
            ids.has(edge.callee) &&
            edge.caller !== edge.callee
        )
        .map((edge) => JSON.stringify([edge.caller, edge.callee]))
    ),
  ]
    .sort()
    .map((edge) => {
      const [caller, callee] = JSON.parse(edge) as [string, string]
      return { caller, callee }
    })
  return JSON.stringify({ nodes, edges })
}

export function layoutGraph(
  topology: GraphTopology,
  dimensions: 2 | 3
): GraphLayout {
  const adjacency = new Map(topology.nodes.map((id) => [id, new Set<string>()]))
  for (const { caller, callee } of topology.edges) {
    adjacency.get(caller)?.add(callee)
    adjacency.get(callee)?.add(caller)
  }
  const visited = new Set<string>()
  const components: string[][] = []
  for (const id of topology.nodes) {
    if (visited.has(id)) continue
    const members = [id]
    visited.add(id)
    for (let index = 0; index < members.length; index++) {
      for (const neighbor of adjacency.get(members[index]) ?? []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor)
          members.push(neighbor)
        }
      }
    }
    components.push(members.sort())
  }
  const groups = components
    .map((members) => {
      const ids = new Set(members)
      const nodes: SimulationNode[] = members.map((id) => ({ id }))
      // Solve each connected component independently. Isolated nodes cannot push
      // the main graph into a ball or drift arbitrarily far from it.
      const simulation = forceSimulation(nodes, dimensions)
        .stop()
        .force(
          "links",
          forceLink(
            topology.edges
              .filter((edge) => ids.has(edge.caller) && ids.has(edge.callee))
              .map((edge) => ({ source: edge.caller, target: edge.callee }))
          )
            .id((node) => node.id)
            .distance(65)
            .iterations(2)
        )
        .force("repulsion", forceManyBody().strength(-180))
        .force("collision", forceCollide(15).iterations(3))
        .force("center", forceCenter())
      simulation.tick(400)
      const minX = Math.min(...nodes.map((node) => node.x ?? 0)) - 25
      const minY = Math.min(...nodes.map((node) => node.y ?? 0)) - 25
      const width = Math.max(...nodes.map((node) => node.x ?? 0)) - minX + 25
      const height = Math.max(...nodes.map((node) => node.y ?? 0)) - minY + 25
      return { nodes, minX, minY, width, height }
    })
    .sort((a, b) => b.height - a.height || b.width - a.width)

  // Pack disconnected components, including singletons, without overlaps.
  const rowWidth = Math.max(
    1,
    ...groups.map((group) => group.width),
    Math.sqrt(
      groups.reduce(
        (area, group) => area + (group.width + 30) * (group.height + 30),
        0
      )
    ) * 1.5
  )
  const positions: Record<string, GraphPosition> = {}
  let x = 0,
    y = 0,
    rowHeight = 0,
    width = 0
  for (const group of groups) {
    if (x && x + group.width > rowWidth) {
      y += rowHeight + 30
      x = 0
      rowHeight = 0
    }
    for (const node of group.nodes)
      positions[node.id] = {
        x: (node.x ?? 0) - group.minX + x,
        y: (node.y ?? 0) - group.minY + y,
        z: dimensions === 3 ? (node.z ?? 0) : 0,
      }
    width = Math.max(width, x + group.width)
    x += group.width + 30
    rowHeight = Math.max(rowHeight, group.height)
  }
  return {
    positions,
    width: Math.max(100, width),
    height: Math.max(100, y + rowHeight),
  }
}
