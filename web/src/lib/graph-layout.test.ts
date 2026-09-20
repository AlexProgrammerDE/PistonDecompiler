import { describe, expect, it } from "vitest"
import { layoutGraph, topologyKey, type GraphTopology } from "./graph-layout"

const topology: GraphTopology = {
  nodes: Array.from({ length: 30 }, (_, i) => `${i}`),
  edges: Array.from({ length: 23 }, (_, i) => ({
    caller: `${i % 7}`,
    callee: `${i + 1}`,
  })),
}

describe.each([2, 3] as const)("%d-dimensional call graph", (dimensions) => {
  it("keeps every node finite and separated, including disconnected nodes", () => {
    const layout = layoutGraph(topology, dimensions)
    expect(Object.keys(layout.positions)).toHaveLength(topology.nodes.length)
    const points = Object.values(layout.positions)
    for (const [index, point] of points.entries()) {
      expect(Object.values(point).every(Number.isFinite)).toBe(true)
      if (dimensions === 2) expect(point.z).toBe(0)
      for (const other of points.slice(index + 1)) {
        expect(
          Math.hypot(point.x - other.x, point.y - other.y, point.z - other.z)
        ).toBeGreaterThan(25)
      }
    }
  })
  it("is deterministic and reacts to changed call relationships", () => {
    expect(layoutGraph(topology, dimensions)).toEqual(
      layoutGraph(topology, dimensions)
    )
    expect(layoutGraph({ ...topology, edges: [] }, dimensions)).not.toEqual(
      layoutGraph(topology, dimensions)
    )
  })
  it("handles empty and single-node graphs", () => {
    for (const nodes of [[], ["single"]]) {
      const result = layoutGraph({ nodes, edges: [] }, dimensions)
      expect(Object.keys(result.positions)).toHaveLength(nodes.length)
      expect(result.width).toBeGreaterThan(0)
      expect(result.height).toBeGreaterThan(0)
    }
  })
})

it("ignores status, ordering, duplicate edges, self-calls, and absent endpoints in its cache key", () => {
  const graph = {
    nodes: topology.nodes.map((id) => ({ id, resultId: "" })),
    edges: topology.edges,
  }
  const updated = {
    nodes: [...graph.nodes]
      .reverse()
      .map((node) => ({ ...node, resultId: "changed" })),
    edges: [
      ...[...topology.edges].reverse(),
      topology.edges[0],
      { caller: "0", callee: "0" },
      { caller: "0", callee: "absent" },
    ],
  }
  expect(topologyKey(updated)).toBe(topologyKey(graph))
})
