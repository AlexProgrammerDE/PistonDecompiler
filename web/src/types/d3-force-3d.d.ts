// d3-force-3d does not publish TypeScript declarations.
declare module "d3-force-3d" {
  export interface SimulationNode {
    id: string
    index?: number
    x?: number
    y?: number
    z?: number
    vx?: number
    vy?: number
    vz?: number
  }
  export interface SimulationLink {
    source: string | SimulationNode
    target: string | SimulationNode
  }
  export interface Force {
    (alpha: number): void
  }
  export interface LinkForce extends Force {
    id(accessor: (node: SimulationNode) => string): this
    distance(value: number): this
    iterations(value: number): this
  }
  export interface ManyBodyForce extends Force {
    strength(value: number): this
  }
  export interface CollisionForce extends Force {
    iterations(value: number): this
  }
  export interface Simulation {
    stop(): this
    force(name: string, force: Force): this
    tick(iterations: number): this
  }
  export function forceSimulation(
    nodes: SimulationNode[],
    dimensions: 2 | 3
  ): Simulation
  export function forceLink(links: SimulationLink[]): LinkForce
  export function forceManyBody(): ManyBodyForce
  export function forceCollide(radius: number): CollisionForce
  export function forceCenter(x?: number, y?: number, z?: number): Force
}
