import { useEffect, useEffectEvent, useRef, useState } from "react"
import * as THREE from "three"
import { OrbitControls } from "three/addons/controls/OrbitControls.js"
import type { Graph } from "@/gen/piston/v1/piston_pb"

import type { GraphLayout } from "@/lib/graph-layout"
import { Button } from "@/components/ui/button"

type Runtime = {
  fit: () => void
  update: (graph: Graph, running: Set<string>, layout: GraphLayout) => void
}

export default function CallGraph3D({
  graph,
  layout,
  running,
  onSelect,
}: {
  graph: Graph
  layout: GraphLayout
  running: Set<string>
  onSelect: (id: string) => void
}) {
  const host = useRef<HTMLDivElement>(null)
  const runtime = useRef<Runtime | null>(null)
  const [unavailable, setUnavailable] = useState(false)
  const [hovered, setHovered] = useState("")
  const select = useEffectEvent((id: string) => onSelect(id))
  const refresh = useEffectEvent(() =>
    runtime.current?.update(graph, running, layout)
  )

  useEffect(() => {
    const container = host.current
    if (!container) return
    let renderer: THREE.WebGLRenderer
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    } catch {
      setUnavailable(true)
      return
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    const canvas = renderer.domElement
    canvas.setAttribute("aria-label", "Three-dimensional function call graph")
    canvas.setAttribute("role", "img")
    container.appendChild(canvas)
    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 10000)
    camera.position.set(0, 10, 80)
    const controls = new OrbitControls(camera, canvas)
    controls.enableDamping = false
    controls.minDistance = 5
    controls.maxDistance = 5000
    // Render only on interaction or data changes. There is no automatic camera motion.
    const render = () => renderer.render(scene, camera)
    controls.addEventListener("change", render)
    const geometry = new THREE.SphereGeometry(0.65, 12, 8)
    const pending = new THREE.MeshBasicMaterial({ color: 0x929587 })
    const analyzed = new THREE.MeshBasicMaterial({ color: 0xa1cb37 })
    const active = new THREE.MeshBasicMaterial({ color: 0x63882b })
    const stale = new THREE.MeshBasicMaterial({
      color: 0x929587,
      wireframe: true,
    })
    const edgeMaterial = new THREE.LineBasicMaterial({
      color: 0x929587,
      transparent: true,
      opacity: 0.35,
    })
    const meshes = new Map<
      string,
      THREE.Mesh<THREE.SphereGeometry, THREE.MeshBasicMaterial>
    >()
    let lines: THREE.LineSegments | undefined
    let fittedLayout: GraphLayout | undefined
    let highlightLines: THREE.LineSegments | undefined
    let currentEdges: Graph["edges"] = []
    let hoveredId: string | undefined
    const highlightMaterial = new THREE.LineBasicMaterial({ color: 0xd7ddc8 })
    const dimmed = new THREE.MeshBasicMaterial({ color: 0x45483c })
    const fit = () => {
      if (!meshes.size) return
      const bounds = new THREE.Box3().setFromObject(scene)
      const center = bounds.getCenter(new THREE.Vector3())
      const size = bounds.getSize(new THREE.Vector3())
      const vertical = THREE.MathUtils.degToRad(camera.fov / 2)
      const distance = Math.max(
        25,
        (Math.max(
          size.y / (2 * Math.tan(vertical)),
          size.x / (2 * Math.tan(vertical) * camera.aspect)
        ) +
          size.z / 2) *
          1.15
      )
      controls.target.copy(center)
      camera.position.copy(center).add(new THREE.Vector3(0, 0, distance))
      controls.update()
      render()
    }
    const highlight = (id: string | undefined) => {
      hoveredId = id
      if (highlightLines) {
        scene.remove(highlightLines)
        highlightLines.geometry.dispose()
        highlightLines = undefined
      }
      const related = new Set([id])
      const points: THREE.Vector3[] = []
      if (id)
        for (const edge of currentEdges) {
          if (edge.caller !== id && edge.callee !== id) continue
          related.add(edge.caller)
          related.add(edge.callee)
          const from = meshes.get(edge.caller),
            to = meshes.get(edge.callee)
          if (from && to) points.push(from.position, to.position)
        }
      for (const [nodeId, mesh] of meshes)
        mesh.material =
          id && !related.has(nodeId) ? dimmed : mesh.userData.material
      edgeMaterial.opacity = id ? 0.06 : 0.25
      if (points.length) {
        highlightLines = new THREE.LineSegments(
          new THREE.BufferGeometry().setFromPoints(points),
          highlightMaterial
        )
        scene.add(highlightLines)
      }
      render()
    }
    runtime.current = {
      fit,
      update(next, busy, nextLayout) {
        currentEdges = next.edges
        const ids = new Set(next.nodes.map((node) => node.id))
        for (const [id, mesh] of meshes) {
          if (!ids.has(id)) {
            scene.remove(mesh)
            meshes.delete(id)
          }
        }
        const positions = new Map<string, THREE.Vector3>()
        for (const node of next.nodes) {
          const point = nextLayout.positions[node.id]
          if (!point) continue
          const position = new THREE.Vector3(
            point.x * 0.12,
            -point.y * 0.12,
            point.z * 0.12
          )
          positions.set(node.id, position)
          let mesh = meshes.get(node.id)
          if (!mesh) {
            mesh = new THREE.Mesh(geometry, pending)
            meshes.set(node.id, mesh)
            scene.add(mesh)
          }
          mesh.position.copy(position)
          mesh.material = node.stale
            ? stale
            : busy.has(node.id)
              ? active
              : node.resultId
                ? analyzed
                : pending
          mesh.scale.setScalar(busy.has(node.id) ? 1.5 : 1)
          mesh.userData = {
            material: mesh.material,
            id: node.id,
            label: `${node.proposedName || node.name} · ${node.address}${busy.has(node.id) ? " · analyzing" : ""}`,
          }
        }
        if (lines) {
          scene.remove(lines)
          lines.geometry.dispose()
        }
        const points: THREE.Vector3[] = []
        for (const edge of next.edges) {
          const from = positions.get(edge.caller)
          const to = positions.get(edge.callee)
          if (from && to) points.push(from, to)
        }
        lines = new THREE.LineSegments(
          new THREE.BufferGeometry().setFromPoints(points),
          edgeMaterial
        )
        scene.add(lines)
        if (fittedLayout !== nextLayout && meshes.size) {
          fit()
          fittedLayout = nextLayout
        }
        highlight(hoveredId)
      },
    }
    const resize = new ResizeObserver(() => {
      const width = container.clientWidth
      const height = container.clientHeight
      if (!width || !height) return
      renderer.setSize(width, height)
      camera.aspect = width / height
      camera.updateProjectionMatrix()
      render()
    })
    resize.observe(container)
    const raycaster = new THREE.Raycaster()
    const pointer = new THREE.Vector2()
    const hit = (event: PointerEvent) => {
      const rect = canvas.getBoundingClientRect()
      pointer.set(
        ((event.clientX - rect.left) / rect.width) * 2 - 1,
        -((event.clientY - rect.top) / rect.height) * 2 + 1
      )
      raycaster.setFromCamera(pointer, camera)
      return raycaster.intersectObjects([...meshes.values()], false)[0]?.object
    }
    const move = (event: PointerEvent) => {
      const object = hit(event)
      setHovered(object?.userData.label ?? "")
      if (object?.userData.id !== hoveredId) highlight(object?.userData.id)
      canvas.style.cursor = object ? "pointer" : "grab"
    }
    let pressed: { x: number; y: number } | undefined
    const down = (event: PointerEvent) => {
      pressed = { x: event.clientX, y: event.clientY }
    }
    const up = (event: PointerEvent) => {
      if (
        pressed &&
        Math.hypot(event.clientX - pressed.x, event.clientY - pressed.y) < 4
      ) {
        const object = hit(event)
        if (object) select(object.userData.id)
      }
      pressed = undefined
    }
    const leave = () => {
      setHovered("")
      highlight(undefined)
      pressed = undefined
    }
    const lost = (event: Event) => {
      event.preventDefault()
      setUnavailable(true)
    }
    canvas.addEventListener("pointermove", move)
    canvas.addEventListener("pointerdown", down)
    canvas.addEventListener("pointerup", up)
    canvas.addEventListener("pointerleave", leave)
    canvas.addEventListener("webglcontextlost", lost)
    renderer.setSize(container.clientWidth, container.clientHeight)
    camera.aspect = container.clientWidth / Math.max(1, container.clientHeight)
    camera.updateProjectionMatrix()
    refresh()
    return () => {
      runtime.current = null
      resize.disconnect()
      controls.removeEventListener("change", render)
      controls.dispose()
      canvas.removeEventListener("pointermove", move)
      canvas.removeEventListener("pointerdown", down)
      canvas.removeEventListener("pointerup", up)
      canvas.removeEventListener("pointerleave", leave)
      canvas.removeEventListener("webglcontextlost", lost)
      geometry.dispose()
      for (const material of [
        pending,
        analyzed,
        active,
        stale,
        edgeMaterial,
        highlightMaterial,
        dimmed,
      ])
        material.dispose()
      lines?.geometry.dispose()
      highlightLines?.geometry.dispose()
      renderer.dispose()
      canvas.remove()
    }
  }, [])
  useEffect(() => {
    refresh()
  }, [graph, running, layout])

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-sm text-muted-foreground">
          Drag to orbit, scroll to zoom, and select a node to inspect it. Hover
          a function to highlight its calls. Use 2D for keyboard navigation.
        </p>
        <Button variant="outline" onClick={() => runtime.current?.fit()}>
          Fit graph
        </Button>
      </div>
      <div
        ref={host}
        className="h-[32rem] w-full overflow-hidden rounded-md border"
        hidden={unavailable}
      />
      {unavailable ? (
        <p>
          3D rendering is unavailable. Select the 2D view to explore this graph.
        </p>
      ) : null}
      <p className="min-h-6 font-mono text-sm break-all">
        {hovered ||
          "Larger nodes are active; wireframe nodes need reconsideration."}
      </p>
    </div>
  )
}
