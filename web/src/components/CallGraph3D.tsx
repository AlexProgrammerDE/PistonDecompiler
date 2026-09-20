import { useEffect, useEffectEvent, useRef, useState } from "react"
import * as THREE from "three"
import { OrbitControls } from "three/addons/controls/OrbitControls.js"
import type { Graph } from "@/gen/piston/v1/piston_pb"

type Runtime = {
  update: (graph: Graph, running: Set<string>) => void
}

export default function CallGraph3D({
  graph,
  running,
  onSelect,
}: {
  graph: Graph
  running: Set<string>
  onSelect: (id: string) => void
}) {
  const host = useRef<HTMLDivElement>(null)
  const runtime = useRef<Runtime | null>(null)
  const [unavailable, setUnavailable] = useState(false)
  const [hovered, setHovered] = useState("")
  const select = useEffectEvent((id: string) => onSelect(id))
  const refresh = useEffectEvent(() => runtime.current?.update(graph, running))

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
    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 2000)
    camera.position.set(0, 10, 80)
    const controls = new OrbitControls(camera, canvas)
    controls.enableDamping = false
    controls.minDistance = 5
    controls.maxDistance = 300
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
    let fitted = false
    runtime.current = {
      update(next, busy) {
        const ids = new Set(next.nodes.map((node) => node.id))
        for (const [id, mesh] of meshes) {
          if (!ids.has(id)) {
            scene.remove(mesh)
            meshes.delete(id)
          }
        }
        const modules = [
          ...new Set(next.nodes.map((node) => node.module)),
        ].sort()
        const positions = new Map<string, THREE.Vector3>()
        const columns = Math.max(1, Math.ceil(Math.sqrt(modules.length)))
        for (const [groupIndex, module] of modules.entries()) {
          const members = next.nodes
            .filter((node) => node.module === module)
            .sort((a, b) => a.address.localeCompare(b.address))
          const radius = Math.max(3, Math.sqrt(members.length) * 1.5)
          for (const [index, node] of members.entries()) {
            const angle = index * Math.PI * (3 - Math.sqrt(5))
            const y =
              members.length === 1 ? 0 : 1 - (2 * index) / (members.length - 1)
            const ring = Math.sqrt(1 - y * y)
            const position = new THREE.Vector3(
              ((groupIndex % columns) - (columns - 1) / 2) * 24 +
                Math.cos(angle) * ring * radius,
              -Math.floor(groupIndex / columns) * 24 + y * radius,
              Math.sin(angle) * ring * radius
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
              id: node.id,
              label: `${node.proposedName || node.name} · ${node.address}${busy.has(node.id) ? " · analyzing" : ""}`,
            }
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
        if (!fitted && meshes.size) {
          const bounds = new THREE.Box3().setFromObject(scene)
          const center = bounds.getCenter(new THREE.Vector3())
          const size = bounds.getSize(new THREE.Vector3()).length()
          controls.target.copy(center)
          camera.position
            .copy(center)
            .add(new THREE.Vector3(0, size * 0.2, Math.max(25, size * 1.4)))
          controls.update()
          fitted = true
        }
        render()
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
      for (const material of [pending, analyzed, active, stale, edgeMaterial])
        material.dispose()
      lines?.geometry.dispose()
      renderer.dispose()
      canvas.remove()
    }
  }, [])
  useEffect(() => {
    refresh()
  }, [graph, running])

  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm text-muted-foreground">
        Drag to orbit, scroll to zoom, and select a node to inspect it.
        Functions are grouped by module. Use the 2D view for keyboard
        navigation.
      </p>
      <div
        ref={host}
        className="h-96 w-full overflow-hidden rounded-md border"
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
