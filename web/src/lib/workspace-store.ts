import { createStore } from "@tanstack/react-store"

export const workspaceStore = createStore({ importOpen: false, dark: false })
export function setImportOpen(importOpen: boolean) {
  workspaceStore.setState((s) => ({ ...s, importOpen }))
}
export function toggleTheme() {
  const dark = !workspaceStore.get().dark
  document.documentElement.classList.toggle("dark", dark)
  workspaceStore.setState((s) => ({ ...s, dark }))
}
