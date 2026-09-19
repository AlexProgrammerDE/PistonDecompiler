import { createStore } from "@tanstack/react-store"

export const workspaceStore = createStore({ importOpen: false })
export function setImportOpen(importOpen: boolean) {
  workspaceStore.setState((s) => ({ ...s, importOpen }))
}
