import { useState } from "react"
import { useForm } from "@tanstack/react-form"
import { useStore } from "@tanstack/react-store"
import { useMutation } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { UploadSimpleIcon } from "@phosphor-icons/react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldDescription,
  FieldError,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { ErrorNotice } from "@/components/Feedback"
import { api, queryClient } from "@/lib/api"
import { workspaceStore, setImportOpen } from "@/lib/workspace-store"

export function ImportDialog() {
  const open = useStore(workspaceStore, (s) => s.importOpen)
  const [file, setFile] = useState<File | null>(null)
  const navigate = useNavigate()
  const mutation = useMutation({
    mutationFn: async (path: string) => {
      if (file && file.size > 120 * 1024 * 1024)
        throw new Error("For files larger than 120 MiB, use a server path.")
      return api.importBinary(
        file
          ? {
              name: file.name,
              content: new Uint8Array(await file.arrayBuffer()),
            }
          : { path }
      )
    },
    onSuccess: async (binary) => {
      await queryClient.invalidateQueries({ queryKey: ["binaries"] })
      setImportOpen(false)
      setFile(null)
      form.reset()
      await navigate({
        to: "/binaries/$binaryId",
        params: { binaryId: binary.id },
        search: { view: "functions" },
      })
    },
  })
  const form = useForm({
    defaultValues: { path: "" },
    onSubmit: async ({ value }) => {
      await mutation.mutateAsync(value.path).catch(() => {})
    },
  })
  return (
    <Dialog open={open} onOpenChange={setImportOpen}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Import a binary</DialogTitle>
          <DialogDescription>
            Choose an ELF, PE, Mach-O, COFF, or Wasm file. Piston stores a copy
            for analysis.
          </DialogDescription>
        </DialogHeader>
        <form
          onSubmit={(event) => {
            event.preventDefault()
            event.stopPropagation()
            void form.handleSubmit()
          }}
          className="flex flex-col gap-4"
        >
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="binary-file">Upload file</FieldLabel>
              <Input
                id="binary-file"
                type="file"
                onChange={(e) => {
                  setFile(e.target.files?.[0] ?? null)
                  mutation.reset()
                }}
              />
              <FieldDescription>
                Up to 120 MiB. For larger binaries, enter a path on the backend
                machine.
              </FieldDescription>
            </Field>
            <form.Field
              name="path"
              validators={{
                onSubmit: ({ value }) =>
                  !file && !value.trim()
                    ? "Choose a file or enter a server path."
                    : undefined,
              }}
            >
              {(field) => (
                <Field data-invalid={!field.state.meta.isValid}>
                  <FieldLabel htmlFor="binary-path">Server path</FieldLabel>
                  <Input
                    id="binary-path"
                    placeholder="/path/to/binaries/program"
                    disabled={!!file}
                    value={field.state.value}
                    onBlur={field.handleBlur}
                    onChange={(e) => field.handleChange(e.target.value)}
                    aria-invalid={!field.state.meta.isValid}
                  />
                  <FieldError
                    errors={field.state.meta.errors.map((message) => ({
                      message,
                    }))}
                  />
                </Field>
              )}
            </form.Field>
          </FieldGroup>
          <ErrorNotice error={mutation.error} />
          <Button type="submit" disabled={mutation.isPending}>
            <UploadSimpleIcon data-icon="inline-start" />
            {mutation.isPending ? "Importing…" : "Import binary"}
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  )
}
