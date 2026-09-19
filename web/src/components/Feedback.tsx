import { WarningCircleIcon } from "@phosphor-icons/react"
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert"
import {
  Empty,
  EmptyHeader,
  EmptyTitle,
  EmptyDescription,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { generateN } from "@/lib/format"
export function ErrorNotice({ error }: { error: Error | null }) {
  if (!error) return null
  return (
    <Alert variant="destructive">
      <WarningCircleIcon />
      <AlertTitle>Request failed</AlertTitle>
      <AlertDescription>{error.message}</AlertDescription>
    </Alert>
  )
}
export function EmptyNotice({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <Empty>
      <EmptyHeader>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}
export function LoadingRows() {
  return (
    <div className="flex flex-col gap-3 p-4" aria-label="Loading rows">
      {generateN(5).map((id) => (
        <Skeleton key={id} className="h-8 w-full" />
      ))}
    </div>
  )
}
