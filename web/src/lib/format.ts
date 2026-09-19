export const count = (n: number | bigint) =>
  new Intl.NumberFormat("en-US").format(n)
export const money = (n: number) =>
  new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 4,
  }).format(n)
export function bytes(n: number | bigint) {
  const value = Number(n)
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`
  return `${(value / 1024 ** 2).toFixed(1)} MiB`
}
export const dateTime = (seconds: bigint) =>
  new Date(Number(seconds) * 1000).toLocaleString()
export function generateN(count: number) {
  return Array.from({ length: Math.max(0, Math.floor(count)) }, (_, i) => i + 1)
}
