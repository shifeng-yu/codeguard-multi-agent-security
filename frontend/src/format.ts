/** Shared formatting helpers for the console. */

const pad = (value: number) => String(value).padStart(2, '0')

/**
 * Render an ISO-8601 UTC timestamp in the viewer's local timezone.
 * Backend stores UTC; showing "07:03" for a 15:03 scan is confusing.
 */
export function fmtTime(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value.slice(0, 19).replace('T', ' ')
  }
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  )
}

/** Compact form without seconds, for dense table cells. */
export function fmtTimeShort(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value.slice(5, 16).replace('T', ' ')
  return (
    `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}`
  )
}

export function fmtDuration(ms?: number | null): string {
  if (ms == null) return '—'
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}
