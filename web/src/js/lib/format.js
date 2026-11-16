// Display helpers shared by list pages.
const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const df = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' })

export function isSet(iso) { return !!iso && !String(iso).startsWith('0001-') }
export function fmtDateTime(iso, never = 'Never') { return isSet(iso) ? dtf.format(new Date(iso)) : never }
export function fmtDate(iso, never = '—') { return isSet(iso) ? df.format(new Date(iso)) : never }

export function relTime(iso, never = 'Never') {
  if (!isSet(iso)) return never
  const s = (Date.now() - new Date(iso).getTime()) / 1000
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  for (const [unit, secs] of [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60]]) {
    if (Math.abs(s) >= secs) return rtf.format(-Math.round(s / secs), unit)
  }
  return 'just now'
}

export const ROLE_LABEL = { super_admin: 'Super admin', admin: 'Admin', manager: 'Manager', user: 'User' }
export const ROLE_BADGE = { super_admin: 'badge-danger', admin: 'badge-accent', manager: 'badge-info', user: 'badge-plain' }

export function initials(name) {
  const parts = String(name || '?').trim().split(/\s+/).slice(0, 2)
  return parts.map((p) => p[0] || '').join('').toUpperCase() || '?'
}

// Times typed in the console are the viewer's own (the browser's time zone), and go to the server as an RFC 3339 time
// in UTC; the server keeps every time in UTC, and the console shows them in the viewer's time zone again.

const pad2 = (n) => String(n).padStart(2, '0')

// The viewer's time zone, named for a form: "Australia/Perth, UTC+08:00" (the offset now, or at `at`).
export function localZoneText(at) {
  const d = at ? new Date(at) : new Date()
  const off = -d.getTimezoneOffset()
  const sign = off < 0 ? '-' : '+'
  const abs = Math.abs(off)
  let name = ''
  try { name = Intl.DateTimeFormat().resolvedOptions().timeZone || '' } catch (e) { /* offset alone */ }
  const utc = `UTC${sign}${pad2(Math.floor(abs / 60))}:${pad2(abs % 60)}`
  return name ? `${name}, ${utc}` : utc
}

// An RFC 3339 time as a datetime-local input value in the viewer's time zone ("2026-11-17T15:00"), or "" for none.
export function toLocalInput(iso) {
  if (!isSet(iso)) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}`
}

// A datetime-local input value, read in the viewer's time zone, as an RFC 3339 time in UTC ("" for none, or for a
// value that is no time: the server then says what is wrong).
export function fromLocalInput(v) {
  if (!v) return ''
  const d = new Date(v) // no offset: the browser reads it as local time
  return Number.isNaN(d.getTime()) ? v : d.toISOString()
}

// endInput is a form's end time: the value for its datetime-local input, and the body value to send. An end the form
// was opened with and left alone is sent as it was (to the second, as an API may have set it), not as the minute the
// input shows.
export function endInput(iso) {
  const shown = toLocalInput(iso)
  return { shown, send: (v) => (v === shown && isSet(iso) ? iso : fromLocalInput(v)) }
}
