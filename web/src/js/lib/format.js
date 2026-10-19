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
