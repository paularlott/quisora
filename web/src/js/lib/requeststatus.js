// The status of an access request, laid out the same wherever it is listed (Request access, the console's Access
// requests): a badge, then up to three lines: who (and their email), when, and the approver's note.
import { fmtDateTime, isSet } from './format.js'

const person = (verb, name, email) => `${verb} ${name || 'someone'}${email ? ' · ' + email : ''}`

// requestStatus gives request r (the API's view of it) { stateText, badgeClass, lines, live }: live while the access
// an approval gave lasts.
export function requestStatus(r) {
  const live = !!r.live && (!isSet(r.ends) || Date.parse(r.ends) > Date.now())
  const approved = person('Approved by', r.decided_by_name, r.decided_by_email)
  let state, badge, who, when
  const note = r.note ? `“${r.note}”` : ''
  let message = ''
  switch (r.state) {
    case 'pending':
      state = 'Waiting'; badge = 'badge-warning'
      who = `Waiting for ${r.approvers_name}`
      when = `Lapses ${fmtDateTime(r.lapses)}`
      break
    case 'approved':
    case 'expired':
      if (r.state === 'approved' && live) {
        state = 'Active'; badge = 'badge-success'
        when = isSet(r.ends) ? `Until ${fmtDateTime(r.ends)}` : 'With no end: given before this request'
      } else {
        state = 'Expired'; badge = 'badge-plain'
        when = `Ended ${fmtDateTime(r.ends)}`
      }
      who = approved
      message = note
      break
    case 'denied':
      state = 'Denied'; badge = 'badge-danger'
      who = person('Denied by', r.decided_by_name, r.decided_by_email)
      when = fmtDateTime(r.decided_at)
      message = note
      break
    case 'cancelled':
      state = 'Cancelled'; badge = 'badge-plain'
      who = person('Cancelled by', r.decided_by_name, r.decided_by_email)
      when = fmtDateTime(r.decided_at)
      break
    case 'lapsed':
      state = 'Lapsed'; badge = 'badge-plain'
      who = 'Nobody decided it in time'
      when = `Lapsed ${fmtDateTime(r.lapses)}`
      break
    case 'ended':
      state = 'Ended early'; badge = 'badge-plain'
      who = person('Ended by', r.ended_by_name, r.ended_by_email)
      when = fmtDateTime(r.ended_at)
      break
    default:
      state = r.state; badge = 'badge-plain'
  }
  return { stateText: state, badgeClass: 'badge ' + badge, lines: [who, when, message].filter(Boolean), live }
}
