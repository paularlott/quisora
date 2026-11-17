// Access requests (docs/design/access-requests.md): the Request access page (ask for access to a tenant for a while,
// see your requests, cancel or end them) and the Approvals page (decide the requests your groups approve, end access
// they gave). Both talk to the account API (session + CSRF); deciding and ending someone's access ask you to confirm it
// is you first (withReauth).
import { ApiError, accountApi, get, post, qs } from '../lib/api.js'
import { formMixin } from '../lib/form.js'
import { dialogMixin } from '../lib/dialog.js'
import { comboMixin } from '../lib/combo.js'
import { toast } from '../lib/announce.js'
import { mix } from '../lib/mix.js'
import { fmtDateTime, relTime } from '../lib/format.js'
import { refetchOnReturn } from '../lib/live.js'
import { withReauth } from './account.js'

const enc = encodeURIComponent
const LENGTHS = { 3600: '1 hour', 14400: '4 hours', 28800: '8 hours', 86400: '1 day', 259200: '3 days', 604800: '1 week',
  1209600: '2 weeks', 2592000: '1 month' }
const lengthText = (secs) => LENGTHS[secs] || `${Math.round(secs / 3600)} hours`
const isSet = (t) => !!t && !t.startsWith('0001-')

// shape gives a request the status line the pages show.
function shape(r) {
  const now = Date.now()
  let stateText = 'Waiting', badge = 'badge-warning', detail = ''
  switch (r.state) {
    case 'pending':
      detail = `Waiting for ${r.approvers_name}. Lapses ${relTime(r.lapses)} if nobody decides.`
      break
    case 'approved':
      if (r.live) {
        stateText = 'Active'; badge = 'badge-success'
        detail = isSet(r.ends) ? `Until ${fmtDateTime(r.ends)}. Approved by ${r.decided_by_name}.` : `Approved by ${r.decided_by_name}. You had access with no end already.`
      } else {
        stateText = 'Ended'; badge = 'badge-plain'
        detail = `Ended ${fmtDateTime(r.ends)}. Approved by ${r.decided_by_name}.`
      }
      break
    case 'denied':
      stateText = 'Denied'; badge = 'badge-danger'
      detail = `By ${r.decided_by_name}${r.note ? `: “${r.note}”` : '.'}`
      break
    case 'cancelled':
      stateText = 'Cancelled'; badge = 'badge-plain'
      detail = `Cancelled ${fmtDateTime(r.decided_at)}.`
      break
    case 'lapsed':
      stateText = 'Lapsed'; badge = 'badge-plain'
      detail = 'Nobody decided it within a day.'
      break
    case 'ended':
      stateText = 'Ended early'; badge = 'badge-plain'
      detail = `Ended by ${r.ended_by_name}, ${fmtDateTime(r.ended_at)}.`
      break
  }
  if (r.note && r.state === 'approved') detail += ` Note: “${r.note}”`
  return { ...r, stateText, badgeClass: 'badge ' + badge, detail, live: !!r.live && (!isSet(r.ends) || Date.parse(r.ends) > now),
    canCancel: r.state === 'pending', cancelLabel: `Cancel the request for ${r.tenant_display_name}`,
    endLabel: `End now: your access to ${r.tenant_display_name}` }
}

export default function (Alpine) {
  // ---- Request access ------------------------------------------------------------------------------------------
  const tenantSource = {
    async search(q) {
      const r = await get(accountApi('/access-requests/tenants') + qs({ q }))
      return r.items.map((t) => ({ value: t.id, label: t.display_name, detail: t.description || t.name }))
    },
  }
  Alpine.data('accessRequests', () => mix(formMixin(), comboMixin({ tenant_id: tenantSource }), {
    approvers: [], items: [], loaded: false, guest: false, loadError: '',
    init() {
      this.resetForm({ tenant_id: '', approvers: '', length: '', reason: '' })
      this.load()
      refetchOnReturn(() => this.load())
    },
    async load() {
      try {
        const r = await get(accountApi('/access-requests'))
        this.approvers = r.approvers
        this.items = r.items.map(shape)
        this.guest = !!r.guest
        this.loadError = ''
        if (!this.approvers.some((g) => g.id === this.form.approvers)) this.form.approvers = this.approvers.length ? this.approvers[0].id : ''
        this.approversChanged()
      } catch (e) {
        this.loadError = e.message
      } finally {
        this.loaded = true
      }
    },
    get hasLoadError() { return this.loadError !== '' },
    get canAsk() { return this.loaded && this.approvers.length > 0 && !this.guest },
    get cannotAsk() { return this.loaded && !this.hasLoadError && (this.approvers.length === 0 || this.guest) },
    get manyApprovers() { return this.approvers.length > 1 },
    get oneApprover() { return this.approvers.length === 1 },
    get approverText() { return this.oneApprover ? `A member of ${this.approvers[0].name} decides.` : '' },
    get chosen() { return this.approvers.find((g) => g.id === this.form.approvers) },
    get lengths() { return (this.chosen ? this.chosen.lengths : []).map((s) => ({ value: String(s), label: lengthText(s) })) },
    approversChanged() {
      const ls = this.lengths
      if (!ls.some((l) => l.value === this.form.length)) this.form.length = ls.length ? ls[0].value : ''
    },
    get isEmpty() { return this.loaded && this.items.length === 0 },
    get hasItems() { return this.items.length > 0 },
    get askLabel() { return this.busy ? 'Sending…' : 'Send request' },
    async ask() {
      if (this.comboPending('tenant_id') || !this.form.tenant_id) {
        this.setErrors(new ApiError(422, { error: 'Choose a tenant from the list.', field: 'tenant_id' }))
        return
      }
      const f = this.form
      const res = await this.run(() => post(accountApi('/access-requests'), { tenant_id: f.tenant_id, approvers: f.approvers,
        length: Number(f.length), reason: f.reason }))
      if (!res) return
      toast(`Request sent to ${res.approvers_name}. You get an email when they decide.`)
      f.reason = ''
      this.comboSet('tenant_id', '', '')
      await this.load()
    },
    async cancel(ev) {
      const r = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!r) return
      try {
        await post(accountApi(`/access-requests/${enc(r.id)}/cancel`))
        toast('Request cancelled.')
        await this.load()
      } catch (e) { toast(e.message, 'error') }
    },
    async end(ev) {
      const r = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!r) return
      const ok = await Alpine.store('confirm').ask({ title: 'End your access', message: `End your access to ${r.tenant_display_name} now?`,
        detail: 'You are signed out of its applications. To use it again, send a new request.', confirmLabel: 'End access' })
      if (!ok) return
      try {
        await post(accountApi(`/access-requests/${enc(r.id)}/end`))
        toast(`Your access to ${r.tenant_display_name} has ended.`)
        await this.load()
      } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- Approvals -----------------------------------------------------------------------------------------------
  Alpine.data('accessApprovals', () => mix(formMixin(), dialogMixin(), {
    pending: [], active: [], loaded: false, loadError: '', deciding: null, approving: true, opener: null, timer: null,
    init() {
      this.resetForm({ note: '' })
      this.load()
      refetchOnReturn(() => this.load())
      this.timer = setInterval(() => { if (!document.hidden) this.load() }, 30000) // new requests come in meanwhile
    },
    destroy() { clearInterval(this.timer) },
    async load() {
      try {
        const r = await get(accountApi('/approvals'))
        this.pending = r.pending.map((p) => ({ ...p, askedText: `Asked ${relTime(p.created)}`,
          approveLabel: `Approve ${p.user_name}’s request for ${p.tenant_display_name}`, denyLabel: `Deny ${p.user_name}’s request for ${p.tenant_display_name}` }))
        this.active = r.active.map((p) => ({ ...p, untilText: fmtDateTime(p.ends), endLabel: `End now: ${p.user_name}’s access to ${p.tenant_display_name}` }))
        this.loadError = ''
      } catch (e) {
        this.loadError = e.message
      } finally {
        this.loaded = true
      }
    },
    get hasLoadError() { return this.loadError !== '' },
    get pendingCount() { return String(this.pending.length) },
    get noPending() { return this.loaded && this.pending.length === 0 },
    get hasPending() { return this.pending.length > 0 },
    get noActive() { return this.loaded && this.active.length === 0 },
    get hasActive() { return this.active.length > 0 },
    get decideTitle() { return this.approving ? 'Approve the request' : 'Deny the request' },
    get decideLabel() { return this.busy ? (this.approving ? 'Approving…' : 'Denying…') : (this.approving ? 'Approve' : 'Deny') },
    get decideSummary() {
      const d = this.deciding
      return d ? `${d.user_name} asks for access to ${d.tenant_display_name} for ${d.length_text}.` : ''
    },
    get decideReason() { return this.deciding ? `Why: ${this.deciding.reason}` : '' },
    open(ev, approving) {
      const r = this.pending.find((p) => p.id === ev.currentTarget.dataset.id)
      if (!r) return
      this.deciding = r
      this.approving = approving
      this.opener = ev.currentTarget
      this.resetForm({ note: '' })
      this.openDlg('decide-dialog', ev.currentTarget)
    },
    openApprove(ev) { this.open(ev, true) },
    openDeny(ev) { this.open(ev, false) },
    async submitDecision() {
      const r = this.deciding
      if (!r) return
      const verb = this.approving ? 'approve' : 'deny'
      const res = await this.run(() => withReauth(Alpine, () => post(accountApi(`/approvals/${enc(r.id)}/${verb}`), { note: this.form.note }),
        this.opener, this))
      if (!res) return
      this.closeDlg('decide-dialog')
      toast(this.approving ? `Approved: ${r.user_name} has access to ${r.tenant_display_name} until ${fmtDateTime(res.ends)}.` :
        `Denied ${r.user_name}’s request for ${r.tenant_display_name}.`)
      await this.load()
    },
    async end(ev) {
      const opener = ev.currentTarget
      const r = this.active.find((p) => p.id === opener.dataset.id)
      if (!r) return
      const ok = await Alpine.store('confirm').ask({ title: 'End access', message: `End ${r.user_name}’s access to ${r.tenant_display_name} now?`,
        detail: 'They are signed out of its applications at once, and get an email saying so.', confirmLabel: 'End access' })
      if (!ok) return
      try {
        await withReauth(Alpine, () => post(accountApi(`/approvals/${enc(r.id)}/end`)), opener)
        toast(`${r.user_name}’s access to ${r.tenant_display_name} has ended.`)
        await this.load()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }))
}
