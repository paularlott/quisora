// Access requests (docs/ACCESS-REQUESTS.md): the Request access page (ask for access to a tenant for a while, see your
// requests a page at a time, cancel or end them) and the Approvals page (decide the requests your groups approve, end
// access they gave, each list a page at a time). Both talk to the account API (session + CSRF); deciding and ending
// someone's access ask you to confirm it is you first (withReauth). The lists are tables of their own (tableMixin) in
// the page, told to load again by window events when the page changes something: requests-changed, approvals-changed.
import { ApiError, accountApi, get, post, qs } from '../lib/api.js'
import { formMixin } from '../lib/form.js'
import { dialogMixin } from '../lib/dialog.js'
import { comboMixin } from '../lib/combo.js'
import { tableMixin } from '../lib/table.js'
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
const POLL = 30000 // the approver lists look again this often while the page is shown: requests come in meanwhile

// shape gives one of your requests the status line the Request access page shows.
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
    case 'expired':
      stateText = 'Ended'; badge = 'badge-plain'
      detail = `Ended ${fmtDateTime(r.ends)}. Approved by ${r.decided_by_name}.`
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
      detail = 'Nobody decided it in time.'
      break
    case 'ended':
      stateText = 'Ended early'; badge = 'badge-plain'
      detail = `Ended by ${r.ended_by_name}, ${fmtDateTime(r.ended_at)}.`
      break
  }
  if (r.note && (r.state === 'approved' || r.state === 'expired')) detail += ` Note: “${r.note}”`
  return { ...r, stateText, badgeClass: 'badge ' + badge, detail, live: !!r.live && (!isSet(r.ends) || Date.parse(r.ends) > now),
    canCancel: r.state === 'pending', cancelLabel: `Cancel the request for ${r.tenant_display_name}`,
    endLabel: `End now: your access to ${r.tenant_display_name}` }
}

// userLink is the user page of the person a request is for, for managers and administrators (the page's data-users).
function userLink(el, p) {
  const base = el.closest('[data-users]')
  return base ? `${base.dataset.users}/${enc(p.user_id)}` : ''
}

// accountTable is a table of the account API's list at path, a page at a time, loading again on event (a window
// event) and when the tab comes back; poll, when set, also every POLL while the page is shown.
function accountTable(path, event, poll) {
  return {
    _poll: null,
    init() {
      this.$el.dataset.api = accountApi(path)
      refetchOnReturn(() => this.load(false, true))
      window.addEventListener(event, () => this.load())
      if (poll) this._poll = setInterval(() => { if (!document.hidden) this.load(false, true) }, POLL)
      return this.initTable()
    },
    destroy() { clearInterval(this._poll) },
    get hasLoadError() { return this.loadError !== '' },
  }
}

export default function (Alpine) {
  // ---- Request access ------------------------------------------------------------------------------------------
  const tenantSource = {
    async search(q) {
      const r = await get(accountApi('/access-requests/tenants') + qs({ q }))
      return r.items.map((t) => ({ value: t.id, label: t.display_name, detail: t.description || t.name }))
    },
  }
  Alpine.data('accessRequests', () => mix(formMixin(), dialogMixin(), comboMixin({ tenant_id: tenantSource }), {
    approvers: [], loaded: false, guest: false, loadError: '',
    init() {
      this.resetForm({ tenant_id: '', approvers: '', length: '', reason: '' })
      this.load()
      refetchOnReturn(() => this.load())
    },
    async load() {
      try {
        const r = await get(accountApi('/access-requests/options'))
        this.approvers = r.approvers
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
    get askLabel() { return this.busy ? 'Sending…' : 'Send request' },
    openAsk(ev) {
      const approvers = this.form.approvers
      this.resetForm({ tenant_id: '', approvers, length: '', reason: '' })
      this.comboSet('tenant_id', '', '')
      this.approversChanged()
      this.openDlg('ask-dialog', ev.currentTarget)
    },
    async ask() {
      if (this.comboPending('tenant_id') || !this.form.tenant_id) {
        this.setErrors(new ApiError(422, { error: 'Choose a tenant from the list.', field: 'tenant_id' }))
        return
      }
      const f = this.form
      const res = await this.run(() => post(accountApi('/access-requests'), { tenant_id: f.tenant_id, approvers: f.approvers,
        length: Number(f.length), reason: f.reason }))
      if (!res) return
      this.closeDlg('ask-dialog')
      toast(`Request sent to ${res.approvers_name}. You get an email when they decide.`)
      window.dispatchEvent(new CustomEvent('requests-changed'))
    },
  }))

  // Your requests: newest first, a page at a time.
  Alpine.data('ownRequests', () => mix(tableMixin(), accountTable('/access-requests', 'requests-changed', false), {
    transform: shape,
    async cancel(ev) {
      const r = this.rowFromEvent(ev)
      if (!r) return
      try {
        await post(accountApi(`/access-requests/${enc(r.id)}/cancel`))
        toast('Request cancelled.')
        await this.load()
      } catch (e) { toast(e.message, 'error') }
    },
    async end(ev) {
      const r = this.rowFromEvent(ev)
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
  // The page holds the decision dialog; its two lists ask it to open (a decide event) and are told to load again
  // after a decision (approvals-changed).
  Alpine.data('accessApprovals', () => mix(formMixin(), dialogMixin(), {
    deciding: null, approving: true, opener: null,
    init() { this.resetForm({ note: '' }) },
    get decideTitle() { return this.approving ? 'Approve the request' : 'Deny the request' },
    get decideLabel() { return this.busy ? (this.approving ? 'Approving…' : 'Denying…') : (this.approving ? 'Approve' : 'Deny') },
    get decideSummary() {
      const d = this.deciding
      return d ? `${d.user_name} asks for access to ${d.tenant_display_name} for ${d.length_text}.` : ''
    },
    get decideReason() { return this.deciding ? `Why: ${this.deciding.reason}` : '' },
    onDecide(ev) {
      const { row, approving, opener } = ev.detail
      this.deciding = row
      this.approving = approving
      this.opener = opener
      this.resetForm({ note: '' })
      this.openDlg('decide-dialog', opener)
    },
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
      window.dispatchEvent(new CustomEvent('approvals-changed'))
    },
  }))

  // Waiting for a decision: oldest first, a page at a time. The approver's own request is listed, for someone else.
  Alpine.data('approvalsWaiting', () => mix(tableMixin(), accountTable('/approvals/pending', 'approvals-changed', true), {
    transform(p) {
      return { ...p, askedText: relTime(p.created), canDecide: !p.yours, userHref: userLink(this.$el, p),
        approveLabel: `Approve ${p.user_name}’s request for ${p.tenant_display_name}`, denyLabel: `Deny ${p.user_name}’s request for ${p.tenant_display_name}` }
    },
    get countText() { return String(this.total) },
    decide(ev, approving) {
      const row = this.rowFromEvent(ev)
      if (row) this.$dispatch('decide', { row, approving, opener: ev.currentTarget })
    },
    openApprove(ev) { this.decide(ev, true) },
    openDeny(ev) { this.decide(ev, false) },
  }))

  // Access the approver's groups gave that runs: newest first, a page at a time.
  Alpine.data('approvalsRunning', () => mix(tableMixin(), accountTable('/approvals/active', 'approvals-changed', true), {
    transform(p) { return { ...p, untilText: fmtDateTime(p.ends), userHref: userLink(this.$el, p), endLabel: `End now: ${p.user_name}’s access to ${p.tenant_display_name}` } },
    async end(ev) {
      const opener = ev.currentTarget
      const r = this.rowFromEvent(ev)
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
