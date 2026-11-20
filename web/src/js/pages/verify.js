// Caller verification (docs/CALLER-VERIFICATION.md). Verify a caller, the agent's page: find the customer (an
// organization, then a person by name or email), start a verification, read its code out, and see the customer's
// answer as it comes. Verify a call, the customer's: enter the code, see who asks, confirm it is you (after confirming
// it is you to Quisora: withReauth) or say it is not; and who has verified you before.
import { ApiError, accountApi, get, post, qs } from '../lib/api.js'
import { formMixin } from '../lib/form.js'
import { comboMixin } from '../lib/combo.js'
import { tableMixin } from '../lib/table.js'
import { toast, announce } from '../lib/announce.js'
import { mix } from '../lib/mix.js'
import { fmtDateTime } from '../lib/format.js'
import { refetchOnReturn } from '../lib/live.js'
import { withReauth } from './account.js'

const enc = encodeURIComponent
// Both pages follow the person's own stream (GET /o/<org>/api-internal/account/events: Server-Sent Events), which
// says when a verification about them changed: the customer's page shows a verification as soon as the agent starts
// it, the agent's the answer as soon as it is given. They also look again now and then, slowly, in case the stream is
// not there (a proxy that will not stream, or another server's change it did not hear of).
const POLL = 10000 // the agent's page, while the customer has the code
const WAITING_POLL = 15000 // the customer's page, while the code is to be entered

// ownStream calls onChange when a verification about the person changes (or the stream was behind and missed some),
// until close() is called.
function ownStream(onChange) {
  let es = null
  try { es = new EventSource(accountApi('/events')) } catch { return () => {} }
  es.addEventListener('change', onChange)
  es.addEventListener('resync', onChange)
  es.addEventListener('ended', () => es.close()) // signed out: the page's own calls say so
  return () => es.close()
}

// The code is shown to the agent when they start a verification, and the server keeps only a hash of it: this browser
// keeps it too, until it runs out, so a reload (or another tab) can show it again. Browser storage may be missing
// (a private window, blocked site data): then a reloaded page shows how the verification stands, without the code.
const CODE_KEY = 'quisora-verify-code:'
function keepCode(id, code, expires) {
  try { localStorage.setItem(CODE_KEY + id, JSON.stringify({ code, expires })) } catch { /* not kept */ }
}
function keptCode(id) {
  try {
    const v = JSON.parse(localStorage.getItem(CODE_KEY + id) || 'null')
    if (v && Date.parse(v.expires) > Date.now()) return v.code
  } catch { /* none */ }
  dropCode(id)
  return ''
}
function dropCode(id) {
  try { localStorage.removeItem(CODE_KEY + id) } catch { /* nothing to drop */ }
}

// callText says who placed the call, as the customer reads it.
const callText = (v) => v.direction === 'outbound' ? `${v.agent_org_name} called you` : `You called ${v.agent_org_name}`

// verifyState is the badge and the line under it for verification v, as the agent or the customer sees it.
function verifyState(v, forAgent) {
  switch (v.state) {
    case 'pending':
      return { stateText: 'Waiting', badgeClass: 'badge badge-warning', detail: forAgent ? 'Waiting for them to enter the code.' : '' }
    case 'confirmed':
      return { stateText: 'Confirmed', badgeClass: 'badge badge-success',
        detail: forAgent ? (v.second_factor ? 'With a passkey or second factor.' : 'With their password only: their account has no passkey or second factor.') : '' }
    case 'denied':
      return { stateText: 'Not them', badgeClass: 'badge badge-danger', detail: forAgent ? 'They said it was not them.' : '' }
    case 'cancelled':
      return { stateText: 'Cancelled', badgeClass: 'badge badge-plain', detail: '' }
    case 'expired':
      return { stateText: 'Ran out', badgeClass: 'badge badge-plain', detail: forAgent ? 'Nobody entered the code in time.' : '' }
  }
  return { stateText: v.state, badgeClass: 'badge badge-plain', detail: '' }
}

export default function (Alpine) {
  // ---- Verify a caller (the agent) ---------------------------------------------------------------------------
  const orgSource = {
    async search(q) {
      const r = await get(accountApi('/verify-caller/orgs') + qs({ q }))
      return r.items.map((o) => ({ value: o.id, label: o.display_name, detail: o.own ? 'Your organization' : o.name }))
    },
  }
  Alpine.data('verifyCaller', () => mix(formMixin(), comboMixin({
    org: orgSource,
    user_id: {
      async search(q) {
        const org = this.form.org
        if (!org) return []
        const r = await get(accountApi('/verify-caller/users') + qs({ org, q }))
        return r.items.map((u) => ({ value: u.id, label: u.name, detail: u.email }))
      },
    },
  }), {
    current: null, code: '', today: [], loadError: '', loaded: false, now: Date.now(), manyOrgs: false, _poll: null, _tick: null, _resumed: false,
    async init() {
      this.resetForm({ org: '', user_id: '', direction: '', reason: '' })
      this.loadToday()
      refetchOnReturn(() => this.loadToday())
      this._tick = setInterval(() => { this.now = Date.now() }, 1000)
      this._unstream = ownStream(() => { if (this.isPending) this.poll(); this.loadToday() })
      // their own organization to start with: most calls are about it. With no other to choose from (an agent of another
      // organization than the primary one, or no organization lets the primary's agents verify its people) the form
      // asks only for the person.
      try {
        const r = await get(accountApi('/verify-caller/orgs'))
        const own = r.items.find((o) => o.own)
        this.manyOrgs = r.items.length > 1
        if (own && !this.form.org) this.comboSet('org', own.id, own.display_name)
      } catch (e) { this.loadError = e.message }
    },
    destroy() { clearInterval(this._poll); clearInterval(this._tick); if (this._unstream) this._unstream() },
    comboChanged(name) { if (name === 'org') this.comboSet('user_id', '', '') }, // another organization: another person
    async loadToday() {
      try {
        const r = await get(accountApi('/verify-caller'))
        this.today = r.items.map((v) => {
          const open = v.state === 'pending' && v.live
          if (!open) dropCode(v.id)
          return { ...v, ...verifyState(v, true), startedText: fmtDateTime(v.created), open,
            callText: v.direction === 'outbound' ? 'You called them' : 'They called you',
            openLabel: `Open the verification of ${v.customer_name}`, cancelLabel: `Cancel the verification of ${v.customer_name}` }
        })
        this.loadError = ''
        // back on the page (a reload): the newest verification still waiting is shown again, with its code if kept
        if (!this.current && !this._resumed) {
          this._resumed = true
          const waiting = this.today.find((v) => v.open)
          if (waiting) this.watch(waiting)
        }
      } catch (e) { this.loadError = e.message } finally { this.loaded = true }
    },
    // watch shows verification v as the current one and follows its answer
    watch(v) {
      this.current = v
      this.code = keptCode(v.id)
      clearInterval(this._poll)
      this._poll = setInterval(() => this.poll(), POLL)
    },
    openFromList(ev) {
      const v = this.today.find((x) => x.id === ev.currentTarget.dataset.id)
      if (!v) return
      this.watch(v)
      this.$nextTick(() => { const h = document.getElementById('current-h'); if (h) h.focus() })
    },
    async cancelFromList(ev) {
      const id = ev.currentTarget.dataset.id
      try {
        const v = await post(accountApi(`/verify-caller/${enc(id)}/cancel`))
        dropCode(id)
        if (this.current && this.current.id === id) { this.current = v; this.code = ''; clearInterval(this._poll) }
        toast('Verification cancelled.')
        this.loadToday()
      } catch (e) { toast(e.message, 'error') }
    },
    get noCodeHere() { return this.isPending && this.code === '' },
    get hasLoadError() { return this.loadError !== '' },
    get hasToday() { return this.today.length > 0 },
    get noneToday() { return this.loaded && this.today.length === 0 },
    get startLabel() { return this.busy ? 'Starting…' : 'Start verification' },
    get hasCurrent() { return !!this.current },
    get showStart() { return !this.current },
    get isPending() { return !!this.current && this.current.state === 'pending' && this.secondsLeft > 0 },
    get isDone() { return !!this.current && !this.isPending },
    get canCancel() { return this.isPending },
    get showCode() { return this.isPending && this.code !== '' },
    get codeText() { return this.code ? this.code.slice(0, 3) + ' ' + this.code.slice(3) : '' },
    get codeSpoken() { return this.code.split('').join(' ') },
    get currentTitle() { return this.current ? `Verifying ${this.current.customer_name}` : '' },
    get currentWho() {
      const v = this.current
      return v ? `${v.customer_email || ''} · ${v.customer_org_name} · ${v.direction === 'outbound' ? 'You called them' : 'They called you'}` : ''
    },
    get whereText() {
      const v = this.current
      return v ? `They enter it under Verify a call in their account menu (${location.origin}${v.verify_path}). They see your name and why you are asking.` : ''
    },
    get secondsLeft() { return this.current ? Math.max(0, Math.round((Date.parse(this.current.expires) - this.now) / 1000)) : 0 },
    get runsOutText() {
      const s = this.secondsLeft
      return `The code works for ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} more.`
    },
    get statusInfo() {
      if (!this.current) return { stateText: '', badgeClass: '', detail: '' }
      const v = this.current.state === 'pending' && this.secondsLeft === 0 ? { ...this.current, state: 'expired' } : this.current
      return verifyState(v, true)
    },
    get statusText() { return this.statusInfo.stateText },
    get statusClass() { return this.statusInfo.badgeClass },
    get statusDetail() { return this.statusInfo.detail },
    async start() {
      if (this.comboPending('org') || !this.form.org) {
        this.setErrors(new ApiError(422, { error: 'Choose an organization from the list.', field: 'org' }))
        return
      }
      if (this.comboPending('user_id') || !this.form.user_id) {
        this.setErrors(new ApiError(422, { error: 'Choose the person from the list.', field: 'user_id' }))
        return
      }
      if (!this.form.direction) {
        this.setErrors(new ApiError(422, { error: 'Say who placed the call.', field: 'direction' }))
        return
      }
      const f = this.form
      const res = await this.run(() => post(accountApi('/verify-caller'), { org: f.org, user_id: f.user_id, direction: f.direction, reason: f.reason }))
      if (!res) return
      this.current = res.verification
      this.code = res.code
      keepCode(res.verification.id, res.code, res.verification.expires)
      announce(`Verification started. The code is ${res.code.split('').join(' ')}.`)
      this.$nextTick(() => { const h = document.getElementById('current-h'); if (h) h.focus() })
      clearInterval(this._poll)
      this._poll = setInterval(() => this.poll(), POLL)
      this.loadToday()
    },
    async poll() {
      if (!this.current) return
      try {
        const v = await get(accountApi(`/verify-caller/${enc(this.current.id)}`))
        const was = this.current.state
        this.current = v
        if (v.state !== 'pending' || !v.live) {
          clearInterval(this._poll)
          this.code = ''
          dropCode(v.id)
          if (was === 'pending') this.loadToday()
        }
      } catch (e) { /* the next one tries again */ }
    },
    async cancel() {
      if (!this.current) return
      try {
        this.current = await post(accountApi(`/verify-caller/${enc(this.current.id)}/cancel`))
        clearInterval(this._poll)
        this.code = ''
        dropCode(this.current.id)
        toast('Verification cancelled.')
        this.loadToday()
      } catch (e) { toast(e.message, 'error') }
    },
    another() {
      clearInterval(this._poll)
      this.current = null
      this.code = ''
      this.form.reason = ''
      this.form.direction = ''
      this.comboSet('user_id', '', '')
      this.$nextTick(() => { const i = document.getElementById('f-user_id'); if (i) i.focus() })
    },
  }))

  // ---- Verify a call (the customer) --------------------------------------------------------------------------
  Alpine.data('verifyCall', () => mix(formMixin(), {
    found: null, answered: null, waiting: [], waitingLoaded: false, _poll: null,
    init() {
      this.resetForm({ code: '' })
      this.loadWaiting()
      refetchOnReturn(() => this.loadWaiting())
      // who is verifying them shows as soon as the agent starts (the stream), or at the next look while the code is
      // to be entered
      this._unstream = ownStream(() => {
        if (this.showEntry) this.loadWaiting()
        window.dispatchEvent(new CustomEvent('verifications-changed'))
      })
      this._poll = setInterval(() => { if (!document.hidden && this.showEntry) this.loadWaiting() }, WAITING_POLL)
    },
    destroy() { clearInterval(this._poll); if (this._unstream) this._unstream() },
    async loadWaiting() {
      try {
        const r = await get(accountApi('/verify-call/waiting'))
        this.waiting = r.items.map((w) => ({ ...w, fromText: `of ${w.agent_org_name}${w.agent_email ? ' · ' + w.agent_email : ''}`, callText: callText(w), outbound: w.direction === 'outbound',
          whyText: w.reason ? `Why: ${w.reason}` : '' }))
      } catch (e) { /* the next look tries again */ } finally { this.waitingLoaded = true }
    },
    get hasWaiting() { return this.waiting.length > 0 },
    // the code box only while someone is verifying them: with nobody, there is no code to enter
    get entryTitle() { return this.noWaiting ? 'Nobody is verifying you right now' : 'Enter the code' },
    get noWaiting() { return this.waitingLoaded && this.waiting.length === 0 },
    get showEntry() { return !this.found && !this.answered },
    get showAsk() { return !!this.found && !this.answered },
    get showDone() { return !!this.answered },
    get findLabel() { return this.busy ? 'Checking…' : 'Continue' },
    get confirmLabel() { return this.busy ? 'Confirming…' : 'Yes, it’s me' },
    get askAgent() { return this.found ? this.found.agent_name : '' },
    get askAgentEmail() { return this.found ? this.found.agent_email || '' : '' },
    get askOrg() { return this.found ? this.found.agent_org_name : '' },
    get askReason() { return this.found ? this.found.reason || '' : '' },
    get askCall() { return this.found ? callText(this.found) : '' },
    get askWarning() {
      const a = this.found
      if (!a) return ''
      const mismatch = a.direction === 'outbound' ? `If you called them, this is not your call: choose Not me.` :
        `If someone called you, this is not your call (it says you called ${a.agent_org_name}): choose Not me.`
      return `Only confirm if you are on a call with ${a.agent_name} of ${a.agent_org_name} right now. ${mismatch}`
    },
    get doneTitle() { return this.answered && this.answered.state === 'confirmed' ? 'Thank you: you are verified' : 'Thank you: they have been told' },
    get doneText() {
      const a = this.answered
      if (!a) return ''
      return a.state === 'confirmed' ? `${a.agent_name} now sees that it is you.` :
        `${a.agent_name} sees that you said it was not you. If you did not expect this call, contact ${a.agent_org_name} through a number or address you already know.`
    },
    async find() {
      const code = this.form.code
      if (code.length !== 6) {
        this.setErrors(new ApiError(422, { error: 'Enter the 6 digits you were given.', field: 'code' }))
        return
      }
      const res = await this.run(() => post(accountApi('/verify-call/find'), { code }))
      if (!res) { this.form.code = ''; return }
      this.found = res
      this.$nextTick(() => { const h = document.getElementById('ask-h'); if (h) h.focus() })
    },
    async confirm(ev) {
      const f = this.found
      if (!f) return
      const res = await this.run(() => withReauth(Alpine, () => post(accountApi(`/verify-call/${enc(f.id)}/confirm`)), ev.currentTarget, this))
      if (res) this.done(res)
    },
    async deny() {
      const f = this.found
      if (!f) return
      const res = await this.run(() => post(accountApi(`/verify-call/${enc(f.id)}/deny`)))
      if (res) this.done(res)
    },
    done(res) {
      this.answered = res
      window.dispatchEvent(new CustomEvent('verifications-changed'))
      this.$nextTick(() => { const h = document.getElementById('done-h'); if (h) h.focus() })
    },
    again() {
      this.found = null
      this.answered = null
      this.resetForm({ code: '' })
      this.loadWaiting()
      this.$nextTick(() => { const i = document.getElementById('f-code'); if (i) i.focus() })
    },
  }))

  // Who verified you: newest first, a page at a time.
  Alpine.data('pastVerifications', () => mix(tableMixin(), {
    init() {
      this.$el.dataset.api = accountApi('/verify-call')
      refetchOnReturn(() => this.load(false, true))
      window.addEventListener('verifications-changed', () => this.load())
      return this.initTable()
    },
    transform(v) { return { ...v, ...verifyState(v, false), startedText: fmtDateTime(v.created), callText: callText(v) } },
    get hasLoadError() { return this.loadError !== '' },
  }))
}
