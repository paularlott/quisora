// Account page: profile, password, passkeys, Authenticator App, sessions, API tokens, connected apps. Every form
// submits through the account API (accountApi: session + CSRF); errors appear inline next to the field and are announced.
import { ApiError, accountApi, get, post, patch, del } from '../lib/api.js'
import { formMixin } from '../lib/form.js'
import { subscribe, liveRunner, useStream } from '../lib/live.js'
import { dialogMixin } from '../lib/dialog.js'
import { toast, announce } from '../lib/announce.js'
import { mix } from '../lib/mix.js'
import { fmtDateTime, relTime, fmtDate, isSet } from '../lib/format.js'
import { emailsMixin } from '../lib/emails.js'
import { comboMixin, localeSource, zoneSource } from '../lib/combo.js'
import { createCredential, getAssertion, passkeysSupported } from './login.js'

const enc = encodeURIComponent

// A compact description of a user agent string: "Firefox on Linux".
export function describeAgent(ua) {
  if (!ua) return 'Unknown device'
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' :
    /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl|python|go-http|node/i.test(ua) ? 'Script' : 'Browser'
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad|iOS/.test(ua) ? 'iOS' :
    /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : ''
  return os ? `${browser} on ${os}` : browser
}

const SCOPE_TEXT = { api: 'Your organization’s applications (they check the token with Quisora)', scim: 'Provisioning (SCIM)', admin: 'Administration API',
  backup: 'Backups of the whole server (expires within 30 days)',
  import: 'Import users with a password hash from another system (with Administration API)' }

// Sensitive actions (changing the email address, adding or deleting a passkey, creating an API token, removing the
// Authenticator App) need a recent re-authentication. The server answers 403 with field "reauth"; withReauth opens
// the shared re-authentication dialog and retries the action once it succeeded. Cancelling rejects with an
// AbortError, which form.run() and the callers below treat as "nothing to report".
export const needsReauth = (e) => e instanceof ApiError && e.status === 403 && e.field === 'reauth'
const cancelled = () => Object.assign(new Error('Cancelled'), { name: 'AbortError' })

// vm is the calling form component: its busy flag (which disables the submit button) is lifted while the dialog
// is open so that focus can return to the button when the user gives up.
export async function withReauth(Alpine, fn, opener, vm) {
  try { return await fn() } catch (e) {
    if (!needsReauth(e)) throw e
    if (vm) vm.busy = false
    const ok = await Alpine.store('reauth').ask(opener)
    if (vm) vm.busy = true
    if (!ok) throw cancelled()
    return fn()
  }
}

// liveSelf: on the account page, run fn (quietly; held back while a dialog is open or someone types) when a record of
// one of kinds changes. The page's stream is the signed-in user's own: an administrator adding an address, a sign-in
// on another device, a verification link followed in another tab.
function liveSelf(kinds, fn) {
  useStream(accountApi('/events'))
  const run = liveRunner(fn)
  subscribe(kinds, () => run.trigger())
}

// Shared account state: loaded once, reloaded after changes that alter what the page shows. On the account page
// (watch) a change to the user's own record or passkeys elsewhere reloads it and tells the cards that read it
// (account-live).
function accountStore(Alpine) {
  Alpine.store('account', {
    loaded: false, user: null, org: null, security: { has_password: false, totp: false, passkeys: 0 },
    _p: null,
    load(force = false) {
      if (this._p && !force) return this._p
      this._p = get(accountApi()).then((r) => {
        this.user = r.user; this.org = r.org; this.security = r.security; this.loaded = true
        return r
      }).catch((e) => { this._p = null; throw e })
      return this._p
    },
    reload() { return this.load(true) },
    // Called by the account page (accountProfile): the store is on every page, the personal stream is not.
    watch() {
      if (this._watching) return
      this._watching = true
      liveSelf(['user', 'passkey', 'identity'], async () => {
        try { await this.reload() } catch { return }
        window.dispatchEvent(new CustomEvent('account-live'))
      })
    },
  })
}

// scoped adds runIn(prefix, fn): like run(), but server field names get a prefix so identical names in different
// forms of this page (every id on a page is unique) land on the right control.
function scoped() {
  return {
    async runIn(prefix, fn) {
      return this.run(async () => {
        try { return await fn() } catch (e) {
          if (e instanceof ApiError && e.field) e.field = prefix + e.field
          throw e
        }
      })
    },
  }
}

export default function (Alpine) {
  accountStore(Alpine)
  Alpine.store('reauth', {
    comp: null,
    // ask opens the dialog and resolves true once the user re-authenticated, false when they gave up.
    ask(opener) { return this.comp.ask(opener || document.activeElement) },
    // ensure resolves true at once when the session was re-authenticated recently.
    async ensure(opener) {
      const o = opener || document.activeElement
      try { if ((await get(accountApi('/reauth'))).valid) return true } catch { /* ask below */ }
      return this.ask(o)
    },
  })

  // ---- Re-authentication dialog (shared) ---------------------------------------------------------------------
  Alpine.data('accountReauth', () => mix(formMixin(), dialogMixin(), scoped(), {
    hasPassword: true, hasPasskeys: false, passkeyOk: false, totp: false, resolve: null,
    init() { this.passkeyOk = passkeysSupported(); Alpine.store('reauth').comp = this },
    get reauthLabel() { return this.busy ? 'Checking…' : 'Confirm' },
    // Re-authentication asks for what the account signs in with: the password, plus the code when the account has
    // the authenticator app; an account whose second factor is a passkey confirms with the passkey only.
    get askPassword() { return this.hasPassword && (this.totp || !this.hasPasskeys) },
    get askCode() { return this.totp },
    get canUsePasskey() { return this.hasPasskeys && this.passkeyOk },
    // nothing to confirm with on this page (e.g. signed in through a provider only): sign in again instead
    get mustSignIn() { return !this.askPassword && !this.askCode && !this.canUsePasskey },
    get canConfirm() { return this.askPassword || this.askCode },
    async ask(opener) {
      this.settle(false)
      try {
        const r = await Alpine.store('account').load()
        this.hasPassword = r.security.has_password
        this.totp = r.security.totp
        this.hasPasskeys = r.security.passkeys > 0 && r.security.passkeys_available
      } catch { /* the dialog still works with the defaults */ }
      return new Promise((resolve) => {
        this.resolve = resolve
        this.resetForm({ ra_password: '', ra_code: '' })
        this.openDlg('reauth-dialog', opener)
      })
    },
    settle(v) { const r = this.resolve; this.resolve = null; if (r) r(v) },
    done() { const r = this.resolve; this.resolve = null; this.closeDlg('reauth-dialog'); if (r) r(true) },
    afterClose() { this.settle(false) }, // Esc, Cancel or backdrop
    async reauth() {
      const body = {}
      if (this.askPassword) body.password = this.form.ra_password
      if (this.askCode) body.code = this.form.ra_code
      const res = await this.runIn('ra_', () => post(accountApi('/reauth'), body))
      if (res) this.done()
    },
    async reauthPasskey() {
      const res = await this.runIn('ra_', async () => {
        const begin = await post(accountApi('/reauth/passkey/begin'))
        const credential = await getAssertion(begin.options)
        return post(accountApi('/reauth/passkey/finish'), { challenge: begin.challenge, credential })
      })
      if (res) this.done()
    },
  }))

  // ---- Profile -----------------------------------------------------------------------------------------------
  // Work details, as labels and values for the read-only list on the account page.
  const WORK_LABELS = [['title', 'Job title'], ['department', 'Department'], ['organization', 'Company'], ['division', 'Division'],
    ['cost_center', 'Cost center'], ['employee_number', 'Employee number']]
  Alpine.data('accountProfile', () => mix(formMixin(), scoped(), comboMixin({ locale: localeSource, zoneinfo: zoneSource }), {
    loading: true, loadError: '', info: {}, canVerify: false, verifyBusy: false, emailNotice: '',
    async init() {
      const q = new URLSearchParams(location.search).get('email')
      if (q === 'verified') this.emailNotice = 'Your email address is verified.'
      else if (q === 'invalid') this.emailNotice = 'That verification link is invalid or has expired.'
      window.addEventListener('account-emails-changed', async () => { try { this.fill(await Alpine.store('account').reload()) } catch { /* the card shows errors */ } })
      Alpine.store('account').watch() // the account page follows the user's own changes made elsewhere
      try {
        const r = await Alpine.store('account').load()
        this.fill(r)
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    fill(r) {
      const u = r.user
      this.info = { username: u.username, role: u.role, org: r.org.display_name, verified: u.email_verified, hasEmail: !!u.email,
        email: u.email || '', lastLogin: fmtDateTime(u.last_login, 'Not yet') }
      this.canVerify = r.security.mail_available
      this.resetForm({ given_name: u.given_name, family_name: u.family_name, email: u.email, locale: u.locale || '', zoneinfo: u.zoneinfo || '', phone_number: u.phone_number || '' })
      this.comboSet('locale', u.locale || '')
      this.comboSet('zoneinfo', u.zoneinfo || '')
      const w = u.work || {}
      const rows = WORK_LABELS.filter(([k]) => w[k]).map(([k, label]) => ({ key: k, label, value: w[k] }))
      if (u.user_type) rows.unshift({ key: 'user_type', label: 'User type', value: u.user_type })
      if (u.valid_until) rows.push({ key: 'valid_until', label: 'Account ends', value: fmtDateTime(u.valid_until) })
      this.workRows = rows
    },
    workRows: [],
    get hasWork() { return this.workRows.length > 0 },
    get hasLoadError() { return this.loadError !== '' },
    get hasNotice() { return this.emailNotice !== '' },
    get showVerify() { return this.canVerify && this.info.hasEmail && !this.info.verified },
    get emailBadge() { return !this.info.hasEmail ? '' : this.info.verified ? 'Verified' : 'Not verified' },
    get emailBadgeClass() { return this.info.verified ? 'badge badge-success' : 'badge badge-warning' },
    get hasEmailBadge() { return this.info.hasEmail },
    get saveLabel() { return this.busy ? 'Saving…' : 'Save profile' },
    get verifyLabel() { return this.verifyBusy ? 'Sending…' : 'Send verification email' },
    async save() {
      const opener = document.activeElement
      const body = { ...this.form }
      delete body.email // shown, never changed here
      const res = await this.runIn('', () => withReauth(Alpine, () => patch(accountApi(), body), opener, this))
      if (!res) return
      toast('Profile saved.')
      const r = await Alpine.store('account').reload()
      this.fill(r)
    },
    async sendVerification() {
      if (this.verifyBusy) return
      this.verifyBusy = true
      try { await post(accountApi('/email/verify')); toast('Verification email sent.') } catch (e) { toast(e.message, 'error') } finally { this.verifyBusy = false }
    },
  }))

  // ---- Email addresses -----------------------------------------------------------------------------------------
  // Your addresses are added, removed and changed by another manager or administrator, whatever your role. The card
  // only shows once there is more than the primary address: verify, resend, make a verified address primary.
  Alpine.data('accountEmails', () => mix(formMixin(), scoped(), emailsMixin({
    self: true, canResend: true, manage: false,
    load: async () => (await Alpine.store('account').load()).user,
    url: (s) => accountApi('/emails') + s,
    guard: (fn, opener, vm) => withReauth(Alpine, fn, opener, vm),
    changed: () => { Alpine.store('account').reload(); window.dispatchEvent(new CustomEvent('account-emails-changed')) },
  }), {
    init() {
      window.addEventListener('account-live', () => this.loadEmails())
      return this.loadEmails()
    },
  }))

  // ---- Password ----------------------------------------------------------------------------------------------
  // The row offers "Change…" to users who have a password, "Set a password…" to those without one where their
  // organization uses passwords (after confirming it is them), and an explanation otherwise.
  Alpine.data('accountPassword', () => mix(formMixin(), dialogMixin(), scoped(), {
    hasPassword: false, allowed: false, loaded: false,
    async init() {
      this.resetForm({ pw_current: '', pw_new: '', pw_confirm: '' })
      const read = async () => {
        try {
          const sec = (await Alpine.store('account').load()).security
          this.hasPassword = sec.has_password
          this.allowed = !!sec.passwords_allowed
          this.loaded = true
        } catch { /* shown by the profile card */ }
      }
      window.addEventListener('account-live', read)
      await read()
    },
    // an account set up without a password (a passkey, an authenticator app, a sign-in provider) may add one where its
    // organization uses passwords, after confirming it is them
    get canSetPassword() { return this.loaded && !this.hasPassword && this.allowed },
    get statusText() { return !this.loaded ? '' : this.hasPassword ? 'Set' : 'Not set' },
    get statusClass() { return this.hasPassword ? 'badge badge-success' : 'badge badge-plain' },
    get note() {
      if (!this.loaded) return ''
      if (this.hasPassword) return 'Changing your password signs you out of every other browser and device.'
      return this.allowed ? 'You sign in without a password. You can add one as another way to sign in.'
        : 'Your organization does not sign people in with passwords.'
    },
    get dialogTitle() { return this.hasPassword ? 'Change password' : 'Set a password' },
    get dialogNote() {
      return this.hasPassword ? 'Changing your password signs you out of every other browser and device.'
        : 'You will confirm it is you first, with your passkey or authenticator app. Your other sign-in methods keep working.'
    },
    get submitLabel() { return this.busy ? 'Saving…' : this.hasPassword ? 'Change password' : 'Set password' },
    open(ev) {
      this.resetForm({ pw_current: '', pw_new: '', pw_confirm: '' })
      this.openDlg('password-dialog', ev.currentTarget)
    },
    async submit() {
      const opener = document.activeElement
      const f = this.form
      if (f.pw_new !== f.pw_confirm) {
        this.setErrors(new ApiError(422, { error: 'The two passwords do not match.', field: 'pw_confirm' }))
        return
      }
      const first = !this.hasPassword
      const send = () => post(accountApi('/password'), first ? { new: f.pw_new } : { current: f.pw_current, new: f.pw_new })
      const res = await this.runIn('pw_', () => (first ? withReauth(Alpine, send, opener, this) : send()))
      if (!res) return
      this.closeDlg('password-dialog')
      this.resetForm({ pw_current: '', pw_new: '', pw_confirm: '' })
      toast(first ? 'Password set. You can now sign in with it as well.'
        : res.signed_out > 0 ? `Password changed. ${res.signed_out} other session${res.signed_out === 1 ? ' was' : 's were'} signed out.` : 'Password changed.')
      Alpine.store('account').reload()
    },
  }))

  // ---- Passkeys ----------------------------------------------------------------------------------------------
  Alpine.data('accountPasskeys', () => mix(formMixin(), dialogMixin(), scoped(), {
    items: [], loading: true, loadError: '', available: true, supported: true, renaming: null, nameDefault: '',
    async init() {
      this.supported = passkeysSupported()
      liveSelf(['passkey'], () => this.load())
      await this.load()
    },
    async load() {
      try {
        const r = await get(accountApi('/passkeys'))
        this.available = r.available
        this.items = r.items.map((p) => ({ ...p, createdText: fmtDate(p.created), lastText: relTime(p.last_used, 'Never used'),
          kind: p.backup_eligible ? (p.backup_state ? 'Synced passkey' : 'Passkey (can be synced)') : 'Device-bound passkey',
          problemText: p.problem === 'disabled' ? 'Disabled' : p.problem === 'unverified' ? 'Cannot sign in' : '',
          renameLabel: 'Rename ' + p.name, deleteLabel: 'Delete ' + p.name }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    get hasItems() { return this.items.length > 0 },
    get hasProblems() { return this.items.some((p) => p.problem) },
    get problemsText() {
      const d = this.items.some((p) => p.problem === 'disabled'), u = this.items.some((p) => p.problem === 'unverified')
      return [d ? 'A passkey was disabled because a sign-in with it looked like it came from a copy of your authenticator. If you did not expect this, delete it and change your password.' : '',
        u ? 'A passkey marked “Cannot sign in” was added without a PIN or biometric check, which signing in now requires. Delete it and add it again.' : ''].filter(Boolean).join(' ')
    },
    get isEmpty() { return !this.loading && this.items.length === 0 && this.loadError === '' },
    get canAdd() { return this.available && this.supported },
    get unavailableText() {
      return !this.available ? 'Passkeys are not available on this server.' : !this.supported ? 'This browser does not support passkeys.' : ''
    },
    get showUnavailable() { return !this.canAdd },
    get hasLoadError() { return this.loadError !== '' },
    get addLabel() { return this.busy ? 'Waiting for your device…' : 'Add passkey' },
    get renameSubmitLabel() { return this.busy ? 'Saving…' : 'Save name' },

    openAdd(ev) {
      this.resetForm({ pk_name: this.nameDefault || describeAgent(navigator.userAgent).replace(' on ', ' · ') })
      this.openDlg('add-passkey-dialog', ev.currentTarget)
    },
    async add() {
      const name = (this.form.pk_name || '').trim()
      const opener = document.activeElement
      const res = await this.runIn('pk_', () => withReauth(Alpine, async () => {
        const begin = await post(accountApi('/passkeys/register/begin'))
        const credential = await createCredential(begin.options)
        return post(accountApi('/passkeys/register/finish'), { challenge: begin.challenge, name, credential })
      }, opener, this))
      if (!res) return
      this.closeDlg('add-passkey-dialog')
      toast('Passkey added.')
      await this.load()
      Alpine.store('account').reload()
    },
    openRename(ev) {
      const p = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!p) return
      this.renaming = p
      this.resetForm({ rn_name: p.name })
      this.openDlg('rename-passkey-dialog', ev.currentTarget)
    },
    async rename() {
      const res = await this.runIn('rn_', () => patch(accountApi('/passkeys/') + enc(this.renaming.id), { name: (this.form.rn_name || '').trim() }))
      if (!res) return
      this.closeDlg('rename-passkey-dialog')
      toast('Passkey renamed.')
      await this.load()
    },
    async remove(ev) {
      const p = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!p) return
      const opener = ev.currentTarget
      const ok = await Alpine.store('confirm').ask({ title: 'Delete passkey', message: `Delete “${p.name}”?`,
        detail: 'You will no longer be able to sign in with it. Remove it from your device or password manager too.', confirmLabel: 'Delete passkey' })
      if (!ok) return
      try {
        await withReauth(Alpine, () => del(accountApi('/passkeys/') + enc(p.id)), opener)
        toast('Passkey deleted.')
        await this.load()
        Alpine.store('account').reload()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }))

  // ---- Authenticator App (TOTP) ------------------------------------------------------------------------------
  Alpine.data('accountTotp', () => mix(formMixin(), dialogMixin(), scoped(), {
    enabled: false, replacing: false, loading: true, qr: '', secret: '', hasPassword: true, hasPasskeys: false, passkeyOk: false, requireMFA: false,
    async init() {
      this.passkeyOk = passkeysSupported()
      window.addEventListener('account-live', () => this.refresh())
      await this.refresh()
    },
    async refresh() {
      try {
        const r = await Alpine.store('account').load()
        this.enabled = r.security.totp
        this.hasPassword = r.security.has_password
        this.hasPasskeys = r.security.passkeys > 0 && r.security.passkeys_available
        this.requireMFA = r.org.require_mfa
      } catch { /* the profile card shows the error */ } finally { this.loading = false }
    },
    get notEnabled() { return !this.enabled },
    get statusText() { return this.loading ? '' : this.enabled ? 'On' : 'Off' },
    get statusClass() { return this.enabled ? 'badge badge-success' : 'badge badge-plain' },
    get startLabel() { return this.busy ? 'Starting…' : 'Set up Authenticator App' },
    get confirmLabel() { return this.busy ? 'Verifying…' : this.replacing ? 'Switch over' : 'Turn on' },
    get dialogTitle() { return this.replacing ? 'Set up Authenticator App again' : 'Set up Authenticator App' },

    // begin starts a first set-up; beginAgain a new secret replacing the current one (to add or change phones),
    // which the server only allows after a recent re-authentication.
    begin(ev) { return this.start(ev.currentTarget, false) },
    beginAgain(ev) { return this.start(ev.currentTarget, true) },
    async start(opener, replacing) {
      this.replacing = replacing
      const res = await this.runIn('totp_', () => withReauth(Alpine, () => post(accountApi('/totp/begin')), opener, this))
      if (!res) return
      this.qr = res.qr
      this.secret = res.secret
      this.resetForm({ totp_code: '' })
      this.openDlg('totp-dialog', opener)
    },
    async confirm() {
      const res = await this.runIn('totp_', () => post(accountApi('/totp/confirm'), { code: this.form.totp_code }))
      if (!res) return
      this.closeDlg('totp-dialog')
      this.secret = this.qr = ''
      toast(this.replacing ? 'Authenticator App set up again' : 'Authenticator App is on')
      await Alpine.store('account').reload()
      await this.refresh()
    },

    // Removing asks to confirm, then needs a recent re-authentication (shared dialog, see accountReauth).
    async startRemove(ev) {
      const opener = ev.currentTarget
      const ok = await Alpine.store('confirm').ask({ title: 'Remove Authenticator App', message: 'Remove your Authenticator App?',
        detail: 'Signing in will no longer ask for a code.', confirmLabel: 'Remove' })
      if (!ok) return
      // the confirm dialog's own focus return runs on close; give reauth the row button as its opener
      if (!(await Alpine.store('reauth').ensure(opener))) return
      try {
        await del(accountApi('/totp'))
        toast('Authenticator App removed.')
        await Alpine.store('account').reload()
        await this.refresh()
      } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- Recovery codes ----------------------------------------------------------------------------------------
  // Made (or replaced) after a recent re-authentication and shown once, in a dialog with copy and download.
  Alpine.data('accountRecovery', () => mix(formMixin(), dialogMixin(), scoped(), {
    left: 0, created: null, available: false, loading: true, codes: [],
    async init() {
      window.addEventListener('account-live', () => this.refresh())
      await this.refresh()
    },
    async refresh() {
      try {
        const r = await Alpine.store('account').load()
        this.left = r.security.recovery_left
        this.created = r.security.recovery_created
        this.available = r.security.recovery_available
      } catch { /* the profile card shows the error */ } finally { this.loading = false }
    },
    get has() { return this.created !== null && this.created !== undefined },
    get statusText() { return this.loading ? '' : this.has ? `${this.left} left` : 'None' },
    get statusClass() { return this.has && this.left > 3 ? 'badge badge-success' : this.has ? 'badge badge-warning' : 'badge badge-plain' },
    get note() {
      if (!this.available) return 'Set up an Authenticator App or a passkey first: recovery codes stand in for them when they are not at hand.'
      if (!this.has) return 'Codes that sign you in when your Authenticator App or passkey is not at hand, each once. Make them now, before you need them.'
      const made = `Made ${fmtDate(this.created)}.`
      return this.left === 0 ? `${made} All have been used: make new ones.` : this.left <= 3 ? `${made} Only a few are left: make new ones.` : `${made} Each signs you in once when your Authenticator App or passkey is not at hand.`
    },
    get canCreate() { return !this.loading && this.available },
    get createLabel() { return this.busy ? 'Creating…' : this.has ? 'Create new codes…' : 'Create codes…' },
    get codesText() { return this.codes.join('\n') },
    async create(ev) {
      const opener = ev.currentTarget
      if (this.has) {
        const ok = await Alpine.store('confirm').ask({ title: 'Create new recovery codes', message: 'Replace your recovery codes?',
          detail: 'Your current codes stop working at once, used or not.', confirmLabel: 'Create new codes' })
        if (!ok) return
      }
      const res = await this.runIn('recovery_', () => withReauth(Alpine, () => post(accountApi('/recovery-codes')), opener, this))
      if (!res) return
      this.codes = res.codes
      this.openDlg('recovery-dialog', opener)
      announce('Your recovery codes are shown. Save them now: they are not shown again.')
      await Alpine.store('account').reload()
      await this.refresh()
    },
    download() {
      const site = document.title.split(' · ').pop() || 'Quisora'
      const text = `${site} recovery codes (made ${new Date().toLocaleDateString()}). Each works once.\n\n${this.codes.join('\n')}\n`
      const a = document.createElement('a')
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
      a.download = 'recovery-codes.txt'
      a.click()
      setTimeout(() => URL.revokeObjectURL(a.href), 1000)
    },
    afterClose() { this.codes = [] }, // not kept in the page once the dialog is closed
  }))

  // ---- Sessions ----------------------------------------------------------------------------------------------
  Alpine.data('accountSessions', () => ({
    items: [], loading: true, loadError: '', busy: false,
    init() { liveSelf(['session'], () => this.load()); return this.load() },
    async load() {
      try {
        const r = await get(accountApi('/sessions'))
        this.items = r.items.map((s) => ({ ...s, agent: describeAgent(s.user_agent), lastText: s.current ? 'Now' : relTime(s.last_seen),
          createdText: fmtDateTime(s.created), notCurrent: !s.current, revokeLabel: 'Sign out ' + describeAgent(s.user_agent) + ' at ' + s.ip,
          methods: (s.amr || []).join(', ') }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    get hasItems() { return this.items.length > 0 },
    get hasOthers() { return this.items.some((s) => !s.current) },
    get hasLoadError() { return this.loadError !== '' },
    async revoke(ev) {
      const s = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!s) return
      const ok = await Alpine.store('confirm').ask({ title: 'Sign out session', message: `Sign out ${s.agent} (${s.ip})?`,
        detail: 'That device will have to sign in again.', confirmLabel: 'Sign out' })
      if (!ok) return
      try { await del(accountApi('/sessions/') + enc(s.id)); toast('Session signed out.'); await this.load() } catch (e) { toast(e.message, 'error') }
    },
    async revokeOthers() {
      const ok = await Alpine.store('confirm').ask({ title: 'Sign out other sessions', message: 'Sign out everywhere else?',
        detail: 'Every other browser and device will have to sign in again. This session stays signed in.', confirmLabel: 'Sign out others' })
      if (!ok) return
      try {
        const r = await del(accountApi('/sessions'))
        toast('Other sessions signed out.')
        await this.load()
        announce(`${r && r.revoked || 0} sessions signed out.`)
      } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- API tokens --------------------------------------------------------------------------------------------
  Alpine.data('accountTokens', () => mix(formMixin(), dialogMixin(), scoped(), {
    items: [], loading: true, loadError: '', scopes: [], maxDays: 0, created: '', createdName: '', regenerated: false, scopeChoices: [],
    apps: [], editingToken: null,
    init() { liveSelf(['apitoken'], () => this.load()); return this.load() },
    async load() {
      try {
        const r = await get(accountApi('/tokens'))
        this.scopes = r.scopes
        this.maxDays = r.max_days
        this.scopeChoices = r.scopes.map((s) => ({ value: s, label: SCOPE_TEXT[s] || s }))
        this.apps = r.apps || []
        const appName = (id) => (this.apps.find((a) => a.id === id) || { name: 'an application' }).name
        this.items = r.items.map((t) => ({ ...t, audience: t.audience || [], app_scopes: t.app_scopes || [] })).map((t) => ({ ...t, expiresText: isSet(t.expires) ? fmtDate(t.expires) : 'Never',
          scopesText: [t.scopes.join(', '), t.audience.length ? 'for ' + t.audience.map(appName).join(', ') : '',
            t.app_scopes.length ? 'only ' + t.app_scopes.join(', ') : ''].filter(Boolean).join('; '),
          lastText: relTime(t.last_used, 'Never used'), deleteLabel: 'Delete token ' + t.name, regenLabel: 'New secret for token ' + t.name,
          editLabel: 'Edit token ' + t.name }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    get hasItems() { return this.items.length > 0 },
    get isEmpty() { return !this.loading && this.items.length === 0 && this.loadError === '' },
    get hasLoadError() { return this.loadError !== '' },
    get isEditToken() { return this.editingToken !== null },
    get tokenDialogTitle() { return this.isEditToken ? 'Edit API token' : 'New API token' },
    get submitLabel() { return this.isEditToken ? (this.busy ? 'Saving…' : 'Save changes') : this.busy ? 'Creating…' : 'Create token' },
    get editExpiryText() {
      const t = this.editingToken
      return t ? (isSet(t.expires) ? `Expires ${fmtDate(t.expires)}; the expiry cannot be changed.` : 'Never expires.') : ''
    },
    // the applications section is for api tokens only
    get forApps() { return (this.form.tk_scopes || []).includes('api') },
    get noApps() { return this.apps.length === 0 },
    // the scopes of the ticked applications only, each with the applications declaring it (none ticked: the token is
    // for every application, with full access, and there is nothing to limit)
    get appScopeChoices() {
      const chosen = this.form.tk_audience || []
      const by = new Map()
      for (const app of this.apps) {
        if (!chosen.includes(app.id)) continue
        for (const sc of app.scopes) by.set(sc, [...(by.get(sc) || []), app.name])
      }
      return [...by.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([value, names]) => ({ value, apps: names.join(', ') }))
    },
    get hasScopeChoices() { return this.forApps && this.appScopeChoices.length > 0 },
    // ticked scopes that the chosen applications no longer offer are dropped
    tokenScopesPicked() {
      const offered = this.appScopeChoices.map((c) => c.value)
      return this.forApps ? (this.form.tk_app_scopes || []).filter((s) => offered.includes(s)) : []
    },
    get expiryHelp() { return this.maxDays > 0 ? `Between 1 and ${this.maxDays} days. Leave empty for ${this.maxDays}.` : 'Leave empty for a token that never expires, or enter 1 to 3650 days.' },
    openCreate(ev) {
      this.editingToken = null
      this.resetForm({ tk_name: '', tk_expires_days: '', tk_scopes: ['api'], tk_audience: [], tk_app_scopes: [] })
      this.openDlg('token-dialog', ev.currentTarget)
    },
    openEdit(ev) {
      const t = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!t) return
      this.editingToken = t
      this.resetForm({ tk_name: t.name, tk_expires_days: '', tk_scopes: [...t.scopes], tk_audience: [...t.audience], tk_app_scopes: [...t.app_scopes] })
      this.openDlg('token-dialog', ev.currentTarget)
    },
    submitToken() { return this.isEditToken ? this.saveEdit() : this.create() },
    async saveEdit() {
      const f = this.form
      const t = this.editingToken
      const opener = document.activeElement
      const body = { name: (f.tk_name || '').trim(), audience: this.forApps ? f.tk_audience : [], app_scopes: this.tokenScopesPicked() }
      const res = await this.runIn('tk_', () => withReauth(Alpine, () => patch(accountApi('/tokens/') + enc(t.id), body), opener, this))
      if (!res) return
      this.closeDlg('token-dialog')
      toast('Token saved.')
      await this.load()
    },
    async create() {
      const f = this.form
      const days = String(f.tk_expires_days || '').trim()
      const opener = document.activeElement
      const res = await this.runIn('tk_', () => withReauth(Alpine, () => post(accountApi('/tokens'), { name: (f.tk_name || '').trim(),
        scopes: f.tk_scopes, expires_days: days === '' ? 0 : Number(days), audience: this.forApps ? f.tk_audience : [],
        app_scopes: this.tokenScopesPicked() }), opener, this))
      if (!res) return
      this.closeDlg('token-dialog')
      this.created = res.token
      this.createdName = res.item.name
      this.regenerated = false
      await this.load()
      this.openDlg('token-secret-dialog')
    },
    // regenerate gives a token a new secret, after a confirmation: the old one stops working at once, so a stray
    // click must not break whatever uses it.
    async regenerate(ev) {
      const opener = ev.currentTarget
      const t = this.items.find((i) => i.id === opener.dataset.id)
      if (!t) return
      const ok = await Alpine.store('confirm').ask({ title: 'Make a new secret?', message: `Make a new secret for the token “${t.name}”?`,
        detail: 'The current secret stops working immediately: anything using it fails until you give it the new one. The name, access and expiry stay the same.',
        confirmLabel: 'Make new secret', danger: true })
      if (!ok) return
      try {
        const res = await withReauth(Alpine, () => post(accountApi('/tokens/') + enc(t.id) + '/regenerate', {}), opener)
        if (!res) return
        this.created = res.token
        this.createdName = res.item.name
        this.regenerated = true
        await this.load()
        this.openDlg('token-secret-dialog', opener)
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
    async remove(ev) {
      const t = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!t) return
      const ok = await Alpine.store('confirm').ask({ title: 'Delete API token', message: `Delete the token “${t.name}”?`,
        detail: 'Anything using it will stop working immediately.', confirmLabel: 'Delete token' })
      if (!ok) return
      try { await del(accountApi('/tokens/') + enc(t.id)); toast('Token deleted.'); await this.load() } catch (e) { toast(e.message, 'error') }
    },
    afterClose(id) { if (id === 'token-secret-dialog') { this.created = ''; this.regenerated = false } },
  }))

  // ---- Connected apps ----------------------------------------------------------------------------------------
  // ---- Sign-in providers: connect one to this account (or disconnect it). Connecting leaves for the provider and
  // comes back to /account?provider=connected|taken|failed#providers.
  Alpine.data('accountProviders', () => ({
    items: [], loadError: '', busy: false,
    init() {
      const q = new URLSearchParams(window.location.search).get('provider')
      const msg = { connected: ['Provider connected.', 'success'], taken: ['That account at the provider is already connected to someone else here.', 'error'],
        failed: ['The provider could not be connected. Try again.', 'error'],
        domain: ['That provider account\u2019s email address is not at a domain this organization allows.', 'error'] }[q]
      if (msg) {
        toast(msg[0], msg[1])
        history.replaceState(null, '', window.location.pathname + window.location.hash)
      }
      liveSelf(['identity'], () => this.load())
      return this.load()
    },
    async load() {
      try {
        const r = await get(accountApi('/providers'))
        this.items = r.items.map((p) => ({ ...p, canConnect: !p.connected, badgeText: p.connected ? 'Connected' : 'Not connected',
          badgeClass: p.connected ? 'badge badge-success' : 'badge badge-plain', forName: ' ' + p.name }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message }
    },
    get hasProviders() { return this.items.length > 0 || this.loadError !== '' },
    get hasLoadError() { return this.loadError !== '' },
    async connect(ev) {
      const opener = ev.currentTarget
      const id = opener.dataset.id
      this.busy = true
      try {
        const r = await withReauth(Alpine, () => post(accountApi('/providers/') + enc(id) + '/connect'), opener, this)
        if (r && r.url) { window.location.assign(r.url); return }
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
      this.busy = false
    },
    async disconnect(ev) {
      const opener = ev.currentTarget
      const p = this.items.find((i) => i.id === opener.dataset.id)
      if (!p) return
      const ok = await Alpine.store('confirm').ask({ title: 'Disconnect provider', message: `Disconnect ${p.name}?`,
        detail: 'You will no longer be able to sign in with it until you connect it again.', confirmLabel: 'Disconnect' })
      if (!ok) return
      try {
        await withReauth(Alpine, () => del(accountApi('/providers/') + enc(p.id)), opener, this)
        toast(p.name + ' disconnected.')
        await this.load()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }))

  Alpine.data('accountApps', () => ({
    items: [], loading: true, loadError: '',
    init() { liveSelf(['grant'], () => this.load()); return this.load() },
    async load() {
      try {
        const r = await get(accountApi('/apps'))
        this.items = r.items.map((a) => ({ ...a, id: a.client_id, scopesText: a.scopes.join(', ') || '—', sinceText: fmtDate(a.since),
          lastText: relTime(a.last_used), revokeLabel: 'Remove access for ' + a.name }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    get hasItems() { return this.items.length > 0 },
    get isEmpty() { return !this.loading && this.items.length === 0 && this.loadError === '' },
    get hasLoadError() { return this.loadError !== '' },
    async revoke(ev) {
      const a = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!a) return
      const ok = await Alpine.store('confirm').ask({ title: 'Remove access', message: `Remove access for ${a.name}?`,
        detail: 'It will no longer be able to refresh its access to your account. You may be asked to approve it again next time.', confirmLabel: 'Remove access' })
      if (!ok) return
      try { await del(accountApi('/apps/') + enc(a.id)); toast('Access removed.'); await this.load() } catch (e) { toast(e.message, 'error') }
    },
  }))
}
