// Account page: profile, password, passkeys, Authenticator App, sessions, API tokens, SSH certificates, connected apps. Every form
// submits through the account API (accountApi: session + CSRF); errors appear inline next to the field and are announced.
import { ApiError, accountApi, get, post, patch, del } from '../lib/api.js'
import { formMixin } from '../lib/form.js'
import { dialogMixin } from '../lib/dialog.js'
import { focusWhenShown } from '../lib/focus.js'
import { toast, announce } from '../lib/announce.js'
import { mix } from '../lib/mix.js'
import { fmtDateTime, relTime, fmtDate, isSet, ROLE_LABEL, ROLE_BADGE } from '../lib/format.js'
import { emailsMixin } from '../lib/emails.js'
import { comboMixin, localeSource, zoneSource } from '../lib/combo.js'
import { createCredential, getAssertion, passkeysSupported } from './login.js'
import { refetchOnReturn } from '../lib/live.js'
import { pictureMixin } from '../lib/picture.js'

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

// The name OpenSSH gives a private key of a type; its certificate is <that>-cert.pub, beside it.
const SSH_KEY_FILES = { 'ssh-ed25519': 'id_ed25519', 'ssh-rsa': 'id_rsa', 'ecdsa-sha2-nistp256': 'id_ecdsa', 'ecdsa-sha2-nistp384': 'id_ecdsa',
  'ecdsa-sha2-nistp521': 'id_ecdsa', 'sk-ssh-ed25519@openssh.com': 'id_ed25519_sk', 'sk-ecdsa-sha2-nistp256@openssh.com': 'id_ecdsa_sk' }
const sshFileName = (key) => SSH_KEY_FILES[(key || '').trim().split(/\s+/)[0]] || 'id_ed25519'

// Why a certificate stopped counting (the service's reasons).
// Why the account page offers no certificate for a tenant with SSH on (the account API's unavailable[].reason).
const SSH_BLOCKED = {
  role: 'This tenant gives no certificates to managers and administrators. An administrator can allow it in the tenant’s SSH settings.',
  sign_in_method: 'Not after the way you signed in: the tenant’s sign-in rules do not allow it. Sign out and sign in another way.',
  no_principals: 'Its settings give you no principal (no username, group or role it uses), so a certificate would let you log in nowhere. Ask an administrator.',
}
const SSH_REASON = { revoked: 'Revoked by you or an administrator.', ca_key_removed: 'The key that signed it was removed.', user_deleted: 'Your account was deleted.',
  user_disabled: 'Your account is disabled.', sessions_ended: 'You were signed out everywhere.',
  sign_in_ended: 'The sign-in it was issued under was ended (signed out, or the app\u2019s access revoked).', signed_out: 'Everyone was signed out.',
  role_not_allowed: 'Your role may no longer get certificates here.', access_removed: 'You lost access to this tenant\u2019s SSH.',
  principals_changed: 'Your principals changed.', ssh_off: 'SSH certificates are turned off for this tenant.',
  app_unavailable: 'This tenant\u2019s SSH application is disabled.', settings_changed: 'It grants more than this tenant now allows: get a new one.' }

const ttlText = (secs) => {
  if (secs % 3600 === 0) { const h = secs / 3600; return h === 1 ? '1 hour' : h + ' hours' }
  const m = Math.round(secs / 60)
  return m === 1 ? '1 minute' : m + ' minutes'
}

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

// Shared account state: loaded once, reloaded after changes that alter what the page shows; a reload tells the cards
// that read it (account-reloaded). The page shows changes made elsewhere (an administrator, another device) when it is
// loaded again or the tab comes back (refetchOnReturn): it has no live updates.
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
    reload() {
      const p = this.load(true)
      p.then(() => window.dispatchEvent(new CustomEvent('account-reloaded')), () => {})
      return p
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
    hasPassword: true, hasPasskeys: false, passkeyOk: false, totp: false, passkeyFactor: false, recoveryLeft: 0, useRecovery: false, resolve: null,
    init() { this.passkeyOk = passkeysSupported(); Alpine.store('reauth').comp = this },
    get reauthLabel() { return this.busy ? 'Checking…' : 'Confirm' },
    // Re-authentication asks for what the account signs in with: the password, plus the code when the account has
    // the authenticator app; an account whose second factor is a passkey confirms with the passkey only. A recovery
    // code stands in for either (the password as well, when there is one).
    get askPassword() { return this.hasPassword && (this.useRecovery || this.totp || !this.hasPasskeys) },
    get askCode() { return this.totp && !this.useRecovery },
    get canUsePasskey() { return this.hasPasskeys && this.passkeyOk && !this.useRecovery },
    get canUseRecovery() { return (this.totp || this.passkeyFactor) && this.recoveryLeft > 0 && !this.useRecovery },
    get recoveryLinkText() { return this.totp ? 'Lost your authenticator app? Use a recovery code' : 'Lost your passkey? Use a recovery code' },
    // nothing to confirm with on this page (e.g. signed in through a provider only): sign in again instead
    get mustSignIn() { return !this.askPassword && !this.askCode && !this.canUsePasskey && !this.canUseRecovery },
    get canConfirm() { return this.askPassword || this.askCode || this.useRecovery },
    async ask(opener) {
      this.settle(false)
      try {
        const r = await Alpine.store('account').load()
        this.hasPassword = r.security.has_password
        this.totp = r.security.totp
        this.hasPasskeys = r.security.passkeys > 0 && r.security.passkeys_available
        this.passkeyFactor = r.security.passkeys > 0
        this.recoveryLeft = r.security.recovery_left || 0
      } catch { /* the dialog still works with the defaults */ }
      return new Promise((resolve) => {
        this.resolve = resolve
        this.useRecovery = false
        this.resetForm({ ra_password: '', ra_code: '', ra_recovery_code: '' })
        this.openDlg('reauth-dialog', opener)
      })
    },
    startRecovery() { this.switchTo(true, 'f-ra_recovery_code') },
    stopRecovery() { this.switchTo(false, this.askPassword ? 'f-ra_password' : 'f-ra_code') },
    switchTo(on, focusId) {
      this.useRecovery = on
      this.clearErrors()
      focusWhenShown(focusId)
    },
    settle(v) { const r = this.resolve; this.resolve = null; if (r) r(v) },
    done() { const r = this.resolve; this.resolve = null; this.closeDlg('reauth-dialog'); if (r) r(true) },
    afterClose() { this.settle(false) }, // Esc, Cancel or backdrop
    async reauth() {
      const body = {}
      if (this.askPassword) body.password = this.form.ra_password
      if (this.askCode) body.code = this.form.ra_code
      if (this.useRecovery) body.recovery_code = this.form.ra_recovery_code
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
    loading: true, loadError: '', emailNotice: '',
    async init() {
      const q = new URLSearchParams(location.search).get('email')
      if (q === 'verified') this.emailNotice = 'Your email address is verified.'
      else if (q === 'invalid') this.emailNotice = 'That verification link is invalid or has expired.'
      window.addEventListener('account-emails-changed', async () => { try { this.fill(await Alpine.store('account').reload()) } catch { /* the card shows errors */ } })
      // the cards that read the account store refresh from it (account-reloaded); the profile form keeps what is typed
      refetchOnReturn(() => Alpine.store('account').reload())
      try {
        const r = await Alpine.store('account').load()
        this.fill(r)
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    fill(r) {
      const u = r.user
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
    get saveLabel() { return this.busy ? 'Saving…' : 'Save profile' },
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
  }))

  // ---- Identity header --------------------------------------------------------------------------------------------
  // The page's header: your picture (the control that changes it), name, username, role and email address with its
  // verification badge (the link is sent from the Email addresses card, shown while an address is unverified), all read from
  // the account store (so a change made elsewhere shows when the page reloads it, see accountProfile). An organization
  // may leave pictures to its administrators (can_change_picture: the picture is shown, not a control) or have them off
  // (pictures_enabled false: initials only).
  Alpine.data('accountHeader', () => mix(formMixin(), pictureMixin(Alpine, {
    path: () => accountApi('/picture'), who: () => ({ self: true, title: '' }),
    apply: () => Alpine.store('account').reload(),
  }), {
    u: {},
    async init() {
      window.addEventListener('account-reloaded', () => this.refresh())
      await this.refresh()
    },
    async refresh() {
      try {
        const r = await Alpine.store('account').load()
        this.u = r.user
        this.setPictureUser(r.user)
        this.picEnabled = r.pictures_enabled !== false
        this.canChange = this.picEnabled && r.can_change_picture !== false
      } catch { /* the profile card shows the error */ }
    },
    get fullName() { return [this.u.given_name, this.u.family_name].filter(Boolean).join(' ') || this.u.username || '' },
    get roleText() { return ROLE_LABEL[this.u.role] || this.u.role },
    get roleClass() { return 'badge ' + (ROLE_BADGE[this.u.role] || 'badge-plain') },
    get hasEmail() { return !!this.u.email },
    // each once: the username unless it is the email address or the heading (a name-less account's heading is its
    // username), and the address unless it is the heading
    get showUsername() { const n = (this.u.username || '').toLowerCase(); return !!n && n !== (this.u.email || '').toLowerCase() && n !== this.fullName.toLowerCase() },
    get showEmailText() { return this.hasEmail && this.u.email.toLowerCase() !== this.fullName.toLowerCase() },

    get emailBadge() { return this.u.email_verified ? 'Verified' : 'Not verified' },
    get emailBadgeClass() { return 'badge ' + (this.u.email_verified ? 'badge-success' : 'badge-warning') },
    get picReadOnlyText() { return 'Your organization’s administrators set pictures. Ask one of them to change yours.' },
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
      window.addEventListener('account-reloaded', () => this.loadEmails())
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
      window.addEventListener('account-reloaded', read)
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
      refetchOnReturn(() => this.load())
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
      window.addEventListener('account-reloaded', () => this.refresh())
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
      window.addEventListener('account-reloaded', () => this.refresh())
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
    // An account with a second factor and no codes is warned, not just labelled: someone whose authenticator app was brought
    // from another system has none, and is one lost phone from needing an administrator.
    get statusClass() { return this.has && this.left > 3 ? 'badge badge-success' : this.has || this.available ? 'badge badge-warning' : 'badge badge-plain' },
    get note() {
      if (!this.available) return 'Set up an Authenticator App or a passkey first: recovery codes stand in for them when they are not at hand.'
      if (!this.has) return 'You have no recovery codes yet. They sign you in when your Authenticator App or passkey is not at hand, each once: make them now, before you need them.'
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
    items: [], loading: true, loadError: '', busy: false, lastLoginText: '',
    init() { refetchOnReturn(() => this.load()); window.addEventListener('account-reloaded', () => this.showLastLogin()); return this.load() },
    async showLastLogin() {
      try { this.lastLoginText = fmtDateTime((await Alpine.store('account').load()).user.last_login, 'Not yet') } catch { /* the profile card shows the error */ }
    },
    get hasLastLogin() { return this.lastLoginText !== '' },
    async load() {
      this.showLastLogin()
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
      const opener = ev.currentTarget
      const s = this.items.find((i) => i.id === opener.dataset.id)
      if (!s) return
      const ok = await Alpine.store('confirm').ask({ title: 'Sign out session', message: `Sign out ${s.agent} (${s.ip})?`,
        detail: 'That device will have to sign in again.', confirmLabel: 'Sign out' })
      if (!ok) return
      try {
        await withReauth(Alpine, () => del(accountApi('/sessions/') + enc(s.id)), opener)
        toast('Session signed out.')
        await this.load()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
    async revokeOthers(ev) {
      const opener = ev.currentTarget
      const ok = await Alpine.store('confirm').ask({ title: 'Sign out other sessions', message: 'Sign out everywhere else?',
        detail: 'Every other browser and device will have to sign in again. This session stays signed in.', confirmLabel: 'Sign out others' })
      if (!ok) return
      try {
        const r = await withReauth(Alpine, () => del(accountApi('/sessions')), opener)
        toast('Other sessions signed out.')
        await this.load()
        announce(`${r && r.revoked || 0} sessions signed out.`)
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }))

  // ---- API tokens --------------------------------------------------------------------------------------------
  Alpine.data('accountTokens', () => mix(formMixin(), dialogMixin(), scoped(), {
    items: [], loading: true, loadError: '', scopes: [], maxDays: 0, created: '', createdName: '', regenerated: false, scopeChoices: [],
    apps: [], editingToken: null,
    init() { refetchOnReturn(() => this.load()); return this.load() },
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
    // Which scopes may be chosen is the server's answer (the role, and the organization's setting for the api scope): a
    // person who may make none has nothing to create.
    get canCreate() { return this.scopes.length > 0 },
    get cannotCreate() { return !this.loading && this.loadError === '' && this.scopes.length === 0 },
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
      this.resetForm({ tk_name: '', tk_expires_days: '', tk_scopes: this.scopes.includes('api') ? ['api'] : [], tk_audience: [], tk_app_scopes: [] })
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

  // ---- SSH certificates --------------------------------------------------------------------------------------
  // The section is shown when the account API lists a tenant with SSH for the user. A certificate is made from a
  // pasted public key; it needs a second factor (the session's) and a recent re-authentication, like an API token.
  Alpine.data('accountSSH', () => mix(formMixin(), dialogMixin(), scoped(), {
    tenants: [], unavailable: [], items: [], mfa: true, loading: true, loadError: '', cert: '', issued: null, fileName: 'id_ed25519-cert.pub',
    // an administrator revoking one of the user's certificates (or a revocation Quisora wrote down) shows at once
    init() { refetchOnReturn(() => this.load()); return this.load() },
    async load() {
      try {
        const r = await get(accountApi('/ssh'))
        this.mfa = r.mfa
        this.tenants = r.tenants.map((t) => ({ ...t, cmdId: 'ssh-cmd-' + t.id, cmdLabel: 'Command for ' + t.name, copyLabel: 'Copy the command for ' + t.name,
          detail: `You would get the principals ${t.principals.join(', ')}. A certificate lasts ${ttlText(t.cert_ttl)}.` }))
        this.unavailable = (r.unavailable || []).map((t) => ({ ...t, why: SSH_BLOCKED[t.reason] || 'You cannot get a certificate here.' }))
        this.items = r.certificates.map((c) => ({ ...c, principalsText: c.principals.join(', '), expiresText: fmtDateTime(c.valid_before),
          active: c.status === 'active', statusText: c.status === 'active' ? 'Active' : 'Revoked',
          statusClass: c.status === 'active' ? 'badge badge-success' : 'badge badge-danger', reasonText: SSH_REASON[c.reason] || '', hasReason: !!SSH_REASON[c.reason],
          revokeLabel: `Revoke the certificate for ${c.tenant} (${c.principals.join(', ')})` }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    // also where SSH is on for the user but they get no certificate, to say why (an administrator would otherwise see nothing)
    get visible() { return this.tenants.length > 0 || this.unavailable.length > 0 },
    get hasTenants() { return this.tenants.length > 0 },
    get hasUnavailable() { return this.unavailable.length > 0 },
    get cannotGet() { return this.noMfa || !this.hasTenants },
    get noMfa() { return !this.mfa },
    get hasItems() { return this.items.length > 0 },
    get isEmpty() { return !this.loading && this.items.length === 0 && this.loadError === '' },
    get hasLoadError() { return this.loadError !== '' },
    get manyTenants() { return this.tenants.length > 1 },
    get hasCert() { return this.cert !== '' },
    get dialogTitle() { return this.hasCert ? 'Your certificate' : 'Get a certificate' },
    get submitLabel() { return this.busy ? 'Signing…' : 'Get certificate' },
    get chosen() { return this.tenants.find((t) => t.id === this.form.ssh_tenant) || this.tenants[0] || null },
    get tenantHelp() { return this.chosen ? this.chosen.detail : '' },
    get issuedText() {
      const c = this.issued
      return c ? `Certificate for ${c.principals.join(', ')}, valid until ${fmtDateTime(c.valid_before)}.` : ''
    },
    openGet(ev) {
      this.cert = ''
      this.issued = null
      this.resetForm({ ssh_tenant: this.tenants.length ? this.tenants[0].id : '', ssh_public_key: '' })
      this.openDlg('ssh-dialog', ev.currentTarget)
    },
    async submit() {
      const f = this.form
      const key = (f.ssh_public_key || '').trim()
      const opener = document.activeElement
      const res = await this.runIn('ssh_', () => withReauth(Alpine, () => post(accountApi('/ssh/sign'),
        { tenant_id: f.ssh_tenant, public_key: key }), opener, this))
      if (!res) return
      this.cert = res.certificate.trim()
      this.issued = res
      this.fileName = sshFileName(key) + '-cert.pub'
      announce('Certificate ready.')
      await this.load()
      focusWhenShown(() => document.querySelector('#ssh-dialog [data-autofocus]:not(textarea)'))
    },
    // download saves the certificate as a file named for the key: OpenSSH reads <key>-cert.pub beside the key.
    download() {
      const url = URL.createObjectURL(new Blob([this.cert + '\n'], { type: 'text/plain' }))
      const a = Object.assign(document.createElement('a'), { href: url, download: this.fileName })
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    },
    async revoke(ev) {
      const c = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!c) return
      const ok = await Alpine.store('confirm').ask({ title: 'Revoke certificate', message: `Revoke the certificate for ${c.tenant} (${c.principalsText})?`,
        detail: 'Servers stop accepting it once they have the tenant\u2019s latest revocation list. You can get a new one at any time.', confirmLabel: 'Revoke certificate' })
      if (!ok) return
      try { await post(accountApi('/ssh/certificates/') + enc(c.id) + '/revoke', {}); toast('Certificate revoked.'); await this.load() } catch (e) { toast(e.message, 'error') }
    },
    afterClose(id) { if (id === 'ssh-dialog') { this.cert = ''; this.issued = null } },
  }))

  // ---- Connected apps ----------------------------------------------------------------------------------------
  // ---- Sign-in providers: connect one to this account (or disconnect it). Connecting leaves for the provider and
  // comes back to /account?provider=connected|taken|failed|domain|group#providers.
  Alpine.data('accountProviders', () => ({
    items: [], loadError: '', busy: false,
    init() {
      const q = new URLSearchParams(window.location.search).get('provider')
      const msg = { connected: ['Provider connected.', 'success'], taken: ['That account at the provider is already connected to someone else here.', 'error'],
        failed: ['The provider could not be connected. Try again.', 'error'],
        domain: ['That provider account\u2019s email address is not at a domain this organization allows.', 'error'],
        group: ['That account is not in a group allowed to sign in this way.', 'error'] }[q]
      if (msg) {
        toast(msg[0], msg[1])
        history.replaceState(null, '', window.location.pathname + window.location.hash)
      }
      refetchOnReturn(() => this.load())
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
    init() { refetchOnReturn(() => this.load()); return this.load() },
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
        detail: 'It is signed out and will no longer be able to refresh its access to your account. It will ask for your approval again next time.', confirmLabel: 'Remove access' })
      if (!ok) return
      try { await del(accountApi('/apps/') + enc(a.id)); toast('Access removed.'); await this.load() } catch (e) { toast(e.message, 'error') }
    },
  }))
}
