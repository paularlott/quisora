// Sign-in pages: organization sign-in (password, TOTP, passkeys, MFA enrolment, forgotten password),
// invitation / reset, logout. The anonymous sign-in endpoints answer 401 for wrong credentials, so this module has
// its own fetch wrapper (lib/api.js treats 401 as "session ended" and navigates away). It also hosts the WebAuthn
// helpers that account.js reuses.
import { ApiError, orgBase } from '../lib/api.js'
import { focusWhenShown, isShown } from '../lib/focus.js'
import { formMixin } from '../lib/form.js'
import { announce, toast } from '../lib/announce.js'
import { mix } from '../lib/mix.js'

const csrf = () => {
  const m = document.querySelector('meta[name="csrf-token"]')
  return m ? m.content : ''
}

// anon POSTs JSON to a path of the page's organization (/o/<id>/..., see orgBase) with the anonymous double-submit
// CSRF header and never redirects on 401.
export async function anon(path, body) {
  let res
  try {
    res = await fetch(orgBase() + path, {
      method: 'POST', credentials: 'same-origin',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
      body: JSON.stringify(body || {}),
    })
  } catch {
    throw new ApiError(0, { error: 'The server could not be reached. Check your connection and try again.' })
  }
  let data = null
  try { data = await res.json() } catch { data = null }
  if (!res.ok) throw new ApiError(res.status, data)
  return data
}

// ---------------------------------------------------------------------------------------------------------------
// WebAuthn helpers (JSON in the shapes the server produces and expects)

const b64uToBuf = (s) => {
  const p = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')
  return Uint8Array.from(atob(p), (c) => c.charCodeAt(0)).buffer
}
const bufToB64u = (b) =>
  btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

export const passkeysSupported = () => typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials

export async function conditionalSupported() {
  try {
    return passkeysSupported() && !!PublicKeyCredential.isConditionalMediationAvailable &&
      (await PublicKeyCredential.isConditionalMediationAvailable())
  } catch { return false }
}

function creationOptions(json) {
  const pk = json.publicKey || json
  if (PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(pk)
  return {
    ...pk, challenge: b64uToBuf(pk.challenge), user: { ...pk.user, id: b64uToBuf(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  }
}

function requestOptions(json) {
  const pk = json.publicKey || json
  if (PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(pk)
  return { ...pk, challenge: b64uToBuf(pk.challenge), allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })) }
}

function credentialJSON(c) {
  if (c.toJSON) return c.toJSON()
  const r = c.response
  const out = { id: c.id, rawId: bufToB64u(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment,
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {}, response: {
      clientDataJSON: bufToB64u(r.clientDataJSON) } }
  if (r.attestationObject) {
    out.response.attestationObject = bufToB64u(r.attestationObject)
    out.response.transports = r.getTransports ? r.getTransports() : []
  } else {
    out.response.authenticatorData = bufToB64u(r.authenticatorData)
    out.response.signature = bufToB64u(r.signature)
    if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle)
  }
  return out
}

function describe(e, what) {
  if (e && e.name === 'AbortError') return e
  if (e && e.name === 'NotAllowedError') return new ApiError(0, { error: `${what} was cancelled or timed out. Try again.` })
  if (e && e.name === 'InvalidStateError') return new ApiError(0, { error: 'This authenticator already has a passkey for this account.' })
  if (e instanceof ApiError) return e
  return new ApiError(0, { error: `${what} did not work on this device.` })
}

// getAssertion runs navigator.credentials.get for the server's options and returns the response JSON.
export async function getAssertion(options, { conditional = false, signal } = {}) {
  try {
    const cred = await navigator.credentials.get({ publicKey: requestOptions(options),
      mediation: conditional ? 'conditional' : undefined, signal })
    if (!cred) throw new ApiError(0, { error: 'No passkey was provided.' })
    return credentialJSON(cred)
  } catch (e) { throw describe(e, 'Passkey sign-in') }
}

// createCredential runs navigator.credentials.create for the server's options.
export async function createCredential(options) {
  try {
    const cred = await navigator.credentials.create({ publicKey: creationOptions(options) })
    if (!cred) throw new ApiError(0, { error: 'No passkey was created.' })
    return credentialJSON(cred)
  } catch (e) { throw describe(e, 'Creating the passkey') }
}

// Local path check for redirects after sign-in (the server already sanitises; this is belt and braces).
const localPath = (p) => typeof p === 'string' && p.startsWith('/') && !p.startsWith('//') && !p.includes('\\')

function go(next) { window.location.assign(localPath(next) ? next : orgBase() + '/account') }

// ---------------------------------------------------------------------------------------------------------------
// Passkey sign-in on the organization page

function passkeyMixin() {
  return {
    canPasskey: false, passkeyOn: false, conditional: null,
    get showPasskey() { return this.passkeyOn && this.canPasskey },

    async startConditional(extra) {
      if (!this.showPasskey || !(await conditionalSupported())) return
      this.conditional = new AbortController()
      const signal = this.conditional.signal
      try {
        const begin = await anon('/api-internal/login/passkey/begin', extra)
        const credential = await getAssertion(begin.options, { conditional: true, signal })
        const res = await anon('/api-internal/login/passkey/finish', { challenge: begin.challenge, credential })
        this.afterPasskey(res)
      } catch (e) {
        if (!(e && e.name === 'AbortError')) { /* autofill is best effort: stay quiet */ }
      } finally {
        // only this ceremony's controller: a stopped one finishing late must not clear one started since
        if (this.conditional && this.conditional.signal === signal) this.conditional = null
      }
    },
    stopConditional() { if (this.conditional) { this.conditional.abort(); this.conditional = null } },

    // passkeyLogin runs the explicit ceremony. extra carries next and tenant, or the ticket of a password step.
    async passkeyLogin(extra) {
      this.stopConditional()
      const res = await this.run(async () => {
        const begin = await anon('/api-internal/login/passkey/begin', extra)
        const credential = await getAssertion(begin.options)
        return anon('/api-internal/login/passkey/finish', { challenge: begin.challenge, credential })
      })
      if (res) this.afterPasskey(res)
    },
    afterPasskey(res) { announce('Signed in. Redirecting.'); go(res.next) },
  }
}

// ---------------------------------------------------------------------------------------------------------------
// The steps after a verified password (or an invitation): authenticator code, passkey as second factor, MFA
// enrolment. Shared by the organization sign-in page and the invitation page; the markup is the "login-steps"
// template partial.

function stepsMixin() {
  return {
    step: 'password', ticket: '', methods: [], alternatives: [], email: '', emailSent: false, qr: '', secret: '', enrolStarted: false,
    // at a second-factor step: '' the step itself, 'choose' the "Try another way" list, 'recovery' a recovery code,
    // 'email_code' a code by email
    view: '',

    get secondFactor() { return this.step === 'totp' || this.step === 'passkey' || this.step === 'email_code' },
    get isEmailCode() { return (this.step === 'email_code' && this.view === '') || (this.secondFactor && this.view === 'email_code') },
    get altEmail() { return this.alternatives.includes('email_code') && this.view !== 'email_code' && this.step !== 'email_code' },
    get emailTo() { return this.email || 'your email address' },
    get emailOptionText() { return this.email ? `Email a code to ${this.email}` : 'Email me a code' },
    get isTotp() { return this.step === 'totp' && this.view === '' },
    get isPasskeyStep() { return this.step === 'passkey' && this.view === '' },
    get isChooser() { return this.secondFactor && this.view === 'choose' },
    get isRecovery() { return this.secondFactor && this.view === 'recovery' },
    get altPasskey() { return this.step === 'totp' && this.alternatives.includes('passkey') && this.canPasskey },
    get altRecovery() { return this.alternatives.includes('recovery') },
    get noOtherWayText() {
      return (this.altPasskey || this.altEmail || this.altRecovery ? 'None of these? ' : 'There is no other way to finish signing in to this account. ') +
        'Ask your administrator for a new invitation: it lets you set up your sign-in again.'
    },
    get isEnrol() { return this.step === 'enrol' },
    get canEnrolPasskey() { return this.methods.includes('passkey') && this.canPasskey },
    get hasQR() { return this.qr !== '' },
    get verifyLabel() { return this.busy ? 'Verifying…' : 'Verify' },

    // run the request; ApiError field names get a prefix when the same field exists in two panels
    async call(prefix, fn) {
      return this.run(async () => {
        try { return await fn() } catch (e) {
          if (e instanceof ApiError && e.field) e.field = prefix + e.field
          throw e
        }
      })
    },

    // focusFirst moves focus to the first visible [data-step-focus] of the step now shown. The step's markup may
    // become visible a frame or two after the state changes, so it retries briefly; until then the previous step can
    // still be showing, so the field that already has focus (the password just submitted) only counts on the last
    // try. $root, not $el: $el is the element whose handler is running (e.g. the password form), which does not
    // contain the next step's field.
    focusFirst() {
      const attempt = (left) => {
        const target = [...this.$root.querySelectorAll('[data-step-focus]')].find(isShown)
        if (target && (target !== document.activeElement || left === 0)) target.focus()
        else if (left > 0) requestAnimationFrame(() => attempt(left - 1))
      }
      this.$nextTick(() => attempt(30))
    },

    // handle moves on to the step the server asked for, or to the page it signed the user in to.
    handle(res) {
      if (res.next) { announce('Signed in. Redirecting.'); go(res.next); return }
      this.step = res.step
      this.view = ''
      this.alternatives = res.alternatives || []
      this.email = res.email || ''
      this.form.mcode = ''
      this.emailSent = res.step === 'email_code' // the server sent the first code itself
      this.ticket = res.ticket
      this.methods = res.methods || []
      if (this.stopConditional) this.stopConditional()
      this.clearErrors()
      announce(({ totp: 'Enter the code from your Authenticator App.', passkey: 'Confirm with your passkey to finish signing in.',
        email_code: 'We emailed you a code. Enter it to finish signing in.' })[res.step] || '')
      // MFA enrolment goes straight to the authenticator-app set-up (QR code and code box); a passkey is offered
      // underneath when available. No intermediate "choose a method" screen.
      if (res.step === 'enrol') { this.startTotpEnrol(); return }
      this.focusFirst()
    },

    async submitTotp() {
      const res = await this.call('', () => anon('/api-internal/login/totp', { ticket: this.ticket, code: this.form.code }))
      if (res) this.handle(res)
    },
    confirmWithPasskey() { return this.passkeyLogin({ ticket: this.ticket }) },
    tryAnotherWay() {
      this.view = 'choose'
      this.clearErrors()
      this.focusFirst()
    },
    backToStep() {
      this.view = ''
      this.clearErrors()
      this.focusFirst()
    },
    // an emailed code: chosen under "Try another way" (sends one, unless one was sent already), or asked for again
    async chooseEmailCode() {
      if (!this.emailSent) {
        const res = await this.call('', () => anon('/api-internal/login/email/send', { ticket: this.ticket }))
        if (!res) return
        this.email = res.email || this.email
        this.emailSent = true
      }
      this.view = 'email_code'
      this.form.mcode = ''
      this.clearErrors()
      announce('We emailed you a code. Enter it to finish signing in.')
      this.focusFirst()
    },
    async resendEmailCode() {
      const res = await this.call('m', () => anon('/api-internal/login/email/send', { ticket: this.ticket }))
      if (!res) return
      toast('A new code is on its way. Only the newest one works.')
      this.focusFirst()
    },
    async submitEmailCode() {
      const res = await this.call('', () => anon('/api-internal/login/email', { ticket: this.ticket, code: this.form.mcode }))
      if (res) this.handle(res)
    },
    startRecovery() {
      this.view = 'recovery'
      this.clearErrors()
      announce('Enter one of your recovery codes.')
      this.focusFirst()
    },
    async submitRecovery() {
      const res = await this.call('', () => anon('/api-internal/login/recovery', { ticket: this.ticket, code: this.form.rcode }))
      if (res) this.handle(res)
    },

    // ---- MFA enrolment
    async startTotpEnrol() {
      const res = await this.call('', () => anon('/api-internal/login/enrol/totp/begin', { ticket: this.ticket }))
      if (!res) return
      this.qr = res.qr
      this.secret = res.secret
      this.enrolStarted = true
      announce('Set up your Authenticator App: scan the QR code, then enter the code it shows.')
      this.focusFirst()
    },
    async confirmTotpEnrol() {
      const res = await this.call('e', () => anon('/api-internal/login/enrol/totp/confirm', { ticket: this.ticket, code: this.form.ecode }))
      if (res) this.handle(res)
    },
    async enrolPasskey() {
      const res = await this.run(async () => {
        const begin = await anon('/api-internal/login/enrol/passkey/begin', { ticket: this.ticket })
        const credential = await createCredential(begin.options)
        return anon('/api-internal/login/enrol/passkey/finish', { ticket: this.ticket, challenge: begin.challenge, name: 'Passkey', credential })
      })
      if (res) this.handle(res)
    },
  }
}

export default function (Alpine) {
  // ---- the organization's sign-in page -----------------------------------------------------------------------
  Alpine.data('loginPage', () => mix(formMixin(), passkeyMixin(), stepsMixin(), {
    next: '', tenant: '', forgotSent: false, forgotOpen: false,

    init() {
      const d = this.$el.dataset
      this.tenant = d.tenant || ''
      this.next = d.next || ''
      this.passkeyOn = d.passkey === '1'
      this.canPasskey = passkeysSupported()
      this.resetForm({ email: d.hint || '', password: '', code: '', ecode: '', fg_email: '' })
      this.step = 'email' // the sign-in starts with the email address (or a provider, or a passkey)
      // Back from a provider with a second factor due: continue with that step.
      if (d.step && d.ticket) {
        this.handle({ step: d.step, ticket: d.ticket, methods: (d.methods || '').split(' ').filter(Boolean),
          alternatives: (d.alternatives || '').split(' ').filter(Boolean), email: d.email || '' })
        return
      }
      this.startConditional({ next: this.next, tenant: this.tenant })
    },

    // step getters (the CSP build wants plain property paths in templates)
    get isEmail() { return this.step === 'email' },
    get emailInitial() { return (this.form.email || '?').charAt(0).toUpperCase() },
    get isPassword() { return this.step === 'password' && !this.forgotOpen },
    get passkeyChoice() { return this.isEmail && this.showPasskey }, // the passkey button, last of the one-step sign-ins
    get isForgot() { return this.step === 'password' && this.forgotOpen },
    get submitLabel() { return this.busy ? 'Signing in…' : 'Sign in' },
    get forgotNotSent() { return !this.forgotSent },

    // An error about the address (from the server, after the password step) is shown on the email step.
    errorKey(field) {
      if (field === 'email' && this.step === 'password') this.step = 'email'
      return field
    },

    // continueToPassword moves from the email step to the password step. It asks the server nothing, so the next
    // step is the same for every address, an account or not.
    continueToPassword() {
      const email = this.form.email.trim()
      if (!email) {
        this.setErrors(new ApiError(422, { error: 'Enter your email address.', field: 'email' }))
        return
      }
      if (!/^[^\s@]+@[^\s@]+$/.test(email)) {
        this.setErrors(new ApiError(422, { error: 'Enter an email address, like name@example.com.', field: 'email' }))
        return
      }
      this.form.email = email
      this.stopConditional()
      this.clearErrors()
      this.step = 'password'
      this.focusFirst()
    },
    changeEmail() {
      this.form.password = ''
      this.clearErrors()
      this.step = 'email'
      focusWhenShown('f-email')
      this.startConditional({ next: this.next, tenant: this.tenant })
    },

    async submitPassword() {
      const f = this.form
      if (!f.password) {
        this.setErrors(new ApiError(422, { error: 'Enter your password.', field: 'password' }))
        return
      }
      const res = await this.call('', () => anon('/api-internal/login/password', { email: f.email.trim(), password: f.password, next: this.next, tenant: this.tenant }))
      if (res) { this.form.password = ''; this.handle(res) }
    },
    signInWithPasskey() { return this.passkeyLogin({ next: this.next, tenant: this.tenant }) },

    // ---- forgotten password
    openForgot() {
      this.forgotOpen = true
      this.forgotSent = false
      this.clearErrors()
      this.form.fg_email = this.form.email
      this.stopConditional()
      this.focusFirst()
    },
    closeForgot() { this.forgotOpen = false; this.clearErrors(); this.focusFirst() },
    async submitForgot() {
      if (!this.form.fg_email.trim()) {
        this.setErrors(new ApiError(422, { error: 'Enter your email address.', field: 'fg_email' }))
        return
      }
      const res = await this.call('fg_', () => anon('/api-internal/password/forgot', { tenant: this.tenant, email: this.form.fg_email.trim() }))
      if (res) { this.forgotSent = true; announce('If an account matches, a reset link is on its way.') }
    },
  }))

  // ---- /reset ------------------------------------------------------------------------------------------------
  Alpine.data('passwordSetup', () => mix(formMixin(), {
    token: '', action: '', done: false, nextUrl: '',
    init() { // the root's data attributes: elsewhere this.$el is the element being evaluated, not the root
      this.token = this.$el.dataset.token
      this.action = this.$el.dataset.action || 'Set password'
      this.resetForm({ password: '', confirm: '' })
    },
    get notDone() { return !this.done },
    get submitLabel() { return this.busy ? 'Saving…' : this.action },
    async submit() {
      const f = this.form
      if (f.password !== f.confirm) {
        this.setErrors(new ApiError(422, { error: 'The two passwords do not match.', field: 'confirm' }))
        return
      }
      const res = await this.run(() => anon('/api-internal/password/reset', { token: this.token, password: f.password }))
      if (!res) return
      this.nextUrl = localPath(res.next) ? res.next : orgBase() + '/login'
      this.done = true
      this.form.password = this.form.confirm = ''
      announce('Your password has been saved. You can sign in now.')
      focusWhenShown('signin-link')
    },
  }))

  // ---- /invite: sign-up --------------------------------------------------------------------------------------
  // One page, up to two ways to finish: a password and/or a passkey (what the organization allows). Creating a
  // passkey asks the server for options authorised by the invitation, runs the browser ceremony and sends the
  // credential together with the password, if one was typed.
  Alpine.data('invitePage', () => mix(formMixin(), passkeyMixin(), stepsMixin(), {
    token: '', passwordOn: false, passkeyAllowed: false,
    init() {
      const d = this.$el.dataset
      this.token = d.token
      this.passwordOn = d.password === '1'
      this.passkeyAllowed = d.passkey === '1'
      this.canPasskey = passkeysSupported()
      this.step = 'setup'
      this.resetForm({ password: '', confirm: '', code: '', ecode: '' })
    },
    get isSetup() { return this.step === 'setup' },
    get showPasskeyButton() { return this.passkeyAllowed && this.canPasskey },
    get noPasskeySupport() { return this.passkeyAllowed && !this.canPasskey },
    get passwordLabel() { return this.busy ? 'Saving…' : this.passwordOn && this.passkeyAllowed ? 'Set password' : 'Activate account' },
    // the passkey comes first and is the main action where it can be created; the password button is then secondary
    get passwordButtonClass() { return this.showPasskeyButton ? 'btn-secondary' : 'btn-primary' },

    async submitPassword() {
      const f = this.form
      if (!f.password) {
        this.setErrors(new ApiError(422, { error: 'Enter a password.', field: 'password' }))
        return
      }
      if (f.password !== f.confirm) {
        this.setErrors(new ApiError(422, { error: 'The two passwords do not match.', field: 'confirm' }))
        return
      }
      const res = await this.call('', () => anon('/api-internal/invite/complete', { token: this.token, password: f.password }))
      if (res) { this.form.password = this.form.confirm = ''; this.handle(res) }
    },
    async createPasskey() {
      const res = await this.run(async () => {
        const f = this.form
        if ((f.password || f.confirm) && f.password !== f.confirm) {
          throw new ApiError(422, { error: 'The two passwords do not match.', field: 'confirm' })
        }
        const begin = await anon('/api-internal/invite/passkey/begin', { token: this.token })
        const credential = await createCredential(begin.options)
        const body = { token: this.token, challenge: begin.challenge, name: 'Passkey', credential }
        if (this.passwordOn && f.password) body.password = f.password
        return anon('/api-internal/invite/complete', body)
      })
      if (res) { this.form.password = this.form.confirm = ''; this.handle(res) }
    },
  }))

  // ---- /logout -----------------------------------------------------------------------------------------------
  Alpine.data('logoutPage', () => mix(formMixin(), {
    next: '',
    init() { this.next = this.$el.dataset.next || '' }, // the root's attribute; in submit, this.$el is the form
    async submit() {
      const next = this.next
      const res = await this.run(async () => {
        const r = await fetch(orgBase() + '/logout' + (next ? '?next=' + encodeURIComponent(next) : ''), {
          method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'X-CSRF-Token': csrf() } })
        let data = null
        try { data = await r.json() } catch { data = null }
        if (!r.ok) throw new ApiError(r.status, data)
        return data
      })
      if (res) window.location.assign(localPath(res.next) ? res.next : orgBase() + '/login')
    },
    get submitLabel() { return this.busy ? 'Signing out…' : 'Sign out' },
  }))
}
