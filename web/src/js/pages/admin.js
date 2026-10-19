// Admin pages: organizations, users, groups, clients, providers, settings, audit. Every list is server-side
// (search, sort, paging); every form submits through the management API (/api/v1) and shows errors inline.
import { get, post, put, patch, del, qs, ApiError } from '../lib/api.js'
import { tableMixin } from '../lib/table.js'
import { formMixin, lines, words } from '../lib/form.js'
import { dialogMixin } from '../lib/dialog.js'
import { toast, announce } from '../lib/announce.js'
import { mix } from '../lib/mix.js'
import { emailsMixin } from '../lib/emails.js'
import { tagsMixin } from '../lib/tags.js'
import { pickerMixin } from '../lib/picker.js'
import { comboMixin, localeSource, zoneSource, userTypeSource } from '../lib/combo.js'
import accessComponent from './access.js'
import { listFieldMixin, listRows, listValues } from '../lib/listfield.js'
import { subscribe, liveRunner, announceUpdate, getOrNull, typingNow, CHANGED_TEXT } from '../lib/live.js'
import { fmtDate, fmtDateTime, relTime, isSet, ROLE_LABEL, ROLE_BADGE } from '../lib/format.js'
import { withReauth, describeAgent } from './account.js'

const enc = encodeURIComponent

// Confirmation through the shared dialog; resolves true/false.
// mailOn: the server has email set up (an SMTP server); without it nothing offers to send email.
const mailOn = () => document.documentElement.dataset.mail === '1'

function confirmAction(Alpine, opts) { return Alpine.store('confirm').ask(opts) }

// Focus an element that has just been revealed (x-show applies on the next frame, so retry briefly).
function focusSoon(id) {
  let n = 0
  const tick = () => {
    const el = document.getElementById(id)
    if (el) el.focus()
    if (++n < 6 && (!el || document.activeElement !== el)) setTimeout(tick, 40)
  }
  setTimeout(tick, 30)
}

// Tags as shown in tables: a list of badge descriptors.
function tagView(tags, what) {
  const list = tags || []
  return { hasTags: list.length > 0, noTags: list.length === 0, tagItems: list.map((t) => ({ value: t, filterLabel: `Show ${what} tagged ${t}` })) }
}

function activeBadge(on, yes = 'Active', no = 'Disabled') {
  return on ? { text: yes, cls: 'badge badge-success' } : { text: no, cls: 'badge badge-danger' }
}

// ---------------------------------------------------------------------------------------------------------------
// User dialog (shared by the users list and the user page)
const WORK_FIELDS = ['title', 'department', 'organization', 'division', 'cost_center', 'employee_number']
// statusNote describes the last time a user was disabled or enabled again: when, by whom and why.
function statusNote(u) {
  const s = u.status_changed
  if (!s) return ''
  const who = s.by === 'system' ? 'automatically' : 'by ' + (s.by || 'someone')
  return `${u.active ? 'Enabled again' : 'Disabled'} ${fmtDateTime(s.at)} ${who}${s.reason ? ': ' + s.reason : '.'}`
}

// The date part (UTC) of an end date, for a date input.
const dateOnly = (iso) => (iso ? new Date(iso).toISOString().slice(0, 10) : '')

function userDialogMixin(Alpine) {
  return mix(tagsMixin(), comboMixin({
    locale: localeSource, zoneinfo: zoneSource, user_type: userTypeSource,
    manager_id: {
      async search(q) {
        const res = await get(`${this.apiBase}/users${qs({ q, limit: 20 })}`)
        const self = this.editingUser ? this.editingUser.id : ''
        return res.items.filter((u) => u.id !== self).map((u) => ({ value: u.id, label: u.name || u.username, detail: u.email }))
      },
    },
  }), {
    editingUser: null, apiBase: '', workOpen: false,
    // Server field names of work details (work.title, work.manager_id) to this form's fields.
    errorKey(f) { return !f || !f.startsWith('work.') ? f : f === 'work.manager_id' ? 'manager_id' : 'work_' + f.slice(5) },
    // The profile and work fields of the form, for a request body.
    profileBody() {
      const f = this.form
      const work = { manager_id: f.manager_id || '' }
      for (const k of WORK_FIELDS) work[k] = f['work_' + k] || ''
      return { locale: f.locale || '', zoneinfo: f.zoneinfo || '', user_type: f.user_type || '', valid_until: f.valid_until || '', work,
        phone_number: f.phone_number || '', phone_number_verified: !!f.phone_number_verified && !!(f.phone_number || '').trim() }
    },
    fillProfile(u) {
      const w = (u && u.work) || {}
      for (const k of WORK_FIELDS) this.form['work_' + k] = w[k] || ''
      this.form.valid_until = dateOnly(u && u.valid_until)
      this.form.phone_number = (u && u.phone_number) || ''
      this.form.phone_number_verified = !!(u && u.phone_number_verified)
      this.form.status_reason = ''
      this.comboSet('locale', u ? u.locale : '')
      this.comboSet('zoneinfo', u ? u.zoneinfo : '')
      this.comboSet('user_type', u ? u.user_type : '')
      this.comboSet('manager_id', w.manager_id || '', u && u.manager ? u.manager.name : '')
      if (w.manager_id && !(u && u.manager)) { // a user from a list: look the manager's name up
        getOrNull(`${this.apiBase}/users/${enc(w.manager_id)}`).then((m) => { if (m && this.form.manager_id === w.manager_id) this.comboSet('manager_id', m.id, m.name) })
      }
      this.workOpen = WORK_FIELDS.some((k) => w[k]) || !!w.manager_id
    },
    get isCreate() { return this.editingUser === null },
    // The active switch differs from the saved state: the change can carry a reason.
    get statusChanging() { return this.editingUser !== null && !!this.form.active !== !!this.editingUser.active },
    get statusReasonHelp() { return this.form.active ? 'Optional. Why the account is enabled again; shown on the user\u2019s page and kept in the audit log.' : 'Optional. Why the account is disabled; shown on the user\u2019s page and kept in the audit log.' },
    get isEdit() { return this.editingUser !== null },
    // Editing yourself: your own address is changed by another manager or administrator (shown, never sent).
    get editingSelf() { return this.editingUser !== null && this.editingUser.id === document.documentElement.dataset.me },
    get emailEditable() { return !this.editingSelf },
    get userDialogTitle() { return this.editingUser ? 'Edit user' : 'New user' },
    get userSubmitLabel() { return this.editingUser ? 'Save changes' : 'Create user' },
    get busyLabel() { return this.busy ? 'Saving…' : this.userSubmitLabel },
    openCreateUser(ev) {
      this.editingUser = null
      this.resetForm({ username: '', email: '', given_name: '', family_name: '', role: 'user', invite: false, tags: [] })
      this.resetChipText()
      this.fillProfile(null)
      if (!this._emailWatch) {
        this._emailWatch = true
        // "Email the invitation" follows the email field: ticked once an address is typed, cleared when it is removed
        this.$watch('form.email', (v, old) => { const has = !!(v || '').trim(); if (mailOn() && this.isCreate && has !== !!(old || '').trim()) this.form.invite = has })
      }
      this.openDlg('user-dialog', ev.currentTarget)
    },
    // ---- invitation link dialog (after creating a user, or from the user page) ----
    inviteUrl: '', inviteExpires: '', inviteName: '', inviteTo: '', inviteNote: '', inviteSent: false, inviteUserId: '', inviteBusy: false, inviteError: '',
    _emailWatch: false,
    get hasInvite() { return this.inviteUrl !== '' },
    get noInvite() { return this.inviteUrl === '' },
    get canEmailInvite() { return mailOn() && this.inviteUrl !== '' && this.inviteTo !== '' && !this.inviteSent },
    get hasInviteNote() { return this.inviteNote !== '' },
    get hasInviteError() { return this.inviteError !== '' },
    get inviteExpiresText() { return this.inviteExpires ? fmtDateTime(this.inviteExpires) : '' },
    get inviteSentText() { return this.inviteSent ? `Emailed to ${this.inviteTo}.` : '' },
    get inviteTitle() { return this.inviteUrl ? 'Invitation link' : 'New invitation link' },
    get inviteWho() { return this.inviteName },
    get inviteGenLabel() { return this.inviteBusy ? 'Working…' : 'Generate link' },
    get inviteMailLabel() { return this.inviteBusy ? 'Sending…' : 'Send by email' },
    openInvite(u, res, opener) {
      Object.assign(this, { inviteUserId: u.id, inviteName: u.name || u.username, inviteTo: u.email || '', inviteError: '', inviteBusy: false,
        inviteUrl: res ? res.url || '' : '', inviteExpires: res ? res.expires || '' : '', inviteSent: !!(res && res.emailed), inviteNote: res ? res.email_warning || '' : '' })
      // let x-show reveal the right state first, then open and focus its main control
      this.$nextTick(() => {
        this.openDlg('invite-dialog', opener)
        focusSoon(this.inviteUrl ? 'invite-copy' : 'invite-generate')
      })
    },
    async makeInvite(email) {
      if (this.inviteBusy) return
      this.inviteBusy = true
      this.inviteError = ''
      try {
        const res = await post(`${this.apiBase}/users/${enc(this.inviteUserId)}/invite`, email ? { email: true } : {})
        Object.assign(this, { inviteUrl: res.url, inviteExpires: res.expires, inviteSent: !!res.emailed, inviteNote: res.email_warning || '' })
        announce(email && res.emailed ? 'Invitation emailed.' : 'Invitation link created.')
        focusSoon('invite-copy')
      } catch (e) { this.inviteError = e.message; announce(e.message, 'assertive') }
      this.inviteBusy = false
    },
    generateInvite() { return this.makeInvite(false) },
    sendInvite() { return this.makeInvite(true) },
    openEditUser(u, opener) {
      this.editingUser = u
      this.resetForm({ username: u.username, email: u.email || '', role: u.role, active: u.active,
        given_name: u.given_name || '', family_name: u.family_name || '', tags: [...(u.tags || [])] })
      this.resetChipText()
      this.fillProfile(u)
      this.openDlg('user-dialog', opener)
      this.watchEdit({ kinds: ['user'], record: u, fetchOne: () => getOrNull(`${this.apiBase}/users/${enc(u.id)}`) })
    },
    async submitUser() {
      if (!this.tagsReady()) { this.focusTagInput(); return }
      if (this.comboPending('manager_id')) { // typed but not chosen: the field only takes a person from the list
        this.workOpen = true
        this.$nextTick(() => this.setErrors(new ApiError(422, { error: 'Choose the manager from the list, or clear the field.', field: 'work.manager_id' })))
        return
      }
      const f = this.form
      const res = await this.run(() => {
        if (this.editingUser) {
          const body = { username: f.username, email: f.email, given_name: f.given_name, family_name: f.family_name, role: f.role, active: !!f.active, tags: f.tags, ...this.profileBody() }
          if (this.editingSelf) delete body.email
          if (this.statusChanging && (f.status_reason || '').trim()) body.status_reason = f.status_reason.trim()
          return patch(`${this.apiBase}/users/${enc(this.editingUser.id)}`, body)
        }
        return post(`${this.apiBase}/users`, { username: f.username, email: f.email, given_name: f.given_name, family_name: f.family_name, role: f.role, tags: f.tags, ...this.profileBody(),
          invite: { email: mailOn() && !!f.invite && !!(f.email || '').trim() } })
      })
      if (!res) return
      this.closeDlg('user-dialog')
      if (this.editingUser) toast('User saved.')
      else setTimeout(() => this.openInvite(res, res.invite, null), 60) // after the user dialog's close handler returned focus
      await this.afterUserSaved(res)
    },
  })
}

// ---------------------------------------------------------------------------------------------------------------
// Tenants (shared by the tenants list and the tenant page)
const clientsText = (n) => (n === 1 ? '1 client' : n + ' clients')
// Provider types (internal/model ProviderTypes): label, and the address field each takes.
const PROVIDER_TYPES = {
  oidc: { text: 'OpenID Connect', name: 'Single sign-on', address: 'Issuer URL', placeholder: 'https://login.example.com', required: true,
    help: 'The provider\u2019s https issuer; discovery runs from it.' },
  google: { text: 'Google', name: 'Google' },
  microsoft: { text: 'Microsoft', name: 'Microsoft' },
  github: { text: 'GitHub', name: 'GitHub' },
  gitlab: { text: 'GitLab', name: 'GitLab', address: 'GitLab address', placeholder: 'https://gitlab.com',
    help: 'Leave empty for gitlab.com. For GitLab self-managed, your server\u2019s address.' },
  auth0: { text: 'Auth0', name: 'Auth0', address: 'Auth0 domain', placeholder: 'acme.eu.auth0.com', required: true,
    help: 'Your Auth0 tenant\u2019s domain, or its custom domain.' },
}
const providerTypeText = (t) => (PROVIDER_TYPES[t] || PROVIDER_TYPES.oidc).text
const providerSub = (p) => p.type === 'github' ? 'github.com' : p.type === 'microsoft' ? 'Entra ID \u00b7 ' + (p.tenant === 'organizations' ? (p.allowed_tenants || []).length + ' allowed tenants' : p.tenant) : p.issuer
const shapeProvider = (p) => ({ id: p.id, name: p.name, enabled: p.enabled, typeText: providerTypeText(p.type), stateText: p.enabled ? 'enabled' : 'disabled' })

function methodsText(t) {
  const s = t.settings
  const parts = []
  if (s.password_login) parts.push('Password')
  if (s.passkey_login) parts.push('Passkeys')
  if (s.all_providers) parts.push('All providers')
  else if ((s.providers || []).length) parts.push((s.providers.length === 1 ? '1 provider' : s.providers.length + ' providers'))
  return parts.join(', ') || 'None'
}

// The tenant create/edit dialog (partials/admin.html "tenant-dialog"). Form keys tenant_name / tenant_description keep
// the element ids distinct from the client dialog's name / description on the tenant page.
function tenantDialogMixin(Alpine) {
  return {
    editingTenant: null, apiBase: '', providers: [], orgPassword: true, orgPasskey: true, orgMFA: false, _form: 'tenant',
    errorKey(f) { return this._form === 'tenant' && (f === 'name' || f === 'description') ? 'tenant_' + f : f },
    async loadOrgInfo() {
      try {
        const [org, provs] = await Promise.all([get(`${this.apiBase}/settings`), get(`${this.apiBase}/providers${qs({ sort: 'name', limit: 100 })}`)])
        this.orgPassword = org.settings.password_login
        this.orgPasskey = org.settings.passkey_login
        this.orgMFA = !!org.settings.require_mfa
        this.providers = provs.items.map(shapeProvider)
      } catch (e) { toast(e.message, 'error') }
    },
    get tenantDialogTitle() { return this.editingTenant ? 'Edit sign-in rules' : 'New tenant' },
    get tenantSubmitLabel() { return this.busy ? 'Saving…' : this.editingTenant ? 'Save changes' : 'Create tenant' },
    get passwordOff() { return !this.orgPassword },
    get passkeyOff() { return !this.orgPasskey },
    get tenantMFAOption() { return !this.orgMFA },
    get hasProviders() { return this.providers.length > 0 },
    get noProviders() { return this.providers.length === 0 },
    get pickProviders() { return !this.form.all_providers },
    get providerHelp() { return this.hasProviders ? 'Only enabled providers can be used to sign in, whatever is ticked here.' : 'This organization has no sign-in providers yet.' },
    tenantToForm(t) {
      const s = t.settings
      return { tenant_name: t.name, display_name: t.display_name, tenant_description: t.description || '', who: s.members_only ? 'members' : 'everyone', password_login: !!s.password_login, passkey_login: !!s.passkey_login,
        all_providers: s.all_providers !== false, providers: [...(s.providers || [])], require_mfa: !!s.require_mfa }
    },
    openCreateTenant(opener) {
      this._form = 'tenant'
      this.editingTenant = null
      this.resetForm(this.tenantToForm({ name: '', display_name: '', settings: { members_only: true, password_login: true, passkey_login: true, all_providers: true, providers: [], require_mfa: true } }))
      this.openDlg('tenant-dialog', opener)
      this.loadOrgInfo()
    },
    openEditTenant(t, opener) {
      this._form = 'tenant'
      this.editingTenant = t
      this.resetForm(this.tenantToForm(t))
      this.openDlg('tenant-dialog', opener)
      this.loadOrgInfo()
      this.watchEdit({ kinds: ['tenant'], record: t, fetchOne: () => getOrNull(`${this.apiBase}/tenants/${enc(t.id)}`) })
    },
    async submitTenant() {
      const f = this.form
      const body = { display_name: f.display_name, description: f.tenant_description, settings: { members_only: f.who === 'members', password_login: f.password_login, passkey_login: f.passkey_login,
        all_providers: f.all_providers, providers: f.all_providers ? [] : f.providers, require_mfa: f.require_mfa } }
      if (!this.editingTenant || f.tenant_name !== this.editingTenant.name) body.name = f.tenant_name
      const edit = this.editingTenant
      const res = await this.run(() => edit ? patch(`${this.apiBase}/tenants/${enc(edit.id)}`, body) : post(`${this.apiBase}/tenants`, body))
      if (!res) return
      this.closeDlg('tenant-dialog')
      toast(edit ? 'Sign-in rules saved.' : 'Tenant created.')
      await this.afterTenantSaved(res)
    },
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Client dialogs (create / edit / secret shown once); used on the tenant page.
const GRANTS = ['authorization_code', 'refresh_token', 'client_credentials']
// Standard scopes shown as checkboxes (the rest of a client's scopes are its own API scopes, edited as rows).
const STD_SCOPES = [
  { value: 'openid', help: 'Required for OpenID Connect sign-in: the user\u2019s identity.' },
  { value: 'profile', help: 'The user\u2019s name, username and picture.' },
  { value: 'email', help: 'The user\u2019s email address and whether it is verified.' },
  { value: 'groups', help: 'The user\u2019s group names and tags.' },
  { value: 'org', help: 'The user\u2019s organization and tenant.' },
  { value: 'offline_access', help: 'Refresh tokens, so the application can stay signed in.' },
]
const STD_NAMES = STD_SCOPES.map((s) => s.value)
// Scope tokens are printable ASCII except space, " and \ (RFC 6749 §3.3); the server enforces the same.
const SCOPE_RE = /^[\x21\x23-\x5B\x5D-\x7E]{1,100}$/
// Server field -> the list editor that shows it.
const LIST_OF_FIELD = { redirect_uris: 'redirect_uris', post_logout_redirect_uris: 'post_logout_redirect_uris', scopes: 'custom_scopes', resources: 'resources' }
const LIST_ITEMS = { redirect_uris: 'Redirect URI', post_logout_redirect_uris: 'Post-logout redirect URI', custom_scopes: 'Scope', resources: 'Resource' }
function clientDialogMixin(Alpine) {
  return mix(listFieldMixin(), {
    stdScopes: STD_SCOPES.map((s) => ({ ...s, id: 'f-scope-' + s.value })),
    // A server error about a list field goes onto the row it names; otherwise it is shown under the whole list.
    listError(err) {
      const name = this._form === 'client' && LIST_OF_FIELD[err.field]
      if (!name) return false
      if (this.setListError(name, err.message)) return true
      this.errors = { [name]: err.message }
      this.invalid = { [name]: 'true' }
      announce(err.message, 'assertive')
      this.$nextTick(() => { const r = this.form[name][0]; const el = r && document.getElementById(r.inputId); if (el) el.focus() })
      return true
    },
    // Checks the editor can make itself; marks the rows and returns false when the form must not be sent.
    clientListsValid() {
      let first = null
      const seen = []
      for (const r of this.form.custom_scopes) {
        const v = r.value.trim()
        if (!v) continue
        let msg = ''
        if (!SCOPE_RE.test(v)) msg = `${v} is not a valid scope: use printable characters without spaces, quotes or backslashes (at most 100).`
        else if (STD_NAMES.includes(v)) msg = `${v} is a standard scope: tick it above instead.`
        else if (seen.includes(v)) msg = `${v} is listed twice.`
        seen.push(v)
        if (msg) { this.setRowError(r, msg); first = first || r }
      }
      if (!first) return true
      announce(first.error, 'assertive')
      this.$nextTick(() => { const el = document.getElementById(first.inputId); if (el) el.focus() })
      return false
    },
    get usesRedirects() { return (this.form.grant_types || []).includes('authorization_code') },
    editingClient: null, apiBase: '', secret: '', secretClient: '', secretTitle: '', canScim: false, tenants: [], tenantId: '',
    shapeClient(c) {
      const b = activeBadge(c.enabled, 'Enabled', 'Disabled')
      return { ...c, createdText: fmtDate(c.created), statusText: b.text, statusClass: b.cls, copyLabel: 'Copy client ID of ' + c.name,
        editLabel: 'Edit ' + c.name, deleteLabel: 'Delete ' + c.name, rotateLabel: 'Rotate secret of ' + c.name,
        methodText: { client_secret_post: 'Secret (POST)', client_secret_basic: 'Secret (Basic)', private_key_jwt: 'Private key JWT', none: 'Public (no secret)' }[c.token_endpoint_auth_method] || c.token_endpoint_auth_method,
        hasSecret: c.token_endpoint_auth_method !== 'none', firstParty: c.first_party, grantsText: (c.grant_types || []).join(', '), sub: c.description || '' }
    },
    tenantName(id) { const t = this.tenants.find((x) => x.id === id); return t ? t.display_name : '' },
    get canMove() { return this.editingClient !== null && this.tenants.length > 1 },
    get isEditClient() { return this.editingClient !== null },
    get isPublic() { return this.form.token_endpoint_auth_method === 'none' },
    get notPublic() { return this.form.token_endpoint_auth_method !== 'none' },
    get methodHelp() {
      return { client_secret_post: 'The secret is sent in the request body. The default for server-side apps.', client_secret_basic: 'The secret is sent in an HTTP Basic header. Many client libraries only do this.',
        private_key_jwt: 'The client signs a JWT with its private key; you register the public keys. For high-assurance server apps.',
        none: 'Public client: no secret. For single-page apps, mobile and desktop apps and CLIs. PKCE protects the flow.' }[this.form.token_endpoint_auth_method] || ''
    },
    get isJwt() { return this.form.token_endpoint_auth_method === 'private_key_jwt' },
    get clientDialogTitle() { return this.editingClient ? 'Edit client' : 'New client' },
    get clientSubmitLabel() { return this.busy ? 'Saving…' : this.editingClient ? 'Save changes' : 'Create client' },
    clientToForm(c) {
      const scopes = c.scopes || []
      return { tenant_id: c.tenant_id || '', name: c.name, description: c.description || '',
        redirect_uris: listRows(c.redirect_uris, LIST_ITEMS.redirect_uris), post_logout_redirect_uris: listRows(c.post_logout_redirect_uris, LIST_ITEMS.post_logout_redirect_uris, true),
        backchannel_logout_uri: c.backchannel_logout_uri || '', grant_types: [...(c.grant_types || [])], resources: listRows(c.resources, LIST_ITEMS.resources, true),
        std_scopes: STD_NAMES.filter((n) => scopes.includes(n)), custom_scopes: listRows(scopes.filter((x) => !STD_NAMES.includes(x)), LIST_ITEMS.custom_scopes, true), token_endpoint_auth_method: c.token_endpoint_auth_method, jwks: c.jwks || '', jwks_uri: c.jwks_uri || '',
        first_party: !!c.first_party, enabled: c.enabled !== false, rotate_refresh_tokens: !!c.rotate_refresh_tokens, require_pkce: c.require_pkce !== false, scim: !!c.scim }
    },
    openCreateClient(opener) {
      this._form = 'client'
      this.editingClient = null
      this.resetForm(this.clientToForm({ tenant_id: this.tenantId, name: '', grant_types: ['authorization_code', 'refresh_token'], scopes: ['openid', 'profile', 'email'],
        token_endpoint_auth_method: 'client_secret_post', enabled: true }))
      this.openDlg('client-dialog', opener)
    },
    openEditClient(c, opener) {
      this._form = 'client'
      this.editingClient = c
      this.resetForm(this.clientToForm(c))
      this.openDlg('client-dialog', opener)
      this.watchEdit({ kinds: ['client'], record: c, fetchOne: () => getOrNull(`${this.apiBase}/clients/${enc(c.id)}`) })
    },
    clientBody() {
      const f = this.form
      const pub = f.token_endpoint_auth_method === 'none'
      const redirects = this.usesRedirects
      const b = { name: f.name, description: f.description, redirect_uris: redirects ? listValues(f.redirect_uris) : [], post_logout_redirect_uris: redirects ? listValues(f.post_logout_redirect_uris) : [],
        backchannel_logout_uri: f.backchannel_logout_uri.trim(), resources: listValues(f.resources),
        grant_types: GRANTS.filter((g) => f.grant_types.includes(g) && !(pub && g === 'client_credentials')),
        scopes: [...STD_NAMES.filter((n) => f.std_scopes.includes(n)), ...listValues(f.custom_scopes)], token_endpoint_auth_method: f.token_endpoint_auth_method,
        first_party: f.first_party, enabled: f.enabled, rotate_refresh_tokens: pub ? true : f.rotate_refresh_tokens, require_pkce: pub ? true : f.require_pkce }
      if (f.tenant_id) b.tenant_id = f.tenant_id
      if (f.token_endpoint_auth_method === 'private_key_jwt') { b.jwks = f.jwks; b.jwks_uri = f.jwks_uri }
      if (this.canScim) b.scim = pub ? false : f.scim
      return b
    },
    async submitClient() {
      if (!this.clientListsValid()) return
      const edit = this.editingClient
      const body = this.clientBody()
      const res = await this.run(() => edit ? patch(`${this.apiBase}/clients/${enc(edit.id)}`, body) : post(`${this.apiBase}/clients`, body))
      if (!res) return
      this.closeDlg('client-dialog')
      const moved = !!edit && res.tenant_id !== this.tenantId
      if (res.secret) this.showSecret(res.secret, res.name, 'Client created')
      else if (moved) toast(`Client “${res.name}” moved to ${this.tenantName(res.tenant_id) || 'another tenant'} and left this list.`)
      else toast('Client saved.')
      await this.afterClientSaved(res, moved)
    },
    showSecret(secret, name, title) {
      this.secret = secret
      this.secretClient = name
      this.secretTitle = title
      this.$nextTick(() => this.openDlg('secret-dialog'))
    },
    async rotateClient(c) {
      const yes = await confirmAction(Alpine, { title: 'Rotate client secret?', message: `Issue a new secret for “${c.name}”?`,
        detail: 'The current secret stops working immediately. Update every application that uses it.', confirmLabel: 'Rotate secret', danger: true })
      if (!yes) return
      try {
        const res = await post(`${this.apiBase}/clients/${enc(c.id)}/secret`)
        this.showSecret(res.secret, c.name, 'New client secret')
      } catch (e) { toast(e.message, 'error') }
    },
    async removeClient(c) {
      const yes = await confirmAction(Alpine, { title: 'Delete client?', message: `Delete the client “${c.name}”?`,
        detail: 'Applications using it will no longer be able to sign users in. This cannot be undone.', confirmLabel: 'Delete client' })
      if (!yes) return
      try { await del(`${this.apiBase}/clients/${enc(c.id)}`); toast(`Client “${c.name}” deleted.`); this.load(); this.refreshTenant(true) } catch (e) { toast(e.message, 'error') }
    },
  })
}

// The email addresses card of the user page (see lib/emails.js). With email set up, an address added here starts
// unverified and the user is mailed a link (which can be sent again); without email it counts as verified at once.
function userEmailsComponent(Alpine) {
  Alpine.data('adminUserEmails', () => mix(formMixin(), emailsMixin({
    self: false, canResend: true,
    // your own addresses: the server asks for a recent re-authentication, the shared dialog provides it
    guard: (fn, opener, vm) => withReauth(Alpine, fn, opener, vm),
    load() { const d = this.$el.closest('[data-user]').dataset; return get(`${d.base}/users/${enc(d.user)}`) },
    url(s) { const d = this.$el.closest('[data-user]').dataset; return `${d.base}/users/${enc(d.user)}/emails${s}` },
    changed() { window.dispatchEvent(new CustomEvent('user-emails-changed')) },
  }), {
    init() { return this.loadEmails() },
  }))
}

// The API tokens card of the user page: the user's personal tokens (never their secrets), each revocable at once.
function userTokensComponent(Alpine) {
  Alpine.data('adminUserTokens', () => ({
    items: [], loading: true, loadError: '',
    init() { return this.load() },
    url(s = '') { const d = this.$el.closest('[data-user]').dataset; return `${d.base}/users/${enc(d.user)}/tokens${s}` },
    async load() {
      try {
        const r = await get(this.url('?limit=100'))
        this.items = r.items.map((t) => ({ ...t, scopesText: t.scopes.join(', ') + ((t.audience || []).length ? ' (for ' + t.audience.length + ' application' + (t.audience.length === 1 ? '' : 's') + ')' : ''),
          expiresText: isSet(t.expires) ? fmtDate(t.expires) : 'Never', lastText: relTime(t.last_used, 'Never used'), revokeLabel: 'Revoke token ' + t.name }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    get hasItems() { return this.items.length > 0 },
    get isEmpty() { return !this.loading && this.items.length === 0 && this.loadError === '' },
    get hasLoadError() { return this.loadError !== '' },
    async revoke(ev) {
      const t = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!t) return
      const yes = await confirmAction(Alpine, { title: 'Revoke API token?', message: `Revoke the token “${t.name}”?`,
        detail: 'Anything using it stops working immediately. The user can make a new one.', confirmLabel: 'Revoke token' })
      if (!yes) return
      try { await del(this.url('/' + enc(t.id))); toast('Token revoked.'); await this.load() } catch (e) { toast(e.message, 'error') }
    },
  }))
}

// What the user is connected to, for whoever sorts their account out and for yourself: where they are signed in, the
// applications they allowed (removing one signs them out of it) and their sign-in providers. Your own sensitive
// changes (disconnecting a provider) ask for a recent re-authentication through the shared dialog.
const AMR_TEXT = { pwd: 'Password', otp: 'Authenticator code', hwk: 'Passkey', swk: 'Passkey', fed: 'Sign-in provider', user: '', mfa: '' }
const PROVIDER_ICON = { github: 'isGitHub', google: 'isGoogle', gitlab: 'isGitLab', auth0: 'isAuth0', microsoft: 'isMicrosoft' }
const VIA_TEXT = { email: 'matched by a verified email address', provision: 'created by signing in', connect: 'connected by the user', admin: 'linked by an administrator' }
function userConnectionsComponents(Alpine) {
  const base = (el, s) => { const d = el.closest('[data-user]').dataset; return `${d.base}/users/${enc(d.user)}${s}` }
  const listState = () => ({
    items: [], loading: true, loadError: '',
    get hasItems() { return this.items.length > 0 },
    get isEmpty() { return !this.loading && this.items.length === 0 && this.loadError === '' },
    get hasLoadError() { return this.loadError !== '' },
  })
  const focusHeading = (id) => setTimeout(() => { const h = document.getElementById(id); if (h) h.focus() }, 80)

  Alpine.data('adminUserSessions', () => mix(listState(), {
    init() { return this.load() },
    async load() {
      try {
        const r = await get(base(this.$el, '/sessions'))
        this.items = r.items.map((s) => {
          const amr = [...new Set((s.amr || []).map((m) => (m in AMR_TEXT ? AMR_TEXT[m] : m)).filter(Boolean))]
          const device = describeAgent(s.user_agent)
          return { ...s, device, amrText: amr.join(', ') || '—', createdText: fmtDateTime(s.created), lastText: relTime(s.last_seen, 'Never'),
            canEnd: !s.current, endLabel: `Sign out ${device} (${s.ip || 'unknown address'})` }
        })
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    async end(ev) {
      const s = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!s) return
      const yes = await confirmAction(Alpine, { title: 'Sign out this session?', message: `Sign out ${s.device} at ${s.ip || 'an unknown address'}?`,
        detail: 'It ends at once, and the applications it signed in to are told to sign out too. Signing in again starts a new session.', confirmLabel: 'Sign out' })
      if (!yes) return
      try {
        await del(base(this.$el, '/sessions/' + enc(s.id)))
        toast('Session signed out.')
        await this.load()
        focusHeading('sessions-h')
      } catch (e) { toast(e.message, 'error') }
    },
  }))

  Alpine.data('adminUserApps', () => mix(listState(), { // mix keeps listState's getters live (a spread would copy values)
    init() { return this.load() },
    async load() {
      try {
        const r = await get(base(this.$el, '/apps'))
        this.items = r.items.map((a) => ({ ...a, scopesText: a.scopes.join(', ') || '—', sinceText: fmtDate(a.since),
          lastText: relTime(a.last_used, 'Never'), removeLabel: 'Remove access for ' + a.name }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    async remove(ev) {
      const opener = ev.currentTarget
      const a = this.items.find((i) => i.client_id === opener.dataset.id)
      if (!a) return
      const yes = await confirmAction(Alpine, { title: 'Remove access?', message: `Remove this user\u2019s access to ${a.name}?`,
        detail: `${a.name} is told to sign them out, and its tokens stop working now. They can sign in to it again, and allow it again if it asks.`, confirmLabel: 'Remove access' })
      if (!yes) return
      try {
        await withReauth(Alpine, () => del(base(this.$el, '/apps/' + enc(a.client_id))), opener)
        toast(`Access to ${a.name} removed.`)
        await this.load()
        focusHeading('apps-h')
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }))

  Alpine.data('adminUserProviders', () => mix(listState(), {
    init() { return this.load() },
    async load() {
      try {
        const r = await get(base(this.$el, '/providers'))
        this.items = r.items.map((p) => {
          const flag = PROVIDER_ICON[p.type] || 'isOther'
          const parts = [p.email, VIA_TEXT[p.via], 'since ' + fmtDate(p.linked)].filter(Boolean)
          return { ...p, [flag]: true, disabled: !p.enabled, forName: ' ' + p.name, detail: parts.join(', ') }
        })
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    async disconnect(ev) {
      const opener = ev.currentTarget
      const p = this.items.find((i) => i.provider_id === opener.dataset.id)
      if (!p) return
      const yes = await confirmAction(Alpine, { title: 'Disconnect provider?', message: `Disconnect ${p.name} from this user?`,
        detail: `They can no longer sign in with ${p.name} until they connect it again from their account page. If it was their only way to sign in, send them a new invitation link.`, confirmLabel: 'Disconnect' })
      if (!yes) return
      try {
        await withReauth(Alpine, () => del(base(this.$el, '/providers/' + enc(p.provider_id))), opener)
        toast(`${p.name} disconnected.`)
        await this.load()
        focusHeading('links-h')
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }))
}

export default function (Alpine) {
  userEmailsComponent(Alpine)
  userTokensComponent(Alpine)
  userConnectionsComponents(Alpine)
  accessComponent(Alpine)
  // ---- Organizations -----------------------------------------------------------------------------------------
  Alpine.data('adminOrgs', () => mix(tableMixin(), formMixin(), dialogMixin(), {
    editing: null, base: '',
    init() { this.base = this.$el.dataset.base; this.initTable() },
    transform(o) {
      return { ...o, usersText: o.users === undefined ? '—' : String(o.users), createdText: fmtDate(o.created),
        href: `${this.base}/${enc(o.name)}/users`, editLabel: 'Edit ' + o.display_name, deleteLabel: 'Delete ' + o.display_name,
        notPrimary: !o.primary }
    },
    get isEdit() { return this.editing !== null },
    get dialogTitle() { return this.editing ? 'Edit organization' : 'New organization' },
    get submitLabel() { return this.busy ? 'Saving…' : this.editing ? 'Save changes' : 'Create organization' },
    openCreate(ev) {
      this.editing = null
      this.resetForm({ name: '', display_name: '' })
      this.openDlg('org-dialog', ev.currentTarget)
    },
    edit(ev) {
      const o = this.rowFromEvent(ev)
      this.editing = o
      this.resetForm({ name: o.name, display_name: o.display_name })
      this.openDlg('org-dialog', ev.currentTarget)
      this.watchEdit({ kinds: ['org'], record: o, fetchOne: () => getOrNull(`/api/v1/orgs/${enc(o.name)}`) })
    },
    async submit() {
      const body = { name: this.form.name.trim(), display_name: this.form.display_name.trim() }
      if (!body.display_name) delete body.display_name
      const res = await this.run(() => this.editing ? patch(`/api/v1/orgs/${enc(this.editing.name)}`, body) : post('/api/v1/orgs', body))
      if (!res) return
      this.closeDlg('org-dialog')
      toast(this.editing ? 'Organization saved.' : 'Organization created.')
      this.load()
    },
    async remove(ev) {
      const o = this.rowFromEvent(ev)
      const detail = o.users > 0 ? `This also deletes its ${o.users} user${o.users === 1 ? '' : 's'}, groups, clients and sign-in providers. This cannot be undone.`
        : 'This cannot be undone.'
      const yes = await confirmAction(Alpine, { title: 'Delete organization?', message: `Delete “${o.display_name}” (${o.name})?`, detail,
        confirmLabel: 'Delete organization', requireText: o.name })
      if (!yes) return
      try {
        await del(`/api/v1/orgs/${enc(o.name)}${qs({ cascade: o.users > 0 })}`)
        toast(`Organization “${o.display_name}” deleted.`)
        this.load()
      } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- Users --------------------------------------------------------------------------------------------------
  Alpine.data('adminUsers', () => mix(tableMixin(), formMixin(), dialogMixin(), userDialogMixin(Alpine), {
    pageUrl: '',
    init() {
      this.apiBase = this.$el.dataset.base
      this.pageUrl = this.$el.dataset.page
      // a shared link /users?tag=dept:finance opens the list already filtered
      let tag = ''
      try { tag = new URLSearchParams(window.location.search).get('tag') || '' } catch (e) { /* no query string */ }
      if (tag) this.extra = { ...this.extra, tag }
      this.initTable()
    },
    // ---- filter by tag (clicking a tag badge) ----
    get activeTag() { return this.extra.tag || '' },
    get hasTagFilter() { return this.activeTag !== '' },
    get clearTagLabel() { return 'Clear tag filter ' + this.activeTag },
    setTagFilter(tag) {
      this.extra = { ...this.extra, tag }
      this.offset = 0
      try {
        const u = new URL(window.location.href)
        if (tag) u.searchParams.set('tag', tag); else u.searchParams.delete('tag')
        window.history.replaceState(null, '', u)
      } catch (e) { /* history unavailable */ }
    },
    async filterByTag(ev) {
      const tag = ev.currentTarget.dataset.tag
      this.setTagFilter(tag)
      focusSoon('clear-tag-filter')
      await this.load()
      announce(`Showing users tagged ${tag}. ${this.statusText}`)
    },
    async clearTagFilter() {
      this.setTagFilter('')
      await this.load()
      announce('Tag filter cleared. ' + this.statusText)
      const i = document.getElementById('list-search')
      if (i) i.focus()
    },
    transform(u) {
      const b = activeBadge(u.active)
      return { ...u, title: u.name || u.username, initial: (u.name || u.username || '?').slice(0, 1).toUpperCase(), sub: u.email || u.username, roleText: ROLE_LABEL[u.role] || u.role,
        roleClass: 'badge ' + (ROLE_BADGE[u.role] || 'badge-plain'), statusText: b.text, statusClass: b.cls,
        lastLoginText: relTime(u.last_login), href: `${this.pageUrl}/${enc(u.id)}`, editLabel: 'Edit ' + (u.name || u.username),
        deleteLabel: 'Delete ' + (u.name || u.username), createdText: fmtDate(u.created), noPassword: !u.has_password, ...tagView(u.tags, 'users') }
    },
    edit(ev) { this.openEditUser(this.rowFromEvent(ev), ev.currentTarget) },
    afterUserSaved() { return this.load() },
    async remove(ev) {
      const u = this.rowFromEvent(ev)
      const yes = await confirmAction(Alpine, { title: 'Delete user?', message: `Delete ${u.title} (${u.username})?`,
        detail: 'Their sessions, passkeys and API tokens are deleted too. This cannot be undone.', confirmLabel: 'Delete user' })
      if (!yes) return
      try { await del(`${this.apiBase}/users/${enc(u.id)}`); toast(`User ${u.title} deleted.`); this.load() } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- One user -------------------------------------------------------------------------------------------------
  Alpine.data('adminUser', () => mix(formMixin(), dialogMixin(), userDialogMixin(Alpine), {
    reloadUser() { return this.refresh(true) },
    user: null, loading: true, loadError: '', userId: '', listUrl: '', gone: false, _sig: '', _lr: null,
    init() {
      const d = this.$el.dataset
      this.apiBase = d.base
      this.userId = d.user
      this.listUrl = d.list
      this._lr = liveRunner(() => this.refresh(true))
      subscribe(['user', 'group', 'member'], () => this._lr.trigger())
      return this.refresh()
    },
    // quiet = a live refresh: nothing changes on screen unless the record did; a deleted user is reported.
    async refresh(quiet = false) {
      try {
        const raw = await get(`${this.apiBase}/users/${enc(this.userId)}`)
        const sig = JSON.stringify(raw)
        if (quiet && sig === this._sig) return
        this._sig = sig
        this.user = this.shape(raw)
        this.loadError = ''
        this.gone = false
        if (quiet) announceUpdate('User details updated')
      } catch (e) {
        if (quiet && e.status === 404) {
          if (!this.gone) { this.gone = true; this.user = null; announce('This user was deleted by someone else.', 'assertive') }
        } else if (!quiet) this.loadError = e.message
      }
      this.loading = false
    },
    get userDeleted() { return this.gone },
    shape(u) {
      const b = activeBadge(u.active)
      return { ...u, title: u.name || u.username, roleText: ROLE_LABEL[u.role] || u.role, roleClass: 'badge ' + (ROLE_BADGE[u.role] || 'badge-plain'),
        statusText: b.text, statusClass: b.cls, lastLoginText: fmtDateTime(u.last_login), createdText: fmtDateTime(u.created),
        emailText: u.email || '—', emailVerifiedText: u.email ? (u.email_verified ? 'Verified' : 'Not verified') : '',
        groupsText: (u.groups || []).map((g) => g.display_name).join(', ') || 'None', externalText: u.external_id || '—', ...tagView(u.tags, 'users'), initial: (u.name || u.username || '?').slice(0, 1).toUpperCase(),
        phoneText: u.phone_number || '—', phoneVerifiedText: u.phone_number ? (u.phone_number_verified ? 'Verified' : 'Not verified') : '',
        statusNote: statusNote(u), hasStatusNote: !!u.status_changed,
        passwordDetail: u.password_changed_at ? (u.has_password ? 'Last changed ' : 'Removed ') + fmtDateTime(u.password_changed_at) : '',
        mfaText: u.mfa_enrolled_at ? 'Set up ' + fmtDateTime(u.mfa_enrolled_at) : 'Not set up' }
    },
    get showUser() { return this.user !== null },
    get hasLoadError() { return this.loadError !== '' },
    get groups() { return this.user ? this.user.groups || [] : [] },
    get hasGroups() { return this.groups.length > 0 },
    edit(ev) { this.openEditUser(this.user, ev.currentTarget) },
    async afterUserSaved(res) { await this.refresh() },
    get passwordText() { return this.user.has_password ? 'Set' : 'Not set' },
    get passkeysText() { const n = this.user.passkeys; return n === undefined ? '—' : n === 0 ? 'None' : String(n) },
    get hasPassword() { return this.user.has_password },
    newInvite(ev) { this.openInvite(this.user, null, ev.currentTarget) },
    async removePassword(ev) {
      const yes = await confirmAction(Alpine, { title: 'Remove password?', message: `Remove the password of ${this.user.title}?`,
        detail: 'They can no longer sign in with a password until they accept a new invitation. Their sessions end now.', confirmLabel: 'Remove password' })
      if (!yes) return
      try { await del(`${this.apiBase}/users/${enc(this.userId)}/password`); toast('Password removed. Sessions ended.'); await this.refresh() } catch (e) { toast(e.message, 'error') }
    },
    async revoke(ev) {
      const yes = await confirmAction(Alpine, { title: 'Sign out everywhere?', message: `End every session of ${this.user.title}?`,
        detail: 'They will have to sign in again on every device.', confirmLabel: 'Revoke sessions' })
      if (!yes) return
      try { await del(`${this.apiBase}/users/${enc(this.userId)}/sessions`); toast('Sessions revoked.') } catch (e) { toast(e.message, 'error') }
    },
    async remove(ev) {
      const yes = await confirmAction(Alpine, { title: 'Delete user?', message: `Delete ${this.user.title} (${this.user.username})?`,
        detail: 'Their sessions, passkeys and API tokens are deleted too. This cannot be undone.', confirmLabel: 'Delete user' })
      if (!yes) return
      try { await del(`${this.apiBase}/users/${enc(this.userId)}`); window.location.assign(this.listUrl) } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- Groups ---------------------------------------------------------------------------------------------------
  Alpine.data('adminGroups', () => mix(tableMixin(), formMixin(), dialogMixin(), tagsMixin(), pickerMixin({
    // active users of the organization who are not members yet; choosing one adds them at once
    async search(q) {
      const res = await get(`${this.apiBase}/users${qs({ q, limit: 10, active: 1 })}`)
      const have = new Set(this.members.map((m) => m.id))
      const items = res.items.filter((u) => !have.has(u.id))
      return { more: res.total > res.items.length, items: items.map((u) => ({ type: 'user', id: u.id, label: u.name || u.username, detail: u.email, kind: 'User' })) }
    },
    chosen(p) { return this.addMember(p) },
    clearOnChoose: true,
  }), {
    editing: null, apiBase: '', group: null, members: [], membersTotal: 0, membersLoading: false,
    _mt: null, membersGone: false,
    init() {
      this.apiBase = this.$el.dataset.base
      this.initTable()
      subscribe(['member', 'group', 'user'], (ev) => this.liveMembers(ev))
    },
    // The members dialog follows changes made by other administrators while it is open (never moves focus).
    liveMembers() {
      clearTimeout(this._mt)
      this._mt = setTimeout(() => {
        const dlg = document.getElementById('members-dialog')
        if (!dlg || !dlg.open || !this.group) return
        if (typingNow()) { this.liveMembers(); return }
        this.loadMembers(true)
      }, 300)
    },
    transform(g) {
      return { ...g, createdText: fmtDate(g.created), externalText: g.external_id || '—', membersText: String(g.members || 0), editLabel: 'Edit ' + g.display_name,
        deleteLabel: 'Delete ' + g.display_name, membersLabel: 'Members of ' + g.display_name, ...tagView(g.tags, 'groups') }
    },
    get isEdit() { return this.editing !== null },
    get dialogTitle() { return this.editing ? 'Edit group' : 'New group' },
    get submitLabel() { return this.busy ? 'Saving…' : this.editing ? 'Save changes' : 'Create group' },
    openCreate(ev) { this.editing = null; this.resetForm({ display_name: '', external_id: '', tags: [] }); this.resetChipText(); this.openDlg('group-dialog', ev.currentTarget) },
    edit(ev) {
      const g = this.rowFromEvent(ev)
      this.editing = g
      this.resetForm({ display_name: g.display_name, external_id: g.external_id || '', tags: [...(g.tags || [])] })
      this.resetChipText()
      this.openDlg('group-dialog', ev.currentTarget)
      this.watchEdit({ kinds: ['group'], record: g, fetchOne: () => getOrNull(`${this.apiBase}/groups/${enc(g.id)}`) })
    },
    async submit() {
      if (!this.tagsReady()) { this.focusTagInput(); return }
      const body = { display_name: this.form.display_name, external_id: this.form.external_id, tags: this.form.tags }
      const res = await this.run(() => this.editing ? patch(`${this.apiBase}/groups/${enc(this.editing.id)}`, body) : post(`${this.apiBase}/groups`, body))
      if (!res) return
      this.closeDlg('group-dialog')
      toast(this.editing ? 'Group saved.' : 'Group created.')
      this.load()
    },
    async remove(ev) {
      const g = this.rowFromEvent(ev)
      const yes = await confirmAction(Alpine, { title: 'Delete group?', message: `Delete the group “${g.display_name}”?`,
        detail: 'Its members stay in the organization; they just leave the group.', confirmLabel: 'Delete group' })
      if (!yes) return
      try { await del(`${this.apiBase}/groups/${enc(g.id)}`); toast(`Group “${g.display_name}” deleted.`); this.load() } catch (e) { toast(e.message, 'error') }
    },
    // members
    get showMembers() { return !this.membersGone },
    get membersDeleted() { return this.membersGone },
    get membersTitle() { return this.group ? 'Members of ' + this.group.display_name : 'Members' },
    get hasMembers() { return this.members.length > 0 },
    get noMembers() { return !this.membersLoading && this.members.length === 0 },
    get memberCount() { return this.membersTotal + (this.membersTotal === 1 ? ' member' : ' members') },
    openMembers(ev) {
      this.group = this.rowFromEvent(ev)
      this.membersGone = false
      this.resetPicker()
      this.members = []
      this.openDlg('members-dialog', ev.currentTarget)
      return this.loadMembers()
    },
    async loadMembers(quiet = false) {
      if (!quiet) this.membersLoading = true
      try {
        const res = await get(`${this.apiBase}/groups/${enc(this.group.id)}/members${qs({ limit: 100 })}`)
        const items = res.items.map((m) => ({ ...m, removeLabel: 'Remove ' + (m.name || m.username) + ' from group', title: m.name || m.username }))
        const sig = items.map((m) => m.id).join()
        const changed = !quiet || sig !== this.members.map((m) => m.id).join()
        if (changed) {
          this.members = items
          this.membersTotal = res.total
          if (quiet) announceUpdate('Members list updated')
        }
      } catch (e) {
        if (e.status === 404 && quiet) { if (!this.membersGone) { this.membersGone = true; announce('This group was deleted by someone else.', 'assertive') } }
        else if (!quiet) toast(e.message, 'error')
      }
      this.membersLoading = false
    },
    async addMember(p) {
      try {
        await put(`${this.apiBase}/groups/${enc(this.group.id)}/members/${enc(p.id)}`)
        toast(`${p.label} added to ${this.group.display_name}.`)
        await this.loadMembers()
        this.load(false, true) // the member count in the list
      } catch (e) { toast(e.message, 'error') }
      const s = document.getElementById('f-member')
      if (s) s.focus()
    },
    async removeMember(ev) {
      const id = ev.currentTarget.dataset.id
      const m = this.members.find((u) => u.id === id)
      try {
        await del(`${this.apiBase}/groups/${enc(this.group.id)}/members/${enc(id)}`)
        toast(`${m.title} removed from ${this.group.display_name}.`)
        await this.loadMembers()
        this.load(false, true) // the member count in the list
        const s = document.getElementById('f-member')
        if (s) s.focus()
      } catch (e) { toast(e.message, 'error') }
    },
  }))


  // ---- Tenants list -----------------------------------------------------------------------------------------------
  Alpine.data('adminTenants', () => mix(tableMixin(), formMixin(), dialogMixin(), tenantDialogMixin(Alpine), {
    pageBase: '',
    async init() {
      const d = this.$el.dataset
      this.apiBase = d.base
      this.pageBase = d.page
      await this.loadOrgInfo() // the rows show the organization's second-factor rule
      this.initTable()
    },
    transform(t) {
      return { ...t, methodsText: methodsText(t), mfaText: this.orgMFA || t.settings.require_mfa ? 'Requires a second factor' : '', clientsText: clientsText(t.clients),
        editLabel: 'Edit ' + t.display_name, deleteLabel: 'Delete ' + t.display_name, isDefault: t.name === 'default', hasDescription: !!t.description,
        href: `${this.pageBase}/${enc(t.name)}`, clientsLabel: clientsText(t.clients) + ' in ' + t.display_name }
    },
    openCreate(ev) { this.openCreateTenant(ev.currentTarget) },
    edit(ev) { this.openEditTenant(this.rowFromEvent(ev), ev.currentTarget) },
    afterTenantSaved() { return this.load() },
    async remove(ev) {
      const t = this.rowFromEvent(ev)
      const yes = await confirmAction(Alpine, { title: 'Delete tenant?', message: `Delete the tenant “${t.display_name}”?`,
        detail: 'A tenant that still has clients cannot be deleted. This cannot be undone.', confirmLabel: 'Delete tenant' })
      if (!yes) return
      try { await del(`${this.apiBase}/tenants/${enc(t.id)}`); toast(`Tenant “${t.display_name}” deleted.`); this.load() } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- One tenant: its sign-in rules and its clients ---------------------------------------------------------------
  Alpine.data('adminTenant', () => mix(tableMixin(), formMixin(), dialogMixin(), tenantDialogMixin(Alpine), clientDialogMixin(Alpine), {
    tenant: null, tenantId: '', pageBase: '', gone: false, tenantError: '', _tsig: '', _tlive: null, titleText: '',
    async init() {
      const d = this.$el.dataset
      this.apiBase = d.base
      this.pageBase = d.page
      this.tenantId = d.tenant
      this.titleText = d.title
      this.canScim = d.canScim === '1'
      this.scope = { tenant: this.tenantId }
      this.initTable()
      this._tlive = liveRunner(() => this.refreshTenant(true))
      subscribe(['tenant', 'client', 'provider', 'org'], () => this._tlive.trigger())
      await this.refreshTenant(false)
    },
    // The tenant record, with what the summary needs (organization methods, provider names, all tenants for the move select).
    async refreshTenant(quiet) {
      try {
        const [t, org, provs, tenants] = await Promise.all([
          getOrNull(`${this.apiBase}/tenants/${enc(this.tenantId)}`), get(`${this.apiBase}/settings`),
          get(`${this.apiBase}/providers${qs({ sort: 'name', limit: 100 })}`), get(`${this.apiBase}/tenants${qs({ sort: 'name', limit: 100 })}`)])
        if (t === null) {
          if (!this.gone) { this.gone = true; this.tenant = null; announce('This tenant was deleted by someone else.', 'assertive') }
          return
        }
        const sig = JSON.stringify([t, org.settings, provs.items.map((p) => [p.id, p.name, p.enabled, p.updated]), tenants.items.map((x) => [x.id, x.display_name])])
        if (quiet && sig === this._tsig) return
        this._tsig = sig
        const before = this.tenant
        this.gone = false
        this.tenantError = ''
        this.tenant = t
        Alpine.store('tenantPage').tenant = t // read by the Access card (pages/access.js)
        this.orgPassword = org.settings.password_login
        this.orgPasskey = org.settings.passkey_login
        this.providers = provs.items.map(shapeProvider)
        this.tenants = tenants.items
        this.titleText = t.display_name
        document.title = document.title.replace(/^Tenant: [^·]*/, 'Tenant: ' + t.display_name + ' ')
        if (before && before.name !== t.name) history.replaceState(null, '', `${this.pageBase}/${enc(t.name)}`)
        if (quiet && before) announceUpdate('Tenant updated')
      } catch (e) { if (!quiet) this.tenantError = e.message }
    },
    get showTenant() { return this.tenant !== null },
    get tenantGone() { return this.gone },
    get hasTenantError() { return this.tenantError !== '' },
    get tenantTitle() { return this.titleText },
    get tenantDescription() { return this.tenant && this.tenant.description ? this.tenant.description : '' },
    get hasTenantDescription() { return this.tenantDescription !== '' },
    get isDefaultTenant() { return !!this.tenant && this.tenant.name === 'default' },
    get tenantSlug() { return this.tenant ? this.tenant.name : '' },
    get clientCountText() { return this.tenant ? clientsText(this.tenant.clients) : '' },
    get summaryRows() {
      if (!this.tenant) return []
      const s = this.tenant.settings
      const row = (label, on, orgOn, what) => {
        if (!on) return { label, text: 'Not allowed', cls: 'badge badge-plain', note: 'Turned off for this tenant.' }
        if (!orgOn) return { label, text: 'Not allowed', cls: 'badge badge-warning', note: `Turned on here, but the organization has turned ${what} off.` }
        return { label, text: 'Allowed', cls: 'badge badge-success', note: '' }
      }
      const names = (s.providers || []).map((id) => (this.providers.find((p) => p.id === id) || { name: 'Removed provider' }).name)
      const prov = s.all_providers ? { text: 'All of the organization’s providers', note: 'Includes providers added later.' }
        : names.length ? { text: names.join(', '), note: 'Only enabled providers can be used.' } : { text: 'None', note: '' }
      return [
        { label: 'Who can sign in', text: s.members_only ? 'Only users and groups given access' : 'Everyone in the organization',
          cls: s.members_only ? 'badge badge-info' : 'badge badge-plain', note: s.members_only ? 'Manage them under Access below.' : 'Every user of the organization can sign in to its applications.' },
        row('Password', s.password_login, this.orgPassword, 'passwords'),
        row('Passkeys', s.passkey_login, this.orgPasskey, 'passkeys'),
        { label: 'Sign-in providers', text: prov.text, cls: 'cell-title', note: prov.note },
        this.orgMFA ? { label: 'Second factor', text: 'Required', cls: 'badge badge-info', note: 'The organization requires one for every sign-in.' }
          : { label: 'Second factor', text: s.require_mfa ? 'Required' : 'Not required', cls: s.require_mfa ? 'badge badge-info' : 'badge badge-plain',
            note: s.require_mfa ? 'Every sign-in to this tenant\u2019s applications needs one, unless the provider used counts as one.' : '' },
      ]
    },
    // tenant dialog
    editTenant(ev) { this.openEditTenant(this.tenant, ev.currentTarget) },
    async afterTenantSaved(res) {
      if (res.name !== this.tenant.name) { window.location.replace(`${this.pageBase}/${enc(res.name)}`); return }
      await this.refreshTenant(false)
    },
    // clients table
    transform(c) { return this.shapeClient(c) },
    openCreate(ev) { this.openCreateClient(ev.currentTarget) },
    edit(ev) { this.openEditClient(this.rowFromEvent(ev), ev.currentTarget) },
    rotate(ev) { return this.rotateClient(this.rowFromEvent(ev)) },
    remove(ev) { return this.removeClient(this.rowFromEvent(ev)) },
    afterClientSaved(res, moved) {
      this.load()
      this.refreshTenant(true)
    },
  }))

  // ---- Providers --------------------------------------------------------------------------------------------------
  Alpine.data('adminProviders', () => mix(tableMixin(), formMixin(), dialogMixin(), listFieldMixin(), {
    editing: null, apiBase: '', publicUrl: '', newId: '',
    init() { this.apiBase = this.$el.dataset.base; this.publicUrl = this.$el.dataset.public; this.initTable() },
    transform(p) {
      const b = activeBadge(p.enabled, 'Enabled', 'Disabled')
      return { ...p, copyCallbackLabel: 'Copy callback URL of ' + p.name, createdText: fmtDate(p.created), statusText: b.text, statusClass: b.cls, typeText: providerTypeText(p.type),
        editLabel: 'Edit ' + p.name, deleteLabel: 'Delete ' + p.name, sub: providerSub(p),
        domainsText: (p.allowed_domains || []).join(', ') || 'Any', provisionText: (p.auto_provision ? 'Creates accounts' : 'Existing users only') + (p.trust_mfa ? '; counts as a second factor' : '') }
    },
    get isEdit() { return this.editing !== null },
    get ptype() { return PROVIDER_TYPES[this.form.type] || PROVIDER_TYPES.oidc },
    get hasAddress() { return !!this.ptype.address },
    get addressLabel() { return this.ptype.address || '' },
    get addressPlaceholder() { return this.ptype.placeholder || '' },
    get addressHelp() { return this.ptype.help || '' },
    get addressRequired() { return !!this.ptype.required },
    get addressRequiredAttr() { return this.ptype.required ? 'true' : 'false' },
    get isMicrosoft() { return this.form.type === 'microsoft' },
    get multiTenant() { return this.isMicrosoft && (this.form.tenant || '').trim().toLowerCase() === 'organizations' },
    get namePlaceholder() { return this.ptype.name },
    get nameHelp() { return `Shown on the sign-in page. Leave empty for \u201c${this.ptype.name}\u201d.` },
    get callbackHelp() {
      return { github: 'Register this as the Authorization callback URL of your GitHub OAuth app.',
        microsoft: 'Register this as a Web redirect URI of your app registration in Microsoft Entra ID.',
        google: 'Register this as an authorised redirect URI of your OAuth client in Google Cloud.',
        gitlab: 'Register this as the redirect URI of your GitLab application.',
        auth0: 'Register this as an allowed callback URL of your Auth0 application.' }[this.form.type] ||
        'Register this as a redirect URI of your client at the provider. Each provider has its own.'
    },
    // a new provider: the type's own scopes until they are edited
    typeChanged() {
      if (this.editing) return
      const gh = 'read:user user:email'
      const oidc = 'openid profile email'
      if (this.form.scopes === gh || this.form.scopes === oidc) this.form.scopes = this.form.type === 'github' ? gh : oidc
    },
    // Each provider has its own callback address. A new one gets its id now, so the address can be registered with the
    // provider before its client ID and secret are known.
    get callbackUrl() { return this.editing ? this.editing.callback_url : `${this.publicUrl}/login/callback/${this.newId}` },
    get secretHelp() { return this.editing ? 'Leave blank to keep the current secret. It is never shown.' : 'Stored encrypted. It is never shown again.' },
    get secretRequired() { return !this.editing },
    get dialogTitle() { return this.editing ? 'Edit provider' : 'New sign-in provider' },
    get submitLabel() { return this.busy ? 'Saving…' : this.editing ? 'Save changes' : 'Create provider' },
    toForm(p) {
      return { type: p.type, name: p.name, issuer: p.issuer || '', client_id: p.client_id || '', client_secret: '', scopes: (p.scopes || []).join(' '),
        allowed_domains: listRows(p.allowed_domains, 'Domain', true), tenant: p.tenant || '', allowed_tenants: listRows(p.allowed_tenants, 'Tenant ID', true), auto_provision: !!p.auto_provision, trust_mfa: !!p.trust_mfa, link_by_email: p.link_by_email !== false, enabled: p.enabled !== false }
    },
    openCreate(ev) {
      this.editing = null
      this.newId = crypto.randomUUID()
      this.resetForm(this.toForm({ type: 'oidc', name: '', scopes: ['openid', 'profile', 'email'], enabled: true }))
      this.openDlg('provider-dialog', ev.currentTarget)
    },
    edit(ev) {
      const p = this.rowFromEvent(ev)
      this.editing = p
      this.resetForm(this.toForm(p))
      this.openDlg('provider-dialog', ev.currentTarget)
      this.watchEdit({ kinds: ['provider'], record: p, fetchOne: () => getOrNull(`${this.apiBase}/providers/${enc(p.id)}`) })
    },
    // a server message about one domain goes on its row (it starts with the domain)
    listError(err) { return (err.field === 'allowed_domains' || err.field === 'allowed_tenants') && this.setListError(err.field, err.message) },
    async submit() {
      const f = this.form
      const body = { type: f.type, name: f.name, client_id: f.client_id, scopes: words(f.scopes), allowed_domains: listValues(f.allowed_domains),
        auto_provision: f.auto_provision, trust_mfa: f.trust_mfa, link_by_email: f.link_by_email, enabled: f.enabled }
      if (PROVIDER_TYPES[f.type] && PROVIDER_TYPES[f.type].address) body.issuer = f.issuer
      if (f.type === 'microsoft') { body.tenant = f.tenant; body.allowed_tenants = listValues(f.allowed_tenants) }
      if (f.client_secret) body.client_secret = f.client_secret
      if (!this.editing) body.id = this.newId
      const res = await this.run(() => this.editing ? patch(`${this.apiBase}/providers/${enc(this.editing.id)}`, body) : post(`${this.apiBase}/providers`, body))
      if (!res) return
      this.closeDlg('provider-dialog')
      toast(this.editing ? 'Provider saved.' : 'Provider created.')
      this.load()
    },
    async remove(ev) {
      const p = this.rowFromEvent(ev)
      const yes = await confirmAction(Alpine, { title: 'Delete provider?', message: `Delete the sign-in provider “${p.name}”?`,
        detail: 'Users who sign in only through it will no longer be able to. This cannot be undone.', confirmLabel: 'Delete provider' })
      if (!yes) return
      try { await del(`${this.apiBase}/providers/${enc(p.id)}`); toast(`Provider “${p.name}” deleted.`); this.load() } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- Settings ---------------------------------------------------------------------------------------------------
  Alpine.data('adminSettings', () => mix(formMixin(), {
    apiBase: '', base: '', loading: true, loadError: '', org: null, defaults: { ttl: 0, idle: 0 }, saved: false,
    otherChanged: false, _latest: null, _pristine: '', _sig: '', _lr: null,
    async init() {
      this.apiBase = this.$el.dataset.base
      this.base = this.$el.dataset.page
      this._lr = liveRunner(() => this.refreshSettings())
      subscribe(['org'], () => this._lr.trigger())
      try { this.apply(await get(`${this.apiBase}/settings`)) } catch (e) { this.loadError = e.message }
      this.loading = false
    },
    // Live refresh. Edits in progress are never overwritten: a notice offers the latest version instead.
    async refreshSettings() {
      try {
        const o = await get(`${this.apiBase}/settings`)
        const sig = JSON.stringify(o)
        if (sig === this._sig) return
        if (JSON.stringify(this.form) !== this._pristine) { this._latest = o; this.otherChanged = true; return }
        this.apply(o)
        announceUpdate('Settings updated')
      } catch { /* offline */ }
    },
    get hasOtherChange() { return this.otherChanged },
    get otherChangeText() { return CHANGED_TEXT },
    loadLatest() { if (this._latest) this.apply(this._latest) },
    apply(o) {
      this._sig = JSON.stringify(o)
      this.otherChanged = false
      this._latest = null
      this.org = o
      const s = o.settings
      this.defaults = { ttl: Math.round(o.default_session_ttl / 3600), idle: Math.round(o.default_session_idle / 60) }
      this.resetForm({ name: o.name, display_name: o.display_name, password_login: s.password_login, passkey_login: s.passkey_login,
        require_mfa: s.require_mfa, session_ttl: s.session_ttl ? String(Math.round(s.session_ttl / 3600)) : '', session_idle: s.session_idle ? String(Math.round(s.session_idle / 60)) : '' })
      this._pristine = JSON.stringify(this.form)
    },
    get showForm() { return this.org !== null },
    get hasLoadError() { return this.loadError !== '' },
    get ttlHelp() { return 'Hours before a session ends, whatever the activity. Leave blank for the server default (' + this.defaults.ttl + ' h).' },
    get idleHelp() { return 'Minutes of inactivity before a session ends. Leave blank for the server default (' + (this.defaults.idle || 'none') + ').' },
    get saveLabel() { return this.busy ? 'Saving…' : 'Save settings' },
    get noMethod() { return !this.form.password_login && !this.form.passkey_login },
    async submit() {
      const f = this.form
      const num = (v, mult, field) => {
        if (String(v).trim() === '') return 0
        const n = Number(v)
        if (!Number.isFinite(n) || n < 0) throw Object.assign(new Error('Enter a whole number, or leave blank.'), { field, status: 422 })
        return Math.round(n * mult)
      }
      const res = await this.run(async () => {
        const settings = { password_login: f.password_login, passkey_login: f.passkey_login, require_mfa: f.require_mfa,
          session_ttl: num(f.session_ttl, 3600, 'session_ttl'), session_idle: num(f.session_idle, 60, 'session_idle') }
        return put(`${this.apiBase}/settings`, { name: f.name.trim(), display_name: f.display_name.trim(), settings })
      })
      if (!res) return
      toast('Settings saved.')
      if (res.name !== this.org.name) { window.location.assign(`/admin/orgs/${enc(res.name)}/settings`); return }
      this.apply(res)
      try { this._sig = JSON.stringify(await get(`${this.apiBase}/settings`)) } catch { /* the live refresh will catch up */ }
    },
  }))

  // ---- Audit ----------------------------------------------------------------------------------------------------
  Alpine.data('adminAudit', () => mix(tableMixin(), {
    sourceNote: '',
    init() { this.initTable() },
    transform(a) {
      const d = a.detail ? Object.entries(a.detail).map(([k, v]) => `${k}: ${v}`).join(', ') : ''
      return { ...a, timeText: fmtDateTime(a.created), detailText: d || '—', actorText: a.actor || 'system', ipText: a.ip || '—', targetText: a.target || '—',
        orgText: a.org_name || (a.org_id ? a.org_id : 'No organization') }
    },
    // Where the events come from: every node of a gossip cluster (some may not have answered), or VictoriaLogs.
    afterLoad(res) {
      if (res.source === 'cluster' && res.nodes_answered < res.nodes) {
        this.sourceNote = `Events from ${res.nodes_answered} of ${res.nodes} nodes: the others did not answer, so their events are missing.`
      } else if (res.source === 'victorialogs') {
        this.sourceNote = 'Events are read from VictoriaLogs.'
      } else {
        this.sourceNote = ''
      }
    },
    get hasSourceNote() { return this.sourceNote !== '' },
  }))

  // ---- Signing keys (super admins, primary organization) -----------------------------------------------------------
  const KEY_STATE = {
    signing: { text: 'Signing', cls: 'badge badge-success', note: 'Signs every new token.' },
    next: { text: 'Next', cls: 'badge badge-info', note: 'Takes over at its start time.' },
    previous: { text: 'Previous', cls: 'badge badge-plain', note: 'Kept until the tokens it signed expire.' },
  }
  Alpine.data('adminKeys', () => ({
    keys: [], loading: true, loadError: '', busy: false, apiBase: '', rotationDays: 0,
    init() {
      this.apiBase = this.$el.dataset.api
      this.rotationDays = Number(this.$el.dataset.rotation) || 0
      return this.load()
    },
    async load() {
      try {
        const res = await get(`${this.apiBase}/keys`)
        this.keys = res.items.map((k) => {
          const st = KEY_STATE[k.state] || KEY_STATE.previous
          return { ...k, stateText: st.text, stateClass: st.cls, stateNote: st.note, fromText: fmtDateTime(k.not_before),
            retireText: fmtDateTime(k.retire_at), removeText: fmtDateTime(k.expires) }
        })
        this.loadError = ''
      } catch (e) { this.loadError = e.message }
      this.loading = false
    },
    get showTable() { return !this.loading && this.keys.length > 0 },
    get noKeys() { return !this.loading && !this.loadError && this.keys.length === 0 },
    get hasLoadError() { return this.loadError !== '' },
    get busyAttr() { return this.busy ? 'true' : 'false' },
    get rotateLabel() { return this.busy ? 'Rotating…' : 'Rotate now' },
    get scheduleText() {
      return this.rotationDays > 0
        ? `A new key is made automatically every ${this.rotationDays} days.`
        : 'Keys are only rotated by hand.'
    },
    async rotate(ev) {
      const yes = await confirmAction(Alpine, { title: 'Rotate signing keys?', message: 'Make a new signing key now?',
        detail: 'Applications pick it up by themselves, and tokens already issued keep working.', confirmLabel: 'Rotate now' })
      if (!yes) return
      this.busy = true
      try {
        await post(`${this.apiBase}/keys/rotate`)
        toast('Signing keys rotated.')
        await this.load()
      } catch (e) { toast(e.message, 'error') }
      this.busy = false
    },
  }))

  // ---- Cluster: the nodes and this node's view, refreshed while the page is visible ---------------------------------
  const NODE_STATE = {
    alive: { text: 'Alive', cls: 'badge badge-success' },
    suspect: { text: 'Suspect', cls: 'badge badge-warning' },
    dead: { text: 'Dead', cls: 'badge badge-danger' },
    leaving: { text: 'Leaving', cls: 'badge badge-plain' },
  }
  const CLUSTER_POLL_MS = 5000
  Alpine.data('adminCluster', () => ({
    nodes: [], here: {}, size: 0, quorum: 0, alive: 0, loading: true, loaded: false, loadError: '', apiBase: '',
    updated: null, timer: null,
    init() {
      this.apiBase = this.$el.dataset.api
      this.timer = setInterval(() => { if (document.visibilityState === 'visible') this.load() }, CLUSTER_POLL_MS)
      return this.load()
    },
    destroy() { clearInterval(this.timer) },
    async load() {
      try {
        const st = await get(`${this.apiBase}/cluster`)
        this.size = st.size || 0
        this.quorum = st.quorum || 0
        this.alive = st.alive || 0
        this.nodes = (st.nodes || []).map((n) => {
          const s = NODE_STATE[n.state] || { text: n.state, cls: 'badge badge-plain' }
          return { ...n, stateText: s.text, stateClass: s.cls, addressText: n.address || '—', versionText: n.version || '—',
            readyText: n.ready ? 'Ready' : 'Not ready', readyClass: n.ready ? 'badge badge-success' : 'badge badge-warning' }
        })
        this.here = { // this node's own figures
          id: st.node_id,
          readyText: (st.ready ? 'Yes' : 'No') + (st.catching_up ? ' (catching up)' : '') + (st.behind ? ' (out of date: the others purged deletions it never saw)' : ''),
          writableText: st.writable ? 'Yes' : 'No',
          syncText: fmtDateTime(st.last_sync),
          unconfirmed: st.unconfirmed || 0,
          unconfirmedClass: st.unconfirmed ? 'badge badge-danger' : '',
          refused: st.refused || 0,
          skewText: `${st.clock_skewed || 0} received, ${st.skew_refused || 0} not followed`,
          forced: st.forced_start || '',
        }
        this.updated = new Date()
        this.loadError = ''
        this.loaded = true
      } catch (e) { this.loadError = e.message }
      this.loading = false
    },
    get showTable() { return this.loaded && this.nodes.length > 0 },
    get hasLoadError() { return this.loadError !== '' },
    get quorumText() {
      if (!this.loaded) return ''
      return `${this.alive} of ${this.size} nodes in view. Changes need a majority: ${this.quorum} of ${this.size}.`
    },
    get updatedText() {
      return this.updated ? `Updated ${this.updated.toLocaleTimeString()}, every ${CLUSTER_POLL_MS / 1000} seconds.` : ''
    },
  }))

  // ---- Small shared page behaviours -------------------------------------------------------------------------------
  Alpine.data('pageBase', () => ({}))
}
