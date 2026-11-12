// Admin pages: organizations, users, groups, clients, providers, settings, audit. Every list is server-side
// (search, sort, paging); every form submits through the management API (/api) and shows errors inline.
import { get, post, put, patch, del, qs, ApiError } from '../lib/api.js'
import { tableMixin } from '../lib/table.js'
import { formMixin, lines } from '../lib/form.js'
import { dialogMixin } from '../lib/dialog.js'
import { focusWhenShown } from '../lib/focus.js'
import { toast, announce } from '../lib/announce.js'
import { mix } from '../lib/mix.js'
import { emailsMixin } from '../lib/emails.js'
import { tagsMixin } from '../lib/tags.js'
import { pickerMixin } from '../lib/picker.js'
import { comboMixin, localeSource, zoneSource, userTypeSource } from '../lib/combo.js'
import accessComponent from './access.js'
import sshComponent, { certNote, CERT_STATUS } from './ssh.js'
import { listFieldMixin, listRows, listValues } from '../lib/listfield.js'
import { subscribe, liveRunner, announceUpdate, getOrNull, typingNow, CHANGED_TEXT } from '../lib/live.js'
import { fmtDate, fmtDateTime, relTime, isSet, ROLE_LABEL, ROLE_BADGE } from '../lib/format.js'
import { withReauth, describeAgent } from './account.js'
import { skinPreviewMixin } from '../lib/skinpreview.js'
import { pictureMixin } from '../lib/picture.js'
import { avatarOf } from '../lib/avatar.js'
import { detailsText, checkDetails, describeProblem } from '../lib/authdetails.js'

// newId makes an id as the server does (model.NewID): the 16 bytes of a UUIDv7 (a 48-bit millisecond timestamp, the
// version and variant bits, random bits) read as one big-endian number and written in base 62 (digits, then upper,
// then lower case letters: ASCII order), left-padded with '0' to 22 characters.
const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
function newId() {
  const b = crypto.getRandomValues(new Uint8Array(16))
  for (let i = 5, ms = Date.now(); i >= 0; i--, ms = Math.floor(ms / 256)) b[i] = ms % 256
  b[6] = 0x70 | (b[6] & 0x0f)
  b[8] = 0x80 | (b[8] & 0x3f)
  let v = 0n
  for (const x of b) v = (v << 8n) | BigInt(x)
  let out = ''
  for (let i = 0; i < 22; i++, v /= 62n) out = BASE62[Number(v % 62n)] + out
  return out
}

// aboutUser: may a live event concern this user? Their own record, a membership of theirs or one of their own records
// (sessions, passkeys...: the event names its owner) does; another user's does not; an event naming nobody (a foreign
// or unknown scope, a group, a client) might, so it counts.
function aboutUser(ev, userId) {
  if (ev.kind === '*') return true
  const who = ev.kind === 'user' ? ev.id : ev.kind === 'member' ? (ev.id || '').split(':')[1] : ev.user
  return !who || who === userId
}
// liveUser: on the user page, run fn (quietly, held back while a dialog is open or someone types) when a record of
// one of kinds changes for the user the page shows.
function liveUser(el, kinds, fn) {
  const userId = el.closest('[data-user]').dataset.user
  const run = liveRunner(fn)
  subscribe(kinds, (ev) => { if (aboutUser(ev, userId)) run.trigger() })
}

const enc = encodeURIComponent

const KEY_STATE = {
  signing: { text: 'Signing', cls: 'badge badge-success', note: 'Signs every new token.' },
  next: { text: 'Next', cls: 'badge badge-info', note: 'Takes over at its start time.' },
  previous: { text: 'Previous', cls: 'badge badge-plain', note: 'Kept until the tokens it signed expire.' },
}

// clusterMixin: the cluster on the system page (GET /api/cluster): every node, and this node's own view, polled while
// the page is visible. The page calls startCluster when the server replicates over gossip, and stopCluster.
const NODE_STATE = {
  alive: { text: 'Alive', cls: 'badge badge-success' },
  suspect: { text: 'Suspect', cls: 'badge badge-warning' },
  dead: { text: 'Dead', cls: 'badge badge-danger' },
  leaving: { text: 'Leaving', cls: 'badge badge-plain' },
}
const CLUSTER_POLL_MS = 5000
// one node's report from a configuration reload (POST /api/cluster/reload)
function reloadRow(r) {
  if (r.error) return { node: r.node, text: r.error, cls: 'badge badge-danger' }
  const changed = (r.changes || []).join('; ') || 'no change'
  return { node: r.node, text: r.size > 1 ? `cluster.size ${r.size}: ${changed}` : changed, cls: 'badge badge-success' }
}
function clusterMixin(Alpine) {
  return {
    cluster: {}, nodes: [], here: {}, clLoaded: false, clError: '', clUpdated: null, clTimer: null,
    reloading: false, reloadReport: [],
    startCluster() {
      if (this.clTimer) return
      this.clTimer = setInterval(() => { if (document.visibilityState === 'visible') this.loadCluster() }, CLUSTER_POLL_MS)
      return this.loadCluster()
    },
    stopCluster() { clearInterval(this.clTimer); this.clTimer = null },
    async loadCluster() {
      try {
        const st = await get(`${this.apiBase}/cluster`)
        this.cluster = st
        this.nodes = (st.nodes || []).map((n) => {
          const s = NODE_STATE[n.state] || { text: n.state, cls: 'badge badge-plain' }
          return { ...n, stateText: s.text, stateClass: s.cls, addressText: n.address || '—', versionText: n.version || '—',
            readyText: n.ready ? 'Ready' : 'Not ready', readyClass: n.ready ? 'badge badge-success' : 'badge badge-warning' }
        })
        this.here = { // this node's own figures
          id: st.node_id,
          readyText: (st.ready ? 'Yes' : 'No') + (st.resyncing ? ' (copying everything from the other nodes)' : st.catching_up ? ' (catching up)' : ''),
          writableText: st.writable ? 'Yes' : 'No',
          partitionsText: `${st.partitions_owned || 0} of 64`,
          unconfirmed: st.unconfirmed || 0,
          unconfirmedClass: st.unconfirmed ? 'badge badge-danger' : '',
          refused: st.refused || 0,
          skewText: `${st.clock_skewed || 0} received, ${st.skew_refused || 0} not followed`,
          forced: st.forced_start || '',
          // gossip keys: the one that encrypts, then those still read during a cluster key rotation
          keysText: (st.cluster_keys || []).length === 0 ? '—'
            : st.cluster_keys[0] + (st.cluster_keys.length > 1 ? ` (still reads ${st.cluster_keys.slice(1).join(', ')})` : ''),
        }
        this.clUpdated = new Date()
        this.clError = ''
        this.clLoaded = true
      } catch (e) { this.clError = e.message }
    },
    get reloadBusyAttr() { return this.reloading ? 'true' : 'false' },
    get reloadLabel() { return this.reloading ? 'Reloading…' : 'Reload configuration' },
    get hasReloadReport() { return this.reloadReport.length > 0 },
    async reloadConfig(ev) {
      const opener = ev.currentTarget
      const yes = await confirmAction(Alpine, { title: 'Reload the configuration?', message: 'Have every node re-read its configuration file?',
        detail: 'Master keys, cluster keys, cluster.size and cluster.peers. Every node checks first; nothing changes unless all can apply it. Change cluster.size by one node at a time: to add a node, add it to every configuration and reload, then start it; to remove one, stop it first, then reload.',
        confirmLabel: 'Reload' })
      if (!yes) return
      this.reloading = true
      try {
        const res = await withReauth(Alpine, () => post(`${this.apiBase}/cluster/reload`), opener)
        this.reloadReport = (res.nodes || []).map(reloadRow)
        toast('Configuration reloaded on every node.')
        await this.loadCluster()
      } catch (e) {
        if (e.name !== 'AbortError') {
          if (e.body && e.body.nodes) this.reloadReport = e.body.nodes.map(reloadRow)
          toast(e.message, 'error')
        }
      }
      this.reloading = false
    },
    get showNodes() { return this.clLoaded && this.nodes.length > 0 },
    get hasClusterError() { return this.clError !== '' },
    get clusterHealthy() { return !!(this.cluster.ready && this.cluster.writable) },
    get clusterState() { return this.clusterHealthy ? 'Healthy' : this.cluster.ready ? 'Not accepting changes' : 'Not ready' },
    get clusterClass() { return this.clusterHealthy ? 'badge badge-success' : 'badge badge-warning' },
    get quorumText() {
      const c = this.cluster
      return this.clLoaded ? `${c.alive || 0} of ${c.size || 0} nodes in view. Changes need a majority: ${c.quorum || 0} of ${c.size || 0}.` : ''
    },
    get clusterUpdatedText() {
      return this.clUpdated ? `As this node sees it; updated ${this.clUpdated.toLocaleTimeString()}, every ${CLUSTER_POLL_MS / 1000} seconds.` : ''
    },
  }
}

// keysMixin: the signing keys on the system page (GET /api/keys), rotating them and removing one that no longer signs.
// The page calls loadKeys; it sets apiBase and rotationDays.
function keysMixin(Alpine) {
  return {
    keys: [], keysLoading: true, keysError: '', rotating: false, rotationDays: 0,
    async loadKeys() {
      try {
        const res = await get(`${this.apiBase}/keys`)
        this.keys = res.items.map((k) => {
          const st = KEY_STATE[k.state] || KEY_STATE.previous
          return { ...k, stateText: st.text, stateClass: st.cls, stateNote: st.note, fromText: fmtDateTime(k.not_before),
            retireText: fmtDateTime(k.retire_at), removeText: fmtDateTime(k.expires),
            removable: k.state === 'previous', removeLabel: `Remove now, key ${k.id}`,
            shortId: k.id.length > 16 ? `${k.id.slice(0, 8)}…${k.id.slice(-6)}` : k.id }
        })
        this.keysError = ''
      } catch (e) { this.keysError = e.message }
      this.keysLoading = false
    },
    get showKeysTable() { return !this.keysLoading && this.keys.length > 0 },
    get noKeys() { return !this.keysLoading && !this.keysError && this.keys.length === 0 },
    get hasKeysError() { return this.keysError !== '' },
    get rotateBusyAttr() { return this.rotating ? 'true' : 'false' },
    get rotateLabel() { return this.rotating ? 'Rotating…' : 'Rotate now' },
    get scheduleText() {
      return this.rotationDays > 0
        ? `A new key is made automatically every ${this.rotationDays} days.`
        : 'Keys are only rotated by hand.'
    },
    async rotate(ev) {
      const opener = ev.currentTarget
      const yes = await confirmAction(Alpine, { title: 'Rotate signing keys?', message: 'Make a new signing key now?',
        detail: 'Applications pick it up by themselves, and tokens already issued keep working.', confirmLabel: 'Rotate now' })
      if (!yes) return
      this.rotating = true
      try {
        await withReauth(Alpine, () => post(`${this.apiBase}/keys/rotate`), opener)
        toast('Signing keys rotated.')
        await this.loadKeys()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
      this.rotating = false
    },
    async removeKey(ev) {
      const opener = ev.currentTarget
      const id = opener.dataset.id
      const yes = await confirmAction(Alpine, { title: 'Remove this key now?', message: `Remove key ${id} now?`,
        detail: 'Tokens it signed stop working at once, here and in applications once they fetch the keys again. Applications get new tokens through their refresh tokens; nobody is signed out. Do this for a key that may have been exposed.',
        confirmLabel: 'Remove key' })
      if (!yes) return
      try {
        await withReauth(Alpine, () => del(`${this.apiBase}/keys/${enc(id)}`), opener)
        toast('Key removed. The tokens it signed no longer work.')
        await this.loadKeys()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }
}

// signOutMixin: the emergency sign-out (break glass) of the system page (signOutScope 'server') and of an
// organization's page (signOutScope = its URL name, signOutDisplay = its display name): the dialog in
// partials/admin.html (signout-dialog), the last pull (signout-last). The page sets lastSignOut from what it loads.
function signOutMixin(Alpine) {
  return {
    lastSignOut: null, signOutScope: '', signOutDisplay: '',
    get signOutServer() { return this.signOutScope === 'server' },
    openSignOut(ev) {
      this.resetForm({ reason: '', api_tokens: false, confirm: '' })
      this.openDlg('signout-dialog', ev.currentTarget)
    },
    get signOutWord() { return this.signOutServer ? 'everyone' : this.signOutScope },
    get signOutConfirmLabel() { return `Type ${this.signOutWord} to confirm` },
    get signOutWhat() {
      return this.signOutServer ? 'Everyone in every organization will be signed out.'
        : `Everyone in ${this.signOutDisplay || this.signOutScope} will be signed out.`
    },
    get signOutBlocked() { return this.busy || (this.form.confirm || '').trim() !== this.signOutWord },
    get signOutLabel() { return this.busy ? 'Signing everyone out…' : 'Sign everyone out' },
    get hasLastSignOut() { return !!this.lastSignOut },
    get lastSignOutText() {
      const l = this.lastSignOut
      if (!l) return ''
      return `${fmtDateTime(l.at)} by ${l.by}${l.api_tokens ? ', with API tokens' : ''}: ${l.reason}`
    },
    async pullSignOut(ev) {
      if (this.signOutBlocked) return
      this.clearErrors()
      this.busy = true
      const url = `${this.apiBase}/sign-out` // /api (the server) or /api/orgs/<name>
      const body = { reason: this.form.reason, api_tokens: !!this.form.api_tokens }
      try {
        this.lastSignOut = await withReauth(Alpine, () => post(url, body), ev.submitter || ev.currentTarget, this)
        this.closeDlg('signout-dialog')
        toast(this.signOutServer ? 'Everyone in every organization was signed out.' : 'Everyone in the organization was signed out.')
      } catch (e) { if (e.name !== 'AbortError') this.setErrors(e) }
      this.busy = false
    },
  }
}

// Confirmation through the shared dialog; resolves true/false.
// mailOn: the server has email set up (an SMTP server); without it nothing offers to send email.
const mailOn = () => document.documentElement.dataset.mail === '1'

function confirmAction(Alpine, opts) { return Alpine.store('confirm').ask(opts) }

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

// profileDetails are the user page's display values beyond the basics: locale, time zone, user type, end date and the
// work details (each "—" when unset), and the manager as a link.
function profileDetails(u, listUrl) {
  const w = u.work || {}
  const workRows = WORK_FIELDS.map((k) => ({ key: k, label: WORK_LABELS[k], value: w[k] || '—' }))
  const hasWork = WORK_FIELDS.some((k) => w[k]) || !!u.manager
  let endText = 'No end date', endBadge = '', endClass = ''
  if (isSet(u.valid_until)) {
    const left = new Date(u.valid_until).getTime() - Date.now()
    endText = fmtDateTime(u.valid_until)
    if (left <= 0) { endBadge = 'Ended'; endClass = 'badge badge-danger ml-1' }
    else if (left <= SOON_MS) { endBadge = 'Ends soon'; endClass = 'badge badge-warning ml-1' }
  }
  return {
    localeText: localeName(u.locale), zoneText: u.zoneinfo || '—', userTypeText: u.user_type ? u.user_type[0].toUpperCase() + u.user_type.slice(1) : '—',
    endText, endBadge, endClass, hasEndBadge: endBadge !== '',
    workRows, hasWork, noWork: !hasWork,
    managerName: u.manager ? u.manager.name : '—', hasManager: !!u.manager,
    managerHref: u.manager ? `${listUrl}/${encodeURIComponent(u.manager.id)}` : '',
  }
}

// localeName is a locale tag as a language name and the tag ("English (United Kingdom) · en-GB"), or the tag alone.
function localeName(tag) {
  if (!tag) return '—'
  try {
    const name = new Intl.DisplayNames([navigator.language || 'en'], { type: 'language' }).of(tag)
    return name && name !== tag ? `${name} · ${tag}` : tag
  } catch (e) { return tag }
}
const WORK_LABELS = { title: 'Job title', department: 'Department', organization: 'Organization', division: 'Division',
  cost_center: 'Cost centre', employee_number: 'Employee number' }
const SOON_MS = 7 * 24 * 3600 * 1000 // an end date this close is pointed out

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
      this.resetForm({ username: '', email: '', given_name: '', family_name: '', role: 'user', invite: false, tags: [], external_id: '' })
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
    invitePage: '', // after creating a user on the list: their page, for what comes next (groups, addresses)
    _emailWatch: false,
    get hasInvite() { return this.inviteUrl !== '' },
    get noInvite() { return this.inviteUrl === '' },
    get canEmailInvite() { return mailOn() && this.inviteUrl !== '' && this.inviteTo !== '' && !this.inviteSent },
    get hasInviteNote() { return this.inviteNote !== '' },
    get hasInviteError() { return this.inviteError !== '' },
    get hasInvitePage() { return this.invitePage !== '' },
    get inviteExpiresText() { return this.inviteExpires ? fmtDateTime(this.inviteExpires) : '' },
    get inviteSentText() { return this.inviteSent ? `Emailed to ${this.inviteTo}.` : '' },
    get inviteTitle() { return this.inviteUrl ? 'Invitation link' : 'New invitation link' },
    get inviteWho() { return this.inviteName },
    get inviteGenLabel() { return this.inviteBusy ? 'Working…' : 'Generate link' },
    get inviteMailLabel() { return this.inviteBusy ? 'Sending…' : 'Send by email' },
    openInvite(u, res, opener) {
      Object.assign(this, { inviteUserId: u.id, inviteName: u.name || u.username, inviteTo: u.email || '', inviteError: '', inviteBusy: false, invitePage: '',
        inviteUrl: res ? res.url || '' : '', inviteExpires: res ? res.expires || '' : '', inviteSent: !!(res && res.emailed), inviteNote: res ? res.email_warning || '' : '' })
      // let x-show reveal the right state first, then open and focus its main control
      this.$nextTick(() => {
        this.openDlg('invite-dialog', opener)
        focusWhenShown(this.inviteUrl ? 'invite-copy' : 'invite-generate')
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
        focusWhenShown('invite-copy')
      } catch (e) { this.inviteError = e.message; announce(e.message, 'assertive') }
      this.inviteBusy = false
    },
    generateInvite() { return this.makeInvite(false) },
    sendInvite() { return this.makeInvite(true) },
    openEditUser(u, opener) {
      this.editingUser = u
      this.resetForm({ username: u.username, email: u.email || '', role: u.role, active: u.active,
        given_name: u.given_name || '', family_name: u.family_name || '', tags: [...(u.tags || [])], external_id: u.external_id || '' })
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
      // Making someone an administrator needs a recent re-authentication (the server asks; the dialog provides it).
      const res = await this.run(() => withReauth(Alpine, () => {
        if (this.editingUser) {
          const body = { username: f.username, email: f.email, given_name: f.given_name, family_name: f.family_name, role: f.role, active: !!f.active, tags: f.tags, ...this.profileBody() }
          if (this.editingSelf) delete body.email
          // only administrators have the field; sent when changed, so a save by anyone else leaves it alone
          if (f.external_id !== (this.editingUser.external_id || '')) body.external_id = f.external_id.trim()
          if (this.statusChanging && (f.status_reason || '').trim()) body.status_reason = f.status_reason.trim()
          return patch(`${this.apiBase}/users/${enc(this.editingUser.id)}`, body)
        }
        return post(`${this.apiBase}/users`, { username: f.username, email: f.email, given_name: f.given_name, family_name: f.family_name, role: f.role, tags: f.tags, ...this.profileBody(),
          ...((f.external_id || '').trim() ? { external_id: f.external_id.trim() } : {}),
          invite: { email: mailOn() && !!f.invite && !!(f.email || '').trim() } })
      }, null, this))
      if (!res) return
      this.closeDlg('user-dialog')
      if (this.editingUser) toast('User saved.')
      else {
        // after the user dialog's close handler returned focus; the link is shown only now, so it stays on this page
        setTimeout(() => { this.openInvite(res, res.invite, null); if (this.pageUrl) this.invitePage = `${this.pageUrl}/${enc(res.id)}` }, 60)
      }
      await this.afterUserSaved(res)
    },
  })
}

// ---------------------------------------------------------------------------------------------------------------
// Tenants (shared by the tenants list and the pages of one tenant)
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
  organization: { text: 'Organization', name: 'the organization\u2019s name' },
}
const providerTypeText = (t) => (PROVIDER_TYPES[t] || PROVIDER_TYPES.oidc).text
// The issuer's host alone (accounts.google.com, not https://accounts.google.com): the full address is in the edit dialog.
const issuerHost = (u) => { try { return new URL(u).host || u } catch { return u || '' } }
const providerSub = (p) => p.type === 'github' ? 'github.com' : p.type === 'organization' ? 'Users of ' + (p.source_org_name || 'another organization') : p.type === 'microsoft' ? 'Entra ID \u00b7 ' + (p.tenant === 'organizations' ? (p.allowed_tenants || []).length + ' allowed tenants' : p.tenant) : issuerHost(p.issuer)
const shapeProvider = (p) => ({ id: p.id, name: p.name, enabled: p.enabled, typeText: providerTypeText(p.type), stateText: p.enabled ? 'enabled' : 'disabled' })

// Whether a tenant signs SSH certificates, as the tenants list shows it (the list API gives the settings once SSH was ever turned on).
const sshState = (t) => (t.ssh && t.ssh.enabled ? { sshText: 'On', sshClass: 'badge badge-success' } : { sshText: 'Off', sshClass: 'badge badge-plain' })

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
// the element ids distinct from the client dialog's name / description.
function tenantDialogMixin(Alpine) {
  return {
    editingTenant: null, apiBase: '', providers: [], orgPassword: true, orgReset: true, orgPasskey: true, orgMFA: false, _form: 'tenant',
    errorKey(f) {
      if (this._form === 'tenant' && (f === 'name' || f === 'description' || f === 'resources')) return 'tenant_' + f
      if (this._form === 'client' && f === 'scopes') return 'custom_scopes' // shown on the scopes chip field
      return f
    },
    async loadOrgInfo() {
      try {
        const [org, provs] = await Promise.all([get(this.apiBase), get(`${this.apiBase}/providers${qs({ sort: 'name', limit: 100 })}`)])
        this.orgPassword = org.settings.password_login
        this.orgReset = !!org.settings.password_reset
        this.orgPasskey = org.settings.passkey_login
        this.orgMFA = !!org.settings.require_mfa
        this.providers = provs.items.map(shapeProvider)
      } catch (e) { toast(e.message, 'error') }
    },
    get tenantDialogTitle() { return this.editingTenant ? 'Edit sign-in rules' : 'New tenant' },
    get tenantSubmitLabel() { return this.busy ? 'Saving…' : this.editingTenant ? 'Save changes' : 'Create tenant' },
    get passwordOff() { return !this.orgPassword },
    get passkeyOff() { return !this.orgPasskey },
    get orgResetOff() { return !this.orgPassword || !this.orgReset },
    get resetOff() { return this.orgResetOff || !this.form.password_login },
    get tenantMFAOption() { return !this.orgMFA },
    get hasProviders() { return this.providers.length > 0 },
    get noProviders() { return this.providers.length === 0 },
    get pickProviders() { return !this.form.all_providers },
    get providerHelp() { return this.hasProviders ? 'Only enabled providers can be used to sign in, whatever is ticked here.' : 'This organization has no sign-in providers yet.' },
    tenantToForm(t) {
      const s = t.settings
      return { tenant_name: t.name, display_name: t.display_name, tenant_description: t.description || '', who: s.members_only ? 'members' : 'everyone', password_login: !!s.password_login, password_reset: !!s.password_reset, passkey_login: !!s.passkey_login,
        all_providers: s.all_providers !== false, providers: [...(s.providers || [])], require_mfa: !!s.require_mfa,
        self_registration: !!s.self_registration, tenant_resources: listRows(t.resources || [], 'Resource', true) }
    },
    openCreateTenant(opener) {
      this._form = 'tenant'
      this.editingTenant = null
      this.resetForm(this.tenantToForm({ name: '', display_name: '', settings: { members_only: true, password_login: true, password_reset: true, passkey_login: true, all_providers: true, providers: [], require_mfa: true } }))
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
      const body = { display_name: f.display_name, description: f.tenant_description, settings: { members_only: f.who === 'members', password_login: f.password_login, password_reset: f.password_reset, passkey_login: f.passkey_login,
        all_providers: f.all_providers, providers: f.all_providers ? [] : f.providers, require_mfa: f.require_mfa,
        self_registration: f.self_registration }, resources: listValues(f.tenant_resources) }
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

// What the pages of one tenant share (the tenant page, its clients and its SSH certificates): the tenant's record, kept
// current for the title, the breadcrumb and the notice that someone else deleted it. A page that needs more fetched with
// the record gives tenantExtra, which answers {sig, use}: what changing means a new answer (sig) and what to do with it
// (use). pathSuffix is what follows the tenant in the page's address, kept when the tenant is renamed.
function tenantPageMixin() {
  return {
    tenant: null, tenantId: '', slug: '', pageBase: '', pathSuffix: '', gone: false, tenantError: '', _tsig: '', _tlive: null, titleText: '',
    async initTenantPage(kinds) {
      const d = this.$el.dataset
      this.apiBase = d.base
      this.pageBase = d.page
      this.tenantId = d.tenant
      this.slug = d.slug
      this.titleText = d.title
      this._tlive = liveRunner(() => this.refreshTenant(true))
      subscribe(kinds, () => this._tlive.trigger())
      await this.refreshTenant(false)
    },
    async tenantExtra() { return { sig: null, use() {} } },
    async refreshTenant(quiet) {
      try {
        const [t, extra] = await Promise.all([getOrNull(`${this.apiBase}/tenants/${enc(this.tenantId)}`), this.tenantExtra()])
        if (t === null) {
          if (!this.gone) { this.gone = true; this.tenant = null; announce('This tenant was deleted by someone else.', 'assertive') }
          return
        }
        const sig = JSON.stringify([t, extra.sig])
        if (quiet && sig === this._tsig) return
        this._tsig = sig
        const before = this.tenant
        this.gone = false
        this.tenantError = ''
        this.tenant = t
        extra.use(t)
        this.titleText = t.display_name
        document.title = document.title.replace(/^([^:]+): [^·]*/, '$1: ' + t.display_name + ' ')
        if (before && before.name !== t.name) history.replaceState(null, '', `${this.pageBase}/${enc(t.name)}${this.pathSuffix}`)
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
    // the tenant's pages (the address name is what they are under)
    get tenantHref() { return `${this.pageBase}/${enc(this.tenant ? this.tenant.name : this.slug)}` },
    get clientsHref() { return this.tenant ? `${this.pageBase}/${enc(this.tenant.name)}/clients` : '' },
    get sshHref() { return this.tenant ? `${this.pageBase}/${enc(this.tenant.name)}/ssh` : '' },
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Client dialogs (create / edit / the client's details, its secret shown once); used on the tenant's clients page.
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
const GRANTS = ['authorization_code', 'refresh_token', 'client_credentials', TOKEN_EXCHANGE, DEVICE_CODE]
const CONFIDENTIAL_GRANTS = ['client_credentials', TOKEN_EXCHANGE]
// The client list's names for the grant types whose identifiers are URNs.
const GRANT_NAMES = { [TOKEN_EXCHANGE]: 'token_exchange', [DEVICE_CODE]: 'device_code' }
// Standard scopes shown as checkboxes (the rest of a client's scopes are its own API scopes, edited as rows).
const STD_SCOPES = [
  { value: 'openid', help: 'Required for OpenID Connect sign-in: the user\u2019s identity.' },
  { value: 'profile', help: 'The user\u2019s name, username, language and time zone.' },
  { value: 'email', help: 'The user\u2019s email address and whether it is verified.' },
  { value: 'groups', help: 'The user\u2019s group names.' },
  { value: 'org', help: 'The user\u2019s organization, tenant and Quisora role (org_role).' },
  { value: 'roles', help: 'The user\u2019s application roles and tags for this application.' },
  { value: 'idp', help: 'The account the user signed in with at an upstream provider such as Microsoft or Google: idp_sub, idp_tenant and idp_login.' },
  { value: 'offline_access', help: 'Refresh tokens, so the application can stay signed in.' },
]
const STD_NAMES = STD_SCOPES.map((s) => s.value)
// Server field -> the list editor that shows it.
const LIST_OF_FIELD = { redirect_uris: 'redirect_uris', post_logout_redirect_uris: 'post_logout_redirect_uris', resources: 'resources',
  authorization_details_types: 'authorization_details_types' }
const LIST_ITEMS = { redirect_uris: 'Redirect URI', post_logout_redirect_uris: 'Post-logout redirect URI', resources: 'Resource',
  authorization_details_types: 'Authorization details type' }
function clientDialogMixin(Alpine) {
  return mix(listFieldMixin(), tagsMixin(), {
    stdScopes: STD_SCOPES.map((s) => ({ ...s, id: 'f-scope-' + s.value })),
    // A server error about a list field goes onto the row it names; otherwise it is shown under the whole list.
    listError(err) {
      const name = this._form === 'client' && LIST_OF_FIELD[err.field]
      if (!name) return false
      if (this.setListError(name, err.message)) return true
      this.errors = { [name]: err.message }
      this.invalid = { [name]: 'true' }
      announce(err.message, 'assertive')
      focusWhenShown(() => { const r = this.form[name][0]; return r && document.getElementById(r.inputId) })
      return true
    },
    // Checks the editor can make itself (the chip field checks each scope as it is added); false when the form must
    // not be sent.
    clientListsValid() {
      if (!this.tagsReady()) { this.focusTagInput(); return false }
      const std = this.form.custom_scopes.find((v) => STD_NAMES.includes(v))
      if (std) {
        this.setChipError('custom_scopes', `${std} is a standard scope: tick it above instead.`)
        this.focusTagInput()
        return false
      }
      return true
    },
    get usesRedirects() { return (this.form.grant_types || []).includes('authorization_code') },
    get usesDevice() { return (this.form.grant_types || []).includes(DEVICE_CODE) },
    // The types listed above the client's own authorization details (the details field checks against them).
    get detailTypes() { return listValues(this.form.authorization_details_types || []) },
    get usesClientCredentials() { return this.form.token_endpoint_auth_method !== 'none' && (this.form.grant_types || []).includes('client_credentials') },
    editingClient: null, apiBase: '', issuer: '', clientId: '', secret: '', secretClient: '', secretTitle: '', canFirstParty: false, tenants: [], tenantId: '',
    shapeClient(c) {
      const b = activeBadge(c.enabled, 'Enabled', 'Disabled')
      const locked = !this.canFirstParty && !!c.first_party // first-party clients: super admins only
      return { ...c, createdText: fmtDate(c.created), statusText: b.text, statusClass: b.cls, copyLabel: 'Copy client ID of ' + c.name,
        editLabel: 'Edit ' + c.name, deleteLabel: 'Delete ' + c.name, rotateLabel: 'Rotate secret of ' + c.name,
        methodText: { client_secret_post: 'Secret (POST)', client_secret_basic: 'Secret (Basic)', private_key_jwt: 'Private key JWT', none: 'Public (no secret)' }[c.token_endpoint_auth_method] || c.token_endpoint_auth_method,
        hasSecret: c.token_endpoint_auth_method !== 'none', firstParty: c.first_party,
        canChange: !locked, canRotate: !locked && c.token_endpoint_auth_method !== 'none', grantsText: (c.grant_types || []).map((g) => GRANT_NAMES[g] || g).join(', '), sub: c.description || '' }
    },
    tenantName(id) { const t = this.tenants.find((x) => x.id === id); return t ? t.display_name : '' },
    get canMove() { return this.editingClient !== null && this.tenants.length > 1 },
    get isEditClient() { return this.editingClient !== null },
    get isPublic() { return this.form.token_endpoint_auth_method === 'none' },
    get notPublic() { return this.form.token_endpoint_auth_method !== 'none' },
    // Remembering consent: confidential clients only, and moot for a first-party one (it never asks).
    get showRememberConsent() { return this.notPublic && !this.form.first_party },
    get methodHelp() {
      return { client_secret_post: 'The secret is sent in the request body. The default for server-side apps.', client_secret_basic: 'The secret is sent in an HTTP Basic header. Many client libraries only do this.',
        private_key_jwt: 'The client signs a JWT with its private key; you register the public keys. For high-assurance server apps.',
        none: 'Public client: no secret. For single-page apps, mobile and desktop apps and CLIs. PKCE protects the flow.' }[this.form.token_endpoint_auth_method] || ''
    },
    get isJwt() { return this.form.token_endpoint_auth_method === 'private_key_jwt' },
    get grantsHelp() {
      return this.isPublic
        ? 'Public clients use the authorization code grant or device sign-in, with refresh tokens; refresh tokens always rotate.'
        : 'An application that signs nobody in, such as an API calling other APIs, needs neither Authorization code nor Refresh token: untick them, and it needs no redirect URIs.'
    },
    get clientDialogTitle() { return this.editingClient ? 'Edit client' : 'New client' },
    get clientSubmitLabel() { return this.busy ? 'Saving…' : this.editingClient ? 'Save changes' : 'Create client' },
    clientToForm(c) {
      const scopes = c.scopes || []
      return { tenant_id: c.tenant_id || '', name: c.name, description: c.description || '',
        redirect_uris: listRows(c.redirect_uris, LIST_ITEMS.redirect_uris), post_logout_redirect_uris: listRows(c.post_logout_redirect_uris, LIST_ITEMS.post_logout_redirect_uris, true),
        backchannel_logout_uri: c.backchannel_logout_uri || '', grant_types: [...(c.grant_types || [])], resources: listRows(c.resources, LIST_ITEMS.resources, true),
        authorization_details_types: listRows(c.authorization_details_types, LIST_ITEMS.authorization_details_types, true), authorization_details: detailsText(c.authorization_details),
        std_scopes: STD_NAMES.filter((n) => scopes.includes(n)), custom_scopes: scopes.filter((x) => !STD_NAMES.includes(x)), token_endpoint_auth_method: c.token_endpoint_auth_method, jwks: c.jwks || '', jwks_uri: c.jwks_uri || '',
        first_party: !!c.first_party, remember_consent: !!c.remember_consent, enabled: c.enabled !== false, rotate_refresh_tokens: !!c.rotate_refresh_tokens, introspect_org: !!c.introspect_org, accepts_api_tokens: !!c.accepts_api_tokens, require_pkce: c.require_pkce !== false, require_pushed_authorization_requests: !!c.require_pushed_authorization_requests,
        dpop_bound_access_tokens: !!c.dpop_bound_access_tokens, fapi2_security_profile: !!c.fapi2_security_profile,
        device_privileged_users: !!c.device_privileged_users }
    },
    openCreateClient(opener) {
      this._form = 'client'
      this.editingClient = null
      this.resetForm(this.clientToForm({ tenant_id: this.tenantId, name: '', grant_types: ['authorization_code', 'refresh_token'], scopes: ['openid', 'profile', 'email'],
        token_endpoint_auth_method: 'client_secret_post', enabled: true, rotate_refresh_tokens: true }))
      this.resetChipText()
      this.openDlg('client-dialog', opener)
    },
    openEditClient(c, opener) {
      this._form = 'client'
      this.editingClient = c
      this.resetForm(this.clientToForm(c))
      this.resetChipText()
      this.openDlg('client-dialog', opener)
      this.watchEdit({ kinds: ['client'], record: c, fetchOne: () => getOrNull(`${this.apiBase}/clients/${enc(c.id)}`) })
    },
    clientBody() {
      const f = this.form
      const pub = f.token_endpoint_auth_method === 'none'
      const redirects = this.usesRedirects
      const b = { name: f.name, description: f.description, redirect_uris: redirects ? listValues(f.redirect_uris) : [], post_logout_redirect_uris: redirects ? listValues(f.post_logout_redirect_uris) : [],
        backchannel_logout_uri: f.backchannel_logout_uri.trim(), resources: listValues(f.resources),
        authorization_details_types: listValues(f.authorization_details_types),
        grant_types: GRANTS.filter((g) => f.grant_types.includes(g) && !(pub && CONFIDENTIAL_GRANTS.includes(g))),
        scopes: [...STD_NAMES.filter((n) => f.std_scopes.includes(n)), ...f.custom_scopes], token_endpoint_auth_method: f.token_endpoint_auth_method,
        enabled: f.enabled, rotate_refresh_tokens: pub ? true : f.rotate_refresh_tokens, introspect_org: pub ? false : f.introspect_org, accepts_api_tokens: pub ? false : f.accepts_api_tokens, remember_consent: pub ? false : f.remember_consent, require_pkce: pub ? true : f.require_pkce,
        require_pushed_authorization_requests: redirects && f.require_pushed_authorization_requests,
        dpop_bound_access_tokens: f.dpop_bound_access_tokens,
        device_privileged_users: this.usesDevice && f.device_privileged_users,
        fapi2_security_profile: f.token_endpoint_auth_method === 'private_key_jwt' && f.fapi2_security_profile }
      if (f.tenant_id) b.tenant_id = f.tenant_id
      if (f.token_endpoint_auth_method === 'private_key_jwt') { b.jwks = f.jwks; b.jwks_uri = f.jwks_uri }
      if (this.canFirstParty) b.first_party = f.first_party
      return b
    },
    async submitClient() {
      if (!this.clientListsValid()) return
      const details = checkDetails(this.usesClientCredentials ? this.form.authorization_details : '')
      if (!details.value) {
        const first = details.problems.find((p) => p.severity === 'error')
        this.setErrors(new ApiError(422, { error: describeProblem(first), field: 'authorization_details' }))
        return
      }
      const edit = this.editingClient
      const body = this.clientBody()
      body.authorization_details = details.value
      const res = await this.run(() => edit ? patch(`${this.apiBase}/clients/${enc(edit.id)}`, body) : post(`${this.apiBase}/clients`, body))
      if (!res) return
      this.closeDlg('client-dialog')
      const moved = !!edit && res.tenant_id !== this.tenantId
      if (!edit) this.showClient(res, 'Client created')
      else if (moved) toast(`Client “${res.name}” moved to ${this.tenantName(res.tenant_id) || 'another tenant'} and left this list.`)
      else toast('Client saved.')
      await this.afterClientSaved(res, moved)
    },
    // The dialog of what the application is configured with: client ID, issuer and discovery URL (applications ask for
    // one or the other), and the secret (shown once) of a confidential client (c.secret; a public client has none).
    showClient(c, title) {
      this.clientId = c.id
      this.secret = c.secret || ''
      this.secretClient = c.name
      this.secretTitle = title
      this.$nextTick(() => this.openDlg('secret-dialog'))
    },
    get discoveryUrl() { return this.issuer + '/.well-known/openid-configuration' },
    get hasSecret() { return this.secret !== '' },
    get secretDone() { return this.hasSecret ? 'I have stored it' : 'Done' },
    async rotateClient(c) {
      const yes = await confirmAction(Alpine, { title: 'Rotate client secret?', message: `Issue a new secret for “${c.name}”?`,
        detail: 'The current secret stops working immediately. Update every application that uses it.', confirmLabel: 'Rotate secret', danger: true })
      if (!yes) return
      try {
        const res = await post(`${this.apiBase}/clients/${enc(c.id)}/secret`)
        this.showClient({ id: c.id, name: c.name, secret: res.secret }, 'New client secret')
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
    init() { liveUser(this.$el, ['user'], () => this.loadEmails()); return this.loadEmails() },
  }))
}

// The API tokens card of the user page: the user's personal tokens (never their secrets), each revocable at once.
function userTokensComponent(Alpine) {
  Alpine.data('adminUserTokens', () => ({
    items: [], loading: true, loadError: '',
    init() { liveUser(this.$el, ['apitoken'], () => this.load()); return this.load() },
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

// The SSH certificates card of the user page: the user's certificates that have not expired, across the tenants, each
// revocable at once. Only administrators of the organization have the card (the page leaves it out for anyone else).
function userSSHComponent(Alpine) {
  Alpine.data('adminUserSSH', () => ({
    items: [], loading: true, loadError: '',
    init() { liveUser(this.$el, ['sshcert'], () => this.load()); return this.load() },
    url(s = '') { const d = this.$el.closest('[data-user]').dataset; return `${d.base}/users/${enc(d.user)}/ssh-certificates${s}` },
    async load() {
      try {
        const tenants = this.$el.closest('[data-user]').dataset.tenants
        const r = await get(this.url())
        this.items = r.items.map((c) => {
          const st = CERT_STATUS[c.status] || CERT_STATUS.expired
          return { ...c, principalsText: (c.principals || []).join(', '), expiresText: fmtDateTime(c.valid_before), statusText: st.text, statusClass: st.cls,
            statusNote: certNote(c), active: c.status === 'active', href: `${tenants}/${enc(c.tenant_name)}/ssh`,
            revokeLabel: `Revoke the certificate for ${c.tenant} (${(c.principals || []).join(', ')})` }
        })
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    // Nothing is shown for a user with no certificate that is still valid.
    get visible() { return this.items.length > 0 || this.loadError !== '' },
    get hasItems() { return this.items.length > 0 },
    get hasLoadError() { return this.loadError !== '' },
    async revoke(ev) {
      const c = this.items.find((i) => i.id === ev.currentTarget.dataset.id)
      if (!c) return
      const yes = await confirmAction(Alpine, { title: 'Revoke certificate?', message: `Revoke the certificate for ${c.tenant} (${c.principalsText})?`,
        detail: 'It goes on the revocation list servers fetch, so it stops working within a minute or two. The user can ask for a new certificate straight away.', confirmLabel: 'Revoke certificate' })
      if (!yes) return
      try {
        await post(`${this.$el.closest('[data-user]').dataset.base}/tenants/${enc(c.tenant_id)}/ssh/certificates/${enc(c.id)}/revoke`)
        toast('Certificate revoked.')
        await this.load()
      } catch (e) { toast(e.message, 'error') }
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
    init() { liveUser(this.$el, ['session'], () => this.load()); return this.load() },
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
    init() { liveUser(this.$el, ['grant', 'consent', 'client'], () => this.load()); return this.load() },
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
        detail: `${a.name} is told to sign them out, and its tokens stop working now. They can sign in to it again; it asks them to allow it again.`, confirmLabel: 'Remove access' })
      if (!yes) return
      try {
        await withReauth(Alpine, () => del(base(this.$el, '/apps/' + enc(a.client_id))), opener)
        toast(`Access to ${a.name} removed.`)
        await this.load()
        focusHeading('apps-h')
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }))

  Alpine.data('adminUserPasskeys', () => mix(listState(), {
    init() { liveUser(this.$el, ['passkey'], () => this.load()); return this.load() },
    async load() {
      try {
        const r = await get(base(this.$el, '/passkeys'))
        this.items = r.items.map((p) => ({ ...p,
          kind: p.backup_eligible ? (p.backup_state ? 'Synced passkey' : 'Passkey (can be synced)') : 'Device-bound passkey',
          problemText: p.problem === 'disabled' ? 'Disabled' : p.problem === 'unverified' ? 'Cannot sign in' : '',
          detail: `Added ${fmtDate(p.created)}, ${isSet(p.last_used) ? 'last used ' + fmtDate(p.last_used) : 'never used'}`,
          forName: ' ' + p.name }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    async remove(ev) {
      const opener = ev.currentTarget
      const p = this.items.find((i) => i.id === opener.dataset.id)
      if (!p) return
      const yes = await confirmAction(Alpine, { title: 'Remove passkey?', message: `Remove the passkey "${p.name}" from this user?`,
        detail: 'It can no longer sign them in, and the sessions that signed in with it end. If it was their only way to sign in, send them a new invitation link.', confirmLabel: 'Remove', danger: true })
      if (!yes) return
      try {
        await withReauth(Alpine, () => del(base(this.$el, '/passkeys/' + enc(p.id))), opener)
        toast(`Passkey "${p.name}" removed.`)
        await this.load()
        window.dispatchEvent(new CustomEvent('user-signin-changed'))
        focusHeading('passkeys-h')
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }))

  Alpine.data('adminUserProviders', () => mix(listState(), {
    init() { liveUser(this.$el, ['identity', 'provider'], () => this.load()); return this.load() },
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
  userSSHComponent(Alpine)
  userConnectionsComponents(Alpine)
  accessComponent(Alpine)
  sshComponent(Alpine)
  // ---- Organizations -----------------------------------------------------------------------------------------
  const API_GROUP_LIMIT = 20 // the server's bound on the groups chosen to make API tokens
  const SOURCE_GROUP_LIMIT = 20 // the server's bound on an organization provider's groups (maxSourceGroups)
  // ---- Branding fields (the organization dialog, and the branding card on the organization's page) ----------------
  // b is the saved branding; pending, the logos chosen since: null (nothing), '' (remove) or the new image as a data:
  // URI; form.primary_color, the colour (the component's form holds it).
  const LOGO_MAX = 256 * 1024 // what the server takes of a logo, decoded
  const HEX_COLOR = /^#[0-9a-f]{6}$/i
  const readDataUrl = (file) => new Promise((resolve, reject) => {
    const r = new FileReader()
    r.onload = () => resolve(r.result)
    r.onerror = () => reject(r.error)
    r.readAsDataURL(file)
  })
  const brandingMixin = () => mix(skinPreviewMixin(), {
    b: {}, pending: { logo_light: null, logo_dark: null }, skins: [], brandPrimary: false, brandOrgBase: '',
    // the skins to choose from (GET /api/skins), once; the choice is set again once its option is there
    async loadSkins() {
      if (this.skins.length) return
      try {
        this.skins = (await get('/api/skins')).items
        const v = this.form.skin
        this.form.skin = ''
        this.$nextTick(() => { this.form.skin = v })
      } catch { /* the choice stays as it is: saving it is checked by the server */ }
    },
    get skinOptions() {
      const opts = this.brandPrimary ? [{ value: '', label: 'Default' }]
        : [{ value: '', label: 'Same as the primary organization' }, { value: 'default', label: 'Default' }]
      for (const k of this.skins) if (k.name !== 'default') opts.push({ value: k.name, label: k.display_name + (k.builtin ? '' : ' (custom)') })
      const cur = this.b.skin
      if (cur && cur !== 'default' && this.skins.length && !this.skins.some((k) => k.name === cur)) opts.push({ value: cur, label: cur + ' (removed)' })
      return opts
    },
    get skinHelp() {
      return this.brandPrimary ? "Changes how the primary organization's pages look. Organizations that haven't picked a skin use this one too."
        : "Changes how this organization's sign-in pages and console look."
    },
    get skinChanged() { return (this.form.skin || '') !== (this.b.skin || '') },
    // previewSkin shows the organization's pages in the skin chosen, saved or not (skinPreviewMixin)
    previewSkin(ev) {
      const v = this.form.skin || (this.brandPrimary ? 'default' : 'inherit')
      const o = this.skinOptions.find((x) => x.value === (this.form.skin || ''))
      this.showSkinPreview(ev.currentTarget, v, o ? o.label : v, this.brandOrgBase)
    },
    resetBranding(b, primary, orgBase) {
      this.brandPrimary = !!primary
      this.brandOrgBase = orgBase || ''
      this.loadSkins()
      this.b = b || {}
      this.pending = { logo_light: null, logo_dark: null }
      this.$refs.logo_light.value = ''
      this.$refs.logo_dark.value = ''
    },
    // What a logo's preview shows: the chosen image, else the saved one.
    logo(key, kind, src, emptyText) {
      const p = this.pending[key]
      return { src, has: src !== '', none: src === '', emptyText, locked: false, removeLabel: `Remove ${kind} logo`,
        note: p === null ? '' : p === '' ? 'It is removed when you save.' : 'Chosen: it is saved when you save.' }
    },
    get lightLogo() {
      const p = this.pending.logo_light
      return this.logo('logo_light', 'light', p === null ? this.b.logo_light || '' : p, 'None: the server’s logo is shown.')
    },
    // The dark logo needs a light one; without a dark one of its own the light one shows in the dark theme.
    get darkLogo() {
      const locked = !this.lightLogo.has
      const p = this.pending.logo_dark
      const src = locked ? '' : p === null ? this.b.logo_dark || '' : p
      return { ...this.logo('logo_dark', 'dark', src, locked ? 'Add a logo first.' : 'None: the light logo is shown in the dark theme.'), locked }
    },
    async pickLogo(ev) {
      const input = ev.target
      const key = input.dataset.logo
      const file = input.files[0]
      if (!file) return
      if (file.size > LOGO_MAX) {
        input.value = ''
        this.setErrors(new ApiError(422, { error: `That image is ${Math.ceil(file.size / 1024)} KB; the most is 256 KB.`, field: key }))
        return
      }
      try { this.pending[key] = await readDataUrl(file) } catch (e) { input.value = ''; this.setErrors(e); return }
      this.clearErrors()
    },
    // A saved logo is removed (on saving) only once confirmed; a logo chosen and not yet saved is just set aside.
    async removeLogo(ev) {
      const key = ev.currentTarget.dataset.logo
      if (this.b[key]) {
        const light = key === 'logo_light'
        const yes = await confirmAction(Alpine, { title: 'Remove the logo?', message: `Remove the ${light ? 'light' : 'dark'} theme’s logo?`,
          detail: (light ? 'The server’s logo and name are shown instead' + (this.b.logo_dark ? ', and the dark theme’s logo goes with it' : '')
            : 'The light theme’s logo is shown in the dark theme too') + '. It is removed when you save.',
          confirmLabel: 'Remove logo' })
        if (!yes) return
      }
      this.pending[key] = this.b[key] ? '' : null
      this.$refs[key].value = ''
      if (key === 'logo_light') { this.pending.logo_dark = null; this.$refs.logo_dark.value = '' } // the dark logo goes with it
      this.clearErrors()
      this.$refs[key].focus()
    },
    get colorChanged() { return (this.form.primary_color || '').trim() !== (this.b.primary_color || '') },
    get pickerValue() { return HEX_COLOR.test(this.form.primary_color) ? this.form.primary_color.toLowerCase() : '#000000' },
    get usesDefaultColor() { return !this.form.primary_color },
    pickColor(ev) { this.form.primary_color = ev.target.value },
    useDefaultColor() {
      this.form.primary_color = ''
      this.$refs.primary_color.focus()
    },
    get footerChanged() { return (this.form.footer || '').trim() !== (this.b.footer || '') },
    get brandingChanged() { return this.colorChanged || this.footerChanged || this.skinChanged || this.pending.logo_light !== null || this.pending.logo_dark !== null },
    // the changes, as PATCH <org>/branding and the branding of a new organization take them
    brandingBody() {
      const body = {}
      for (const key of ['logo_light', 'logo_dark']) if (this.pending[key] !== null) body[key] = this.pending[key]
      if (this.colorChanged) body.primary_color = this.form.primary_color.trim()
      if (this.footerChanged) body.footer = this.form.footer.trim()
      if (this.skinChanged) body.skin = this.form.skin || ''
      return body
    },
  })

  Alpine.data('adminOrgs', () => mix(tableMixin(), formMixin(), dialogMixin(), brandingMixin(), pickerMixin({
    // the groups of the organization being edited
    async search(q) {
      const r = await get(`/api/orgs/${enc(this.editing.name)}/groups${qs({ q, limit: 8 })}`)
      const items = r.items.filter((g) => !this.form.api_token_groups.includes(g.id)) // the chosen ones are already chips
      return { more: r.total > r.items.length, items: items.map((g) => ({ type: 'group', id: g.id, label: g.display_name, detail: '', kind: 'Group' })) }
    },
    chosen(p) {
      this.clearErrors()
      if (this.form.api_token_groups.includes(p.id)) return
      if (this.form.api_token_groups.length >= API_GROUP_LIMIT) { toast(`At most ${API_GROUP_LIMIT} groups.`, 'error'); return }
      this.groupNames = { ...this.groupNames, [p.id]: p.label }
      this.form.api_token_groups = [...this.form.api_token_groups, p.id]
      announce(`${p.label} added.`)
    },
    clearOnChoose: true,
    removeLast() {
      const id = this.form.api_token_groups.at(-1)
      if (id) this.dropGroup(id)
    },
  }), {
    editing: null, base: '', publicUrl: '', defaults: { ttl: 0, idle: 0 }, groupNames: {}, help: {},
    init() {
      this.base = this.$el.dataset.base
      this.publicUrl = this.$el.dataset.public
      this.defaults = { ttl: Math.round(Number(this.$el.dataset.ttl) / 3600), idle: Math.round(Number(this.$el.dataset.idle) / 60) }
      // the help of the organization's own policy fields: their range and the server's setting, used when left blank
      const d = this.$el.dataset
      const n = (k) => Number(d[k]) || 0
      const dflt = (v) => ` Leave empty to use the server's setting (${v}).`
      this.help = {
        password_min_length: '8 to 64.' + dflt(n('pwmin')),
        lockout_attempts: 'How many wrong passwords or codes in a row lock the account (1 to 100).' + dflt(n('lockout') || 'never locks'),
        lockout_minutes: 'How long the account stays locked (1 to 1440).' + dflt(n('lockmin') || 15),
        api_token_max_days: '1 to 3650. Tokens created without an expiry get this lifetime.' + dflt(n('tokendays') ? n('tokendays') + ' days' : 'no limit'),
        privileged_ttl: 'Hours before a session ends, even if it is in use.' + dflt(n('pttl') ? Math.round(n('pttl') / 3600) + 'h' : 'as everyone'),
        privileged_idle: 'Minutes of inactivity before a session ends.' + dflt(n('pidle') ? Math.round(n('pidle') / 60) + ' minutes' : 'as everyone'),
        grants_per_user: 'How many application sign-ins one person may keep (10 to 100000); past it the least recently used end. Raise it where many machines sign in as one person.' + dflt(n('grants')),
      }
      this.initTable()
    },
    transform(o) {
      return { ...o, usersText: o.users === undefined ? '—' : String(o.users), createdText: fmtDate(o.created),
        href: `${this.base}/${enc(o.name)}/users`, editLabel: 'Edit ' + o.display_name, deleteLabel: 'Delete ' + o.display_name,
        signInUrl: `${this.publicUrl}/o/${o.name}/login`, copySignInLabel: 'Copy sign-in link for ' + o.display_name,
        notPrimary: !o.primary }
    },
    get isEdit() { return this.editing !== null },
    get dialogTitle() { return this.editing ? 'Edit organization' : 'New organization' },
    get submitLabel() { return this.busy ? 'Saving…' : this.editing ? 'Save changes' : 'Create organization' },
    get ttlHelp() { return `Hours before a session ends, even if it is in use. Leave empty to use the server's setting (${this.defaults.ttl}h).` },
    get idleHelp() { return `Minutes of inactivity before a session ends. Leave empty to use the server's setting (${this.defaults.idle ? this.defaults.idle + ' minutes' : 'none'}).` },
    // The chosen groups need an organization that exists to choose from.
    get groupsUnavailable() { return !this.isEdit },
    get groupsOption() { return this.isEdit ? 'Members of chosen groups' : 'Members of chosen groups (once the organization exists)' },
    get groupsMode() { return this.form.api_tokens === 'groups' },
    get groupChips() {
      return (this.form.api_token_groups || []).map((id) => { const name = this.groupNames[id] || 'Deleted group'; return { id, name, removeLabel: 'Remove ' + name } })
    },
    dropGroup(id) {
      this.form.api_token_groups = this.form.api_token_groups.filter((g) => g !== id)
      announce(`${this.groupNames[id] || 'Deleted group'} removed.`)
    },
    removeGroup(ev) {
      this.dropGroup(ev.currentTarget.dataset.id)
      focusWhenShown('f-api_group')
    },
    // the names of the chosen groups, by id (a group deleted since shows as such)
    async loadGroupNames(o) {
      const ids = o.settings.api_token_groups || []
      const gs = await Promise.all(ids.map((id) => getOrNull(`/api/orgs/${enc(o.name)}/groups/${enc(id)}`)))
      if (this.editing === o) this.groupNames = Object.fromEntries(ids.map((id, i) => [id, gs[i] && gs[i].display_name]).filter(([, n]) => n))
    },
    // a new organization's branding is refused as branding.<field>
    errorKey(f) { return f === 'api_token_groups' ? 'api_group' : f.replace(/^branding\./, '') },
    get noMethod() { return !this.form.password_login && !this.form.passkey_login },
    get resetOff() { return !this.form.password_login },
    // Codes by email need the server to send email. Without it the switch can only be turned off (it was on when the
    // email set-up went away), and says why.
    get emailCodesOff() { return !mailOn() && !this.form.email_codes },
    get emailCodesNote() {
      if (mailOn()) return ''
      return this.form.email_codes ? 'Not in use: email is not set up on the server (mail.smtp_host).'
        : 'Unavailable: email is not set up on the server (mail.smtp_host).'
    },
    orgToForm(o) {
      const s = o.settings
      return { name: o.name, display_name: o.display_name, password_login: !!s.password_login, password_reset: !!s.password_reset,
        passkey_login: !!s.passkey_login, require_mfa: !!s.require_mfa, email_codes: !!s.email_codes, mcp_server: !!s.mcp_server,
        api_tokens: s.api_tokens || 'off', api_token_groups: [...(s.api_token_groups || [])],
        session_ttl: s.session_ttl ? String(Math.round(s.session_ttl / 3600)) : '', session_idle: s.session_idle ? String(Math.round(s.session_idle / 60)) : '',
        password_min_length: s.password_min_length ? String(s.password_min_length) : '', lockout_attempts: s.lockout_attempts ? String(s.lockout_attempts) : '',
        lockout_minutes: s.lockout_minutes ? String(s.lockout_minutes) : '', api_token_max_days: s.api_token_max_days > 0 ? String(s.api_token_max_days) : '',
        api_token_no_limit: s.api_token_max_days === -1,
        privileged_ttl: s.privileged_ttl ? String(Math.round(s.privileged_ttl / 3600)) : '', privileged_idle: s.privileged_idle ? String(Math.round(s.privileged_idle / 60)) : '',
        grants_per_user: s.grants_per_user ? String(s.grants_per_user) : '', pictures: s.pictures || 'everyone',
        primary_color: (o.branding && o.branding.primary_color) || '', footer: (o.branding && o.branding.footer) || '',
        skin: (o.branding && o.branding.skin) || '' }
    },
    openCreate(ev) {
      this.editing = null
      this.resetForm(this.orgToForm({ name: '', display_name: '', settings: { password_login: true, password_reset: true, passkey_login: true, require_mfa: false, email_codes: false, mcp_server: false } }))
      this.resetBranding({})
      this.groupNames = {}
      this.resetPicker()
      this.openDlg('org-dialog', ev.currentTarget)
    },
    edit(ev) {
      const o = this.rowFromEvent(ev)
      this.editing = o
      this.resetForm(this.orgToForm(o))
      this.resetBranding(o.branding, o.primary, '/o/' + o.name)
      this.groupNames = {}
      this.resetPicker()
      this.loadGroupNames(o)
      this.openDlg('org-dialog', ev.currentTarget)
      this.watchEdit({ kinds: ['org'], record: o, fetchOne: () => getOrNull(`/api/orgs/${enc(o.name)}`) })
    },
    async submit() {
      const f = this.form
      const num = (v, mult, field) => {
        if (String(v).trim() === '') return 0
        const n = Number(v)
        if (!Number.isFinite(n) || n < 0) throw Object.assign(new Error('Enter a whole number, or leave blank.'), { field, status: 422 })
        return Math.round(n * mult)
      }
      const edit = this.editing
      const res = await this.run(() => {
        const settings = { password_login: f.password_login, password_reset: f.password_reset, passkey_login: f.passkey_login, require_mfa: f.require_mfa, email_codes: f.email_codes,
          mcp_server: f.mcp_server, api_tokens: f.api_tokens, api_token_groups: f.api_tokens === 'groups' ? f.api_token_groups : [],
          session_ttl: num(f.session_ttl, 3600, 'session_ttl'), session_idle: num(f.session_idle, 60, 'session_idle'),
          password_min_length: num(f.password_min_length, 1, 'password_min_length'), lockout_attempts: num(f.lockout_attempts, 1, 'lockout_attempts'),
          lockout_minutes: num(f.lockout_minutes, 1, 'lockout_minutes'), api_token_max_days: f.api_token_no_limit ? -1 : num(f.api_token_max_days, 1, 'api_token_max_days'),
          privileged_ttl: num(f.privileged_ttl, 3600, 'privileged_ttl'), privileged_idle: num(f.privileged_idle, 60, 'privileged_idle'),
          grants_per_user: num(f.grants_per_user, 1, 'grants_per_user'), pictures: f.pictures }
        const body = { name: f.name.trim(), display_name: f.display_name.trim(), settings }
        if (!body.display_name) delete body.display_name
        // A new organization takes its branding with it; an existing one's is changed apart, by id (the settings may
        // have renamed it). The primary organization's sign-in settings need a recent re-authentication (the server asks).
        if (!edit) return post('/api/orgs', this.brandingChanged ? { ...body, branding: this.brandingBody() } : body)
        return withReauth(Alpine, async () => {
          const o = await patch(`/api/orgs/${enc(edit.name)}`, body)
          return this.brandingChanged ? patch(`/api/orgs/${enc(edit.id)}/branding`, this.brandingBody()) : o
        }, null, this)
      })
      if (!res) return
      this.closeDlg('org-dialog')
      toast(edit ? 'Organization saved.' : 'Organization created.')
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
        await withReauth(Alpine, () => del(`/api/orgs/${enc(o.name)}${qs({ cascade: o.users > 0 })}`), ev.target)
        toast(`Organization “${o.display_name}” deleted.`)
        this.load()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
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
      focusWhenShown('clear-tag-filter')
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
      return { ...u, title: u.name || u.username, avatar: avatarOf(u), sub: u.email || u.username, roleText: ROLE_LABEL[u.role] || u.role,
        roleClass: 'badge ' + (ROLE_BADGE[u.role] || 'badge-plain'), statusText: b.text, statusClass: b.cls,
        lastLoginText: relTime(u.last_login), href: `${this.pageUrl}/${enc(u.id)}`,
        createdText: fmtDate(u.created), noPassword: !u.has_password, ...tagView(u.tags, 'users'),
        // someone above the viewer: a directory entry, so whatever it does not carry is unknown, not "none"
        ...(u.directory ? { sub: '', noPassword: false, lastLoginText: '—' } : {}) }
    },
    // Each user is edited, deleted or locked out on their own page (the name links to it), where everything else
    // about them is too; the list only finds them, and creates new ones.
    afterUserSaved() { return this.load() },
  }))

  // ---- One user -------------------------------------------------------------------------------------------------
  Alpine.data('adminUser', () => mix(formMixin(), dialogMixin(), userDialogMixin(Alpine), pictureMixin(Alpine, {
    path: (vm) => `${vm.apiBase}/users/${enc(vm.userId)}/picture`,
    who: (vm) => ({ self: vm.isSelf, title: vm.user.title }),
    apply: (vm) => vm.refresh(),
  }), {
    reloadUser() { return this.refresh(true) },
    user: null, loading: true, loadError: '', userId: '', listUrl: '', gone: false, _sig: '', _lr: null, isSelf: false,
    init() {
      const d = this.$el.dataset
      this.apiBase = d.base
      this.userId = d.user
      this.isSelf = d.self !== undefined
      this.listUrl = d.list
      this._lr = liveRunner(() => this.refresh(true))
      subscribe(['user', 'group', 'member', 'passkey'], (ev) => { if (aboutUser(ev, this.userId)) this._lr.trigger() })
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
        this.setPictureUser(raw)
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
        emailVerifiedClass: 'badge ml-1 ' + (u.email_verified ? 'badge-success' : 'badge-warning'),
        groupsText: (u.groups || []).map((g) => g.display_name).join(', ') || 'None', externalText: u.external_id || '—', ...tagView(u.tags, 'users'),
        phoneText: u.phone_number || '—', phoneVerifiedText: u.phone_number ? (u.phone_number_verified ? 'Verified' : 'Not verified') : '',
        phoneVerifiedClass: 'badge ml-1 ' + (u.phone_number_verified ? 'badge-success' : 'badge-warning'),
        statusNote: statusNote(u), hasStatusNote: !!u.status_changed,
        directory: !!u.directory, full: !u.directory, hasUsername: !!u.username, avatar: avatarOf(u),
        ...profileDetails(u, this.listUrl),
        linkedView: (u.linked_emails || []).map((l) => ({ address: l.address, badgeText: l.verified ? 'Verified' : 'Not verified',
          badgeClass: 'badge ml-1 ' + (l.verified ? 'badge-success' : 'badge-warning') })),
        passwordDetail: u.password_changed_at ? (u.has_password ? 'Last changed ' : 'Removed ') + fmtDateTime(u.password_changed_at) : '',
        mfaText: u.mfa_enrolled_at ? 'Set up ' + fmtDateTime(u.mfa_enrolled_at) : 'Not set up' }
    },
    get showUser() { return this.user !== null },
    // the picture in the header: whoever may change this user may set or remove it, while the organization has pictures on
    // (a directory entry has none, and no control)
    get picEnabled() { return !!this.user && this.user.pictures_enabled !== false },
    get canChange() { return this.picEnabled && this.manageable },
    get picReadOnly() { return false },
    // Another user of a higher role is shown read-only (the server refuses any change to them anyway); your own page
    // keeps its self-service rules.
    get manageable() { return !!this.user && (this.isSelf || this.user.can_manage !== false) },
    get readOnly() { return !!this.user && !this.manageable },
    get readOnlyFull() { return this.readOnly && !this.user.directory },
    get readOnlyText() {
      return this.user && this.user.directory
        ? 'You can see who this is, but not their contact or sign-in details, and you cannot change them: their role is above yours.'
        : 'You can see this user but not change them.'
    },
    get resetNoteShown() { return this.manageable && this.resetBySuperOnly },
    get hasLoadError() { return this.loadError !== '' },
    get groups() { return this.user ? this.user.groups || [] : [] },
    get hasGroups() { return this.groups.length > 0 },
    edit(ev) { this.openEditUser(this.user, ev.currentTarget) },
    async afterUserSaved(res) { await this.refresh() },
    get passwordText() { return this.user.has_password ? 'Set' : 'Not set' },
    get passkeysText() { const n = this.user.passkeys; return n === undefined ? '—' : n === 0 ? 'None' : String(n) },
    get hasPassword() { return this.user.has_password },
    get canResetSignIn() { return this.user.can_reset_sign_in !== false },
    get resetBySuperOnly() { return this.user.can_reset_sign_in === false },
    get canRemovePassword() { return this.hasPassword && this.canResetSignIn },
    // someone else's: your own is removed on your account page, which keeps your last second factor where one is required
    get canRemoveTOTP() { return !!this.user.mfa_enrolled_at && this.canResetSignIn && !this.isSelf },
    newInvite(ev) { this.openInvite(this.user, null, ev.currentTarget) },
    async removeTOTP(ev) {
      const yes = await confirmAction(Alpine, { title: 'Remove authenticator app?', message: `Remove the authenticator app of ${this.user.title}?`,
        detail: 'For a lost or replaced phone. Their codes stop working now, and so do their recovery codes if it was their only second factor. They keep their password, and set up an authenticator app again on their account page, or when they next sign in if a second factor is required.',
        confirmLabel: 'Remove authenticator app' })
      if (!yes) return
      try {
        await withReauth(Alpine, () => del(`${this.apiBase}/users/${enc(this.userId)}/totp`), ev.currentTarget || ev.target)
        toast('Authenticator app removed.')
        await this.refresh()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
    async removePassword(ev) {
      const yes = await confirmAction(Alpine, { title: 'Remove password?', message: `Remove the password of ${this.user.title}?`,
        detail: 'They can no longer sign in with a password until they accept a new invitation. Their sessions end now.', confirmLabel: 'Remove password' })
      if (!yes) return
      try {
        await withReauth(Alpine, () => del(`${this.apiBase}/users/${enc(this.userId)}/password`), ev.currentTarget || ev.target)
        toast('Password removed. Sessions ended.')
        await this.refresh()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
    async revoke(ev) {
      const yes = await confirmAction(Alpine, { title: 'Sign out everywhere?', message: `End every session of ${this.user.title}?`,
        detail: 'They will have to sign in again on every device.', confirmLabel: 'Revoke sessions' })
      if (!yes) return
      try { await del(`${this.apiBase}/users/${enc(this.userId)}/sessions`); toast('Sessions revoked.') } catch (e) { toast(e.message, 'error') }
    },
    openLockOut(ev) {
      this.resetForm({ reason: '' })
      this.openDlg('lockout-dialog', ev.currentTarget)
    },
    get lockOutWhat() { return this.user ? `Lock ${this.user.title} (${this.user.username}) out?` : '' },
    get lockOutLabel() { return this.busy ? 'Locking out…' : 'Lock out' },
    async lockOut(ev) {
      this.clearErrors()
      this.busy = true
      try {
        await withReauth(Alpine, () => post(`${this.apiBase}/users/${enc(this.userId)}/lock-out`, { reason: this.form.reason }),
          ev.submitter || ev.currentTarget, this)
        this.closeDlg('lockout-dialog')
        toast(`${this.user.title} is locked out.`)
        await this.refresh()
      } catch (e) { if (e.name !== 'AbortError') this.setErrors(e) }
      this.busy = false
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
      // a manager adds plain users only
      const res = await get(`${this.apiBase}/users${qs({ q, limit: 10, active: 1, ...(this.admin ? {} : { role: 'user' }) })}`)
      const have = new Set(this.members.map((m) => m.id))
      const items = res.items.filter((u) => !have.has(u.id))
      return { more: res.total > res.items.length, items: items.map((u) => ({ type: 'user', id: u.id, label: u.name || u.username, detail: u.email, kind: 'User' })) }
    },
    chosen(p) { return this.addMember(p) },
    clearOnChoose: true,
  }), {
    editing: null, apiBase: '', admin: false, group: null, members: [], membersTotal: 0, membersLoading: false,
    _mt: null, membersGone: false,
    init() {
      this.apiBase = this.$el.dataset.base
      this.admin = 'admin' in this.$el.dataset
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
        const items = res.items.map((m) => ({ ...m, removeLabel: 'Remove ' + (m.name || m.username) + ' from group', title: m.name || m.username, avatar: avatarOf(m),
          canRemove: this.admin || m.role === 'user' }))
        const sigOf = (list) => list.map((m) => m.id + (m.picture || '')).join()
        const changed = !quiet || sigOf(items) !== sigOf(this.members)
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
  Alpine.data('adminTenants', () => mix(tableMixin(), formMixin(), dialogMixin(), listFieldMixin(), tenantDialogMixin(Alpine), {
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
        href: `${this.pageBase}/${enc(t.name)}`, clientsHref: `${this.pageBase}/${enc(t.name)}/clients`, clientsLabel: 'Clients of ' + t.display_name + ': ' + clientsText(t.clients),
        ...sshState(t), sshHref: `${this.pageBase}/${enc(t.name)}/ssh`, sshLabel: 'SSH certificates of ' + t.display_name + ': ' + sshState(t).sshText }
    },
    openCreate(ev) { this.openCreateTenant(ev.currentTarget) },
    edit(ev) { this.openEditTenant(this.rowFromEvent(ev), ev.currentTarget) },
    afterTenantSaved() { return this.load() },
    async remove(ev) {
      const t = this.rowFromEvent(ev)
      const yes = await confirmAction(Alpine, { title: 'Delete tenant?', message: `Delete the tenant “${t.display_name}”?`,
        detail: 'A tenant that still has clients, or has SSH certificates on, cannot be deleted. This cannot be undone.', confirmLabel: 'Delete tenant' })
      if (!yes) return
      try { await del(`${this.apiBase}/tenants/${enc(t.id)}`); toast(`Tenant “${t.display_name}” deleted.`); this.load() } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- One tenant: its sign-in rules and its clients ---------------------------------------------------------------
  // The self-registered apps card of the tenant page: the apps users of this tenant authorized, each revocable.
  Alpine.data('tenantSelfReg', () => ({
    items: [], loading: true, loadError: '', url: '',
    init() {
      this.url = this.$el.dataset.api // read once: in a click handler $el is the button
      const live = liveRunner(() => this.load())
      subscribe(['client', 'grant', 'tenant'], () => live.trigger())
      return this.load()
    },
    async load() {
      try {
        const r = await get(this.url)
        this.items = r.items.map((a) => ({ ...a, kindText: a.metadata_document ? 'Metadata document' : 'Registered itself',
          hostText: [...new Set((a.redirect_uris || []).map((u) => { try { return new URL(u).host } catch { return u } }))].join(', '),
          usersText: a.users === 1 ? '1 user' : a.users + ' users', lastText: relTime(a.last_used, 'Never'), revokeLabel: 'Revoke ' + a.name }))
        this.loadError = ''
      } catch (e) { this.loadError = e.message } finally { this.loading = false }
    },
    get hasItems() { return this.items.length > 0 },
    get isEmpty() { return !this.loading && this.items.length === 0 && this.loadError === '' },
    get hasLoadError() { return this.loadError !== '' },
    async revoke(ev) {
      const opener = ev.currentTarget
      const a = this.items.find((i) => i.client_id === opener.dataset.id)
      if (!a) return
      const yes = await confirmAction(Alpine, { title: 'Revoke app?', message: `Revoke ${a.name} for everyone in this organization?`,
        detail: 'Every user\u2019s access to it ends now. It can come back only by asking each user again.', confirmLabel: 'Revoke', danger: true })
      if (!yes) return
      try {
        await del(this.url + '/' + enc(a.client_id))
        toast(`${a.name} revoked.`)
        await this.load()
      } catch (e) { toast(e.message, 'error') }
    },
  }))

  // The tenant page: its sign-in rules, access and self-registered apps, with the numbers that lead to its clients and SSH
  // certificates pages.
  Alpine.data('adminTenant', () => mix(formMixin(), dialogMixin(), listFieldMixin(), tenantDialogMixin(Alpine), tenantPageMixin(), {
    async init() {
      this.canFirstParty = this.$el.dataset.canFirstParty === '1'
      await this.initTenantPage(['tenant', 'client', 'provider', 'org'])
    },
    // The summary needs the organization's methods and the providers' names.
    async tenantExtra() {
      const [org, provs] = await Promise.all([get(this.apiBase), get(`${this.apiBase}/providers${qs({ sort: 'name', limit: 100 })}`)])
      return { sig: [org.settings, provs.items.map((p) => [p.id, p.name, p.enabled, p.updated])], use: () => {
        Alpine.store('tenantPage').tenant = this.tenant // read by the Access card (pages/access.js)
        this.orgPassword = org.settings.password_login
        this.orgReset = org.settings.password_login && !!org.settings.password_reset
        this.orgPasskey = org.settings.passkey_login
        this.providers = provs.items.map(shapeProvider)
      } }
    },
    get clientCountText() { return this.tenant ? clientsText(this.tenant.clients) : '' },
    get sshOn() { return !!(this.tenant && this.tenant.ssh && this.tenant.ssh.enabled) },
    get sshText() { return this.sshOn ? 'On' : 'Off' },
    get sshClass() { return this.sshOn ? 'badge badge-success' : 'badge badge-plain' },
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
        row('Password reset', s.password_login && s.password_reset, this.orgReset, 'password resets'),
        row('Passkeys', s.passkey_login, this.orgPasskey, 'passkeys'),
        { label: 'Sign-in providers', text: prov.text, cls: 'cell-title', note: prov.note },
        this.orgMFA ? { label: 'Second factor', text: 'Required', cls: 'badge badge-info', note: 'The organization requires one for every sign-in.' }
          : { label: 'Second factor', text: s.require_mfa ? 'Required' : 'Not required', cls: s.require_mfa ? 'badge badge-info' : 'badge badge-plain',
            note: s.require_mfa ? 'Every sign-in to this tenant\u2019s applications needs one, unless the provider used counts as one.' : '' },
        { label: 'Self-registered apps', text: s.self_registration ? 'Allowed' : 'Not allowed', cls: s.self_registration ? 'badge badge-warning' : 'badge badge-plain',
          note: (this.tenant.resources || []).length ? 'For ' + this.tenant.resources.join(', ') : s.self_registration ? 'No resources listed yet: none can sign in.' : '' },
        { label: 'SSH certificates', text: this.sshText, cls: this.sshOn ? 'badge badge-success' : 'badge badge-plain',
          note: this.sshOn ? 'Manage them on the ' : 'Turn them on from the ', link: { text: 'SSH certificates page', href: this.sshHref } },
      ]
    },
    // tenant dialog
    editTenant(ev) { this.openEditTenant(this.tenant, ev.currentTarget) },
    async afterTenantSaved(res) {
      if (res.name !== this.tenant.name) { window.location.replace(`${this.pageBase}/${enc(res.name)}`); return }
      await this.refreshTenant(false)
    },
  }))

  // The tenant's clients page: the applications that sign users in through it, with their dialogs.
  Alpine.data('adminTenantClients', () => mix(tableMixin(), formMixin(), dialogMixin(), clientDialogMixin(Alpine), tenantPageMixin(), {
    pathSuffix: '/clients', _form: 'client',
    async init() {
      const d = this.$el.dataset
      this.canFirstParty = d.canFirstParty === '1'
      this.issuer = d.issuer
      this.scope = { tenant: d.tenant }
      this.initTable()
      await this.initTenantPage(['tenant', 'client'])
    },
    errorKey(f) { return f === 'scopes' ? 'custom_scopes' : f }, // shown on the scopes chip field
    // all the tenants, for the move select of the client dialog
    async tenantExtra() {
      const tenants = await get(`${this.apiBase}/tenants${qs({ sort: 'name', limit: 100 })}`)
      return { sig: tenants.items.map((x) => [x.id, x.display_name]), use: () => { this.tenants = tenants.items } }
    },
    get clientCountText() { return this.tenant ? clientsText(this.tenant.clients) : '' },
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

  // The tenant's SSH page: the SSH certificates card (pages/ssh.js) under the tenant's title.
  Alpine.data('adminTenantSSH', () => mix(tenantPageMixin(), {
    pathSuffix: '/ssh',
    init() { return this.initTenantPage(['tenant']) },
  }))

  // ---- Providers --------------------------------------------------------------------------------------------------
  Alpine.data('adminProviders', () => mix(tableMixin(), formMixin(), dialogMixin(), listFieldMixin(), tagsMixin(), pickerMixin({
    // groups of the organization whose users sign in through an organization provider
    async search(q) {
      if (!this.form.source_org) return { items: [] }
      const r = await get(`/api/orgs/${enc(this.form.source_org)}/groups${qs({ q, limit: 8 })}`)
      const items = r.items.filter((g) => !this.form.source_groups.includes(g.id)) // the chosen ones are already chips
      return { more: r.total > r.items.length, items: items.map((g) => ({ type: 'group', id: g.id, label: g.display_name, detail: '', kind: 'Group' })) }
    },
    chosen(p) {
      this.clearErrors()
      if (this.form.source_groups.includes(p.id)) return
      if (this.form.source_groups.length >= SOURCE_GROUP_LIMIT) { toast(`At most ${SOURCE_GROUP_LIMIT} groups.`, 'error'); return }
      this.groupNames = { ...this.groupNames, [p.id]: p.label }
      this.form.source_groups = [...this.form.source_groups, p.id]
      announce(`${p.label} added.`)
    },
    clearOnChoose: true,
    removeLast() {
      const id = this.form.source_groups.at(-1)
      if (id) this.dropGroup(id)
    },
  }), {
    editing: null, apiBase: '', publicUrl: '', orgId: '', newId: '', isSuper: false, orgs: [], orgsLoaded: false, groupNames: {},
    init() {
      this.apiBase = this.$el.dataset.base; this.publicUrl = this.$el.dataset.public; this.orgId = this.$el.dataset.orgId
      this.isSuper = !!this.$el.dataset.super
      this.initTable()
    },
    // The organizations a provider may take its users from: the others, by display name (only super admins set one up).
    async loadOrgs() {
      if (!this.isSuper || this.orgsLoaded) return
      try {
        const r = await get(`/api/orgs${qs({ sort: 'name', limit: 100 })}`)
        this.orgs = r.items.filter((o) => o.id !== this.orgId).map((o) => ({ id: o.id, label: o.display_name || o.name }))
        this.orgsLoaded = true
      } catch (e) { toast(e.message, 'error') }
    },
    transform(p) {
      const b = activeBadge(p.enabled, 'Enabled', 'Disabled')
      return { ...p, copyCallbackLabel: 'Copy callback URL of ' + p.name, createdText: fmtDate(p.created), statusText: b.text, statusClass: b.cls, typeText: providerTypeText(p.type),
        editLabel: 'Edit ' + p.name, deleteLabel: 'Delete ' + p.name, sub: providerSub(p),
        hasCallback: p.type !== 'organization', readOnly: p.type === 'organization' && !this.isSuper, // an organization provider writes into another organization: super admins only
        domainsText: (p.allowed_domains || []).join(', ') || 'Any', provisionText: (p.auto_provision ? 'Creates accounts' : 'Existing users only') +
          (p.source_groups && p.source_groups.length ? `; ${p.source_groups.length === 1 ? '1 group' : p.source_groups.length + ' groups'} only` : '') +
          (p.trust_mfa ? '; counts as a second factor' : '') }
    },
    get groupChips() {
      return (this.form.source_groups || []).map((id) => { const name = this.groupNames[id] || 'Deleted group'; return { id, name, removeLabel: 'Remove ' + name } })
    },
    dropGroup(id) {
      this.form.source_groups = this.form.source_groups.filter((g) => g !== id)
      announce(`${this.groupNames[id] || 'Deleted group'} removed.`)
    },
    removeGroup(ev) {
      this.dropGroup(ev.currentTarget.dataset.id)
      focusWhenShown('f-source_group')
    },
    // the names of the chosen groups, by id (a group deleted since shows as such)
    async loadGroupNames(p) {
      const ids = p.source_groups || []
      const gs = await Promise.all(ids.map((id) => getOrNull(`/api/orgs/${enc(p.source_org)}/groups/${enc(id)}`)))
      if (this.editing === p) this.groupNames = Object.fromEntries(ids.map((id, i) => [id, gs[i] && gs[i].display_name]).filter(([, n]) => n))
    },
    // another organization's groups never carry over: choosing a different one starts the list again
    sourceOrgChanged() {
      if (this.form.source_groups.length) announce('Groups cleared: choose groups of the new organization.')
      this.form.source_groups = []
      this.resetPicker()
    },
    get groupsHelp() {
      return this.form.source_org ? 'Optional. Only members of these groups can sign in this way, checked at every sign-in. Leave empty to allow everyone in the organization.'
        : 'Choose the organization first.'
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
    get isOrg() { return this.form.type === 'organization' },
    get multiTenant() { return this.isMicrosoft && (this.form.tenant || '').trim().toLowerCase() === 'organizations' },
    get namePlaceholder() { return this.isOrg ? (this.orgs.find((o) => o.id === this.form.source_org) || {}).label || this.ptype.name : this.ptype.name },
    get nameHelp() {
      return this.isOrg ? 'Shown on the sign-in page after \u201cContinue with\u201d. Leave empty for the organization\u2019s own name.'
        : `Shown on the sign-in page. Leave empty for \u201c${this.ptype.name}\u201d.`
    },
    get callbackHelp() {
      return { github: 'Register this as the Authorization callback URL of your GitHub OAuth app.',
        microsoft: 'Register this as a Web redirect URI of your app registration in Microsoft Entra ID.',
        google: 'Register this as an authorised redirect URI of your OAuth client in Google Cloud.',
        gitlab: 'Register this as the redirect URI of your GitLab application.',
        auth0: 'Register this as an allowed callback URL of your Auth0 application.' }[this.form.type] ||
        'Register this as a redirect URI of your client at the provider. Each provider has its own.'
    },
    // a new provider: the type's own scopes and email linking until they are edited
    typeChanged() {
      if (this.editing) return
      const gh = ['read:user', 'user:email']
      const oidc = ['openid', 'profile', 'email']
      const now = (this.form.scopes || []).join(' ')
      if (now === gh.join(' ') || now === oidc.join(' ')) this.form.scopes = this.form.type === 'github' ? gh : oidc
      // The source organization's managers can mark any address verified, so guests are not linked by email unless asked.
      this.form.link_by_email = !this.isOrg
    },
    // Each provider has its own callback address. A new one gets its id now, so the address can be registered with the
    // provider before its client ID and secret are known.
    get callbackUrl() { return this.editing ? this.editing.callback_url : `${this.publicUrl}/o/${this.orgId}/login/callback/${this.newId}` },
    get secretHelp() { return this.editing ? 'Leave blank to keep the current secret. It is never shown.' : 'Stored encrypted. It is never shown again.' },
    get secretRequired() { return !this.editing },
    get dialogTitle() { return this.editing ? 'Edit provider' : 'New sign-in provider' },
    get submitLabel() { return this.busy ? 'Saving…' : this.editing ? 'Save changes' : 'Create provider' },
    toForm(p) {
      return { type: p.type, name: p.name, issuer: p.issuer || '', source_org: p.source_org || '', source_groups: [...(p.source_groups || [])], client_id: p.client_id || '', client_secret: '', scopes: [...(p.scopes || [])],
        allowed_domains: [...(p.allowed_domains || [])], tenant: p.tenant || '', allowed_tenants: listRows(p.allowed_tenants, 'Tenant ID', true), auto_provision: !!p.auto_provision, trust_mfa: !!p.trust_mfa, link_by_email: p.link_by_email !== false, enabled: p.enabled !== false }
    },
    async openCreate(ev) {
      const opener = ev.currentTarget
      await this.loadOrgs()
      this.editing = null
      this.newId = newId()
      this.resetForm(this.toForm({ type: 'oidc', name: '', scopes: ['openid', 'profile', 'email'], enabled: true }))
      this.resetChipText()
      this.groupNames = {}
      this.resetPicker()
      this.openDlg('provider-dialog', opener)
    },
    async edit(ev) {
      const p = this.rowFromEvent(ev)
      const opener = ev.currentTarget
      await this.loadOrgs()
      this.editing = p
      this.resetForm(this.toForm(p))
      this.resetChipText()
      this.groupNames = {}
      this.resetPicker()
      if (p.type === 'organization') this.loadGroupNames(p)
      this.openDlg('provider-dialog', opener)
      this.watchEdit({ kinds: ['provider'], record: p, fetchOne: () => getOrNull(`${this.apiBase}/providers/${enc(p.id)}`) })
    },
    // a server message about one tenant goes on its row (it starts with the tenant ID)
    listError(err) { return err.field === 'allowed_tenants' && this.setListError(err.field, err.message) },
    errorKey(f) { return f === 'source_groups' ? 'source_group' : f },
    async submit() {
      if (!this.tagsReady()) { this.focusTagInput(); return }
      const f = this.form
      const body = { type: f.type, name: f.name, allowed_domains: f.allowed_domains,
        auto_provision: f.auto_provision, trust_mfa: f.trust_mfa, link_by_email: f.link_by_email, enabled: f.enabled }
      if (f.type === 'organization') { body.source_org = f.source_org; body.source_groups = f.source_groups } // its client is made with it: no client ID, secret or scopes
      else { body.client_id = f.client_id; body.scopes = f.scopes }
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

  // ---- Service accounts: an organization's non-human principals (client_credentials) ---------------------------------
  // The scopes a service account may hold. Only super admins give import and the orgs:* scopes (the latter on the primary
  // organization alone); the server refuses the rest, so they are not offered.
  const SERVICE_SCOPES = [
    { value: 'users', help: 'Users and managers.' },
    { value: 'manage_admins', help: 'With users: administrators too.' },
    { value: 'groups', help: 'Groups and their members.' },
    { value: 'providers', help: 'Sign-in providers.' },
    { value: 'tenants', help: 'Tenants.' },
    { value: 'clients', help: 'Applications.' },
    { value: 'access', help: 'Tenant access lists.' },
    { value: 'ssh', help: 'Tenants’ SSH certificate authorities: settings, keys and certificates.' },
    { value: 'ssh:host', help: 'Sign SSH host certificates.' },
    { value: 'import', help: 'Password hashes, authenticator secrets and provider links when creating users.', superOnly: true },
    { value: 'scim', help: 'The SCIM API.' },
    { value: 'service_accounts', help: 'This organization’s service accounts, granting no more than it holds.' },
    { value: 'orgs:create', help: 'Create organizations.', superOnly: true, primaryOnly: true },
    { value: 'orgs:delete', help: 'Delete the organizations it created.', superOnly: true, primaryOnly: true },
  ]
  const SERVICE_METHODS = { client_secret_post: 'Secret (POST)', client_secret_basic: 'Secret (Basic)', private_key_jwt: 'Private key JWT' }
  Alpine.data('adminServiceAccounts', () => mix(tableMixin(), formMixin(), dialogMixin(), {
    editing: null, scopeChoices: [], clientId: '', tokenEndpoint: '', secret: '', secretAccount: '', secretTitle: '',
    init() {
      const d = this.$el.dataset
      this.scopeChoices = SERVICE_SCOPES.filter((s) => (!s.superOnly || !!d.super) && (!s.primaryOnly || !!d.primary)).map((s) => ({ ...s, id: 'f-scope-' + s.value }))
      this.initTable()
    },
    transform(a) {
      const b = activeBadge(a.enabled, 'Enabled', 'Disabled')
      const locked = a.scopes.some((sc) => !this.scopeChoices.some((c) => c.value === sc)) // holds a scope this viewer may not give
      return { ...a, statusText: b.text, statusClass: b.cls, copyLabel: 'Copy client ID of ' + a.name, editLabel: 'Edit ' + a.name,
        rotateLabel: 'Rotate secret of ' + a.name, deleteLabel: 'Delete ' + a.name, sub: a.description || '',
        methodText: SERVICE_METHODS[a.token_endpoint_auth_method] || a.token_endpoint_auth_method,
        canChange: !locked, canRotate: !locked && a.token_endpoint_auth_method !== 'private_key_jwt' }
    },
    get isEdit() { return this.editing !== null },
    get isJwt() { return this.form.token_endpoint_auth_method === 'private_key_jwt' },
    get dialogTitle() { return this.editing ? 'Edit service account' : 'New service account' },
    get submitLabel() { return this.busy ? 'Saving…' : this.editing ? 'Save changes' : 'Create service account' },
    get methodHelp() {
      return { client_secret_post: 'Quisora issues a secret, sent in the request body of the token request.', client_secret_basic: 'Quisora issues a secret, sent in an HTTP Basic header.',
        private_key_jwt: 'No secret: the service account signs a JWT with its private key, and you register the public keys.' }[this.form.token_endpoint_auth_method] || ''
    },
    toForm(a) {
      return { name: a.name, description: a.description || '', scopes: [...(a.scopes || [])], token_endpoint_auth_method: a.token_endpoint_auth_method,
        jwks: a.jwks || '', jwks_uri: a.jwks_uri || '', enabled: a.enabled !== false }
    },
    openCreate(ev) {
      this.editing = null
      this.resetForm(this.toForm({ name: '', scopes: [], token_endpoint_auth_method: 'client_secret_post' }))
      this.openDlg('sa-dialog', ev.currentTarget)
    },
    edit(ev) {
      const a = this.rowFromEvent(ev)
      this.editing = a
      this.resetForm(this.toForm(a))
      this.openDlg('sa-dialog', ev.currentTarget)
      this.watchEdit({ kinds: ['client'], record: a, fetchOne: () => getOrNull(`${this.apiUrl}/${enc(a.id)}`) })
    },
    body() {
      const f = this.form
      const b = { name: f.name, description: f.description, scopes: this.scopeChoices.map((c) => c.value).filter((v) => f.scopes.includes(v)),
        token_endpoint_auth_method: f.token_endpoint_auth_method }
      if (this.isJwt) { b.jwks = f.jwks; b.jwks_uri = f.jwks_uri }
      if (this.editing) b.enabled = f.enabled
      return b
    },
    async submit() {
      const edit = this.editing
      const body = this.body()
      // Creating or changing a service account needs a recent re-authentication (the server asks; the dialog provides it).
      const res = await this.run(() => withReauth(Alpine, () => edit ? patch(`${this.apiUrl}/${enc(edit.id)}`, body) : post(this.apiUrl, body),
        document.activeElement, this))
      if (!res) return
      this.closeDlg('sa-dialog')
      if (edit) toast('Service account saved.')
      else this.showSecret(res, 'Service account created')
      this.load()
    },
    // What the service account is configured with: its client ID and token endpoint, and the secret (shown once) of one
    // that authenticates with a secret (a.secret).
    showSecret(a, title) {
      this.clientId = a.id
      this.tokenEndpoint = a.token_endpoint
      this.secret = a.secret || ''
      this.secretAccount = a.name
      this.secretTitle = title
      this.$nextTick(() => this.openDlg('sa-secret-dialog'))
    },
    get hasSecret() { return this.secret !== '' },
    get secretDone() { return this.hasSecret ? 'I have stored it' : 'Done' },
    async rotate(ev) {
      const a = this.rowFromEvent(ev)
      const yes = await confirmAction(Alpine, { title: 'Rotate secret?', message: `Issue a new secret for “${a.name}”?`,
        detail: 'The current secret stops working immediately. Update everything that uses it.', confirmLabel: 'Rotate secret', danger: true })
      if (!yes) return
      try {
        const res = await withReauth(Alpine, () => post(`${this.apiUrl}/${enc(a.id)}/secret`), ev.currentTarget || ev.target)
        this.showSecret({ ...a, secret: res.secret }, 'New secret')
      } catch (e) { toast(e.message, 'error') }
    },
    async remove(ev) {
      const a = this.rowFromEvent(ev)
      const yes = await confirmAction(Alpine, { title: 'Delete service account?', message: `Delete the service account “${a.name}”?`,
        detail: 'Its tokens stop working immediately. This cannot be undone.', confirmLabel: 'Delete service account' })
      if (!yes) return
      try { await del(`${this.apiUrl}/${enc(a.id)}`); toast(`Service account “${a.name}” deleted.`); this.load() } catch (e) { toast(e.message, 'error') }
    },
  }))

  // ---- Audit ----------------------------------------------------------------------------------------------------
  // Kinds of action (the first part of the name: the action_group filter) and the known actions, for the filters.
  const AUDIT_GROUPS = [
    { value: 'login.', label: 'Sign-in' }, { value: 'password.', label: 'Password resets' }, { value: 'invite.', label: 'Invitations' },
    { value: 'account.', label: 'Own account changes' }, { value: 'user.', label: 'Users' }, { value: 'group.', label: 'Groups' },
    { value: 'org.', label: 'Organizations' }, { value: 'tenant.', label: 'Tenants and access' }, { value: 'client.', label: 'Applications' },
    { value: 'service_account.', label: 'Service accounts' }, { value: 'ssh.', label: 'SSH certificates' },
    { value: 'oauth.', label: 'Application sign-ins and tokens' }, { value: 'provider.', label: 'Sign-in providers' }, { value: 'identity.', label: 'Linked sign-ins' },
    { value: 'passkey.', label: 'Passkeys' }, { value: 'apitoken.', label: 'API tokens' }, { value: 'keys.', label: 'Signing keys' },
    { value: 'signout.', label: 'Sign-out sweeps' }, { value: 'backup.', label: 'Backups' }, { value: 'cluster.', label: 'Cluster' },
    { value: 'unique.', label: 'Duplicate values' }, { value: 'server.', label: 'Whole server' },
  ]
  const AUDIT_ACTIONS = ['account.app.revoke', 'account.email.verify', 'account.passkey.add', 'account.passkey.delete',
    'account.provider.connect', 'account.provider.connect_refused', 'account.provider.disconnect',
    'account.recovery_codes.create', 'account.session.revoke', 'account.session.revoke_others', 'account.totp.disable',
    'account.totp.enable', 'account.totp.replace', 'apitoken.create', 'apitoken.delete', 'apitoken.regenerate',
    'apitoken.update', 'backup.download', 'backup.restore', 'client.create', 'client.delete', 'client.secret.rotate',
    'client.self_register', 'client.self_registered.revoke', 'client.update', 'cluster.force_start', 'cluster.reload',
    'cluster.reload.failure', 'group.create', 'group.delete', 'group.member.add', 'group.member.remove', 'group.update',
    'identity.link.email', 'identity.link.refused', 'identity.refresh.refused', 'identity.unlink', 'invite.accept',
    'keys.create', 'keys.remove', 'keys.rotate', 'login.email_code.sent', 'login.failure', 'login.limited', 'login.lockout',
    'login.recovery_code', 'login.success', 'logout', 'mfa.import', 'oauth.client_auth.limited', 'oauth.client_credentials',
    'oauth.code.replay', 'oauth.consent', 'oauth.device.approve', 'oauth.device.start', 'oauth.grant', 'oauth.grant.evict',
    'oauth.refresh', 'oauth.refresh.reuse', 'oauth.revoke', 'oauth.token_exchange', 'org.create', 'org.delete', 'org.primary',
    'org.signout',
    'org.update', 'passkey.clone', 'password.forgot', 'password.reset', 'provider.create', 'provider.delete',
    'provider.update', 'server.signout', 'service_account.create', 'service_account.delete',
    'service_account.secret.rotate', 'service_account.update', 'signout.sweep', 'ssh.ca.create', 'ssh.ca.remove',
    'ssh.ca.rotate', 'ssh.cert.issue', 'ssh.cert.refused', 'ssh.cert.revoke', 'ssh.host.issue', 'ssh.host.refused',
    'ssh.settings.update', 'tenant.access.add', 'tenant.access.remove',
    'tenant.access.update', 'tenant.create', 'tenant.delete', 'tenant.update', 'user.app.revoke',
    'user.create', 'user.delete', 'user.email.add', 'user.email.primary', 'user.email.remove', 'user.email.verify',
    'user.expire', 'user.invite', 'user.invite.break_glass', 'user.locked_out', 'user.passkey.remove',
    'user.password.remove', 'user.provider.disconnect', 'user.provision', 'user.session.revoke', 'user.sessions.revoke',
    'user.signin.reset', 'user.update']
  // The action field offers each kind of action ("login.*": every action whose name starts with "login.") and each
  // known action; any other action can be typed.
  const auditActionSource = { free: true, options: () => Promise.resolve([
    ...AUDIT_GROUPS.map((g) => ({ value: `${g.value}*`, label: `${g.value}*`, detail: `${g.label}: every ${g.value.slice(0, -1)} action` })),
    ...AUDIT_ACTIONS.map((a) => ({ value: a, label: a })),
  ]) }
  const orgSource = { search: (q) => get(`/api/orgs${qs({ q, sort: 'name', limit: 20 })}`)
    .then((r) => r.items.map((o) => ({ value: o.name, label: o.display_name || o.name, detail: o.name }))) }
  // rangeForm fills the range dialog from a range (local "YYYY-MM-DDTHH:MM:SS" ends, "" when open): a start's time
  // defaults to the beginning of its day, an end's to the last second of its day.
  const rangeForm = (from, to) => ({
    range_from: from ? from.slice(0, 10) : '', range_from_time: from ? from.slice(11, 19) || '00:00:00' : '00:00:00',
    range_to: to ? to.slice(0, 10) : '', range_to_time: to ? to.slice(11, 19) || '23:59:59' : '23:59:59',
  })
  const fmtShort = (v) => new Date(v).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })

  Alpine.data('adminAudit', () => mix(tableMixin(), formMixin(), dialogMixin(), comboMixin({ action: auditActionSource, org: orgSource }), {
    sourceNote: '', range: '', rangePrev: '', rangeFrom: '', rangeTo: '', outcome: '', filtersOpen: false,
    init() {
      this.resetForm({ action: '', org: '', ...rangeForm('', '') })
      return this.initTable()
    },
    get customRange() { return this.range === 'custom' },
    get customLabel() {
      if (!this.rangeFrom && !this.rangeTo) return 'Custom range…'
      return `${this.rangeFrom ? fmtShort(this.rangeFrom) : 'Any time'} – ${this.rangeTo ? fmtShort(this.rangeTo) : 'now'}`
    },
    get rangeApplyLabel() { return 'Apply' },
    // ---- the Filters panel (action, outcome, organization) ----
    get filtersExpanded() { return this.filtersOpen ? 'true' : 'false' },
    toggleFilters() {
      this.filtersOpen = !this.filtersOpen
      if (this.filtersOpen) focusWhenShown('f-action')
    },
    closeFilters() { this.filtersOpen = false },
    escFilters() {
      if (!this.filtersOpen) return
      this.filtersOpen = false
      this.$refs.filtersButton.focus()
    },
    get panelFilterCount() { return [this.form.action, this.outcome, this.form.org].filter((v) => v).length },
    get hasPanelFilters() { return this.panelFilterCount > 0 },
    get panelFilterNote() { return this.hasPanelFilters ? `, ${this.panelFilterCount} set` : '' },
    // ---- active filters, as chips ----
    get chips() {
      const out = []
      if (this.range) {
        const t = this.customRange ? this.customLabel : { '15m': 'Last 15 minutes', '30m': 'Last 30 minutes', '1h': 'Last hour', '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days' }[this.range]
        out.push({ key: 'range', text: t, removeLabel: `Remove filter: ${t}` })
      }
      if (this.form.action) out.push({ key: 'action', text: `Action: ${this.form.action}`, removeLabel: `Remove filter: action ${this.form.action}` })
      if (this.outcome) {
        const t = this.outcome === 'failure' ? 'Failed or refused' : 'Succeeded'
        out.push({ key: 'outcome', text: t, removeLabel: `Remove filter: ${t}` })
      }
      if (this.form.org) {
        const t = this.combo.org.label || this.form.org
        out.push({ key: 'org', text: `Organization: ${t}`, removeLabel: `Remove filter: organization ${t}` })
      }
      return out
    },
    async removeFilter(ev) {
      const key = ev.currentTarget.dataset.key
      if (key === 'range') { this.range = this.rangePrev = this.rangeFrom = this.rangeTo = '' }
      if (key === 'outcome') this.outcome = ''
      if (key === 'action' || key === 'org') await this.comboSet(key, '', '')
      this.applyFilters()
      this.$refs.filtersButton.focus() // the chip is gone
    },
    get hasFilters() { return !!(this.range || this.form.action || this.outcome || this.form.org) },
    // an autocomplete filter changed (chosen, typed and confirmed, or cleared)
    comboChanged() { this.applyFilters() },
    rangeChanged(ev) {
      if (this.range === 'custom') { this.openRange(ev); return }
      this.rangePrev = this.range
      this.rangeFrom = this.rangeTo = ''
      this.applyFilters()
    },
    openRange(ev) {
      this.resetForm({ ...this.form, ...rangeForm(this.rangeFrom, this.rangeTo) })
      this.openDlg('range-dialog', ev.currentTarget)
    },
    applyRange() {
      const f = this.form
      const from = f.range_from ? `${f.range_from}T${f.range_from_time || '00:00:00'}` : ''
      const to = f.range_to ? `${f.range_to}T${f.range_to_time || '23:59:59'}` : ''
      if (!from && !to) {
        this.setErrors(new ApiError(422, { error: 'Enter a start date, an end date, or both.', field: 'range_from' }))
        return
      }
      if (from && to && new Date(from) > new Date(to)) {
        this.setErrors(new ApiError(422, { error: 'The end must not be before the start.', field: 'range_to' }))
        return
      }
      this.rangeFrom = from
      this.rangeTo = to
      this.range = this.rangePrev = 'custom'
      this.closeDlg('range-dialog')
      this.applyFilters()
    },
    // the range dialog closed without a range: back to the time window chosen before
    afterClose(id) {
      if (id === 'range-dialog' && this.range === 'custom' && !this.rangeFrom && !this.rangeTo) this.range = this.rangePrev === 'custom' ? '' : this.rangePrev
    },
    // The filters as API parameters. A preset is a window ending now, worked out again on every refresh; an action
    // ending in * is a kind of action (action_group).
    filterParams() {
      const a = this.form.action.trim()
      const p = { outcome: this.outcome, org: this.form.org }
      if (a.endsWith('*')) p.action_group = a.slice(0, -1)
      else p.action = a
      const ms = { '15m': 900e3, '30m': 1800e3, '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 }[this.range]
      if (ms) p.from = new Date(Date.now() - ms).toISOString()
      if (this.customRange) {
        if (this.rangeFrom) p.from = new Date(this.rangeFrom).toISOString()
        if (this.rangeTo) p.to = new Date(new Date(this.rangeTo).getTime() + 1000).toISOString() // the end's whole second is included
      }
      return p
    },
    applyFilters() {
      this.extra = this.filterParams()
      this.offset = 0
      return this.load(true)
    },
    refresh() {
      this.extra = this.filterParams()
      return this.load(true)
    },
    async clearFilters() {
      this.range = this.rangePrev = this.rangeFrom = this.rangeTo = this.outcome = ''
      await this.comboSet('action', '', '')
      await this.comboSet('org', '', '')
      return this.applyFilters()
    },
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

  // ---- Master key rotation (super admins): GET /api/master-key, polled --------------------------------------------
  const MASTER_KEY_POLL_MS = 30000 // the status reads the leader's last report, not the stored secrets
  const MASTER_KEY_STATE = {
    none: { title: 'No rotation in progress.', cls: 'alert alert-success' },
    waiting_for_nodes: { title: 'Waiting for the nodes.', cls: 'alert alert-warning' },
    resealing: { title: 'Re-sealing.', cls: 'alert alert-warning' },
    unopenable: { title: 'Secrets no key opens.', cls: 'alert alert-error' },
    complete: { title: 'Rotation complete: remove the previous keys.', cls: 'alert alert-success' },
  }
  const countBadge = (n, danger) => (n ? (danger ? 'badge badge-danger' : 'badge badge-warning') : 'badge badge-success')
  Alpine.data('adminMasterKey', () => ({
    st: {}, nodes: [], loading: true, loaded: false, loadError: '', apiBase: '', updated: null, timer: null,
    init() {
      this.apiBase = this.$el.dataset.api
      this.timer = setInterval(() => { if (document.visibilityState === 'visible') this.load() }, MASTER_KEY_POLL_MS)
      return this.load()
    },
    destroy() { clearInterval(this.timer) },
    async load() {
      this.loading = true
      try {
        const st = await get(`${this.apiBase}/master-key`)
        this.st = st
        this.nodes = Object.entries(st.nodes || {}).sort(([a], [b]) => a.localeCompare(b)).map(([id, k]) => ({
          id, active: k.active_key,
          activeNote: k.active_key === st.active_key ? 'Same as this node' : 'Different',
          activeClass: k.active_key === st.active_key ? 'badge badge-success' : 'badge badge-warning',
          previousText: (k.previous_keys || []).join(', ') || 'None',
        }))
        this.updated = new Date()
        this.loadError = ''
        this.loaded = true
      } catch (e) { this.loadError = e.message }
      this.loading = false
    },
    get state() { return MASTER_KEY_STATE[this.st.state] || { title: '', cls: 'alert alert-warning' } },
    get stateTitle() { return this.state.title },
    get stateClass() { return this.state.cls },
    get removable() { return !!this.st.previous_keys_removable },
    get notRemovable() { return !this.st.previous_keys_removable },
    get previousText() { return (this.st.previous_keys || []).join(', ') || 'None' },
    get staleClass() { return countBadge(this.st.stale_secrets) },
    get unopenableClass() { return countBadge(this.st.unopenable_secrets, true) },
    get busyAttr() { return this.loading ? 'true' : 'false' },
    get hasLoadError() { return this.loadError !== '' },
    get updatedText() {
      return this.updated ? `Checked ${this.updated.toLocaleTimeString()}, every ${MASTER_KEY_POLL_MS / 1000} seconds.` : ''
    },
  }))

  // ---- An organization's overview (its administrators and super admins), and its emergency sign-out --------------
  const hours = (sec) => `${Math.round(sec / 3600)} hour${Math.round(sec / 3600) === 1 ? '' : 's'}`
  const minutes = (sec) => `${Math.round(sec / 60)} minute${Math.round(sec / 60) === 1 ? '' : 's'}`
  Alpine.data('adminOrg', () => mix(formMixin(), dialogMixin(), signOutMixin(Alpine), {
    org: { settings: {} }, n: {}, loading: true, loaded: false, loadError: '', apiBase: '',
    init() {
      const d = this.$el.dataset
      this.apiBase = d.api
      this.signOutScope = d.org
      this.signOutDisplay = d.display
      const live = liveRunner(async () => { await this.load(); announceUpdate('Overview updated') })
      subscribe(['org', 'user', 'group', 'tenant', 'provider'], () => live.trigger())
      return this.load()
    },
    async load() {
      const total = async (what) => (await get(`${this.apiBase}/${what}?limit=1`)).total
      try {
        const [org, users, groups, tenants, providers] = await Promise.all([get(this.apiBase), total('users'),
          total('groups'), total('tenants'), total('providers')])
        this.org = org
        this.n = { users, groups, tenants, providers }
        this.lastSignOut = org.last_sign_out || null
        this.loadError = ''
        this.loaded = true
      } catch (e) { this.loadError = e.message }
      this.loading = false
    },
    get hasLoadError() { return this.loadError !== '' },
    get passwordText() {
      const s = this.org.settings
      return !s.password_login ? 'Off' : s.password_reset ? 'On, with reset by email' : 'On, no reset by email'
    },
    get passkeyText() { return this.org.settings.passkey_login ? 'On' : 'Off' },
    get mcpText() { return this.org.settings.mcp_server ? 'On' : 'Off' },
    get mfaText() {
      const s = this.org.settings
      return (s.require_mfa ? 'Required' : 'Optional') + (!s.email_codes ? '' : mailOn() ? ', codes by email allowed' : ', codes by email allowed but email is not set up')
    },
    get apiTokensText() {
      const s = this.org.settings
      const n = (s.api_token_groups || []).length
      if (s.api_tokens === 'everyone') return 'Everyone may make them'
      return s.api_tokens === 'groups' ? `Members of ${n} chosen group${n === 1 ? '' : 's'}` : 'Nobody'
    },
    get ttlText() { const t = this.org.settings.session_ttl; return t ? hours(t) : 'Server default' },
    get idleText() { const t = this.org.settings.session_idle; return t ? minutes(t) : 'Server default' },
    get privilegedText() {
      const s = this.org.settings
      if (!s.privileged_ttl && !s.privileged_idle) return 'Server default'
      return [s.privileged_ttl ? hours(s.privileged_ttl) + ' sessions' : 'Server default lifetime',
        s.privileged_idle ? 'signed out when idle for ' + minutes(s.privileged_idle) : 'server default idle timeout'].join(', ')
    },
    get passwordMinText() { const n = this.org.settings.password_min_length; return n ? `${n} characters` : 'Server default' },
    get lockoutText() {
      const s = this.org.settings
      if (!s.lockout_attempts && !s.lockout_minutes) return 'Server default'
      return `${s.lockout_attempts ? `After ${s.lockout_attempts} failed attempts` : 'After the server default attempts'}, for ${s.lockout_minutes ? minutes(s.lockout_minutes * 60) : 'the server default time'}`
    },
    get tokenDaysText() {
      const n = this.org.settings.api_token_max_days
      if (n === -1) return 'No limit: tokens may never expire'
      return n ? `At most ${n} day${n === 1 ? '' : 's'}` : 'Server default'
    },
  }))

  // ---- An organization's branding (its administrators): PATCH <org>/branding --------------------------------------
  // The branding card on the organization's page; the organization dialog has the same fields (brandingMixin).
  Alpine.data('adminBranding', () => mix(formMixin(), dialogMixin(), brandingMixin(), {
    loaded: false, apiBase: '',
    async init() {
      this.apiBase = this.$el.dataset.api
      try { this.show(await get(this.apiBase)) } catch { /* the page's own load of the organization reports it */ }
    },
    show(org) {
      this.resetForm({ primary_color: org.branding.primary_color, footer: org.branding.footer || '', skin: org.branding.skin || '' })
      this.resetBranding(org.branding, org.primary, '/o/' + org.name)
      this.loaded = true
    },
    get saveBlocked() { return this.busy || !this.brandingChanged },
    get saveLabel() { return this.busy ? 'Saving…' : 'Save branding' },
    async save() {
      const org = await this.run(() => patch(`${this.apiBase}/branding`, this.brandingBody()))
      if (!org) return
      this.show(org)
      toast('Branding saved.')
    },
  }))

  // ---- System overview (super admins): the server as a whole, and its emergency sign-out --------------------------
  Alpine.data('adminSystem', () => mix(formMixin(), dialogMixin(), signOutMixin(Alpine), keysMixin(Alpine), clusterMixin(Alpine), {
    s: {}, loading: true, loaded: false, loadError: '', apiBase: '', signOutScope: 'server',
    init() {
      this.apiBase = this.$el.dataset.api
      this.rotationDays = Number(this.$el.dataset.rotation) || 0
      // a key rotated, an organization added or removed, a sign-out elsewhere (another administrator, another node)
      const live = liveRunner(async () => { await this.load(); announceUpdate('Overview updated') })
      subscribe(['key', 'org'], () => live.trigger())
      return this.load()
    },
    async load() {
      try {
        const [s] = await Promise.all([get(`${this.apiBase}/system`), this.loadKeys()])
        if (s.clustered) await this.startCluster()
        this.s = s
        this.lastSignOut = s.last_sign_out || null
        this.loadError = ''
        this.loaded = true
      } catch (e) { this.loadError = e.message }
      this.loading = false
    },
    get hasLoadError() { return this.loadError !== '' },
    destroy() { this.stopCluster() },
    get standalone() { return this.loaded && !this.s.clustered },
    get noMasterKeyRotation() { return this.loaded && !this.s.master_key_rotation },
    // keys read from Vault or 1Password: read them again on every node (the same reload as SIGHUP, cluster-wide)
    storesReport: [],
    get hasSecretStores() { return this.loaded && (this.s.secret_stores || []).length > 0 },
    get secretStoresText() { return (this.s.secret_stores || []).join(' and ') },
    get hasStoresReport() { return this.storesReport.length > 0 },
    get readStoresLabel() { return this.reloading ? 'Reading…' : 'Read secret stores now' },
    async readSecretStores(ev) {
      const opener = ev.currentTarget
      const yes = await confirmAction(Alpine, { title: 'Read the secret stores now?', message: 'Have every node read its keys from the secret stores again?',
        detail: 'The master keys and cluster keys that name a secret store are read again and switched to. Every node checks first; nothing changes unless all can. Rotate the master key in two steps: add the new key as a previous key and read; then make it the master key (the old one previous) and read.',
        confirmLabel: 'Read now' })
      if (!yes) return
      this.reloading = true
      try {
        const res = await withReauth(Alpine, () => post(`${this.apiBase}/cluster/reload`), opener)
        this.storesReport = (res.nodes || []).map(reloadRow)
        toast('Keys read on every node.')
        await this.load()
      } catch (e) {
        if (e.name !== 'AbortError') {
          if (e.body && e.body.nodes) this.storesReport = e.body.nodes.map(reloadRow)
          toast(e.message, 'error')
        }
      }
      this.reloading = false
    },
  }))

  // ---- Small shared page behaviours -------------------------------------------------------------------------------
  Alpine.data('pageBase', () => ({}))
}
