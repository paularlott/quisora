// SSH certificates (the tenant's SSH page): turn the tenant's SSH certificate authority on, change its settings, rotate
// and remove its CA keys, set servers up, and search, page through and revoke the certificates it issued
// (docs/design/ssh-ca.md). Nested inside the adminTenantSSH component; it loads its own data from the tenant's /ssh API,
// and the certificates table (sshCertificates) nested in it from the /ssh/certificates API.
import { ApiError, get, post, patch, del } from '../lib/api.js'
import { tableMixin } from '../lib/table.js'
import { formMixin, lines } from '../lib/form.js'
import { dialogMixin } from '../lib/dialog.js'
import { toast } from '../lib/announce.js'
import { mix } from '../lib/mix.js'
import { withReauth } from './account.js'
import { subscribe, liveRunner, announceUpdate } from '../lib/live.js'
import { fmtDateTime } from '../lib/format.js'

const enc = encodeURIComponent

const KEY_STATE = {
  next: { text: 'Next', cls: 'badge badge-info', note: 'Published; signs from its start time.' },
  active: { text: 'Signing', cls: 'badge badge-success', note: 'Signs every new certificate.' },
  retired: { text: 'Retired', cls: 'badge badge-plain', note: 'No longer signs; certificates it signed still work.' },
}
export const CERT_STATUS = {
  active: { text: 'Active', cls: 'badge badge-success' },
  expired: { text: 'Expired', cls: 'badge badge-plain' },
  revoked: { text: 'Revoked', cls: 'badge badge-danger' },
}
const REASON = {
  revoked: 'Revoked by an administrator',
  ca_key_removed: 'Its CA key was removed',
  user_deleted: 'The user was deleted',
  user_disabled: 'The user was disabled',
  sessions_ended: 'The user’s sessions were ended',
  sign_in_ended: 'The sign-in it was issued under was ended',
  signed_out: 'An emergency sign-out',
  role_not_allowed: 'The user’s role may no longer get certificates',
  access_removed: 'The user lost access to the tenant',
  app_unavailable: 'The tenant’s SSH application is disabled or missing',
  principals_changed: 'The user’s principals changed',
  ssh_off: 'SSH certificates are turned off for the tenant',
  settings_changed: 'It grants more than the tenant’s settings now allow',
}

// certNote says why a certificate is revoked, in words ("" when it is not).
export function certNote(c) {
  if (c.reason === 'revoked' && c.revoked_by) return 'Revoked by ' + c.revoked_by
  return c.reason ? REASON[c.reason] || c.reason : ''
}

// duration says seconds as hours and minutes ("8 hours", "1 hour 30 minutes", "45 minutes").
function duration(s) {
  const h = Math.floor(s / 3600)
  const m = Math.round((s % 3600) / 60)
  const part = (n, w) => (n === 1 ? `1 ${w}` : `${n} ${w}s`)
  if (h === 0) return part(m, 'minute')
  return m === 0 ? part(h, 'hour') : `${part(h, 'hour')} ${part(m, 'minute')}`
}

export default function (Alpine) {
  Alpine.data('tenantSSH', () => mix(formMixin(), dialogMixin(), {
    url: '', ssh: null, loading: true, loadError: '', working: false, _sig: '', rotatePurpose: 'user', orig: {},

    init() {
      const d = this.$el.dataset
      this.url = `${d.base}/tenants/${enc(d.tenant)}/ssh`
      const live = liveRunner(() => this.load(true))
      subscribe(['sshkey', 'tenant'], () => live.trigger())
      return this.load(false)
    },
    async load(quiet) {
      try {
        const s = await get(this.url)
        const sig = JSON.stringify(s)
        if (quiet && sig === this._sig) return
        this._sig = sig
        this.ssh = s
        this.loadError = ''
        if (quiet) announceUpdate('SSH settings updated')
      } catch (e) { if (!quiet) this.loadError = e.message } finally { this.loading = false }
    },
    // After a change that can end certificates (SSH off or on, a CA key removed or rotated, settings): the settings and
    // keys again, and the certificates table, whose statuses follow them.
    async refresh() {
      this._sig = ''
      await this.load(false)
      window.dispatchEvent(new CustomEvent('ssh-changed'))
    },

    // ---- what the card shows
    get ready() { return this.ssh !== null },
    get enabled() { return !!this.ssh && this.ssh.enabled },
    get everEnabled() { return !!this.ssh && (this.ssh.enabled || this.ssh.keys.length > 0) },
    get hasLoadError() { return this.loadError !== '' },
    get stateText() { return this.enabled ? 'On' : 'Off' },
    get stateClass() { return this.enabled ? 'badge badge-success' : 'badge badge-plain' },
    get switchBusy() { return this.working },
    get discovery() { return this.ssh ? this.ssh.endpoints.discovery : '' },
    get hostOn() { return this.enabled && this.ssh.host_certs },
    get hasHostKey() { return !!this.ssh && this.ssh.keys.some((k) => k.purpose === 'host') },
    get offNote() {
      return this.everEnabled ? 'SSH certificates are off: no certificate is signed, and the revocation list servers fetch revokes every certificate already issued and the CA keys themselves. The keys are kept, so that turning SSH on again works with the servers already set up; deleting the tenant deletes them. The tenant’s SSH application is disabled until SSH is on again.'
        : 'SSH certificates are off. Turning them on makes this tenant’s CA key and an SSH application people sign in with.'
    },
    get keysNote() {
      return this.enabled ? 'Servers trust the published keys. A rotated user key is published first and signs a week later; a key that no longer signs can be removed.'
        : 'Kept while SSH is off, and revoked: they sign nothing, and servers that fetch the revocation list accept no certificate of theirs. Rotating is for when SSH is on.'
    },
    get clientId() { return this.ssh ? this.ssh.client_id || '' : '' },
    get hasClient() { return this.clientId !== '' },

    get summaryRows() {
      if (!this.ssh) return []
      const s = this.ssh
      const principals = [s.principal_username && 'Username', s.principal_groups && 'Group names (group:…)', s.principal_roles && 'Application roles (role:…)'].filter(Boolean)
      const rights = [s.permit_pty && 'Terminal', s.permit_user_rc && '~/.ssh/rc', s.permit_port_forwarding && 'Port forwarding',
        s.permit_agent_forwarding && 'Agent forwarding', s.permit_x11_forwarding && 'X11 forwarding'].filter(Boolean)
      return [
        { label: 'Certificate lifetime', text: duration(s.cert_ttl), note: 'People may ask for a shorter one.' },
        { label: 'Sign-in must be newer than', text: duration(s.max_auth_age), note: 'A second factor is always required.' },
        { label: 'Principals', text: principals.join(', ') || 'None', note: principals.length ? 'Servers decide who may log in as which account from these.' : 'Nothing to put in a certificate: none can be signed.' },
        { label: 'A session may use', text: rights.join(', ') || 'Nothing extra', note: '' },
        { label: 'Source addresses', text: s.source_addresses.join(', ') || 'Anywhere', note: s.source_addresses.length ? 'Certificates work from these addresses only.' : '' },
        { label: 'Managers and administrators', text: s.allow_privileged ? 'May get certificates' : 'May not get certificates', note: '' },
        { label: 'User CA rotation', text: s.rotation_days ? `Every ${s.rotation_days} days` : 'By hand only', note: '' },
        { label: 'Host certificates', text: s.host_certs ? `On, up to ${s.host_ttl_days} days` : 'Off', note: s.host_certs ? 'For ' + s.host_patterns.join(', ') : '' },
      ]
    },

    // ---- setting servers up
    get serverSnippet() {
      return [
        '# /etc/ssh/sshd_config',
        'TrustedUserCAKeys /etc/ssh/quisora_user_ca.pub',
        'RevokedKeys /etc/ssh/quisora.krl',
        'AuthorizedPrincipalsFile /etc/ssh/principals/%u',
        '',
        '# keep the CA key and the revocation list current: a cron job or systemd timer, every minute',
        `quisora ssh fetch ${this.discovery}`,
      ].join('\n')
    },
    get hostSnippet() {
      return [
        '# get a certificate for the server’s host key (a token with the ssh:host scope)',
        `quisora ssh host-sign ${this.discovery} /etc/ssh/ssh_host_ed25519_key.pub`,
        '',
        '# /etc/ssh/sshd_config',
        'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub',
        '',
        '# after each renewal, so sshd serves the new certificate',
        'systemctl reload ssh',
      ].join('\n')
    },
    get loginCommand() { return `quisora ssh login ${this.discovery}` },
    get principalsNote() {
      const s = this.ssh
      const what = [s.principal_username && 'their username', s.principal_groups && 'group: and the name of each of their groups',
        s.principal_roles && 'role: and each application role they have here'].filter(Boolean)
      return 'In /etc/ssh/principals/<account>, list the principals allowed to log in as that account, one per line. A user’s certificate carries ' +
        (what.join(', ') || 'no principals yet (turn some on in the settings)') + '.'
    },

    // ---- on and off
    async patchSSH(body, done) {
      this.working = true
      try {
        await patch(this.url, body)
        toast(done)
        await this.refresh()
        return true
      } catch (e) { toast(e.message, 'error'); return false } finally { this.working = false }
    },
    async toggle(ev) {
      const box = ev.currentTarget
      const on = box.checked
      if (!on) {
        const yes = await Alpine.store('confirm').ask({ title: 'Turn off SSH certificates?', message: 'Stop signing SSH certificates for this tenant?',
          detail: 'Nothing is deleted. No new certificate is signed, the tenant’s SSH application is disabled until SSH is on again, and the revocation list servers fetch revokes every certificate already issued and the CA keys themselves, so certificates stop working within a minute plus how often each server fetches the list. The CA keys and the certificate records are kept: turning SSH on again works with the servers already set up, and certificates not revoked for another reason work again. Deleting the tenant deletes them.',
          confirmLabel: 'Turn off' })
        if (!yes) { box.checked = true; return }
      }
      const done = await this.patchSSH({ enabled: on }, on ? 'SSH certificates are on.' : 'SSH certificates are off.')
      if (!done) box.checked = !on
    },

    // ---- settings dialog
    errorKey(f) { return f ? f.replace(/^ssh\./, 'ssh_') : f },
    get hostFields() { return !!this.form.ssh_host_certs },
    get settingsSubmitLabel() { return this.busy ? 'Saving…' : 'Save settings' },
    openSettings(ev) {
      const s = this.ssh
      const minutes = (secs) => String(Math.round(secs / 60))
      this.orig = { ssh_cert_ttl: minutes(s.cert_ttl), ssh_max_auth_age: minutes(s.max_auth_age) }
      this.resetForm({ ...this.orig,
        ssh_principal_username: s.principal_username, ssh_principal_groups: s.principal_groups, ssh_principal_roles: s.principal_roles,
        ssh_permit_pty: s.permit_pty, ssh_permit_user_rc: s.permit_user_rc, ssh_permit_port_forwarding: s.permit_port_forwarding,
        ssh_permit_agent_forwarding: s.permit_agent_forwarding, ssh_permit_x11_forwarding: s.permit_x11_forwarding,
        ssh_source_addresses: s.source_addresses.join('\n'), ssh_allow_privileged: s.allow_privileged, ssh_rotation_days: String(s.rotation_days),
        ssh_host_certs: s.host_certs, ssh_host_ttl_days: String(s.host_ttl_days), ssh_host_patterns: s.host_patterns.join('\n') })
      this.openDlg('ssh-dialog', ev.currentTarget)
    },
    // A whole number from a number field; otherwise the field's error and null (a missing value in the body would
    // leave the setting as it is without saying so).
    whole(name, label) {
      const v = String(this.form[name] ?? '').trim()
      if (/^\d+$/.test(v)) return Number(v)
      this.setErrors(new ApiError(422, { error: label + ' must be a whole number.', field: name }))
      return null
    },
    async submitSettings() {
      const f = this.form
      const ttl = this.whole('ssh_cert_ttl', 'Certificate lifetime')
      if (ttl === null) return
      const age = this.whole('ssh_max_auth_age', 'Sign-in age')
      if (age === null) return
      const rot = this.whole('ssh_rotation_days', 'Rotation')
      if (rot === null) return
      const hostDays = this.whole('ssh_host_ttl_days', 'Host certificate lifetime')
      if (hostDays === null) return
      const body = { principal_username: f.ssh_principal_username, principal_groups: f.ssh_principal_groups, principal_roles: f.ssh_principal_roles,
        permit_pty: f.ssh_permit_pty, permit_user_rc: f.ssh_permit_user_rc, permit_port_forwarding: f.ssh_permit_port_forwarding,
        permit_agent_forwarding: f.ssh_permit_agent_forwarding, permit_x11_forwarding: f.ssh_permit_x11_forwarding,
        source_addresses: lines(f.ssh_source_addresses), allow_privileged: f.ssh_allow_privileged, rotation_days: rot,
        host_certs: f.ssh_host_certs, host_ttl_days: hostDays, host_patterns: lines(f.ssh_host_patterns) }
      // a lifetime that is not a whole number of minutes is kept as it is unless changed
      if (String(ttl) !== this.orig.ssh_cert_ttl) body.cert_ttl = ttl * 60
      if (String(age) !== this.orig.ssh_max_auth_age) body.max_auth_age = age * 60
      const res = await this.run(() => patch(this.url, body))
      if (!res) return
      this.closeDlg('ssh-dialog')
      toast('SSH settings saved.')
      await this.refresh()
    },

    // ---- CA keys
    get keys() {
      if (!this.ssh) return []
      return this.ssh.keys.map((k) => {
        const st = KEY_STATE[k.state] || KEY_STATE.retired
        return { ...k, purposeText: k.purpose === 'host' ? 'Host' : 'User', stateText: st.text, stateClass: st.cls, stateNote: st.note,
          fromText: fmtDateTime(k.not_before), stopText: fmtDateTime(k.retire_at, '—'), untilText: fmtDateTime(k.expires, 'Until removed'),
          removable: k.state === 'retired', removeLabel: `Remove ${k.purpose} CA key ${k.fingerprint}`, copyLabel: `Copy public key of ${k.purpose} CA key ${k.fingerprint}` }
      })
    },
    get hasKeys() { return this.keys.length > 0 },
    get isUserRotation() { return this.rotatePurpose === 'user' },
    get rotateTitle() { return `Rotate the ${this.rotatePurpose} CA key` },
    get rotateImmediate() { return this.form.ssh_rotate_mode === 'immediate' },
    get rotateSubmitLabel() { return this.busy ? 'Rotating…' : this.rotateImmediate ? 'Rotate immediately' : 'Rotate key' },
    get rotateIntro() {
      return this.isUserRotation
        ? 'Make a new key for signing user certificates. Servers must trust it before it signs, so they pick it up when they fetch the CA key list.'
        : 'Make a new key for signing host certificates. It signs at once, and the old key stays published until you remove it, so certificates it signed keep working.'
    },
    openRotate(ev) {
      this.rotatePurpose = ev.currentTarget.dataset.purpose
      this.resetForm({ ssh_rotate_mode: 'scheduled' })
      this.openDlg('ssh-rotate-dialog', ev.currentTarget)
    },
    async submitRotate() {
      const purpose = this.rotatePurpose
      const immediate = this.isUserRotation && this.rotateImmediate
      const opener = document.activeElement
      const res = await this.run(() => withReauth(Alpine, () => post(`${this.url}/rotate`, { purpose, immediate }), opener, this))
      if (!res) return
      this.closeDlg('ssh-rotate-dialog')
      toast(res.state === 'next' ? 'New key made: it starts signing in 7 days.' : 'New key made: it signs now.')
      await this.refresh()
    },
    async removeKey(ev) {
      const opener = ev.currentTarget
      const id = opener.dataset.id
      const k = this.keys.find((x) => x.id === id)
      if (!k) return
      const yes = await Alpine.store('confirm').ask({ title: 'Remove this CA key?', message: `Remove the retired ${k.purpose} CA key ${k.fingerprint}?`,
        detail: 'It is no longer published, and the revocation list revokes the key itself, so servers stop trusting it and the certificates it signed when they next fetch the list, even with an old CA key file. Do this for a key that may have been exposed, after rotating immediately.',
        confirmLabel: 'Remove key' })
      if (!yes) return
      try {
        await withReauth(Alpine, () => del(`${this.url}/keys/${enc(id)}`), opener, this)
        toast('CA key removed.')
        await this.refresh()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
  }))

  // The certificates table of the SSH page: a page at a time, searched, filtered by status, newest first, the same list
  // as the users (tableMixin), from the tenant's certificates API.
  Alpine.data('sshCertificates', () => mix(tableMixin(), {
    extra: { status: 'active' },
    init() { return this.initTable() },
    transform(c) {
      const st = CERT_STATUS[c.status] || CERT_STATUS.expired
      const who = c.host ? (c.principals || [])[0] || 'Host' : c.username || 'Deleted user' // a host by its first name (the badge says Host)
      return { ...c, whoText: who, isHost: !!c.host, keyIdText: c.key_id, principalsText: (c.principals || []).join(', '), issuedText: fmtDateTime(c.created),
        expiresText: fmtDateTime(c.valid_before), statusText: st.text, statusClass: st.cls, statusNote: certNote(c),
        canRevoke: c.status === 'active', revokeLabel: `Revoke certificate ${c.serial} for ${who}` }
    },
    get noCerts() { return !this.loading && this.loadError === '' && this.total === 0 },
    get noCertsText() {
      if (this.q) return `No certificates match “${this.q}”.`
      return this.extra.status === 'all' ? 'No certificates have been issued yet.' : `No ${this.extra.status} certificates.`
    },
    async revoke(ev) {
      const c = this.rowFromEvent(ev)
      if (!c) return
      const yes = await Alpine.store('confirm').ask({ title: 'Revoke certificate?', message: `Revoke certificate ${c.serial} for ${c.whoText}?`,
        detail: 'It goes on the revocation list servers fetch, so it stops working within a minute or two. A user can ask for a new certificate straight away.',
        confirmLabel: 'Revoke' })
      if (!yes) return
      try {
        await post(`${this.apiUrl}/${enc(c.id)}/revoke`)
        toast('Certificate revoked.')
        await this.load()
      } catch (e) { toast(e.message, 'error') }
    },
  }))
}
