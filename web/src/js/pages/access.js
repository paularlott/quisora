// Tenant access (the "Access" card of the tenant page): which users and groups may sign in to the tenant's
// applications when it is members-only, and the application roles and tags they carry there.
// Nested inside the adminTenant component; the tenant itself comes from Alpine.store('tenantPage'), which the page
// component keeps current.
import { ApiError, get, post, patch, del, qs } from '../lib/api.js'
import { tableMixin } from '../lib/table.js'
import { formMixin } from '../lib/form.js'
import { dialogMixin } from '../lib/dialog.js'
import { tagsMixin } from '../lib/tags.js'
import { toast, announce } from '../lib/announce.js'
import { mix } from '../lib/mix.js'
import { pickerMixin } from '../lib/picker.js'
import { subscribe, liveRunner } from '../lib/live.js'
import { fmtDate } from '../lib/format.js'

const enc = encodeURIComponent
const PICK_LIMIT = 8
const fullName = (u) => [u.given_name, u.family_name].filter(Boolean).join(' ') || u.username || u.email

// A date input value (YYYY-MM-DD, local) <-> the server's RFC 3339 time (access ends at the start of that local day).
function dayToTime(day) {
  if (!day) return ''
  const [y, m, d] = day.split('-').map(Number)
  return new Date(y, m - 1, d).toISOString()
}
function timeToDay(t) {
  if (!t) return ''
  const d = new Date(t)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

export default function (Alpine) {
  Alpine.store('tenantPage', { tenant: null })

  Alpine.data('tenantAccess', () => mix(tableMixin(), formMixin(), dialogMixin(), tagsMixin(), pickerMixin({
    // users and groups of the organization in one list, users first
    async search(q) {
      const [us, gs] = await Promise.all([get(`${this.apiBase}/users${qs({ q, limit: PICK_LIMIT })}`), get(`${this.apiBase}/groups${qs({ q, limit: PICK_LIMIT })}`)])
      return { more: us.total + gs.total > us.items.length + gs.items.length, items: [
        ...us.items.map((x) => ({ type: 'user', id: x.id, label: fullName(x), detail: x.email, kind: 'User' })),
        ...gs.items.map((x) => ({ type: 'group', id: x.id, label: x.display_name, detail: '', kind: 'Group' }))] }
    },
    chosen(p) { this.form.acc_subject = p.id; this.clearErrors() },
  }), {
    apiBase: '', tenantId: '', clients: [], editing: null,

    init() {
      const d = this.$el.dataset
      this.apiBase = d.base
      this.tenantId = d.tenant
      const clientsLive = liveRunner(() => this.loadClients())
      subscribe(['client'], () => clientsLive.trigger())
      this.loadClients()
      return this.initTable()
    },
    async loadClients() {
      try {
        const r = await get(`${this.apiBase}/clients${qs({ tenant: this.tenantId, sort: 'name', limit: 100 })}`)
        this.clients = r.items.map((c) => ({ id: c.id, name: c.name }))
        if (this.items.length) this.items = this.items.map((i) => this.transform(i)) // client names in the table
      } catch (e) { /* the table still works; names show as ids */ }
    },

    // ---- the table
    get membersOnly() { const t = Alpine.store('tenantPage').tenant; return !!(t && t.settings.members_only) },
    get accessIntro() { return 'Only these users and groups can sign in to this tenant’s applications. Roles and tags are sent to the applications in tokens.' },
    get accessCountText() { return this.total === 1 ? '1 entry' : this.total + ' entries' },
    get accessEmptyText() { return 'Nobody can sign in to this tenant’s applications until you give a user or group access.' },
    clientName(id) { const c = this.clients.find((x) => x.id === id); return c ? c.name : 'Removed application' },
    transform(e) {
      const isGroup = e.subject_type === 'group'
      const name = e.name || (isGroup ? 'Deleted group' : 'Deleted user')
      let expiresText = 'No end'
      let expiresClass = 'muted'
      if (e.expires) {
        expiresText = e.expired ? 'Ended ' + fmtDate(e.expires) : fmtDate(e.expires)
        expiresClass = e.expired ? 'badge badge-warning' : ''
      }
      return { ...e, whoName: name, whoSub: isGroup ? 'Group' : e.detail || '', isGroup,
        rolesText: (e.roles || []).join(', ') || '—', tagsText: (e.tags || []).join(', '),
        appsText: e.all_clients ? 'All applications' : (e.clients || []).map((id) => this.clientName(id)).join(', '),
        expiresText, expiresClass, editLabel: 'Edit access for ' + name, removeLabel: 'Remove access for ' + name }
    },

    // ---- the dialog
    get isAdd() { return this.editing === null },
    get isEditAccess() { return this.editing !== null },
    get accessDialogTitle() { return this.editing ? 'Edit access' : 'Add access' },
    get accessSubmitLabel() { return this.busy ? 'Saving…' : this.editing ? 'Save changes' : 'Add access' },
    get editingWho() { return this.editing ? this.editing.whoName + (this.editing.isGroup ? ' (group)' : this.editing.detail ? ' · ' + this.editing.detail : '') : '' },
    get pickClients() { return !this.form.acc_all },
    get hasClients() { return this.clients.length > 0 },
    get noClients() { return this.clients.length === 0 },
    errorKey(f) {
      return { subject_id: 'acc_subject', subject_type: 'acc_subject', expires: 'acc_expires', clients: 'acc_clients', all_clients: 'acc_clients' }[f] || f
    },

    openAdd(ev) {
      this.editing = null
      this.resetForm({ acc_subject: '', roles: [], tags: [], acc_all: true, acc_clients: [], acc_expires: '' })
      this.resetChipText()
      this.resetPicker()
      this.openDlg('access-dialog', ev.currentTarget)
    },
    edit(ev) {
      const row = this.rowFromEvent(ev)
      if (!row) return
      this.editing = row
      this.resetForm({ acc_subject: row.subject_id, roles: [...(row.roles || [])], tags: [...(row.tags || [])],
        acc_all: !!row.all_clients, acc_clients: [...(row.clients || [])], acc_expires: timeToDay(row.expires) })
      this.resetChipText()
      this.openDlg('access-dialog', ev.currentTarget)
    },
    async submitAccess() {
      if (!this.tagsReady()) { this.focusTagInput(); return }
      const f = this.form
      const body = { roles: f.roles, tags: f.tags, all_clients: f.acc_all, clients: f.acc_all ? [] : f.acc_clients, expires: dayToTime(f.acc_expires) }
      if (!this.editing) {
        if (!this.pickChoice) {
          this.setErrors(new ApiError(422, { error: 'Choose a user or group from the list.', field: 'acc_subject' }))
          return
        }
        body.subject_type = this.pickChoice.type
        body.subject_id = this.pickChoice.id
      }
      const edit = this.editing
      const url = `${this.apiBase}/tenants/${enc(this.tenantId)}/access`
      const res = await this.run(() => edit ? patch(`${url}/${enc(edit.id)}`, body) : post(url, body))
      if (!res) return
      this.closeDlg('access-dialog')
      toast(edit ? `Access for ${res.name} saved.` : `${res.name} now has access.`)
      this.load()
    },
    async remove(ev) {
      const row = this.rowFromEvent(ev)
      if (!row) return
      const ok = await Alpine.store('confirm').ask({ title: 'Remove access', message: `Remove access for ${row.whoName}?`,
        detail: 'They can no longer sign in to this tenant’s applications, unless they have access another way (directly or through a group).', confirmLabel: 'Remove access' })
      if (!ok) return
      try {
        await del(`${this.apiBase}/tenants/${enc(this.tenantId)}/access/${enc(row.id)}`)
        toast(`Removed access for ${row.whoName}.`)
        this.load()
      } catch (e) { toast(e.message, 'error') }
    },
  }))
}
