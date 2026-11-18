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
import { fmtDateTime, localZoneText, endInput } from '../lib/format.js'
import { detailsText, checkDetails, describeProblem } from '../lib/authdetails.js'

const enc = encodeURIComponent
const PICK_LIMIT = 8
const fullName = (u) => [u.given_name, u.family_name].filter(Boolean).join(' ') || u.username || u.email


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
    apiBase: '', usersBase: '', tenantId: '', clients: [], editing: null, endWas: endInput(''),

    init() {
      const d = this.$el.dataset
      this.apiBase = d.base
      this.usersBase = d.users || ''
      this.tenantId = d.tenant
      const clientsLive = liveRunner(() => this.loadClients())
      subscribe(['client'], () => clientsLive.trigger())
      this.loadClients()
      return this.initTable()
    },
    async loadClients() {
      try {
        const r = await get(`${this.apiBase}/clients${qs({ tenant: this.tenantId, sort: 'name', limit: 100 })}`)
        this.clients = r.items.map((c) => ({ id: c.id, name: c.name, types: c.authorization_details_types || [] }))
        if (this.items.length) this.items = this.items.map((i) => this.transform(i)) // client names in the table
      } catch (e) { /* the table still works; names show as ids */ }
    },

    // ---- the table
    get membersOnly() { const t = Alpine.store('tenantPage').tenant; return !!(t && t.settings.members_only) },
    get accessIntro() { return 'Only these users and groups can sign in to this tenant’s clients. Roles, tags and authorization details are sent to the clients in tokens.' },
    get accessCountText() { return this.total === 1 ? '1 entry' : this.total + ' entries' },
    get accessEmptyText() { return 'Nobody can sign in to this tenant’s clients until you give a user or group access.' },
    clientName(id) { const c = this.clients.find((x) => x.id === id); return c ? c.name : 'Removed client' },
    transform(e) {
      const isGroup = e.subject_type === 'group'
      const name = e.name || (isGroup ? 'Deleted group' : 'Deleted user')
      let expiresText = 'No end'
      let expiresClass = 'muted'
      if (e.expires) {
        expiresText = e.expired ? 'Ended ' + fmtDateTime(e.expires) : fmtDateTime(e.expires)
        expiresClass = e.expired ? 'badge badge-warning' : ''
      }
      // a user's name opens their user page (the console's: /admin/orgs/<org>/users/<id>); a group's, or a deleted
      // user's, is text
      const userHref = !isGroup && e.name && this.usersBase ? `${this.usersBase}/${enc(e.subject_id)}` : ''
      return { ...e, whoName: name, whoSub: isGroup ? 'Group' : e.detail || '', isGroup, userHref,
        rolesText: (e.roles || []).join(', ') || '—', tagsText: (e.tags || []).join(', '),
        appsText: e.all_clients ? 'All clients' : (e.clients || []).map((id) => this.clientName(id)).join(', '),
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
    // The authorization details types of the applications the entry covers (the details field checks against them).
    get detailTypes() {
      const covered = this.form.acc_all ? this.clients : this.clients.filter((c) => (this.form.acc_clients || []).includes(c.id))
      return [...new Set(covered.flatMap((c) => c.types))]
    },
    // The end is typed in the viewer's own time zone, named here.
    get expiresHelp() { return `Optional. Your time (${localZoneText()}). Access stops at this time, and the user or group members it applies to are signed out of the clients (unless other access still lets them in). Leave empty for no end.` },
    errorKey(f) {
      if (this.editingDefaults) return { roles: 'dft_roles', tags: 'dft_tags', authorization_details: 'dft_details' }[f] || f
      return { subject_id: 'acc_subject', subject_type: 'acc_subject', expires: 'acc_expires', clients: 'acc_clients', all_clients: 'acc_clients' }[f] || f
    },
    // The tenant's defaults for new access (access_defaults): copied into each new entry that gives none of its own.
    get defaults() { const t = Alpine.store('tenantPage').tenant; return (t && t.access_defaults) || {} },
    get defaultsText() {
      const d = this.defaults, parts = []
      if ((d.roles || []).length) parts.push('roles ' + d.roles.join(', '))
      if ((d.tags || []).length) parts.push('tags ' + d.tags.join(', '))
      if (d.authorization_details && d.authorization_details.length) parts.push('authorization details')
      return parts.length ? `Defaults for new access: ${parts.join('; ')}.` : 'No defaults for new access: it gets only what you give it.'
    },
    editingDefaults: false,
    get defaultsLabel() { return this.busy ? 'Saving…' : 'Save defaults' },
    openDefaults(ev) {
      const d = this.defaults
      this.editingDefaults = true
      this.resetForm({ dft_roles: [...(d.roles || [])], dft_tags: [...(d.tags || [])], dft_details: detailsText(d.authorization_details) })
      this.resetChipText()
      this.openDlg('defaults-dialog', ev.currentTarget)
    },
    afterClose(id) { if (id === 'defaults-dialog') this.editingDefaults = false },
    async submitDefaults() {
      if (!this.tagsReady()) { this.focusTagInput(); return }
      const f = this.form
      const details = checkDetails(f.dft_details)
      if (!details.value) {
        const first = details.problems.find((p) => p.severity === 'error')
        this.setErrors(new ApiError(422, { error: describeProblem(first), field: 'dft_details' }))
        return
      }
      const res = await this.run(() => patch(`${this.apiBase}/tenants/${enc(this.tenantId)}`, { access_defaults: { roles: f.dft_roles, tags: f.dft_tags, authorization_details: details.value } }))
      if (!res) return
      const store = Alpine.store('tenantPage')
      if (store.tenant) store.tenant = { ...store.tenant, access_defaults: res.access_defaults }
      this.closeDlg('defaults-dialog')
      toast('Defaults for new access saved.')
    },

    openAdd(ev) {
      this.editing = null
      this.endWas = endInput('')
      const d = this.defaults // filled in from the tenant's defaults: what the new access gets unless changed here
      this.resetForm({ acc_subject: '', roles: [...(d.roles || [])], tags: [...(d.tags || [])], authorization_details: detailsText(d.authorization_details),
        acc_all: true, acc_clients: [], acc_expires: '' })
      this.resetChipText()
      this.resetPicker()
      this.openDlg('access-dialog', ev.currentTarget)
    },
    edit(ev) {
      const row = this.rowFromEvent(ev)
      if (!row) return
      this.editing = row
      this.endWas = endInput(row.expires)
      this.resetForm({ acc_subject: row.subject_id, roles: [...(row.roles || [])], tags: [...(row.tags || [])], authorization_details: detailsText(row.authorization_details),
        acc_all: !!row.all_clients, acc_clients: [...(row.clients || [])], acc_expires: this.endWas.shown })
      this.resetChipText()
      this.openDlg('access-dialog', ev.currentTarget)
    },
    async submitAccess() {
      if (!this.tagsReady()) { this.focusTagInput(); return }
      const f = this.form
      const details = checkDetails(f.authorization_details)
      if (!details.value) {
        const first = details.problems.find((p) => p.severity === 'error')
        this.setErrors(new ApiError(422, { error: describeProblem(first), field: 'authorization_details' }))
        return
      }
      const body = { roles: f.roles, tags: f.tags, authorization_details: details.value, all_clients: f.acc_all, clients: f.acc_all ? [] : f.acc_clients, expires: this.endWas.send(f.acc_expires) }
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
        detail: 'They can no longer sign in to this tenant’s clients, and are signed out of them, unless they have access another way (directly or through a group).', confirmLabel: 'Remove access' })
      if (!ok) return
      try {
        await del(`${this.apiBase}/tenants/${enc(this.tenantId)}/access/${enc(row.id)}`)
        toast(`Removed access for ${row.whoName}.`)
        this.load()
      } catch (e) { toast(e.message, 'error') }
    },
  }))
}
