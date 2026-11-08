// The organization's email templates (/admin/orgs/{org}/emails): a tab for the layout and one for each email, each
// with an HTML and a plain-text editor (and the email's subject), previews and test emails rendered by the server from
// the editors as they are. Save and Use the default act on the tab shown: a tab's unsaved edits stay in its editors,
// marked on the tab, until it is saved, and are left out when another tab is saved.
//
// The editors are two Ace editors shared by the tabs: each part (layout_html, emails.reset.text...) has an edit
// session of its own, with its own undo history, which the editors are given when its tab is chosen. Ace objects are
// kept out of Alpine's reactive state (in the closure); `rev` counts edits so the getters that compare texts update.
import { get, post, put } from '../lib/api.js'
import { formMixin } from '../lib/form.js'
import { dialogMixin, openDialog, closeDialog } from '../lib/dialog.js'
import { toast } from '../lib/announce.js'
import { mix } from '../lib/mix.js'

const FIELDS = [
  ['Site', "who the email is from"], ['Org', "the organization's display name"], ['Name', "the recipient's full name"],
  ['Link', 'the link the email carries'], ['Expires', 'how long the link or code works'], ['Code', 'the sign-in code'],
  ['Left', 'recovery codes left'], ['LogoURL', "the logo's address"], ['PrimaryColor', "the organization's primary colour"],
]
const BODY = '{{template "body" .}}'

// completer offers the fields after "{{." and the body after "{{" in a layout.
function completer(isLayout) {
  return () => ({
    identifierRegexps: [/[a-zA-Z_0-9]/],
    getCompletions(editor, session, pos, prefix, callback) {
      const before = session.getLine(pos.row).slice(0, pos.column - prefix.length)
      if (/\{\{-?\s*(?:if\s+|with\s+|not\s+)?\.$/.test(before)) {
        callback(null, FIELDS.map(([name, doc], i) => ({ caption: '.' + name, value: name, meta: 'field', docText: doc, score: 100 - i })))
      } else if (isLayout() && /\{\{$/.test(before)) {
        callback(null, [{ caption: BODY, value: 'template "body" .}}', meta: 'body', docText: "where the email's body goes", score: 100 }])
      } else callback(null, [])
    },
  })
}

const partsOf = (tab) => (tab === 'layout'
  ? { html: 'layout_html', text: 'layout_text' }
  : { html: `emails.${tab}.html`, text: `emails.${tab}.text`, subject: `emails.${tab}.subject` })

// partOf reads one part ("layout_html", "emails.reset.subject") of a template set.
function partOf(set, part) {
  if (!set) return ''
  if (part === 'layout_html') return set.layout_html || ''
  if (part === 'layout_text') return set.layout_text || ''
  const [, name, kind] = part.split('.')
  return ((set.emails || {})[name] || {})[kind] || ''
}

const BADGE_CUSTOM = 'badge-accent'
const BADGE_DEFAULT = '' // the plain badge is the neutral one

export default function register(Alpine) {
  Alpine.data('adminEmails', () => {
    let ace = null // lib/ace.js, once loaded
    let htmlEd = null
    let textEd = null
    const sessions = {} // part -> Ace edit session
    let frameReady = false
    let pending = null // HTML waiting for the preview frame to be ready
    const saved = {} // part -> its text as saved (as the organization sends it)

    return mix(formMixin(), dialogMixin(), {
      apiBase: '', loading: true, loaded: false, loadError: '', saving: false,
      emails: [], own: null, inherited: null, primary: false, mailEnabled: false,
      tab: 'layout', subjects: {}, rev: 0,
      preview: { subject: '', html: '', text: '' }, previewName: '', previewView: 'html',

      async init() {
        this.apiBase = this.$el.dataset.api
        this.resetForm({ subject: '', to: this.$el.dataset.me || '' })
        window.addEventListener('message', (ev) => this.onFrameMessage(ev))
        window.addEventListener('beforeunload', (ev) => { if (this.dirty) { ev.preventDefault(); ev.returnValue = '' } })
        try {
          const [v, mod] = await Promise.all([get(this.apiBase), import('../lib/ace.js')])
          ace = mod
          this.apply(v)
          for (const e of this.emails) this.subjects[e.name] = this.effective(partsOf(e.name).subject)
          for (const tab of ['layout', ...this.emails.map((e) => e.name)]) {
            const p = partsOf(tab)
            sessions[p.html] = ace.newSession(this.effective(p.html), 'html')
            sessions[p.text] = ace.newSession(this.effective(p.text), 'text')
          }
          this.loaded = true
          await this.$nextTick()
          const opts = (name, mode) => ({
            mode, inputId: 'f-' + name, labelId: 'l-' + name, describedBy: ['h-' + name, 'e-' + name], minLines: 8, maxLines: 30,
            completer: completer(() => this.tab === 'layout'), onChange: () => this.edited(),
          })
          htmlEd = ace.createEditor(this.$refs.html, opts('html', 'html'))
          textEd = ace.createEditor(this.$refs.text, opts('text', 'text'))
          // the editors' inputs are the fields: they say when the server refused their text
          const mark = () => {
            for (const k of ['html', 'text']) {
              const el = document.getElementById('f-' + k)
              if (el) el.setAttribute('aria-invalid', this.invalid[k] === 'true' ? 'true' : 'false')
            }
          }
          this.$watch('invalid', mark)
          mark()
          this.showTab('layout')
          for (const p of this.allParts()) saved[p] = this.effective(p)
          this.rev++
        } catch (e) { this.loadError = e.message }
        this.loading = false
      },

      apply(v) {
        this.own = v.own
        this.inherited = v.inherited
        this.primary = v.primary
        this.emails = v.emails
        this.mailEnabled = v.mail_enabled
      },
      // effective is a part as the organization sends it: its own, else the inherited one.
      effective(part) { return partOf(this.own, part) || partOf(this.inherited, part) },
      value(part) {
        if (part.endsWith('.subject')) {
          const name = part.split('.')[1]
          return name === this.tab ? this.form.subject : (this.subjects[name] || '')
        }
        return sessions[part] ? sessions[part].getValue() : ''
      },
      // draft is every part as it is in the editors; the server keeps only those that differ from the inherited ones.
      draft() {
        const set = { layout_html: this.value('layout_html'), layout_text: this.value('layout_text'), emails: {} }
        for (const e of this.emails) {
          const p = partsOf(e.name)
          set.emails[e.name] = { subject: this.value(p.subject), html: this.value(p.html), text: this.value(p.text) }
        }
        return set
      },
      allParts() { return ['layout', ...this.emails.map((e) => e.name)].flatMap((t) => Object.values(partsOf(t))) },
      // setValue puts a text in a part's editor (undoable) or, for a subject, its field.
      setValue(part, text) {
        if (!part.endsWith('.subject')) { sessions[part].doc.setValue(text); return }
        const name = part.split('.')[1]
        if (name === this.tab) this.form.subject = text
        else this.subjects[name] = text
      },
      edited() { this.rev++ },
      get hasLoadError() { return this.loadError !== '' },
      get noMail() { return !this.mailEnabled },
      unsavedTab(tab) { return this.loaded && Object.values(partsOf(tab)).some((p) => this.value(p) !== saved[p]) },
      get dirty() { return this.rev >= 0 && this.loaded && ['layout', ...this.emails.map((e) => e.name)].some((t) => this.unsavedTab(t)) },
      get tabDirty() { void this.rev; return this.unsavedTab(this.tab) },
      get saveBlocked() { return this.busy || !this.tabDirty },
      get saveBusyAttr() { return this.saving ? 'true' : 'false' },
      get tabName() { return this.tabTitle.toLowerCase() },
      get saveLabel() { return this.saving ? 'Saving…' : `Save ${this.tabName}` },
      get resetLabel() { return `Use the default ${this.tabName}` },
      get inheritText() {
        return this.primary
          ? "These are the server's default templates: every organization sends them where it has none of its own. Parts left as they are follow the built-in templates."
          : "Parts left as they are follow the primary organization's templates (else the built-in ones), and change when those do."
      },

      // ---- tabs ----
      customTab(tab) {
        return Object.values(partsOf(tab)).some((p) => this.value(p) !== partOf(this.inherited, p))
      },
      get tabs() {
        void this.rev
        const all = [{ name: 'layout', title: 'Layout' }, ...this.emails]
        return all.map((e) => ({
          id: e.name, title: e.title, tabId: 'et-tab-' + e.name, selected: e.name === this.tab ? 'true' : 'false',
          tabindex: e.name === this.tab ? '0' : '-1', custom: this.loaded && this.customTab(e.name), unsaved: this.unsavedTab(e.name),
        }))
      },
      get panelLabel() { return 'et-tab-' + this.tab },
      get isEmailTab() { return this.tab !== 'layout' },
      get currentEmail() { return this.emails.find((e) => e.name === this.tab) || null },
      get tabTitle() { return this.currentEmail ? this.currentEmail.title : 'Layout' },
      get tabAbout() {
        return this.currentEmail ? this.currentEmail.about : "The header and footer of every email, around each email's body."
      },
      get tabIsDefault() { void this.rev; return !this.loaded || !this.customTab(this.tab) },
      get tabBadgeText() { return this.tabIsDefault ? 'Default' : 'Customized' },
      get tabBadgeClass() { return this.tabIsDefault ? BADGE_DEFAULT : BADGE_CUSTOM },
      get htmlHelp() {
        const e = this.currentEmail
        if (!e) return `HTML around every email's body: place the body with ${BODY}. Inline styles render in the most mail clients.`
        return 'Placed in the HTML layout.' + (e.needs ? ` It must show {{.${e.needs}}}.` : '')
      },
      get textHelp() {
        const e = this.currentEmail
        if (!e) return `The plain-text version, for mail clients that show no HTML: place the body with ${BODY}.`
        return 'Placed in the plain-text layout.' + (e.needs ? ` It must show {{.${e.needs}}}.` : '')
      },
      get htmlInvalid() { return this.invalid.html === 'true' ? 'true' : 'false' },
      get textInvalid() { return this.invalid.text === 'true' ? 'true' : 'false' },

      showTab(tab, keepErrors) {
        if (this.isEmailTab) this.subjects[this.tab] = this.form.subject
        this.tab = tab
        const p = partsOf(tab)
        if (htmlEd) htmlEd.setSession(sessions[p.html])
        if (textEd) textEd.setSession(sessions[p.text])
        this.form.subject = p.subject ? (this.subjects[tab] || '') : ''
        if (!keepErrors) this.clearErrors()
      },
      selectTab(ev) { this.showTab(ev.currentTarget.dataset.tab) },
      tabKey(ev) {
        const ids = this.tabs.map((t) => t.id)
        let i = ids.indexOf(this.tab)
        if (ev.key === 'ArrowRight') i = (i + 1) % ids.length
        else if (ev.key === 'ArrowLeft') i = (i - 1 + ids.length) % ids.length
        else if (ev.key === 'Home') i = 0
        else if (ev.key === 'End') i = ids.length - 1
        else return
        ev.preventDefault()
        this.showTab(ids[i])
        this.$nextTick(() => document.getElementById('et-tab-' + ids[i]).focus())
      },
      // resetTab, once confirmed, puts the inherited parts in this tab's editors (no other tab's; undoable in the
      // editors); saving the tab then drops the organization's own.
      async resetTab() {
        const parts = Object.values(partsOf(this.tab))
        const ok = await window.Alpine.store('confirm').ask({
          title: `Use the default ${this.tabName}?`,
          message: this.primary ? 'The default is the built-in one.' : "The default is the primary organization's, else the built-in one.",
          detail: `Your ${parts.length === 3 ? 'subject, HTML and plain text' : 'HTML and plain text'} in the editors will be replaced. Save the tab to keep it.`,
          confirmLabel: 'Use the default',
        })
        if (!ok) return
        for (const p of parts) this.setValue(p, partOf(this.inherited, p))
        this.edited()
        toast(`The default ${this.tabName} is in the editors. Save the tab to keep it.`)
      },

      // ---- errors: a part at fault is shown on its tab, with the line marked in the editor ----
      errorKey(field) {
        const m = /^layout_(html|text)$/.exec(field)
        const e = /^emails\.(\w+)\.(subject|html|text)$/.exec(field)
        if (m) { if (this.tab !== 'layout') this.showTab('layout', true); return m[1] }
        if (e) { if (this.tab !== e[1]) this.showTab(e[1], true); return e[2] }
        return field
      },
      clearAnnotations() {
        for (const s of Object.values(sessions)) s.clearAnnotations()
      },
      annotate() {
        for (const [kind, ed] of [['html', htmlEd], ['text', textEd]]) {
          const m = /^line (\d+): /.exec(this.errors[kind] || '')
          if (m && ed) {
            const row = Number(m[1]) - 1
            ed.session.setAnnotations([{ row, column: 0, text: this.errors[kind], type: 'error' }])
            ed.gotoLine(row + 1, 0, false)
          }
        }
      },
      async act(fn) {
        this.clearAnnotations()
        const res = await this.run(fn)
        if (!res) this.annotate()
        return res
      },

      // save saves the tab shown: its parts as they are in the editors, every other part as it is saved (the API
      // replaces the whole set). The server keeps a part blank or equal to the inherited one as inherited; the editors
      // are then given the text the organization sends.
      async save() {
        const mine = Object.values(partsOf(this.tab))
        const draft = this.draft()
        const set = { layout_html: '', layout_text: '', emails: {} }
        for (const p of this.allParts()) {
          // untouched parts go as stored ('' = inherited), so they keep following the inherited ones even if those
          // changed since the page loaded; an edit back to the inherited text goes as '' too
          const edited = mine.includes(p) && partOf(draft, p) !== saved[p]
          const text = edited && partOf(draft, p) !== partOf(this.inherited, p) ? partOf(draft, p) : (edited ? '' : partOf(this.own, p))
          if (p.startsWith('layout_')) set[p] = text
          else {
            const [, name, kind] = p.split('.')
            set.emails[name] = { ...set.emails[name], [kind]: text }
          }
        }
        const name = this.tabTitle
        this.saving = true
        const v = await this.act(() => put(this.apiBase, set))
        this.saving = false
        if (!v) return
        this.apply(v)
        for (const p of mine) {
          saved[p] = this.effective(p)
          if (this.value(p) !== saved[p]) this.setValue(p, saved[p])
        }
        this.edited()
        toast(`${name} saved. Every server uses it once it has replicated.`)
      },

      // ---- previews and test emails ----
      // previewEmail previews the tab's email, or on the layout tab the invitation in it.
      get previewFor() { return this.isEmailTab ? this.tab : 'invite' },
      get previewLabel() { return `Preview ${this.tabName}` },
      get previewHelp() {
        return this.isEmailTab
          ? 'Previews and test emails use the templates as they are in the editors, saved or not.'
          : 'The layout is previewed and tested around the invitation, as it is in the editors, saved or not.'
      },
      async previewEmail(ev) {
        const opener = ev.currentTarget
        const name = this.previewFor
        const res = await this.act(() => post(`${this.apiBase}/preview`, { templates: this.draft(), email: name }))
        if (!res) return
        this.preview = res
        this.previewName = name
        this.previewView = 'html'
        openDialog('email-preview', opener)
        this.showFrame(res.html)
      },
      get previewTitle() {
        const e = this.emails.find((x) => x.name === this.previewName)
        if (!this.isEmailTab) return 'Preview: Layout, with the ' + (e ? e.title.toLowerCase() : '')
        return 'Preview: ' + (e ? e.title : '')
      },
      get isHtmlView() { return this.previewView === 'html' },
      get isTextView() { return this.previewView === 'text' },
      get previewHtmlSelected() { return this.previewView === 'html' ? 'true' : 'false' },
      get previewTextSelected() { return this.previewView === 'text' ? 'true' : 'false' },
      get previewHtmlTabindex() { return this.previewView === 'html' ? '0' : '-1' },
      get previewTextTabindex() { return this.previewView === 'text' ? '0' : '-1' },
      selectView(ev) { this.previewView = ev.currentTarget.dataset.view },
      viewKey(ev) {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(ev.key)) return
        ev.preventDefault()
        this.previewView = this.previewView === 'html' ? 'text' : 'html'
        this.$nextTick(() => document.getElementById('pv-tab-' + this.previewView).focus())
      },
      showFrame(html) {
        const f = this.$refs.frame
        if (!frameReady || !f || !f.contentWindow) { pending = html; return }
        pending = null
        f.contentWindow.postMessage({ html }, '*') // the frame is sandboxed: its origin is opaque
      },
      onFrameMessage(ev) {
        const f = this.$refs.frame
        if (!f || ev.source !== f.contentWindow || !ev.data) return
        if (ev.data.previewReady) {
          frameReady = true
          if (pending !== null) this.showFrame(pending)
        } else if (typeof ev.data.previewHeight === 'number') {
          f.style.height = Math.min(Math.max(ev.data.previewHeight + 8, 240), 4000) + 'px'
        }
      },

      // ---- test emails: the tab's email (on the layout tab the invitation), to an address given in a dialog ----
      openTest(ev) {
        this.clearErrors()
        openDialog('email-test', ev.currentTarget)
      },
      get testAbout() {
        return this.isEmailTab
          ? `The ${this.tabName}, from the templates as they are in the editors (saved or not), with [Test] before its subject.`
          : 'The invitation, in the layout as it is in the editors (saved or not), with [Test] before its subject.'
      },
      get sendBlocked() { return this.busy || !this.mailEnabled },
      async sendTest() {
        const to = (this.form.to || '').trim()
        const res = await this.act(() => post(`${this.apiBase}/test`, { templates: this.draft(), email: this.previewFor, to }))
        if (res) {
          closeDialog('email-test')
          toast(`Test email queued for ${to}.`)
        } else if (!this.errors.to) {
          closeDialog('email-test') // a template at fault is shown under its editor
        }
      },
    })
  })
}
