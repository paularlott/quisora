// The skins of the server (/admin/skins, super admins): the built-in ones, which can be viewed and copied, and the
// custom ones, added, changed and removed here. A skin's stylesheet is edited in an Ace editor (CSS); a skin is
// previewed by opening a page with ?skin=<name>. Organizations choose theirs on their branding (pages/admin.js).
import { get, post, patch, del } from '../lib/api.js'
import { formMixin } from '../lib/form.js'
import { dialogMixin, openDialog, closeDialog } from '../lib/dialog.js'
import { focusWhenShown } from '../lib/focus.js'
import { toast } from '../lib/announce.js'
import { mix } from '../lib/mix.js'
import { fmtDate } from '../lib/format.js'
import { skinPreviewMixin } from '../lib/skinpreview.js'

// STARTER is a new skin's stylesheet: [data-skin] styles whichever skin is chosen, so it works under any name.
const STARTER = `/* A skin sets the design tokens of the pages (web/src/css/tokens.css) under :root[data-skin].
   Use light-dark(light, dark) for colours that differ between the themes. Start from a copy of Matte for a full set. */
:root[data-skin] {
  --accent-solid: light-dark(#1d4ed8, #2563eb);
  --accent: light-dark(#1d4ed8, #9db6f5);
}
`

// generic makes a copied stylesheet's selectors name any skin ([data-skin]) rather than the one it was copied from.
const generic = (css, from) => css.replace(new RegExp(`\\[\\s*data-skin\\s*=\\s*(["']?)${from}\\1(\\s+[is])?\\s*\\]`, 'g'), '[data-skin]')

export default function register(Alpine) {
  Alpine.data('adminSkins', () => {
    let ace = null // lib/ace.js, once loaded
    let editor = null

    return mix(formMixin(), dialogMixin(), skinPreviewMixin(), {
      items: [], loading: true, loaded: false, loadError: '', editing: null, builtin: false, savedCSS: '', rev: 0,

      async init() {
        this.$watch('invalid', () => {
          const el = document.getElementById('f-css')
          if (el) el.setAttribute('aria-invalid', this.invalid.css === 'true' ? 'true' : 'false')
        })
        await this.load()
      },
      async load() {
        try {
          const r = await get('/api/skins')
          this.items = r.items.map((k) => ({
            ...k, kind: k.builtin ? 'Built-in' : 'Custom', kindClass: k.builtin ? '' : 'badge-accent',
            updatedText: k.updated ? fmtDate(k.updated) : '—', custom: !k.builtin,
            openLabel: (k.builtin ? 'View ' : 'Edit ') + k.display_name, deleteLabel: 'Remove ' + k.display_name,
            previewLabel: 'Preview ' + k.display_name,
          }))
          this.loadError = ''
          this.loaded = true
        } catch (e) { this.loadError = e.message }
        this.loading = false
      },
      get hasLoadError() { return this.loadError !== '' },
      preview(ev) {
        const k = this.items.find((x) => x.name === ev.currentTarget.dataset.name)
        if (k) this.showSkinPreview(ev.currentTarget, k.name, k.display_name)
      },
      get customOnes() { return this.items.filter((k) => !k.builtin) },

      async ensureEditor() {
        if (editor) return
        ace = await import('../lib/ace.js')
        editor = ace.createEditor(this.$refs.css, {
          mode: 'css', inputId: 'f-css', labelId: 'l-css', describedBy: ['h-css', 'e-css'], minLines: 14, maxLines: 28,
          onChange: () => { this.rev++ },
        })
      },
      setCSS(css, readOnly) {
        editor.session.setValue(css)
        editor.setReadOnly(readOnly)
        this.savedCSS = css
        this.rev++
      },

      // ---- the dialog: add (from blank or a copy of another skin), change a custom skin, or view a built-in one ----
      get isCreate() { return this.editing === null },
      get dialogTitle() {
        if (this.isCreate) return 'New skin'
        return (this.builtin ? '' : 'Edit ') + (this.form.display_name || this.editing)
      },
      get readOnly() { return this.builtin },
      get cancelLabel() { return this.builtin ? 'Close' : 'Cancel' },
      get submitLabel() { return this.busy ? 'Saving…' : this.isCreate ? 'Add skin' : 'Save skin' },
      get saveDisabled() { return this.busy },
      get cssHelp() {
        if (this.editing === 'default') return "Default is Quisora's own look and has no stylesheet. These are its design tokens, ready to copy into a new skin."
        return this.builtin
          ? "Built-in skins can't be changed. Copy it to make your own version."
          : "Plain CSS, up to 256 KB. Set the design tokens under :root[data-skin]. Fonts and images from other sites won't load. Saved changes show straight away. Ctrl+F (⌘F on a Mac) searches."
      },
      async openCreate(ev, css) {
        const opener = ev && ev.currentTarget
        this.editing = null
        this.builtin = false
        this.resetForm({ name: '', display_name: '', start: '' })
        openDialog('skin-dialog', opener)
        await this.ensureEditor()
        this.setCSS(css || STARTER, false)
      },
      // startFrom copies another skin's stylesheet into a new one, its selectors made to style any skin.
      async startFrom() {
        const from = this.form.start
        if (!from) { this.setCSS(STARTER, false); return }
        const k = await this.run(() => get('/api/skins/' + encodeURIComponent(from)))
        if (k) this.setCSS(generic(k.css, from), false)
      },
      async open(ev) {
        const name = ev.currentTarget.dataset.name
        const k = await this.run(() => get('/api/skins/' + encodeURIComponent(name)))
        if (!k) return
        this.editing = k.name
        this.builtin = k.builtin
        this.resetForm({ name: k.name, display_name: k.display_name, start: '' })
        openDialog('skin-dialog', ev.currentTarget)
        await this.ensureEditor()
        this.setCSS(k.css, k.builtin)
      },
      // copy turns the built-in skin being viewed into a new custom skin from a copy of it.
      copyBuiltin() {
        const from = this.editing
        const css = generic(editor.getValue(), from)
        this.editing = null
        this.builtin = false
        this.resetForm({ name: from + '-copy', display_name: this.form.display_name + ' (copy)', start: from })
        this.setCSS(css, false)
        focusWhenShown('f-name')
      },
      errorKey(f) { return f },
      async submit() {
        if (this.builtin) return
        const css = editor.getValue()
        const f = this.form
        const res = await this.run(() => this.isCreate
          ? post('/api/skins', { name: f.name.trim(), display_name: f.display_name.trim(), css })
          : patch('/api/skins/' + encodeURIComponent(this.editing), { display_name: f.display_name.trim(), css }))
        if (!res) return
        closeDialog('skin-dialog')
        toast(this.isCreate ? `Skin “${res.display_name}” added.` : `Skin “${res.display_name}” saved.`)
        this.load()
      },
      async remove(ev) {
        const k = this.items.find((x) => x.name === ev.currentTarget.dataset.name)
        if (!k) return
        const yes = await Alpine.store('confirm').ask({ title: 'Remove the skin?', message: `Remove “${k.display_name}”?`,
          detail: "Organizations using it switch to the primary organization's skin until they pick another (the primary organization switches to Default). This can't be undone.",
          confirmLabel: 'Remove skin' })
        if (!yes) return
        try {
          await del('/api/skins/' + encodeURIComponent(k.name))
          toast(`Skin “${k.display_name}” removed.`)
          this.load()
        } catch (e) { toast(e.message, 'error') }
      },
    })
  })
}
