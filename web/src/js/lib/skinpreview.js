// The skin preview dialog (partials/admin.html, "skin-preview-dialog"): a page of the server in a skin, framed: an
// organization's sign-in page, or the page the dialog is opened from. The server shows a page's ?skin= instead of its
// own skin and lets this site frame it (a skin there is, "default" for Quisora's own look, "inherit" for the primary
// organization's). Alpine's CSP build binds nothing on an iframe, so the frame's address is set here (showFrame).
import { openDialog } from './dialog.js'

export function skinPreviewMixin() {
  return {
    pv: { active: false, skin: '', title: '', base: '', view: 'login' },
    // showSkinPreview opens the dialog on skin (named title), with base the organization's address (/o/<org>), by
    // default the signed-in user's.
    showSkinPreview(opener, skin, title, base) {
      this.pv = { active: true, skin, title, base: base || document.documentElement.dataset.orgBase || '', view: 'login' }
      openDialog('skin-preview', opener)
      this.showFrame()
    },
    showFrame() {
      const f = this.$refs.pvframe
      if (!f) return
      f.title = this.pvFrameTitle
      f.src = this.pvSrc
    },
    get pvTitle() { return 'Preview: ' + this.pv.title },
    get pvSrc() {
      if (!this.pv.active) return 'about:blank'
      const q = '?skin=' + encodeURIComponent(this.pv.skin)
      return this.pv.view === 'login' ? this.pv.base + '/login' + q : location.pathname + q
    },
    get pvFrameTitle() { return (this.pv.view === 'login' ? 'The sign-in page' : 'This page') + ' in ' + this.pv.title },
    get pvLoginSelected() { return this.pv.view === 'login' ? 'true' : 'false' },
    get pvPageSelected() { return this.pv.view === 'page' ? 'true' : 'false' },
    get pvLoginTabindex() { return this.pv.view === 'login' ? '0' : '-1' },
    get pvPageTabindex() { return this.pv.view === 'page' ? '0' : '-1' },
    get pvPanelLabel() { return 'pvs-tab-' + this.pv.view },
    selectPv(ev) { this.pv.view = ev.currentTarget.dataset.view; this.showFrame() },
    pvKey(ev) {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(ev.key)) return
      ev.preventDefault()
      this.pv.view = this.pv.view === 'login' ? 'page' : 'login'
      this.showFrame()
      this.$nextTick(() => document.getElementById('pvs-tab-' + this.pv.view).focus())
    },
  }
}
