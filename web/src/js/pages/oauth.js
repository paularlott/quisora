// OAuth pages: consent, sign-out confirmation and the auto-submitting form_post response.
import { post } from '../lib/api.js'

function message(e) {
  return (e && e.message) || 'Something went wrong. Please try again.'
}

export default function (Alpine) {
  Alpine.data('oauthConsent', () => ({
    busy: false,
    error: '',
    // closed: the request can no longer be decided (it expired, or belongs to another browser or organization), so
    // Allow and Deny give way to a link back to the application.
    closed: false,
    flow: '',
    // Read the root's data attributes here: in a handler, this.$el is the element the handler is on (the button).
    init() { this.flow = this.$el.dataset.flow || '' },
    async decide(approve) {
      if (this.busy) return
      this.busy = true
      this.error = ''
      try {
        const res = await post('/api/oauth/consent', { flow: this.flow, approve })
        window.location.assign(res.redirect)
      } catch (e) {
        this.error = message(e)
        if (e && (e.status === 403 || e.status === 404)) {
          this.closed = true // the clicked button is gone: keep focus on the page, on the way back where there is one
          this.$nextTick(() => { if (this.$refs.back) this.$refs.back.focus() })
          return
        }
        this.busy = false
      }
    },
    approve() { return this.decide(true) },
    deny() { return this.decide(false) },
  }))

  // form_post response mode: the server renders a form with the response parameters; submit it at once.
  Alpine.data('oauthAutoPost', () => ({
    init() { this.$el.submit() },
  }))
}
