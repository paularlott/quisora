// Email addresses of a user: the primary address and the linked ones (used to match sign-ins from GitHub, Google and
// other providers). One mixin serves the account page and the admin user page. Adding and removing addresses is a
// manager's job (the admin user page; managers and up also on their own account page, re-authenticated): set
// this.manage = false and only verifying, resending and making a verified address primary remain. New addresses are
// unverified until the link mailed to them is followed (on the admin page only when email is set up), or until a
// manager marks them verified (the admin user page, when the user's can_verify_email says so: never your own).
//
// Compose with formMixin(): mix(formMixin(), emailsMixin({...}), {...}). cfg:
//   load()            -> Promise of the user (primary: email/email_verified, linked_emails)
//   url(suffix)       -> URL below the address list ('' = the list itself, '/<addr>', '/<addr>/primary', '/<addr>/verify')
//   guard(fn, opener, vm) -> runs fn, handling re-authentication where needed (default: just run it)
//   canResend (bool)  -> whether an unverified address can be mailed a verification link again
//   self (bool)       -> wording for the signed-in user vs. an administrator
//   manage (bool)     -> initial this.manage: whether addresses can be added and removed (default true)
// Template contract (partials/emails.html): the add dialog has id="email-add-dialog", the input id="f-em_address".
// The emails mixin includes the dialog helpers (lib/dialog.js).
import { ApiError, post, del } from './api.js'
import { announce, toast } from './announce.js'
import { closeDialog, dialogMixin, openDialog } from './dialog.js'
import { mix } from './mix.js'

const enc = encodeURIComponent
const userOf = (r) => (r && r.user) || r
const mailOn = () => document.documentElement.dataset.mail === '1'

export function emailsMixin(cfg) {
  const guard = cfg.guard || ((fn) => fn())
  return mix(dialogMixin(), {
    primary: { address: '', verified: false }, items: [], emailsLoading: true, emailsError: '', pending: false, canMark: false,
    manage: cfg.manage !== false,

    async loadEmails() {
      try { this.setEmails(await cfg.load.call(this)); this.emailsError = '' } catch (e) { this.emailsError = e.message } finally { this.emailsLoading = false }
    },
    setEmails(u) {
      if ('can_verify_email' in u) this.canMark = !!u.can_verify_email // only on GET of one user: kept otherwise
      this.primary = { address: u.email, verified: !!u.email_verified, canResend: !!u.email && !u.email_verified && !!cfg.canResend && mailOn() }
      this.items = (u.linked_emails || []).map((l) => ({
        address: l.address, verified: !!l.verified,
        badgeText: l.verified ? 'Verified' : 'Unverified', badgeClass: l.verified ? 'badge badge-success' : 'badge badge-warning',
        canResend: !l.verified && !!cfg.canResend && mailOn(), canPrimary: !!l.verified, canMark: !l.verified && this.canMark,
        forAddress: ' for ' + l.address, removeLabel: 'Remove ' + l.address,
      }))
    },
    notify(u) { if (cfg.changed) cfg.changed.call(this, u) },
    get primaryBadge() { return this.primary.verified ? 'Verified' : 'Not verified' },
    get primaryBadgeClass() { return this.primary.verified ? 'badge badge-success' : 'badge badge-warning' },
    get hasItems() { return this.items.length > 0 },
    get canMarkPrimary() { return this.canMark && !this.primary.verified },
    get forPrimary() { return ' for ' + this.primary.address },
    // The card: always where addresses can be managed; otherwise once there is more than the primary address, or the
    // primary is not verified yet (its link is sent from here). One verified address: the page's header says it all.
    get showCard() { return this.manage || this.items.length > 0 || (!!this.primary.address && !this.primary.verified) },
    get primaryActions() { return this.primary.canResend || this.canMarkPrimary },
    // without email on the server an unverified address has no way to be verified here (said once; mailOff says more)
    get noMailToVerify() { return !mailOn() && !this.mailOff && ((!!this.primary.address && !this.primary.verified) || this.items.some((i) => !i.verified)) },
    get locked() { return !this.manage },
    get hasEmailsError() { return this.emailsError !== '' },
    // Self-service additions are verified by a mailed link: without email set up on the server they cannot be made.
    get mailOff() { return this.manage && !!cfg.self && !mailOn() },
    get canAdd() { return this.manage && !this.emailsLoading && this.items.length < 10 && !this.mailOff },
    get atLimit() { return this.manage && !this.emailsLoading && this.items.length >= 10 },
    get addLabel() { return this.busy ? 'Adding…' : 'Add' },

    // Later than the close handler of a dialog that was open (re-authentication, confirmation), which restores focus itself
    // to the button that opened it, or to the page's fallback when that is gone. Only focus that was lost is moved (that
    // button went with its row or is hidden now, or the fallback took it): focus on a control still in view is where the
    // dialog or the user put it, and is left there.
    focusAddButton() {
      setTimeout(() => {
        const a = document.activeElement
        const lost = !a || a === document.body || a.id === 'main' || a.hasAttribute('data-return-focus') || !a.isConnected || a.offsetParent === null
        if (!lost) return
        const b = document.getElementById('email-add-btn')
        if (b && b.offsetParent !== null) b.focus(); else { const h = document.getElementById('emails-h'); if (h) h.focus() }
      }, 80)
    },
    openAdd(ev) {
      this.resetForm({ em_address: '' })
      openDialog('email-add-dialog', ev.currentTarget)
    },

    async submitAdd() {
      const address = (this.form.em_address || '').trim()
      if (address === '') { this.setErrors(new ApiError(422, { error: 'Enter an email address.', field: 'em_address' })); return }
      const opener = document.activeElement
      const res = await this.run(async () => {
        try { return await guard(() => post(cfg.url.call(this, ''), { address }), opener, this) } catch (e) {
          if (e instanceof ApiError && (e.field === 'address' || e.field === 'email')) e.field = 'em_address'
          throw e
        }
      })
      if (!res) return
      this.setEmails(userOf(res))
      this.notify(userOf(res))
      closeDialog('email-add-dialog') // focus goes back to the Add email button (or the heading at the limit)
      const added = (userOf(res).linked_emails || []).find((l) => l.address.toLowerCase() === address.toLowerCase())
      toast(added && !added.verified
        ? 'Added ' + address + '. ' + (cfg.self ? 'Follow the link we emailed to it to verify it.' : 'We emailed the user a link to verify it.')
        : 'Added ' + address + '.')
    },
    async resend(ev) {
      const address = ev.currentTarget.dataset.address
      if (this.pending) return
      this.pending = true
      try { await post(cfg.url.call(this, '/' + enc(address) + '/verify')); toast('Verification link sent to ' + address + '.') } catch (e) { toast(e.message, 'error') } finally { this.pending = false }
    },
    async markVerified(ev) {
      const address = ev.currentTarget.dataset.address
      const ok = await window.Alpine.store('confirm').ask({ title: 'Mark as verified', message: 'Mark ' + address + ' as verified?',
        detail: 'Only do this if you know this person receives email at this address. Sign-ins from providers that use it will find this account, and applications are told it is verified.',
        confirmLabel: 'Mark as verified', danger: false })
      if (!ok) return
      try {
        const r = await post(cfg.url.call(this, '/' + enc(address) + '/mark-verified'))
        this.setEmails(userOf(r))
        this.notify(userOf(r))
        toast(address + ' is now verified.')
        announce(address + ' is now verified.')
        this.focusAddButton()
      } catch (e) { toast(e.message, 'error') }
    },
    async makePrimary(ev) {
      const address = ev.currentTarget.dataset.address
      const opener = ev.currentTarget
      const ok = await window.Alpine.store('confirm').ask({ title: 'Make primary', message: 'Make ' + address + ' the primary address?',
        detail: 'Password sign-in and password resets use the primary address. The current primary address, ' + this.primary.address + ', stays linked.',
        confirmLabel: 'Make primary', danger: false })
      if (!ok) return
      try {
        const r = await guard(() => post(cfg.url.call(this, '/' + enc(address) + '/primary')), opener, this)
        this.setEmails(userOf(r))
        this.notify(userOf(r))
        toast(address + ' is now the primary address.')
        announce(address + ' is now the primary address.')
        this.focusAddButton()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
    async remove(ev) {
      const address = ev.currentTarget.dataset.address
      const opener = ev.currentTarget
      const ok = await window.Alpine.store('confirm').ask({ title: 'Remove email address', message: 'Remove ' + address + '?',
        detail: 'Sign-ins from providers that use this address will no longer find ' + (cfg.self ? 'your account' : 'this account') + '.', confirmLabel: 'Remove address' })
      if (!ok) return
      try {
        const r = await guard(() => del(cfg.url.call(this, '/' + enc(address))), opener, this)
        this.setEmails(userOf(r))
        this.notify(userOf(r))
        toast('Removed ' + address + '.')
        this.focusAddButton()
      } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'error') }
    },
    // After the add dialog closes: when the list just reached its limit the Add button is gone, so focus the heading.
    afterClose(id) { if (id === 'email-add-dialog') this.focusAddButton() },
  })
}
