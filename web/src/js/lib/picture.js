// Choosing, replacing and removing a profile picture: shared by the account page and the user page of the console.
// Compose into a component that has formMixin() (the error shows at #f-image, the picture's button, see lib/form.js):
//   pictureMixin(Alpine, { path: (vm) => the picture's endpoint, who: (vm) => { self, title }, apply: (vm, user) => ... })
// The file is read in the browser into a data: URI and sent as JSON; the server crops it to a square. The same limits
// the server has are checked first, with its messages, so a wrong file is refused without sending it.
import { ApiError, put, del } from './api.js'
import { toast } from './announce.js'
import { avatarOf } from './avatar.js'
import { focusWhenShown } from './focus.js'

export const PICTURE_MAX = 5 * 1024 * 1024
export const PICTURE_TYPES = ['image/jpeg', 'image/png', 'image/webp']
export const PICTURE_TOO_LARGE = 'The image is larger than 5 MB.'
export const PICTURE_FORMAT = 'Use a JPEG, PNG or WebP image.'

const readDataUrl = (file) => new Promise((resolve, reject) => {
  const r = new FileReader()
  r.onload = () => resolve(r.result)
  r.onerror = () => reject(new Error('The image could not be read.'))
  r.readAsDataURL(file)
})

// checkPicture is the message about a file the server would refuse, or ''.
export function checkPicture(file) {
  if (!PICTURE_TYPES.includes(file.type)) return PICTURE_FORMAT
  if (file.size > PICTURE_MAX) return PICTURE_TOO_LARGE
  return ''
}

export function pictureMixin(Alpine, { path, who, apply }) {
  return {
    pic: null, // the user as the API gave it (picture: its URL)
    canChange: true,
    setPictureUser(u) { this.pic = u },
    get picAvatar() { return avatarOf(this.pic || {}) },
    get picHas() { return !!this.pic && !!this.pic.picture },
    get picNone() { return !this.picHas },
    get picReadOnly() { return !this.canChange },

    // picAction is the name of the picture's button: what choosing it does.
    get picAction() { return this.picHas ? 'Change picture' : 'Upload a picture' },
    // choosePicture: the picture's button opens the file chooser of the hidden input #f-image-file. Nothing while the
    // picture cannot be changed or a change runs.
    choosePicture() {
      if (!this.canChange || this.busy) return
      const input = this.$root.querySelector('#f-image-file')
      if (input) input.click()
    },

    async pickPicture(ev) {
      const input = ev.target
      const file = input.files[0]
      if (!file) return
      const bad = checkPicture(file)
      if (bad) {
        input.value = ''
        this.setErrors(new ApiError(422, { error: bad, field: 'image' }))
        return
      }
      const res = await this.run(async () => put(path(this), { image: await readDataUrl(file) }))
      input.value = ''
      if (!res) return
      this.picturePlaced(res, 'Picture saved.')
    },

    async removePicture(ev) {
      const w = who(this)
      const yes = await Alpine.store('confirm').ask({ title: 'Remove picture', message: w.self ? 'Remove your picture?' : `Remove the picture of ${w.title}?`,
        detail: 'Initials are shown instead.', confirmLabel: 'Remove picture' })
      if (!yes) return
      const res = await this.run(() => del(path(this)))
      if (!res) return
      this.picturePlaced(res, 'Picture removed.')
      focusWhenShown('f-image') // the Remove button has gone: back to the picture
    },

    picturePlaced(res, text) {
      const u = res.user || res // the account API wraps the user, the management API returns it
      this.setPictureUser(u)
      window.dispatchEvent(new CustomEvent('picture-changed', { detail: { id: u.id, picture: u.picture || '' } }))
      toast(text)
      if (apply) apply(this, u)
    },
  }
}
