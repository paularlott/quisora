// Avatars: the picture of a user, else their initials on a colour made from their id (the same user, the same colour
// everywhere). The markup is the "avatar" template (partials/shell.html), fed by avatarOf().
//
// An avatar is decoration: the name is always shown beside it, so it is hidden from assistive technology (alt="",
// aria-hidden). The colour is a data-tone (0-7) styled in components.css, never an inline style (the page's CSP).

const TONES = 8

// toneOf maps an id to one of the avatar colours (FNV-1a).
export function toneOf(id) {
  let h = 0x811c9dc5
  for (const c of String(id || '')) { h ^= c.codePointAt(0); h = Math.imul(h, 0x01000193) >>> 0 }
  return h % TONES
}

// initialsOf: the first letters of the given and family name; else the first of the username; else of the full name.
export function initialsOf(u) {
  const first = (s) => Array.from(String(s || '').trim())[0] || ''
  const i = first(u.given_name) + first(u.family_name)
  return (i || first(u.username) || first(u.name) || '?').toUpperCase()
}

// avatarOf describes how to draw a user (the JSON of the management or account API; a directory entry has no picture).
export function avatarOf(u) {
  const picture = (u && u.picture) || ''
  return { picture, src: picture || undefined, hasPicture: picture !== '', noPicture: picture === '', initials: initialsOf(u || {}), tone: String(toneOf(u && u.id)) }
}

export default function (Alpine) {
  // The avatar in the header's account menu: the signed-in user's own, drawn from the page's data attributes (the
  // layout knows the user), and redrawn when they change their picture on this page (picture-changed).
  Alpine.data('headerAvatar', () => ({
    a: avatarOf({}),
    init() {
      const d = this.$el.dataset
      const user = { id: d.id, given_name: d.given, family_name: d.family, username: d.username, picture: d.picture }
      this.a = avatarOf(user)
      window.addEventListener('picture-changed', (ev) => {
        if (ev.detail.id === user.id) { user.picture = ev.detail.picture || ''; this.a = avatarOf(user) }
      })
    },
  }))
}
