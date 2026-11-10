// Moving focus to an element that the same state change shows.
//
// Alpine's x-show reveals an element on the next animation frame, but $nextTick runs on a timer that can fire before
// that frame: focus() on an element still display:none does nothing, and keyboard and screen reader users are left on
// <body>. focusWhenShown tries once the change has reached the DOM (where $nextTick did: an element already shown has
// the focus before the next key press), then each frame until the element is shown (half a second at most).

// isShown: the element is rendered (not display:none, itself or an ancestor).
export const isShown = (el) => el.offsetParent !== null || getComputedStyle(el).position === 'fixed'

// target is an id, an element, or a function that finds it (for one the same change renders, or replaces).
export function focusWhenShown(target) {
  const find = typeof target === 'function' ? target : typeof target === 'string' ? () => document.getElementById(target) : () => target
  const attempt = (left) => {
    const el = find()
    if (el && isShown(el)) el.focus()
    else if (left > 0) requestAnimationFrame(() => attempt(left - 1))
  }
  setTimeout(() => attempt(30))
}
