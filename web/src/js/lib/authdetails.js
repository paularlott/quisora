// Authorization details (RFC 9396) as the console edits them: a JSON array in a text area (the "authorization_details"
// field of tenant access entries and of clients).

// detailsText is the text area's text for stored details: indented JSON, empty for none.
export function detailsText(v) { return Array.isArray(v) && v.length ? JSON.stringify(v, null, 2) : '' }

// parseDetails reads the text area: { value } (an array; empty text is none) or { error } when it is not a JSON array.
// The server checks the rest (each object needs a type, the limits, the placeholders).
export function parseDetails(text) {
  const t = (text || '').trim()
  if (!t) return { value: [] }
  try {
    const v = JSON.parse(t)
    if (Array.isArray(v)) return { value: v }
  } catch { /* reported below */ }
  return { error: 'Enter a JSON array of objects, each with a type, such as [{"type": "https://example.com/detail"}].' }
}
