// Authorization details (RFC 9396) as the console edits them: a JSON array in a code editor (the "authorization_details"
// field of tenant access entries and of clients, partial "details-field", lib/detailsfield.js).
//
// checkDetails reads the text with a small JSON parser of its own, which knows where each value starts, so every
// problem has a line and column for the editor's gutter, and the messages are the same in every browser. It checks
// what the server checks (internal/model/authdetails.go: each object has a type, the common fields' shapes, the
// limits, the placeholders) and, as warnings, what the server accepts but would leave out of every token: a type the
// application is not registered for.

export const MAX_DETAILS = 16
export const MAX_BYTES = 8192
const MAX_TYPE = 256

// The common fields (RFC 9396 §2.2), offered by the editor's completion.
export const COMMON_FIELDS = [
  { name: 'type', doc: 'The kind of authorization detail, as the API defines it. Required.' },
  { name: 'actions', doc: 'What may be done, as the API names it: an array of strings.' },
  { name: 'locations', doc: 'The APIs it is for: an array of addresses. Only tokens for one of them carry it.' },
  { name: 'datatypes', doc: 'The kinds of data that may be reached: an array of strings.' },
  { name: 'identifier', doc: 'One resource at the API: a string.' },
  { name: 'privileges', doc: 'Levels of access: an array of strings.' },
]
const ARRAY_FIELDS = ['locations', 'actions', 'datatypes', 'privileges']

// The placeholders filled in when a token is minted.
export const PLACEHOLDERS = [
  { name: '{{sub}}', doc: 'The user\u2019s id (for a client\u2019s own tokens, its client ID).' },
  { name: '{{org}}', doc: 'The organization\u2019s id.' },
  { name: '{{tenant}}', doc: 'The tenant\u2019s id.' },
]
const PLACEHOLDER_NAMES = PLACEHOLDERS.map((p) => p.name)

// detailsText is the editor's text for stored details: indented JSON, empty for none.
export function detailsText(v) { return Array.isArray(v) && v.length ? JSON.stringify(v, null, 2) : '' }

class SyntaxProblem extends Error {
  constructor(message, offset) { super(message); this.offset = offset }
}

// parse reads JSON text into nodes that keep their offsets: { kind, start, value } with, for objects, entries
// [{ key, keyStart, node }] and, for arrays, items [node]. It throws a SyntaxProblem at the first error.
function parse(text) {
  let i = 0
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++ }
  const fail = (msg, at = i) => { throw new SyntaxProblem(msg, at) }
  const describe = (at) => (at >= text.length ? 'the end of the text' : `\u201c${text[at]}\u201d`)
  function str() {
    const start = i++
    let out = ''
    for (;;) {
      if (i >= text.length) fail('This string is not closed: add a closing quote (").', start)
      const c = text[i]
      if (c === '"') { i++; return { kind: 'string', start, value: out } }
      if (c === '\\') {
        const e = text[i + 1]
        const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
        if (e in simple) { out += simple[e]; i += 2; continue }
        if (e === 'u' && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) { out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16)); i += 6; continue }
        fail('This escape is not valid in JSON.')
      }
      if (c < ' ') fail(c === '\n' ? 'This string is not closed before the end of the line: add a closing quote (").' : 'Control characters must be escaped in a string.')
      out += c; i++
    }
  }
  function value() {
    ws()
    const start = i
    const c = text[i]
    if (c === '{') {
      i++; ws()
      const entries = []
      if (text[i] === '}') { i++; return { kind: 'object', start, entries } }
      for (;;) {
        ws()
        if (text[i] === "'") fail('Use double quotes (") in JSON, not single quotes.')
        if (text[i] !== '"') fail(text[i] === '}' ? 'Remove the comma before \u201c}\u201d.' : `Expected a field name in double quotes, found ${describe(i)}.`)
        const k = str()
        ws()
        if (text[i] !== ':') fail(`Expected \u201c:\u201d after the field name, found ${describe(i)}.`)
        i++
        entries.push({ key: k.value, keyStart: k.start, node: value() })
        ws()
        if (text[i] === ',') { i++; continue }
        if (text[i] === '}') { i++; return { kind: 'object', start, entries } }
        fail(`Expected \u201c,\u201d or \u201c}\u201d, found ${describe(i)}.`)
      }
    }
    if (c === '[') {
      i++; ws()
      const items = []
      if (text[i] === ']') { i++; return { kind: 'array', start, items } }
      for (;;) {
        ws()
        if (text[i] === ']') fail('Remove the comma before \u201c]\u201d.')
        items.push(value())
        ws()
        if (text[i] === ',') { i++; continue }
        if (text[i] === ']') { i++; return { kind: 'array', start, items } }
        fail(`Expected \u201c,\u201d or \u201c]\u201d, found ${describe(i)}.`)
      }
    }
    if (c === '"') return str()
    const lit = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i))
    if (lit) { i += lit[0].length; return { kind: lit[0] === 'null' ? 'null' : /^[tf]/.test(lit[0]) ? 'boolean' : 'number', start } }
    if (c === "'") fail('Use double quotes (") in JSON, not single quotes.')
    fail(i >= text.length ? 'The text ends too soon: something is not closed.' : `Expected a value, found ${describe(i)}.`)
  }
  const root = value()
  ws()
  if (i < text.length) fail(`Unexpected ${describe(i)} after the end of the array.`)
  return root
}

// position is the 0-based row and column of offset in text.
function position(text, offset) {
  const before = text.slice(0, offset)
  const row = (before.match(/\n/g) || []).length
  return { row, column: offset - (before.lastIndexOf('\n') + 1) }
}

// checkDetails reads the editor's text. types are the authorization details types the application(s) are registered
// for (null: not known, so not checked). It returns { value, problems }: value is the array to send ([] for an empty
// text), or null when there is an error; problems are { severity: 'error' | 'warning', message, offset, row, column },
// in the order of the text.
export function checkDetails(text, types = null) {
  const problems = []
  const add = (severity, message, offset) => problems.push({ severity, message, offset, ...position(text, offset) })
  if (!(text || '').trim()) return { value: [], problems }
  let root
  try {
    root = parse(text)
  } catch (e) {
    if (!(e instanceof SyntaxProblem)) throw e
    add('error', e.message, e.offset)
    return { value: null, problems }
  }
  if (root.kind !== 'array') {
    add('error', 'Authorization details are a JSON array: put the objects in [ ].', root.start)
    return { value: null, problems }
  }
  if (root.items.length > MAX_DETAILS) add('error', `At most ${MAX_DETAILS} authorization details are allowed.`, root.items[MAX_DETAILS].start)
  root.items.forEach((item, n) => {
    if (item.kind !== 'object') { add('error', `Authorization detail ${n + 1} must be a JSON object ({ }).`, item.start); return }
    const field = (name) => item.entries.find((e) => e.key === name)
    const type = field('type')
    if (!type) add('error', `Authorization detail ${n + 1} needs a type.`, item.start)
    else if (type.node.kind !== 'string' || !type.node.value || type.node.value.length > MAX_TYPE || /\s/.test(type.node.value)) {
      add('error', `The type must be a string of up to ${MAX_TYPE} characters without spaces.`, type.node.start)
    } else if (types && !types.includes(type.node.value)) {
      add('warning', `\u201c${type.node.value}\u201d is not one of the application\u2019s authorization details types, so its tokens leave this out.`, type.node.start)
    }
    for (const name of ARRAY_FIELDS) {
      const f = field(name)
      if (!f) continue
      if (f.node.kind !== 'array') add('error', `${name} must be an array of strings.`, f.node.start)
      else for (const el of f.node.items) if (el.kind !== 'string') { add('error', `${name} must hold only strings.`, el.start); break }
    }
    const id = field('identifier')
    if (id && id.node.kind !== 'string') add('error', 'identifier must be a string.', id.node.start)
  })
  // Placeholders, in every string value (keys are left as they are).
  const walk = (node) => {
    if (node.kind === 'string') {
      const rest = PLACEHOLDER_NAMES.reduce((s, p) => s.split(p).join(''), node.value)
      if (rest.includes('{{')) add('error', 'Unknown placeholder: only {{sub}}, {{org}} and {{tenant}} are filled in.', node.start)
    } else if (node.kind === 'array') node.items.forEach(walk)
    else if (node.kind === 'object') node.entries.forEach((e) => walk(e.node))
  }
  walk(root)
  const value = JSON.parse(text)
  if (new TextEncoder().encode(JSON.stringify(value)).length > MAX_BYTES) add('error', `Authorization details are limited to ${MAX_BYTES} bytes.`, root.start)
  problems.sort((a, b) => a.offset - b.offset)
  return { value: problems.some((p) => p.severity === 'error') ? null : value, problems }
}

// describeProblem is a problem as one line of text, its line counted from 1.
export function describeProblem(p) { return `Line ${p.row + 1}: ${p.message}` }

// detailContext says where in the details the text before the cursor ends, for completion: role 'key' (a field name
// goes here), 'colon' (after a field name, before its colon: nothing to offer), 'value' (of field key, or an element
// of its array) or 'item' (a new object goes here: directly in the top array); inString when inside a string; depth
// the nesting (1: the top array, 2: an authorization detail).
export function detailContext(before) {
  const stack = []
  let inString = false, esc = false, last = null, str = ''
  for (const c of before) {
    if (inString) {
      if (esc) esc = false
      else if (c === '\\') esc = true
      else if (c === '"') {
        inString = false; last = str
        const top = stack[stack.length - 1]
        if (top && top.kind === '{' && top.expect === 'key') top.expect = 'colon'
      }
      else str += c
      continue
    }
    const top = stack[stack.length - 1]
    if (c === '"') { inString = true; str = '' }
    else if (c === '{') stack.push({ kind: '{', expect: 'key', key: null })
    else if (c === '[') stack.push({ kind: '[', key: top && top.kind === '{' ? top.key : null })
    else if (c === '}' || c === ']') stack.pop()
    else if (c === ':' && top && top.kind === '{') { top.key = last; top.expect = 'value' }
    else if (c === ',' && top && top.kind === '{') top.expect = 'key'
  }
  const top = stack[stack.length - 1]
  const depth = stack.length
  if (!top) return { role: 'none', key: null, inString, depth }
  // inside the quotes of a field name, the role is still 'key'
  if (top.kind === '{') return { role: inString && top.expect === 'colon' ? 'key' : top.expect, key: top.expect === 'value' ? top.key : null, inString, depth }
  return { role: depth === 1 && !inString ? 'item' : 'value', key: top.key, inString, depth }
}
