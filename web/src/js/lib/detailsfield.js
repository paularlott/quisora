// The authorization details field (partial "details-field"): an Ace JSON editor (lib/ace.js, loaded when the first
// one is shown) bound to form.<name> of the enclosing form component, which keeps the text: the form resets and
// submits it as it does a text area's. It completes the common fields, the application's types and the placeholders,
// and shows checkDetails' problems in the gutter and in a summary under the editor (which describes the editor, so a
// screen reader user hears it there).
//
// The partial's data-types names a getter of the enclosing component: the authorization details types the
// application(s) the details are for are registered for, so a detail of another type is flagged as left out.
import { checkDetails, describeProblem, detailContext, COMMON_FIELDS, PLACEHOLDERS } from './authdetails.js'

const MAX_LISTED = 3
const CHECK_DELAY = 400

// The text before the cursor that a completion replaces: a placeholder being typed ({{su), or a word of a name, type
// or URN (urn:example:ad).
const PLACEHOLDER_RE = /\{\{?[a-z]*$/
function prefixRegexps(editor) {
  const pos = editor.getCursorPosition()
  const before = editor.session.getLine(pos.row).slice(0, pos.column)
  return PLACEHOLDER_RE.test(before) ? [/[a-z{]/] : [/[A-Za-z0-9_:./@-]/]
}
function currentPrefix(editor) {
  const pos = editor.getCursorPosition()
  const line = editor.session.getLine(pos.row)
  const [re] = prefixRegexps(editor)
  let i = pos.column
  while (i > 0 && re.test(line[i - 1])) i--
  return line.slice(i, pos.column)
}

// completer offers, by where the cursor is: the placeholders inside a string after {{; the common field names where a
// field name goes in an authorization detail; the registered types as the value of "type"; a new detail in the array.
function completer(types) {
  return (editor) => ({
    id: 'authorizationDetails',
    triggerCharacters: ['"', '{'],
    get identifierRegexps() { return prefixRegexps(editor) },
    getCompletions(ed, session, pos, prefix, callback) {
      const before = session.getTextRange({ start: { row: 0, column: 0 }, end: pos })
      const line = session.getLine(pos.row).slice(0, pos.column)
      const ctx = detailContext(before)
      let out = []
      if (ctx.inString && PLACEHOLDER_RE.test(line)) {
        out = PLACEHOLDERS.map((p) => ({ caption: p.name, value: p.name, meta: 'placeholder', docText: p.doc, score: 100 }))
      } else if (ctx.role === 'key' && ctx.depth === 2) {
        out = COMMON_FIELDS.map((f, i) => ({ caption: f.name, value: f.name, key: true, meta: 'field', docText: f.doc, score: 50 - i }))
      } else if (ctx.role === 'value' && ctx.key === 'type' && ctx.depth === 2) {
        out = (types() || []).map((t) => ({ caption: t, value: t, quote: true, meta: 'type', docText: 'One of the application’s authorization details types.', score: 50 }))
      } else if (ctx.role === 'item') {
        out = [{ caption: '{ "type": … }', snippet: '{\n  "type": "${1}"\n}', meta: 'new detail', docText: 'A new authorization detail.', score: 50 }]
      }
      // a new detail is a snippet, which Ace inserts itself; the others are inserted by insertMatch below
      for (const c of out) if (!c.snippet) { c.completer = this; c.inString = ctx.inString }
      callback(null, out)
    },
    // Replaces the prefix with the choice: a field name in quotes, followed by ": " (inside the quotes the editor
    // closed, after them); a type in quotes unless already inside them.
    insertMatch(ed, data) {
      for (let n = currentPrefix(ed).length; n > 0; n--) ed.remove('left')
      if (data.key) {
        if (data.inString) {
          ed.insert(data.value)
          const pos = ed.getCursorPosition()
          if (ed.session.getLine(pos.row)[pos.column] === '"') ed.navigateRight(1)
          ed.insert(': ')
        } else ed.insert(`"${data.value}": `)
      } else ed.insert(data.quote && !data.inString ? `"${data.value}"` : data.value)
    },
  })
}

export default function (Alpine) {
  Alpine.data('detailsField', () => {
    let editor = null, applying = false, timer = 0
    return {
      problems: [], fieldName: '',
      init() {
        const el = this.$el
        const name = el.dataset.name
        this.fieldName = name
        const types = () => (el.dataset.types ? this[el.dataset.types] : null)
        const check = () => {
          const { problems } = checkDetails(this.form[name] || '', types())
          this.problems = problems
          if (editor) editor.session.setAnnotations(problems.map((p) => ({ row: p.row, column: p.column, text: p.message, type: p.severity })))
        }
        const later = () => { clearTimeout(timer); timer = setTimeout(check, CHECK_DELAY) }
        // The form's value is the source of truth: a reset (the dialog opening for another record) is copied in.
        const sync = () => {
          const v = this.form[name] || ''
          if (editor && v !== editor.getValue()) {
            applying = true
            editor.session.setValue(v)
            applying = false
            check()
          } else later()
        }
        const invalid = () => {
          const input = document.getElementById('f-' + name)
          if (input) input.setAttribute('aria-invalid', this.invalid[name] === 'true' ? 'true' : 'false')
        }
        this.$watch('form.' + name, sync)
        this.$watch('invalid.' + name, invalid)
        Alpine.effect(() => { types(); later() })
        import('./ace.js').then(({ createEditor }) => {
          editor = createEditor(this.$refs.host, {
            inputId: 'f-' + name, labelId: 'l-' + name, describedBy: ['h-' + name, 'p-' + name, 'e-' + name],
            placeholder: el.dataset.placeholder, completer: completer(types),
            onChange: (text) => { if (!applying) this.form[name] = text },
          })
          applying = true
          editor.session.setValue(this.form[name] || '')
          applying = false
          invalid()
          check()
        })
      },
      get hasProblems() { return this.problems.length > 0 },
      get problemsText() {
        const shown = this.problems.slice(0, MAX_LISTED).map(describeProblem)
        const more = this.problems.length - shown.length
        return shown.join(' ') + (more > 0 ? ` And ${more} more.` : '')
      },
      get invalidAttr() { return this.invalid[this.fieldName] === 'true' ? 'true' : 'false' },
    }
  })
}
