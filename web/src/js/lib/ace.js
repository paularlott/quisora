// The Ace code editor, set up for the console's strict Content-Security-Policy (style-src 'self', no blob: workers).
// Loaded on demand (import('./ace.js')) by the fields that use it, so pages without one never fetch it.
//
//   - useStrictCSP: Ace injects no <style> elements; its stylesheet and our theme (css/ace-theme.css) are bundled.
//   - No worker: syntax checking is the caller's (lib/authdetails.js), shown as gutter annotations.
//   - The theme is one class drawn from the design tokens, so it follows light and dark and any skin.
//   - Accessibility (as in knot's ace-a11y.js): the editor's input textarea takes the field's id, so the <label for>
//     and the form's error focus reach it, and it is named by the label and described by the help and the errors.
//     Tab indents, so Escape arms the next Tab (or Shift+Tab) to leave the editor (WCAG 2.1.2); a second Escape is
//     an ordinary one (closes the dialog).
import ace from 'ace-builds/src-noconflict/ace'
import 'ace-builds/src-noconflict/mode-json'
import 'ace-builds/src-noconflict/mode-html'
import 'ace-builds/src-noconflict/mode-text'
import 'ace-builds/src-noconflict/mode-css'
import 'ace-builds/src-noconflict/ext-language_tools'
import 'ace-builds/src-noconflict/ext-searchbox' // Ctrl+F / ⌘F: find (and Ctrl+H / ⌘⌥F: replace); its styles are in ace.css
import 'ace-builds/css/ace.css'
import '../../css/ace-theme.css'
import { announce } from './announce.js'

ace.config.set('useStrictCSP', true)
// Before any session exists: setting the mode would otherwise start its syntax worker (from a blob: URL) first.
ace.config.setDefaultValue('session', 'useWorker', false)

const THEME = { cssClass: 'ace-quisora', isDark: false }
const HINT_ID = 'ace-keyboard-hint'

function keyboardHint() {
  if (!document.getElementById(HINT_ID)) {
    const hint = document.createElement('div')
    hint.id = HINT_ID
    hint.className = 'sr-only'
    hint.textContent = 'Tab indents. Press Escape, then Tab, to move out of the editor. Control or Command F searches.'
    document.body.append(hint)
  }
  return HINT_ID
}

function keyboardExit(editor) {
  let armed = false
  const disarm = () => { armed = false; editor.container.removeAttribute('data-esc-armed') }
  // Low priority (just above Ace's defaults), so the completion popup and search keep their own Escape.
  editor.keyBinding.addKeyboardHandler({
    handleKeyboard(data, hashId, keyString) {
      if (hashId === -1) { disarm(); return undefined } // typed text
      if (keyString === 'esc' && hashId === 0) {
        if (armed) { disarm(); return { command: 'null', passEvent: true } }
        announce('Press Tab to move out of the editor, or Escape again to close.')
        armed = true
        editor.container.setAttribute('data-esc-armed', '')
        return { command: 'null' }
      }
      if (armed && keyString === 'tab' && (hashId === 0 || hashId === 4)) { disarm(); return { command: 'null', passEvent: true } }
      if (keyString && !['shift', 'ctrl', 'alt', 'cmd', 'meta'].includes(keyString)) disarm()
      return undefined
    },
  }, 1)
  editor.on('blur', disarm)
}

// createEditor makes an editor in host, for JSON unless opts.mode says otherwise ('html', 'text', 'css'). opts: inputId (the
// field's id, given to the input textarea), labelId, describedBy (ids), placeholder, completer (makes the editor's Ace
// completer, given the editor), onChange(text), minLines and maxLines.
export function createEditor(host, opts) {
  const editor = ace.edit(host, {
    mode: 'ace/mode/' + (opts.mode || 'json'),
    useWorker: false,
    theme: THEME,
    minLines: opts.minLines || 10,
    maxLines: opts.maxLines || 24,
    fontSize: '0.875rem',
    tabSize: 2,
    useSoftTabs: true,
    printMargin: false,
    wrap: true,
    showFoldWidgets: false,
    highlightActiveLine: false,
    placeholder: opts.placeholder || '',
    enableBasicAutocompletion: !!opts.completer,
    enableLiveAutocompletion: !!opts.completer,
    enableSnippets: false,
  })
  editor.setTheme(THEME)
  if (opts.completer) editor.completers = [opts.completer(editor)]
  editor.renderer.setScrollMargin(6, 6)
  const input = editor.textInput.getElement()
  input.id = opts.inputId
  if (opts.labelId) input.setAttribute('aria-labelledby', opts.labelId)
  input.setAttribute('aria-describedby', [...(opts.describedBy || []), keyboardHint()].join(' '))
  keyboardExit(editor)
  // On the editor, not its session: it follows the session it is given (newSession, editor.setSession).
  editor.on('change', () => opts.onChange && opts.onChange(editor.getValue()))
  // A dialog that was closed when the editor was made gives it no size: measure again whenever the host changes size.
  new ResizeObserver(() => editor.resize()).observe(host)
  return editor
}

// newSession makes an edit session (a text with its own undo history) in mode ('html', 'text', 'json') to give an
// editor with editor.setSession: one editor can so edit several texts in turn, each keeping its history.
export function newSession(text, mode) {
  const session = ace.createEditSession(text || '', 'ace/mode/' + mode)
  session.setUseWorker(false)
  session.setTabSize(2)
  session.setUseSoftTabs(true)
  session.setUseWrapMode(true)
  return session
}
