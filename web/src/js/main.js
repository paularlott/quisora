// Entry point. Every module registers its Alpine components; the CSP build of Alpine evaluates no inline code,
// so all behaviour lives in Alpine.data() registrations (shared ones in ./lib, page ones in ./pages).
import Alpine from '@alpinejs/csp'
import focus from '@alpinejs/focus'
import announce from './lib/announce.js'
import dialog from './lib/dialog.js'
import theme from './lib/theme.js'
import copy from './lib/copy.js'
import shell from './lib/shell.js'
import live from './lib/live.js'
import otp from './lib/otp.js'
import * as pages from './pages/index.js'

Alpine.plugin(focus)
for (const register of [announce, dialog, theme, copy, shell, live, otp]) register(Alpine)
for (const register of Object.values(pages)) register(Alpine)
window.Alpine = Alpine
Alpine.start()
