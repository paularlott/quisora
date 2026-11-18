// Release gate for the web dependencies (task check): fails on any high or critical advisory npm audit reports,
// except the ones accepted below, each with the reason it does not apply. Every dependency here is a build tool or a
// library bundled into web/dist at build time; nothing from node_modules runs in the server.
import { execFileSync } from 'node:child_process'

// Accepted advisories: url -> why it does not apply, and when that was decided. Review them at each release.
const accepted = {
  'https://github.com/advisories/GHSA-fc5q-39xc-vjpf':
    'picomatch ReDoS on crafted extglob patterns. Only Vite and tinyglobby use it, at build time, on the glob patterns ' +
    'in our own Vite config and the paths in this repository: no pattern comes from outside, and nothing of it is ' +
    'bundled into web/dist or runs in the server. Every release (<=4.0.7) is affected and none is fixed yet; drop this ' +
    'when one is. Decided 2026-11-18.',
}

let report
try {
  report = execFileSync('npm', ['audit', '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] })
} catch (e) {
  report = e.stdout // npm audit exits non-zero when it finds anything
}
const vulns = JSON.parse(report).vulnerabilities || {}

// The advisories themselves are the "via" entries that are objects; string entries name another vulnerable
// package (a dependency chain) and add no advisory of their own.
const found = new Map()
for (const v of Object.values(vulns)) {
  for (const via of v.via) {
    if (typeof via === 'object' && (via.severity === 'high' || via.severity === 'critical')) found.set(via.url, via)
  }
}

let failed = false
for (const [url, a] of found) {
  if (accepted[url]) {
    console.log(`accepted: ${a.name} ${a.severity}: ${a.title}\n  ${url}\n  ${accepted[url]}`)
  } else {
    console.error(`FAIL: ${a.name} ${a.severity}: ${a.title}\n  ${url}`)
    failed = true
  }
}
for (const url of Object.keys(accepted)) {
  if (!found.has(url)) console.log(`note: the accepted advisory ${url} no longer applies: remove it from web/audit.mjs`)
}
if (failed) process.exit(1)
console.log(found.size === 0 ? 'npm audit: no high or critical advisories' : 'npm audit: only accepted advisories')
