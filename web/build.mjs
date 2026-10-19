// Builds web/dist: one JS bundle (esbuild) and one stylesheet (Tailwind CLI), content-hashed, plus manifest.json
// mapping entry names to hashed files. Everything in dist is embedded into the Go binary.
import { build, context } from 'esbuild'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, copyFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const watch = process.argv.includes('--watch')
const out = 'dist/assets'
rmSync(out, { recursive: true, force: true })
mkdirSync(out, { recursive: true })

const hash = (buf) => createHash('sha256').update(buf).digest('hex').slice(0, 10)

function css() {
  execFileSync('npx', ['@tailwindcss/cli', '-i', 'src/css/main.css', '-o', 'dist/tmp-main.css', '--minify'], { stdio: 'inherit' })
  const buf = readFileSync('dist/tmp-main.css')
  const file = `assets/main-${hash(buf)}.css`
  writeFileSync(join('dist', file), buf)
  rmSync('dist/tmp-main.css')
  return file
}

// theme-boot.js runs in <head> before first paint, so it is a separate classic (non-module) script.
async function boot() {
  const res = await build({
    entryPoints: ['src/js/theme-boot.js'], bundle: true, minify: true, format: 'iife', target: 'es2018',
    write: false, legalComments: 'none',
  })
  const buf = res.outputFiles[0].contents
  const file = `assets/theme-boot-${hash(buf)}.js`
  writeFileSync(join('dist', file), buf)
  return file
}

async function js() {
  const res = await build({
    entryPoints: ['src/js/main.js'], bundle: true, minify: true, format: 'esm', target: 'es2022',
    write: false, sourcemap: false, legalComments: 'none',
  })
  const buf = res.outputFiles[0].contents
  const file = `assets/main-${hash(buf)}.js`
  writeFileSync(join('dist', file), buf)
  return file
}

function copyStatic() {
  if (!existsSync('src/static')) return
  for (const f of readdirSync('src/static')) copyFileSync(join('src/static', f), join('dist', f))
}

async function all() {
  const manifest = { 'main.js': { file: await js() }, 'theme-boot.js': { file: await boot() }, 'main.css': { file: css() } }
  copyStatic()
  writeFileSync('dist/manifest.json', JSON.stringify(manifest, null, 2))
  console.log('built', manifest)
}

await all()
if (watch) {
  const { watch: fsWatch } = await import('node:fs')
  let t
  fsWatch('src', { recursive: true }, () => { clearTimeout(t); t = setTimeout(() => all().catch(console.error), 150) })
  fsWatch('templates', { recursive: true }, () => { clearTimeout(t); t = setTimeout(() => all().catch(console.error), 150) })
}
