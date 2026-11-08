// Package webassets embeds the templates and built frontend assets into the binary.
package webassets

import "embed"

// Templates holds layouts/, partials/ and pages/ (*.html).
//
//go:embed templates
var Templates embed.FS

// Dist holds the frontend build output (assets/, api-docs/, openapi.json and manifest.json), produced by
// `npm run build` in web/.
//
//go:embed all:dist
var Dist embed.FS

// Skins holds the built-in skins: skins/<name>/skin.css. See skins/README.md.
//
//go:embed skins/*/*
var Skins embed.FS

// Tokens is the built-in look's design tokens (src/css/tokens.css), which the skins list offers to copy as Default.
//
//go:embed src/css/tokens.css
var Tokens string
