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

// Skins holds the built-in skins (ui.skin): skins/<name>/skin.css and its optional logos. See skins/README.md.
//
//go:embed skins/*/*
var Skins embed.FS
