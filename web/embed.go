// Package webassets embeds the templates and built frontend assets into the binary.
package webassets

import "embed"

// Templates holds layouts/, partials/ and pages/ (*.html).
//
//go:embed templates
var Templates embed.FS

// Dist holds the frontend build output (assets/ and manifest.json), produced by `npm run build` in web/.
//
//go:embed all:dist
var Dist embed.FS
