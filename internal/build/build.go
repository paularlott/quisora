// Package build holds version information set at link time (-ldflags "-X github.com/paularlott/quisora/internal/build.Version=...").
package build

var (
	Version = "dev"
	Commit  = ""
)
