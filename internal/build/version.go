// Package build holds Quisora's version, and what a build sets at link time.
package build

var (
	// Version is the version of Quisora. It is kept here and raised for a release: `task release` tags the code
	// v<Version> (go run ./scripts/getversion prints it).
	Version = "0.1.0"

	// Commit is the git commit the binary was built from (-ldflags "-X github.com/paularlott/quisora/internal/build.Commit=…").
	Commit string

	// Date is when the binary was built (-ldflags "-X github.com/paularlott/quisora/internal/build.Date=…").
	Date string
)
