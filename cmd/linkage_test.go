package cmd

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Test support (the testing package, whose init registers test flags, and net/http/httptest, which reads a test
// certificate at start) is not linked into the binaries released, with or without the optional 1Password support.
func TestReleaseBinariesLinkNoTestSupport(t *testing.T) {
	t.Parallel()
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	for _, tags := range []string{"", "onepassword"} {
		out, err := exec.Command(goTool, "list", "-deps", "-tags", tags, "-f", "{{.ImportPath}}", "github.com/paularlott/quisora").Output()
		if err != nil {
			t.Fatalf("go list (tags %q): %v", tags, err)
		}
		for _, pkg := range strings.Fields(string(out)) {
			if pkg == "testing" || pkg == "net/http/httptest" {
				t.Errorf("the release build (tags %q) links %s", tags, pkg)
			}
		}
	}
}
