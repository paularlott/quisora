package build

import (
	"regexp"
	"testing"
)

// A release is tagged v<Version>, so Version must be a plain semantic version.
func TestVersionIsSemantic(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`).MatchString(Version) {
		t.Errorf("Version %q is not a semantic version (major.minor.patch)", Version)
	}
}
