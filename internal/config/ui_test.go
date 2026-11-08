package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Logos are the built-in one, an https URL or an absolute path to a regular file; anything else fails at load.
func TestLogo(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "logo.svg")
	if err := os.WriteFile(file, []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	for v, ok := range map[string]bool{
		"":                                true,
		"https://cdn.example.com/l.svg":   true,
		file:                              true,
		"http://cdn.example.com/l.svg":    false,
		"https://":                        false,
		"https://u:p@cdn.example.com/l":   false,
		"logo.svg":                        false,
		"../logo.svg":                     false,
		dir:                               false,
		filepath.Join(dir, "missing.svg"): false,
	} {
		for _, dark := range []bool{false, true} {
			c := Default()
			if dark {
				c.UI.LogoDark = v
			} else {
				c.UI.LogoLight = v
			}
			if err := c.Validate(); (err == nil) != ok {
				t.Errorf("logo %q (dark %v): err = %v, want ok %v", v, dark, err, ok)
			}
		}
	}
}
