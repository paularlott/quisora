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

// ui.skin is a built-in skin's name or the path of a folder holding skin.css (named like a skin); a relative path is
// made absolute against the working directory.
func TestSkinSetting(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	good, bare := filepath.Join(root, "acme"), filepath.Join(root, "empty")
	dirCSS := filepath.Join(root, "dircss")
	for _, d := range []string{good, bare, filepath.Join(root, "Bad_Name"), filepath.Join(dirCSS, "skin.css")} { // dircss holds a directory called skin.css
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{good, filepath.Join(root, "Bad_Name")} {
		if err := os.WriteFile(filepath.Join(d, "skin.css"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for v, want := range map[string]string{
		"":                              "",
		"some-skin":                     "some-skin",
		good:                            good,
		"./acme":                        good,
		"./acme/":                       good,
		"empty/../acme":                 good,
		"Some-Skin":                     "error",
		"acme_1":                        "error",
		"./some-skin":                   "error",
		"../acme":                       "error",
		bare:                            "error",
		filepath.Join(root, "Bad_Name"): "error",
		filepath.Join(root, "missing"):  "error",
		dirCSS:                          "error",
	} {
		c := Default()
		c.UI.Skin = v
		err := c.Validate()
		got := c.UI.Skin
		if err != nil {
			got = "error"
		}
		if got != want {
			t.Errorf("skin %q: got %q (err %v), want %q", v, got, err, want)
		}
	}
}
