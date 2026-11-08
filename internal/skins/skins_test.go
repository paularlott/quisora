package skins

import (
	"strings"
	"testing"
)

func TestBuiltins(t *testing.T) {
	b, ok := BuiltinNamed("matte")
	if !ok || b.Title != "Matte" || len(b.CSS) == 0 || b.Version != Version(b.CSS) {
		t.Fatalf("matte: %v %+v", ok, b.Title)
	}
	if OtherName(b.CSS, "matte") != "" {
		t.Fatal("matte's stylesheet styles another skin")
	}
}

func TestNameError(t *testing.T) {
	for name, bad := range map[string]bool{
		"acme": false, "acme-dark": false, "a1": false,
		"": true, "Acme": true, "acme_dark": true, "-acme": true, "acme--dark": true, "default": true, "matte": true,
		strings.Repeat("a", MaxNameLen+1): true,
	} {
		if got := NameError(name) != ""; got != bad {
			t.Errorf("%q: refused %v, want %v", name, got, bad)
		}
	}
}

// A stylesheet's data-skin selectors must name its own skin, or none ([data-skin]: any skin), with the spacing and flags
// CSS allows.
func TestCSSError(t *testing.T) {
	for css, bad := range map[string]bool{
		`:root[data-skin]{--a:1}`:                    false,
		`:root[data-skin="acme"]{}`:                  false,
		`:root[data-skin=acme]{}`:                    false,
		`:root[ data-skin = 'acme' i]{}`:             false,
		`:root{--accent:#123456}`:                    false,
		`[data-skin=other] a{} [data-skin="acme"]{}`: false,
		`:root[data-skin="matte"]{}`:                 true,
		"":                                           true,
		"   ":                                        true,
		"\xff":                                       true,
		strings.Repeat("a", MaxCSSBytes+1):           true,
	} {
		if got := CSSError("acme", css) != ""; got != bad {
			t.Errorf("%.40q: refused %v, want %v", css, got, bad)
		}
	}
}

// Default's copy is the built-in tokens under [data-skin]: light, dark, and dark for pages without JavaScript.
func TestDefaultCSS(t *testing.T) {
	css := DefaultCSS()
	for _, want := range []string{":root[data-skin] {", `:root[data-skin][data-theme="dark"] {`, ":root[data-skin]:not([data-theme])", "--page-bg:", "--accent-solid:"} {
		if !strings.Contains(css, want) {
			t.Errorf("no %q", want)
		}
	}
	if CSSError("acme", css) != "" || strings.Contains(css, "@theme") || strings.Contains(css, "prefers-contrast") {
		t.Errorf("not a skin's stylesheet: %s", CSSError("acme", css))
	}
}
