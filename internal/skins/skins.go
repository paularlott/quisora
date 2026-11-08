// Package skins holds what the built-in and custom skins share: the built-in skins (compiled into the binary from
// web/skins), the rules for a skin's name and stylesheet, and the version that names a stylesheet's address.
//
// A skin is a stylesheet loaded after the built-in one that sets the design tokens (web/src/css/tokens.css) under
// :root[data-skin] (any skin) or :root[data-skin="<name>"] (this one): the pages carry data-skin="<name>" on <html>.
package skins

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	webassets "github.com/paularlott/quisora/web"
)

// Default is Quisora's own look, no skin at all: an organization's skin choice (model.OrgBranding.Skin), and the name
// the skins list gives it (its design tokens, DefaultCSS, can be copied into a custom skin).
const Default = "default"

// Inherit names, in a preview (a page's ?skin=), the primary organization's skin: as an organization that has not
// chosen one shows.
const Inherit = "inherit"

// Limits of a custom skin.
const (
	MaxNameLen        = 40
	MaxDisplayNameLen = 60
	MaxCSSBytes       = 256 << 10
)

// Builtin is a skin compiled into the binary.
type Builtin struct {
	Name    string
	Title   string // its display name: the name, capitalised
	CSS     []byte
	Version string
}

var (
	builtinOnce sync.Once
	builtins    []Builtin
)

// Builtins returns the built-in skins, by name.
func Builtins() []Builtin {
	builtinOnce.Do(func() {
		entries, _ := fs.ReadDir(webassets.Skins, "skins")
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			css, err := fs.ReadFile(webassets.Skins, path.Join("skins", e.Name(), "skin.css"))
			if err != nil {
				continue
			}
			builtins = append(builtins, Builtin{Name: e.Name(), Title: strings.ToUpper(e.Name()[:1]) + e.Name()[1:], CSS: css,
				Version: Version(css)})
		}
		slices.SortFunc(builtins, func(a, b Builtin) int { return strings.Compare(a.Name, b.Name) })
	})
	return builtins
}

// BuiltinNamed returns the built-in skin name.
func BuiltinNamed(name string) (Builtin, bool) {
	for _, b := range Builtins() {
		if b.Name == name {
			return b, true
		}
	}
	return Builtin{}, false
}

// Version is the version of a stylesheet: a hash of it, the ?v= of its address.
func Version(css []byte) string {
	sum := sha256.Sum256(css)
	return hex.EncodeToString(sum[:6])
}

var nameRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// NameError says what is wrong with a custom skin's name, or "": lowercase letters, digits and dashes, not a built-in
// skin's and not Default.
func NameError(name string) string {
	switch {
	case name == "":
		return "is required"
	case len(name) > MaxNameLen:
		return "at most 40 characters"
	case !nameRe.MatchString(name):
		return "lowercase letters, digits and single dashes, such as acme-dark"
	case name == Default, name == Inherit:
		return `"` + name + `" is a word the skin choices use`
	}
	if _, ok := BuiltinNamed(name); ok {
		return "a built-in skin has this name"
	}
	return ""
}

// CSSError says what is wrong with skin name's stylesheet, or "": at most MaxCSSBytes of UTF-8, and its data-skin
// selectors, if it names skins, naming this one (OtherName).
func CSSError(name string, css string) string {
	switch {
	case strings.TrimSpace(css) == "":
		return "is required"
	case len(css) > MaxCSSBytes:
		return "at most 256 KB"
	case !utf8.ValidString(css):
		return "is not UTF-8 text"
	}
	if other := OtherName([]byte(css), name); other != "" {
		return `its [data-skin="` + other + `"] selectors style another skin: write [data-skin] (any skin) or [data-skin="` + name + `"]`
	}
	return ""
}

// selector finds the skin names a stylesheet styles: [data-skin="<name>"], quoted or not, with space around the "="
// and a flag after the value as CSS allows. A bare [data-skin] names none.
var selector = regexp.MustCompile(`\[\s*data-skin\s*=\s*["']?([^"'\]\s]+)`)

// OtherName returns the skin name a stylesheet's data-skin selectors use when none is skin name's own, as in a copy of
// another skin: the stylesheet would style nothing. "" when one is its own, or when it names no skin. It reads the
// text, not the CSS (a selector in a comment counts).
func OtherName(css []byte, name string) string {
	other := ""
	for _, m := range selector.FindAllSubmatch(css, -1) {
		if string(m[1]) == name {
			return ""
		}
		if other == "" {
			other = string(m[1])
		}
	}
	return other
}

var (
	defaultOnce sync.Once
	defaultCSS  string
)

// DefaultCSS is Default's design tokens as a skin's stylesheet, to copy into a custom skin: the light and dark token
// blocks of web/src/css/tokens.css (and the one for pages without JavaScript in a dark OS), under [data-skin]. The
// reduced-transparency and more-contrast overrides stay the built-in stylesheet's, so they still apply under a skin.
func DefaultCSS() string {
	defaultOnce.Do(func() {
		src := webassets.Tokens
		block := func(sel string) string {
			i := strings.Index(src, sel+" {")
			if i < 0 {
				return ""
			}
			open := i + len(sel) + 1
			depth := 0
			for j := open; j < len(src); j++ {
				switch src[j] {
				case '{':
					depth++
				case '}':
					depth--
					if depth == 0 {
						return src[open+1 : j]
					}
				}
			}
			return ""
		}
		var b strings.Builder
		b.WriteString("/* Default: Quisora's own look, as a skin to start from. Change the tokens you need and remove the rest.\n" +
			"   Colours that differ between the themes are set twice: light here, dark under [data-theme=\"dark\"]. */\n")
		b.WriteString(":root[data-skin] {" + block("\n:root") + "}\n\n")
		b.WriteString(":root[data-skin][data-theme=\"dark\"] {" + block(":root[data-theme=\"dark\"]") + "}\n")
		if os := block("  :root:not([data-theme])"); os != "" {
			b.WriteString("\n/* No JavaScript, before the theme is set: follow the OS. */\n@media (prefers-color-scheme: dark) {\n" +
				"  :root[data-skin]:not([data-theme]) {" + os + "}\n}\n")
		}
		defaultCSS = b.String()
	})
	return defaultCSS
}
