package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	webassets "github.com/paularlott/quisora/web"
)

// Skin is a replacement look for the UI (ui.skin): a stylesheet loaded after the built-in one that sets the design
// tokens (web/src/css/tokens.css) under :root[data-skin="<name>"], and optional logos. It is read once at start-up.
type Skin struct {
	Name      string // data-skin on <html>
	CSS       []byte
	Version   string // content hash, the ?v= of the stylesheet URL
	LogoLight *SkinFile
	LogoDark  *SkinFile
}

// SkinFile is a skin's logo.
type SkinFile struct {
	Type string
	Body []byte
}

// logoTypes are the logo files a skin may hold, by extension, in order of preference.
var logoTypes = [][2]string{{".svg", "image/svg+xml"}, {".png", "image/png"}}

// BuiltinSkins lists the skins compiled into the binary.
func BuiltinSkins() []string {
	entries, _ := fs.ReadDir(webassets.Skins, "skins")
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

// LoadSkin loads ui.skin: "" (none), a built-in skin's name, or the absolute path of a skin folder (config.Validate
// checks it and makes a relative one absolute).
func LoadSkin(v string) (*Skin, error) {
	if v == "" {
		return nil, nil
	}
	var fsys fs.FS
	var name string
	if filepath.IsAbs(v) {
		fsys, name = os.DirFS(v), filepath.Base(v)
	} else {
		if !slices.Contains(BuiltinSkins(), v) {
			return nil, fmt.Errorf("ui.skin %q is not a built-in skin (built in: %s)", v, strings.Join(BuiltinSkins(), ", "))
		}
		sub, err := fs.Sub(webassets.Skins, path.Join("skins", v))
		if err != nil {
			return nil, err
		}
		fsys, name = sub, v
	}
	css, err := fs.ReadFile(fsys, "skin.css")
	if err != nil {
		return nil, fmt.Errorf("ui.skin: %w", err)
	}
	sum := sha256.Sum256(css)
	s := &Skin{Name: name, CSS: css, Version: hex.EncodeToString(sum[:6])}
	if s.LogoLight, err = skinLogo(fsys, "logo-light"); err != nil {
		return nil, err
	}
	if s.LogoDark, err = skinLogo(fsys, "logo-dark"); err != nil {
		return nil, err
	}
	if s.LogoDark == nil {
		s.LogoDark = s.LogoLight
	}
	return s, nil
}

// skinSelector finds the skin names a stylesheet styles: [data-skin="<name>"], quoted or not, with space around the
// "=" and a flag after the value as CSS allows.
var skinSelector = regexp.MustCompile(`\[\s*data-skin\s*=\s*["']?([^"'\]\s]+)`)

// skinOtherName returns the skin name a stylesheet's data-skin selectors use when none is the skin's own (its
// folder's), as when the folder was renamed: the stylesheet would then style nothing, without a word. "" when one is
// its own, or when it names no skin (:root { ... }: it is loaded only for this skin). It reads the text, not the CSS
// (a selector in a comment counts), so New only warns of it.
func skinOtherName(css []byte, name string) string {
	other := ""
	for _, m := range skinSelector.FindAllSubmatch(css, -1) {
		if string(m[1]) == name {
			return ""
		}
		if other == "" {
			other = string(m[1])
		}
	}
	return other
}

func skinLogo(fsys fs.FS, base string) (*SkinFile, error) {
	for _, t := range logoTypes {
		b, err := fs.ReadFile(fsys, base+t[0])
		if err == nil {
			return &SkinFile{Type: t[1], Body: b}, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("ui.skin: %w", err)
		}
	}
	return nil, nil
}
