package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
)

func TestLoadSkin(t *testing.T) {
	if s, err := LoadSkin(""); s != nil || err != nil {
		t.Fatalf("no skin: %v %v", s, err)
	}
	if got := BuiltinSkins(); !slices.Equal(got, []string{"corporate"}) {
		t.Errorf("built-in skins: %v", got)
	}
	for _, name := range BuiltinSkins() {
		s, err := LoadSkin(name)
		if err != nil {
			t.Fatal(err)
		}
		if s.Name != name || !strings.Contains(string(s.CSS), `:root[data-skin="`+name+`"]`) || s.Version == "" {
			t.Errorf("%s: %q %q", name, s.Name, s.Version)
		}
	}
	if _, err := LoadSkin("nope"); err == nil || !strings.Contains(err.Error(), "built in: corporate") {
		t.Errorf("unknown skin: %v", err)
	}

	// A folder on disk: its name is the skin's, the dark logo falls back to the light one, and logos are optional.
	dir := skinDir(t, "acme")
	s, err := LoadSkin(dir)
	if err != nil || s.Name != "acme" || s.LogoLight != nil || s.LogoDark != nil {
		t.Fatalf("folder without logos: %+v %v", s, err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "logo-light.png"), []byte("png"), 0o644))
	s, err = LoadSkin(dir)
	if err != nil || s.LogoLight == nil || s.LogoLight.Type != "image/png" || s.LogoDark != s.LogoLight {
		t.Fatalf("folder with a light logo: %+v %v", s, err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "logo-dark.svg"), []byte("<svg/>"), 0o644))
	if s, err = LoadSkin(dir); err != nil || s.LogoDark == nil || s.LogoDark.Type != "image/svg+xml" {
		t.Fatalf("folder with both logos: %+v %v", s, err)
	}
	// A stylesheet written for another name (the folder was renamed) would style nothing: refused, naming both.
	other := filepath.Join(t.TempDir(), "acme-skin")
	must(t, os.Rename(dir, other))
	if _, err := LoadSkin(other); err == nil || !strings.Contains(err.Error(), `"acme"`) || !strings.Contains(err.Error(), `"acme-skin"`) {
		t.Errorf("stylesheet for another name: %v", err)
	}
}

// The skin's stylesheet is served under a content-hashed URL; its logos are used unless ui.logo_* are set.
func TestBrandingSkin(t *testing.T) {
	dir := skinDir(t, "acme")
	must(t, os.WriteFile(filepath.Join(dir, "logo-light.svg"), []byte("<svg>light</svg>"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "logo-dark.svg"), []byte("<svg>dark</svg>"), 0o644))
	skin, err := LoadSkin(dir)
	if err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(t.TempDir(), "own.svg")
	must(t, os.WriteFile(own, []byte("<svg>own</svg>"), 0o644))
	get := func(s *Server, path string) *httptest.ResponseRecorder {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /branding/{name}", s.branding)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}

	plain := &Server{Cfg: config.Default()}
	if rec := get(plain, "/branding/skin.css"); rec.Code != http.StatusNotFound {
		t.Errorf("no skin: skin.css %d", rec.Code)
	}

	s := &Server{Cfg: config.Default(), skin: skin}
	rec := get(s, "/branding/skin.css?v="+skin.Version)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/css") ||
		!strings.Contains(rec.Header().Get("Cache-Control"), "immutable") || rec.Body.String() != string(skin.CSS) {
		t.Errorf("skin.css: %d %v", rec.Code, rec.Header())
	}
	for name, want := range map[string]string{"logo-light": "<svg>light</svg>", "logo-dark": "<svg>dark</svg>"} {
		if rec := get(s, "/branding/"+name); rec.Body.String() != want || rec.Header().Get("Content-Type") != "image/svg+xml" {
			t.Errorf("%s: skin logo not served: %q", name, rec.Body.String())
		}
	}

	// ui.logo_light wins over the skin, for the dark logo too (which falls back to it).
	s.Cfg.UI.LogoLight = own
	for _, name := range []string{"logo-light", "logo-dark"} {
		if rec := get(s, "/branding/"+name); rec.Body.String() != "<svg>own</svg>" {
			t.Errorf("%s with ui.logo_light: %q", name, rec.Body.String())
		}
	}
}

// skinDir makes a skin folder holding only skin.css.
func skinDir(t *testing.T, name string) string {
	dir := filepath.Join(t.TempDir(), name)
	must(t, os.Mkdir(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "skin.css"), []byte(":root[data-skin="+name+"]{}"), 0o644))
	return dir
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// A skin's stylesheet is refused only when its data-skin selectors all name another skin: the selector's spacing and
// flags as CSS allows them, and a stylesheet that names no skin, are its own.
func TestSkinNamed(t *testing.T) {
	for css, ok := range map[string]bool{
		`:root[data-skin="acme"]{}`:                  true,
		`:root[data-skin=acme]{}`:                    true,
		`:root[data-skin='acme']{}`:                  true,
		`:root[ data-skin = "acme" ]{}`:              true,
		`:root[data-skin="acme" i]{}`:                true,
		`:root{--accent:#123456}`:                    true,
		`[data-skin=other] a{} [data-skin="acme"]{}`: true,
		`:root[data-skin="other"]{}`:                 false,
		`:root[data-skin = "acme-skin"]{}`:           false,
	} {
		if err := skinNamed([]byte(css), "acme"); (err == nil) != ok {
			t.Errorf("%s: %v", css, err)
		}
	}
}
