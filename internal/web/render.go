package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
)

// Site is the branding passed to every page.
type Site struct {
	Name         string        // ui.site_name: the server's (the footer's, without ui.footer)
	Brand        string        // the name shown with the logo and in page titles: Name, or the organization's (Site.For)
	DefaultTheme string        // light, dark or system
	LogoLight    string        // URL
	LogoDark     string        // URL (falls back to LogoLight)
	Skin         string        // ui.skin's name (data-skin on <html>), or ""
	SkinCSS      string        // URL of the skin's stylesheet, or ""
	OrgLogo      bool          // the logo is the organization's (Site.For), and Brand its name
	BrandCSS     string        // URL of the organization's primary colour stylesheet (Site.For), or ""
	Footer       template.HTML // ui.footer, limited to links and text emphasis (FooterHTML)
	PublicURL    string
	Mail         bool // an SMTP server is configured (config.Mail.Enabled)
	Clustered    bool // nodes replicate over gossip: super admins get the cluster page
	PasswordMin  int  // limits.password_min_length: the forms say how long a password must be
}

// Page is the data every template receives; Data carries the page-specific values.
type Page struct {
	Site  Site
	Title string
	User  *model.User
	Org   *model.Org // the signed-in user's organization, or, signed out, the organization of the page (/o/<org>)
	// Path is the page's address: the re-authentication dialog every signed-in page carries signs in at the user's
	// organization and comes back here.
	Path    string
	CSRF    string // session CSRF token, or the anonymous double-submit token
	IsSuper bool
	IsAdmin bool // admin of their own org (or super)
	IsMgr   bool // manager+ of their own org
	// KeyRotation: a master key rotation is in progress on this node (previous master keys are configured); super
	// admins get the master key rotation page in the menu.
	KeyRotation bool
	Nav         string
	Data        any
}

// Renderer executes page templates: each pages/<name>.html is combined with layouts/*.html and partials/*.html.
type Renderer struct {
	Log      logger.Logger
	mu       sync.RWMutex
	pages    map[string]*template.Template
	manifest map[string]manifestEntry
}

type manifestEntry struct {
	File string `json:"file"`
}

// NewRenderer parses the templates from tfs (rooted at "templates") and the asset manifest from dist.
func NewRenderer(tfs, dist fs.FS) (*Renderer, error) {
	r := &Renderer{pages: map[string]*template.Template{}, manifest: map[string]manifestEntry{}}
	if b, err := fs.ReadFile(dist, "dist/manifest.json"); err == nil {
		// Vite's manifest is keyed by source path (src/js/main.js); templates name entries by file name (main.js).
		var m map[string]manifestEntry
		_ = json.Unmarshal(b, &m)
		for src, e := range m {
			r.manifest[path.Base(src)] = e
		}
	}
	funcs := template.FuncMap{
		"asset": r.asset,
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"lower": strings.ToLower,
	}
	shared := template.New("").Funcs(funcs)
	for _, dir := range []string{"templates/layouts", "templates/partials"} {
		matches, _ := fs.Glob(tfs, dir+"/*.html")
		for _, m := range matches {
			b, err := fs.ReadFile(tfs, m)
			if err != nil {
				return nil, err
			}
			if _, err := shared.New(path.Base(m)).Parse(string(b)); err != nil {
				return nil, fmt.Errorf("%s: %w", m, err)
			}
		}
	}
	pages, _ := fs.Glob(tfs, "templates/pages/*.html")
	for _, p := range pages {
		t, err := shared.Clone()
		if err != nil {
			return nil, err
		}
		b, err := fs.ReadFile(tfs, p)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(path.Base(p), ".html")
		if _, err := t.New(path.Base(p)).Parse(string(b)); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		r.pages[name] = t
	}
	return r, nil
}

// asset returns the hashed URL of a built entry, named by its source file ("main.js", "theme-boot.js", "main.css").
func (r *Renderer) asset(entry string) string {
	if e, ok := r.manifest[entry]; ok {
		return "/" + e.File
	}
	return "/" + entry
}

// Render executes page `name` (its "page" template, which normally invokes the layout) with status.
func (r *Renderer) Render(w http.ResponseWriter, status int, name string, p *Page) {
	r.mu.RLock()
	t := r.pages[name]
	r.mu.RUnlock()
	if t == nil {
		http.Error(w, "unknown page "+name, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name+".html", p); err != nil {
		if r.Log != nil {
			r.Log.Error("template", "page", name, "error", err)
		}
		http.Error(w, "Something went wrong. Please try again.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// SiteFromConfig builds the branding block.
func SiteFromConfig(c *config.Config) Site {
	s := Site{Name: c.UI.SiteName, Brand: c.UI.SiteName, DefaultTheme: c.UI.DefaultTheme, Footer: FooterHTML(c.UI.Footer), PublicURL: c.Server.PublicURL,
		LogoLight: "/branding/logo-light", LogoDark: "/branding/logo-dark", Mail: c.Mail.Enabled(),
		PasswordMin: c.Limits.PasswordMinLength}
	return s
}
