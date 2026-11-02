package admin_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

const svgLogo = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`

// An organization's admins set its logo and primary colour (PATCH /api/orgs/{org}/branding); its pages then show them:
// the logos and the stylesheet are served under /o/<org>/branding/, and the console's pages name them.
func TestBranding(t *testing.T) {
	w := newWorld(t)
	uri := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svgLogo))
	body := map[string]any{"logo_light": uri, "primary_color": "#1d4ed8"}
	want(t, w.as("manager").patch("/api/orgs/acme/branding", body), 403)
	want(t, w.as("other").patch("/api/orgs/acme/branding", body), 404)
	want(t, w.asServiceAccount(w.acme, service.ScopeUsers, service.ScopeClients).patch("/api/orgs/acme/branding", body), 403)
	wantField(t, w.as("admin").patch("/api/orgs/acme/branding", map[string]any{"primary_color": "#fde047"}), 422, "primary_color")

	r := w.as("admin").patch("/api/orgs/"+w.acme.ID+"/branding", body) // by id, as by name
	want(t, r, 200)
	b, _ := r.JSON["branding"].(map[string]any)
	light, _ := b["logo_light"].(string)
	if b["primary_color"] != "#1d4ed8" || !strings.HasPrefix(light, "/o/"+w.acme.ID+"/branding/logo-light?v=") || b["logo_dark"] != nil {
		t.Fatalf("branding: %v", b)
	}
	if g := w.as("admin").get("/api/orgs/acme"); g.JSON["branding"].(map[string]any)["logo_light"] != light {
		t.Fatalf("the organization's view: %s", g.Raw)
	}

	anon := w.anon()
	g := anon.get("/o/acme/branding/logo-light")
	if g.Status != 200 || string(g.Raw) != svgLogo || g.Header.Get("Content-Type") != "image/svg+xml" ||
		!strings.Contains(g.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("logo: %d %v %s", g.Status, g.Header, g.Raw)
	}
	css := anon.get("/o/" + w.acme.ID + "/branding/brand.css")
	if css.Status != 200 || !strings.HasPrefix(css.Header.Get("Content-Type"), "text/css") || !strings.Contains(string(css.Raw), "#1d4ed8") {
		t.Fatalf("brand.css: %d %s", css.Status, css.Raw)
	}
	for _, p := range []string{"/o/acme/branding/logo-dark", "/o/globex/branding/logo-light", "/o/globex/branding/brand.css", "/o/acme/branding/nope"} {
		want(t, anon.get(p), 404)
	}

	// The console of the organization's users carries its logo, name and colour; another organization's, the server's.
	page := string(w.as("admin").get("/admin/orgs/acme").Raw)
	footer := `<footer class="app-footer"><p>` + w.env.Server.Site.Name + `</p></footer>` // the server's, not the organization's
	for _, s := range []string{light, "/o/" + w.acme.ID + "/branding/brand.css?v=", "· Acme</title>", "data-brand", footer} {
		if !strings.Contains(page, s) {
			t.Errorf("acme's console lacks %q", s)
		}
	}
	if other := string(w.as("other").get("/admin/orgs/globex").Raw); strings.Contains(other, "brand.css") ||
		!strings.Contains(other, `src="/branding/logo-light"`) {
		t.Error("globex's console is branded")
	}

	// A dark logo of its own is named and served apart; without one, the pages show the light one in the dark theme.
	dark := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2 2"/>`
	r = w.as("admin").patch("/api/orgs/acme/branding", map[string]any{"logo_dark": "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(dark))})
	want(t, r, 200)
	darkURL, _ := r.JSON["branding"].(map[string]any)["logo_dark"].(string)
	if g := anon.get(darkURL); !strings.Contains(darkURL, "/branding/logo-dark?v=") || g.Status != 200 || string(g.Raw) != dark {
		t.Fatalf("dark logo %q: %d %s", darkURL, g.Status, g.Raw)
	}

	// Removed, the pages fall back to the server's.
	want(t, w.as("admin").patch("/api/orgs/acme/branding", map[string]any{"logo_light": "", "primary_color": ""}), 200)
	want(t, anon.get("/o/acme/branding/logo-light"), 404)
	if page := string(w.as("admin").get("/admin/orgs/acme").Raw); strings.Contains(page, "brand.css") {
		t.Error("still branded")
	}
}

// The page that sends a signed-out visitor to their application or sign-in link carries the primary organization's
// branding, the server's own: for a page that does not exist, and for an organization's page when there is no such
// organization (rather than a bare 404).
func TestSignInElsewhereBranded(t *testing.T) {
	w := newWorld(t)
	uri := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svgLogo))
	want(t, w.as("super").patch("/api/orgs/"+w.env.Primary.ID+"/branding", map[string]any{"logo_light": uri, "primary_color": "#0f766e"}), 200)
	anon := w.anon()
	for _, p := range []string{"/no/such/page", "/o/" + model.NewID() + "/branding/brand.css", "/o/nosuchorg/branding/logo-light"} {
		r := anon.get(p)
		page := string(r.Raw)
		if r.Status != 404 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") ||
			!strings.Contains(page, "Sign in through your application") || !strings.Contains(page, "lead to a page here") {
			t.Fatalf("%s: %d %.300s", p, r.Status, page)
		}
		for _, s := range []string{"/o/" + w.env.Primary.ID + "/branding/logo-light?v=", "/o/" + w.env.Primary.ID + "/branding/brand.css?v=0f766e", "data-brand"} {
			if !strings.Contains(page, s) {
				t.Errorf("%s lacks the primary organization's %q", p, s)
			}
		}
	}
}

// The service account that creates an organization gives it its branding; the creation's answer shows it.
func TestBrandingOnCreateOrg(t *testing.T) {
	w := newWorld(t)
	uri := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svgLogo))
	r := w.asServiceAccount(w.env.Primary, service.ScopeOrgsCreate).post("/api/orgs", map[string]any{"name": "branded",
		"branding": map[string]any{"logo_light": uri, "primary_color": "#0f766e"}})
	want(t, r, 201)
	if b, _ := r.JSON["branding"].(map[string]any); b["primary_color"] != "#0f766e" || !strings.Contains(b["logo_light"].(string), "/branding/logo-light?v=") {
		t.Fatalf("created: %s", r.Raw)
	}
}
