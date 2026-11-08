package web_test

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

// A page carries the skin of its organization (here the super admin's, the primary organization): data-skin on
// <html> and its stylesheet at an address with its version, served for as long as it is that version. ?skin= previews
// another skin, or the built-in look (default); a name there is not is no preview.
func TestPageSkin(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{admin.New()} }})
	console, _ := env.ConsoleSession(env.Admin)
	ctx := t.Context()
	a := service.ActorForUser(env.Admin, "127.0.0.1")
	page := func(q string) string {
		_, body := get(t, console, env.URL+"/admin/system"+q)
		return body
	}
	if b := page(""); strings.Contains(b, "data-skin=") || strings.Contains(b, "/branding/skins/") {
		t.Fatal("a skin without one chosen")
	}
	matte := "matte"
	if _, err := env.Svc.UpdateBranding(ctx, a, env.Primary.ID, service.BrandingInput{Skin: &matte}); err != nil {
		t.Fatal(err)
	}
	b := page("")
	if !strings.Contains(b, `data-skin="matte"`) || !strings.Contains(b, `href="/branding/skins/matte.css?v=`) {
		t.Fatalf("the primary organization's skin is not on the page: %.600s", b)
	}
	resp, css := get(t, env.Client(), env.URL+"/branding/skins/matte.css?v=x")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/css") ||
		!strings.Contains(resp.Header.Get("Cache-Control"), "immutable") || !strings.Contains(css, `data-skin="matte"`) {
		t.Fatalf("stylesheet: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := get(t, env.Client(), env.URL+"/branding/skins/nope.css"); resp.StatusCode != 404 {
		t.Fatalf("unknown skin: %d", resp.StatusCode)
	}

	name, css2 := "acme", ":root[data-skin]{--accent:#123456}"
	if _, err := env.Svc.CreateSkin(ctx, a, service.SkinInput{Name: &name, CSS: &css2}); err != nil {
		t.Fatal(err)
	}
	if b := page("?skin=acme"); !strings.Contains(b, `data-skin="acme"`) {
		t.Fatal("no preview of a custom skin")
	}
	if b := page("?skin=default"); strings.Contains(b, "data-skin=") {
		t.Fatal("the built-in look's preview has a skin")
	}
	if b := page("?skin=nope"); !strings.Contains(b, `data-skin="matte"`) {
		t.Fatal("a preview of no skin changed the page")
	}
	// a preview may be framed by this site's pages (the preview dialog), and only a preview
	resp, _ = get(t, console, env.URL+"/admin/system?skin=acme")
	if resp.Header.Get("X-Frame-Options") != "SAMEORIGIN" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'self'") {
		t.Fatalf("preview frame headers: %v", resp.Header)
	}
	resp, _ = get(t, console, env.URL+"/admin/system")
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("page frame headers: %v", resp.Header)
	}
	if _, body := get(t, env.Client(), env.URL+"/branding/skins/acme.css"); body != css2 {
		t.Fatalf("custom stylesheet: %q", body)
	}
}
