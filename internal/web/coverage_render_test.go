package web

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/paularlott/logger"
)

func TestRendererRender(t *testing.T) {
	r := &Renderer{Log: logger.NewNullLogger(), manifest: map[string]manifestEntry{"main.js": {File: "assets/main-abc.js"}},
		pages: map[string]*template.Template{
			"ok":  template.Must(template.New("ok.html").Parse(`<p>{{.Title}}</p>`)),
			"bad": template.Must(template.New("bad.html").Parse(`<p>{{.Missing.Field}}</p>`)),
		}}
	rec := httptest.NewRecorder()
	r.Render(rec, 201, "ok", &Page{Title: "<b>hi</b>"})
	if rec.Code != 201 || rec.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(rec.Body.String(), "&lt;b&gt;hi&lt;/b&gt;") {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	rec = httptest.NewRecorder()
	r.Render(rec, 200, "nope", &Page{})
	if rec.Code != 500 {
		t.Fatalf("unknown page: %d", rec.Code)
	}
	// A template that fails midway sends nothing of the half-written page.
	rec = httptest.NewRecorder()
	r.Render(rec, 200, "bad", &Page{})
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "<p>") {
		t.Fatalf("failing template: %d %q", rec.Code, rec.Body)
	}
	if r.asset("main.js") != "/assets/main-abc.js" || r.asset("other.css") != "/other.css" {
		t.Fatalf("asset: %q %q", r.asset("main.js"), r.asset("other.css"))
	}
}

func TestNewRendererRejectsBrokenTemplate(t *testing.T) {
	tfs := fstest.MapFS{"templates/pages/x.html": {Data: []byte(`{{ unclosed`)}}
	if _, err := NewRenderer(tfs, fstest.MapFS{}); err == nil {
		t.Fatal("a template that does not parse was accepted")
	}
}
