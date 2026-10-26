package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/paularlott/logger"
)

// A page is sent escaped, uncached, with its status; a page that fails midway sends none of what it wrote, and an
// unknown page is a 500. Built assets are linked by their hashed names.
func TestRenderEscapesAndNeverSendsAHalfWrittenPage(t *testing.T) {
	tfs := fstest.MapFS{
		"templates/layouts/base.html": {Data: []byte(`{{define "head"}}<script src="{{asset "main.js"}}"></script><link href="{{asset "other.css"}}">{{end}}`)},
		"templates/pages/ok.html":     {Data: []byte(`{{template "head"}}<p>{{.Title}}</p>`)},
		"templates/pages/bad.html":    {Data: []byte(`<p>{{.Missing.Field}}</p>`)},
	}
	dist := fstest.MapFS{"dist/manifest.json": {Data: []byte(`{"src/js/main.js":{"file":"assets/main-abc.js"}}`)}}
	r, err := NewRenderer(tfs, dist)
	if err != nil {
		t.Fatal(err)
	}
	r.Log = logger.NewNullLogger()
	rec := httptest.NewRecorder()
	r.Render(rec, 201, "ok", &Page{Title: "<b>hi</b>"})
	body := rec.Body.String()
	if rec.Code != 201 || rec.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(body, "&lt;b&gt;hi&lt;/b&gt;") {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), body)
	}
	if !strings.Contains(body, `src="/assets/main-abc.js"`) || !strings.Contains(body, `href="/other.css"`) {
		t.Fatalf("asset links: %s", body)
	}
	rec = httptest.NewRecorder()
	r.Render(rec, 200, "nope", &Page{})
	if rec.Code != 500 {
		t.Fatalf("unknown page: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	r.Render(rec, 200, "bad", &Page{})
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "<p>") {
		t.Fatalf("failing template: %d %q", rec.Code, rec.Body)
	}
}

func TestNewRendererRejectsBrokenTemplate(t *testing.T) {
	tfs := fstest.MapFS{"templates/pages/x.html": {Data: []byte(`{{ unclosed`)}}
	if _, err := NewRenderer(tfs, fstest.MapFS{}); err == nil {
		t.Fatal("a template that does not parse was accepted")
	}
}
