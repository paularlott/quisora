package web

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	webassets "github.com/paularlott/quisora/web"
)

// The OpenAPI document and the API reference come from the web build (dist). Without one (go test on a fresh
// checkout) both answer 404; with one, the document is the bundled description and the page may load nothing from
// another origin.
func TestAPIDocs(t *testing.T) {
	_, err := fs.Stat(webassets.Dist, "dist/openapi.json")
	built := err == nil

	rec := httptest.NewRecorder()
	openAPIDocument(rec, httptest.NewRequest("GET", "/api/openapi.json", nil))
	if !built {
		if rec.Code != http.StatusNotFound {
			t.Errorf("unbuilt /api/openapi.json: %d", rec.Code)
		}
	} else {
		var doc struct {
			OpenAPI string `json:"openapi"`
			Info    struct {
				Title string `json:"title"`
			} `json:"info"`
		}
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("/api/openapi.json: %d %s", rec.Code, rec.Header().Get("Content-Type"))
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || doc.OpenAPI != "3.1.0" || doc.Info.Title == "" {
			t.Errorf("/api/openapi.json: %+v %v", doc, err)
		}
	}

	rec = httptest.NewRecorder()
	apiDocs(rec, httptest.NewRequest("GET", "/api-docs/", nil))
	if _, err := fs.Stat(webassets.Dist, "dist/api-docs/index.html"); err != nil {
		if rec.Code != http.StatusNotFound {
			t.Errorf("unbuilt /api-docs/: %d", rec.Code)
		}
		return
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("/api-docs/: %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, d := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "img-src 'self' data:"} {
		if !strings.Contains(csp, d) {
			t.Errorf("/api-docs/ CSP %q lacks %q", csp, d)
		}
	}
	if body := rec.Body.String(); strings.Contains(body, "https://") {
		t.Errorf("/api-docs/ references another origin: %s", body)
	}
}
