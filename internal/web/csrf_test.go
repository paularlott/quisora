package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
)

func TestCheckCSRF(t *testing.T) {
	s := &Server{Cfg: config.Default()}
	s.Cfg.Server.PublicURL = "https://id.example.com"
	req := func(method string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest(method, "/", nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if !s.CheckCSRF(req(m, nil), "") {
			t.Errorf("%s needs no token", m)
		}
	}
	for name, tc := range map[string]struct {
		hdr   map[string]string
		token string
		want  bool
	}{
		"matching token":           {map[string]string{"X-CSRF-Token": "tok"}, "tok", true},
		"same origin":              {map[string]string{"X-CSRF-Token": "tok", "Origin": "https://id.example.com", "Sec-Fetch-Site": "same-origin"}, "tok", true},
		"missing header":           {nil, "tok", false},
		"wrong token":              {map[string]string{"X-CSRF-Token": "other"}, "tok", false},
		"empty expected token":     {map[string]string{"X-CSRF-Token": ""}, "", false},
		"foreign origin":           {map[string]string{"X-CSRF-Token": "tok", "Origin": "https://evil.example"}, "tok", false},
		"cross-site fetch":         {map[string]string{"X-CSRF-Token": "tok", "Sec-Fetch-Site": "cross-site"}, "tok", false},
		"same-site is not allowed": {map[string]string{"X-CSRF-Token": "tok", "Sec-Fetch-Site": "same-site"}, "tok", false},
	} {
		if got := s.CheckCSRF(req("POST", tc.hdr), tc.token); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestAnonCSRF(t *testing.T) {
	s := &Server{Cfg: config.Default()}
	s.Cfg.Server.PublicURL = "https://id.example.com"
	rec := httptest.NewRecorder()
	tok := s.AnonCSRF(rec, httptest.NewRequest("GET", "/", nil))
	cookies := rec.Result().Cookies()
	if len(tok) < 32 || len(cookies) != 1 || cookies[0].Value != tok || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteStrictMode || !strings.HasPrefix(cookies[0].Name, "__Host-") {
		t.Fatalf("token %q cookies %+v", tok, cookies)
	}
	// An existing cookie is reused, and nothing is set again.
	r := httptest.NewRequest("POST", "/", nil)
	r.AddCookie(cookies[0])
	rec2 := httptest.NewRecorder()
	if again := s.AnonCSRF(rec2, r); again != tok || len(rec2.Result().Cookies()) != 0 {
		t.Fatalf("not reused: %q", again)
	}
	// A short (forged) cookie is replaced.
	r = httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookies[0].Name, Value: "short"})
	if fresh := s.AnonCSRF(httptest.NewRecorder(), r); fresh == "short" {
		t.Fatal("a short cookie was accepted")
	}

	// CheckAnonCSRF: the cookie and header must match.
	post := func(cookie, header string) bool {
		r := httptest.NewRequest("POST", "/", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: cookies[0].Name, Value: cookie})
		}
		if header != "" {
			r.Header.Set("X-CSRF-Token", header)
		}
		return s.CheckAnonCSRF(r)
	}
	if !post(tok, tok) || post("", tok) || post(tok, "") || post(tok, tok+"x") {
		t.Fatal("anonymous CSRF double submit")
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://id.example.com", "https://id.example.com", true},
		{"https://id.example.com", "https://id.example.com:443", true},
		{"https://ID.Example.com", "https://id.example.com", true},
		{"https://id.example.com:8443", "https://id.example.com:8443", true},
		{"https://id.example.com:8443", "https://id.example.com", false},
		{"https://evil.example.com", "https://id.example.com", false},
		{"http://id.example.com", "https://id.example.com", false},
		{"null", "https://id.example.com", false},
	}
	for _, c := range cases {
		if got := sameOrigin(c.a, c.b); got != c.want {
			t.Errorf("sameOrigin(%q,%q)=%v", c.a, c.b, got)
		}
	}
}
