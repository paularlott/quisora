package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/service"
)

func TestWriteErrorMapping(t *testing.T) {
	wrap := func(e error) error { return fmt.Errorf("context: %w", e) }
	for name, tc := range map[string]struct {
		err    error
		status int
		msg    string
		field  string
	}{
		"field error":      {&service.FieldError{Field: "email", Msg: "is not valid"}, 422, "is not valid", "email"},
		"forbidden":        {wrap(service.ErrForbidden), 403, "You do not have permission to do that.", ""},
		"not found":        {service.ErrNotFound, 404, "Not found.", ""},
		"conflict":         {wrap(service.ErrConflict), 409, "That already exists.", ""},
		"stale":            {service.ErrStale, 409, "Someone else changed this. Reload and try again.", ""},
		"last admin":       {service.ErrLastAdmin, 409, "", ""},
		"not empty":        {service.ErrNotEmpty, 409, "", ""},
		"not replicated":   {service.ErrNotReplicated, 503, "", ""},
		"unavailable":      {service.ErrUnavailable, 503, "", ""},
		"unknown error":    {errors.New("secret detail: db password is hunter2"), 500, "Something went wrong. Please try again.", ""},
		"too large":        {service.ErrTooLarge, 413, "", ""},
		"invalid":          {service.ErrInvalid, 422, "", ""},
		"primary org":      {service.ErrPrimaryOrg, 409, "", ""},
		"tenant in use":    {service.ErrTenantInUse, 409, "", ""},
		"wrapped not-null": {wrap(wrap(service.ErrNotFound)), 404, "Not found.", ""},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteError(rec, tc.err)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tc.status, rec.Body)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("headers %v", rec.Header())
			}
			body := rec.Body.String()
			if tc.msg != "" && !strings.Contains(body, tc.msg) {
				t.Fatalf("body %s, want %q", body, tc.msg)
			}
			if tc.field != "" && !strings.Contains(body, `"field":"`+tc.field+`"`) {
				t.Fatalf("body %s lacks field", body)
			}
			if strings.Contains(body, "hunter2") {
				t.Fatalf("internal error text leaked: %s", body)
			}
			if tc.status == 503 && tc.err == service.ErrUnavailable && rec.Header().Get("Retry-After") == "" {
				t.Fatal("no Retry-After")
			}
		})
	}
}

func TestCapitalise(t *testing.T) {
	for in, want := range map[string]string{"": "", "abc": "Abc", "Abc": "Abc", "1abc": "1abc", "é": "é"} {
		if got := capitalise(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestDecodeJSON(t *testing.T) {
	type body struct {
		A string `json:"a"`
	}
	run := func(payload string) (body, int, bool) {
		rec := httptest.NewRecorder()
		var b body
		ok := DecodeJSON(rec, httptest.NewRequest("POST", "/", strings.NewReader(payload)), &b)
		return b, rec.Code, ok
	}
	if b, _, ok := run(`{"a":"x"}`); !ok || b.A != "x" {
		t.Fatalf("valid body: %+v %v", b, ok)
	}
	for name, payload := range map[string]string{
		"unknown field": `{"a":"x","b":1}`,
		"not json":      `nope`,
		"empty":         ``,
		"wrong type":    `{"a":5}`,
	} {
		if _, code, ok := run(payload); ok || code != http.StatusBadRequest {
			t.Errorf("%s: ok=%v code=%d", name, ok, code)
		}
	}
	// a body over the limit is refused as too large (413), not as unreadable
	if _, code, ok := run(`{"a":"` + strings.Repeat("x", MaxJSONBody) + `"}`); ok || code != http.StatusRequestEntityTooLarge {
		t.Errorf("too large: ok=%v code=%d", ok, code)
	}
}

func TestWriteReauth(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteReauth(rec)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"field":"reauth"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestRecovererTurnsPanicsIntoJSON500(t *testing.T) {
	h := recoverer(logger.NewNullLogger(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom: secret") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret") || !strings.Contains(rec.Body.String(), "Something went wrong") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// http.ErrAbortHandler is how a handler aborts a response on purpose: it must reach net/http.
func TestRecovererRepanicsAbortHandler(t *testing.T) {
	h := recoverer(logger.NewNullLogger(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Fatalf("recovered %v", v)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	t.Fatal("no panic")
}

func TestValidRequestID(t *testing.T) {
	for id, want := range map[string]bool{
		"": false, "abc-DEF_1.2": true, strings.Repeat("a", 64): true, strings.Repeat("a", 65): false,
		"has space": false, "new\nline": false, "semi;colon": false, "ünï": false,
	} {
		if got := validRequestID(id); got != want {
			t.Errorf("%q: %v", id, got)
		}
	}
}

func TestRequestIDOnlyTrustedFromProxy(t *testing.T) {
	defer SetTrustedProxies(nil)
	var seen string
	h := requestInfo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = service.RequestFrom(r.Context()).ID
	}))
	do := func(remote, id string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if id != "" {
			r.Header.Set("X-Request-ID", id)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Header().Get("X-Request-ID") != seen {
			t.Fatalf("response id %q, context id %q", rec.Header().Get("X-Request-ID"), seen)
		}
		return seen
	}
	SetTrustedProxies([]string{"10.0.0.0/8"})
	if got := do("10.1.2.3:5", "upstream-id-1"); got != "upstream-id-1" {
		t.Fatalf("a trusted proxy's id is kept: %q", got)
	}
	if got := do("10.1.2.3:5", "bad id!"); got == "bad id!" || got == "" {
		t.Fatalf("an invalid id is replaced: %q", got)
	}
	if got := do("203.0.113.5:5", "spoofed"); got == "spoofed" || got == "" {
		t.Fatalf("an untrusted client cannot choose its id: %q", got)
	}
	if got := do("not-an-address", "x"); got == "x" {
		t.Fatalf("an unparsable peer is untrusted: %q", got)
	}
	if !fromTrustedProxy(func() *http.Request { r := httptest.NewRequest("GET", "/", nil); r.RemoteAddr = "10.9.9.9"; return r }()) {
		t.Fatal("a peer without a port is still recognised")
	}
}

func TestSignInFor(t *testing.T) {
	for path, want := range map[string]string{
		"/admin/orgs/acme/users?x=1": "/login/acme?next=%2Fadmin%2Forgs%2Facme%2Fusers%3Fx%3D1",
		"/admin/orgs/acme":           "/login/acme?next=%2Fadmin%2Forgs%2Facme",
		"/admin/orgs/Bad_Name/users": "/",
		"/admin/orgs//users":         "/",
		"/account":                   "/",
		"/admin":                     "/",
	} {
		if got := signInFor(httptest.NewRequest("GET", path, nil)); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}

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

func TestStatusWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}
	if sw.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("Unwrap")
	}
	n, _ := sw.Write([]byte("hello"))
	sw.WriteHeader(404) // too late: the first status stands
	sw.Flush()
	if n != 5 || sw.status != 200 || sw.bytes != 5 || !rec.Flushed {
		t.Fatalf("n=%d status=%d bytes=%d flushed=%v", n, sw.status, sw.bytes, rec.Flushed)
	}
	sw2 := &statusWriter{ResponseWriter: httptest.NewRecorder()}
	sw2.WriteHeader(418)
	sw2.WriteHeader(500)
	if sw2.status != 418 {
		t.Fatalf("status %d", sw2.status)
	}
}

func TestQuiet(t *testing.T) {
	for p, want := range map[string]bool{"/healthz": true, "/readyz": true, "/metrics": true, "/assets/x.js": true,
		"/branding/logo-light": true, "/favicon.ico": true, "/login/acme": false, "/api/orgs": false} {
		if quiet(p) != want {
			t.Errorf("%s", p)
		}
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s := &Server{Cfg: config.Default()}
	get := func(auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/metrics", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		s.metrics(rec, r)
		return rec
	}
	if rec := get(""); rec.Code != 404 {
		t.Fatalf("no token configured: %d", rec.Code)
	}
	s.Cfg.Metrics.Token = "s3cret-token"
	if rec := get(""); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no credentials: %d", rec.Code)
	}
	if rec := get("Bearer wrong"); rec.Code != 401 {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := get("Basic s3cret-token"); rec.Code != 401 {
		t.Fatalf("wrong scheme: %d", rec.Code)
	}
	rec := get("Bearer s3cret-token")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
}

func TestDebugWriter(t *testing.T) {
	n, err := debugWriter{logger.NewNullLogger()}.Write([]byte("http: TLS handshake error\n"))
	if err != nil || n != len("http: TLS handshake error\n") {
		t.Fatalf("%d %v", n, err)
	}
}

func TestReloadCertificateWithoutSource(t *testing.T) {
	if err := (&Server{}).ReloadCertificate(); err != nil {
		t.Fatal(err)
	}
	if got := urlQueryEscape("/a b?c=d&e"); got != "%2Fa+b%3Fc%3Dd%26e" {
		t.Fatal(got)
	}
}
