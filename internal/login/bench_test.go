package login_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
)

const benchCSRF = "0123456789abcdef0123456789abcdef"

func benchEnv(b *testing.B) *env {
	return newEnv(b, func(c *config.Config) {
		c.Limits.LoginPerIPMin = 0
		c.Limits.LockoutAttempts = 0
		c.Limits.PasswordWorkers = 0 // GOMAXPROCS
	})
}

func (e *env) benchPost(path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("X-CSRF-Token", benchCSRF)
	req.AddCookie(&http.Cookie{Name: "__Host-quisora_csrf", Value: benchCSRF})
	rec := httptest.NewRecorder()
	e.Server.Handler().ServeHTTP(rec, req)
	return rec
}

// BenchmarkPasswordLogin is bound by the argon2id hash (19 MiB, 2 passes) plus one session write.
func BenchmarkPasswordLogin(b *testing.B) {
	e := benchEnv(b)
	body := `{"email":"admin@example.com","password":"` + e.Password + `"}`
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if rec := e.benchPost("/o/primary/api-internal/login/password", body); rec.Code != 200 {
			b.Fatalf("%d %s", rec.Code, rec.Body)
		}
	}
}

func BenchmarkPasswordLoginParallel(b *testing.B) {
	e := benchEnv(b)
	body := `{"email":"admin@example.com","password":"` + e.Password + `"}`
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if rec := e.benchPost("/o/primary/api-internal/login/password", body); rec.Code != 200 {
				b.Fatalf("%d %s", rec.Code, rec.Body)
			}
		}
	})
}

// BenchmarkPasswordLoginUnknownUser shows the cost of a failed sign-in for a login that does not exist: the same
// hash, so it is no cheaper for an attacker (or a prober) than a real account.
func BenchmarkPasswordLoginUnknownUser(b *testing.B) {
	e := benchEnv(b)
	body := `{"email":"nobody@example.com","password":"whatever it is"}`
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if rec := e.benchPost("/o/primary/api-internal/login/password", body); rec.Code != 401 {
			b.Fatalf("%d", rec.Code)
		}
	}
}

// BenchmarkPasskeyLoginHTTP is a complete discoverable passkey sign-in over the handlers: begin, assertion
// signed by the virtual authenticator (not timed), finish (verify + counter write + session).
func BenchmarkPasskeyLoginHTTP(b *testing.B) {
	e := benchEnv(b)
	u := e.user(b, e.Primary, "pat", model.RoleUser)
	signed := e.signedIn(b, u)
	signed.registerPasskey("bench")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		rec := e.benchPost("/o/primary/api-internal/login/passkey/begin", `{}`)
		if rec.Code != 200 {
			b.Fatalf("begin: %d %s", rec.Code, rec.Body)
		}
		var begin struct {
			Challenge string          `json:"challenge"`
			Options   json.RawMessage `json:"options"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
			b.Fatal(err)
		}
		cred, _, err := signed.auth.Get(begin.Options)
		if err != nil {
			b.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"challenge": begin.Challenge, "credential": json.RawMessage(cred)})
		b.StartTimer()
		if rec := e.benchPost("/o/primary/api-internal/login/passkey/finish", string(body)); rec.Code != 200 {
			b.Fatalf("%d %s", rec.Code, rec.Body)
		}
	}
}

func benchGet(b *testing.B, path string) {
	e := benchEnv(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		e.Server.Handler().ServeHTTP(rec, req)
		if rec.Code != 200 {
			b.Fatalf("%d", rec.Code)
		}
	}
}

func BenchmarkLandingPage(b *testing.B) { benchGet(b, "/") }
func BenchmarkLoginPage(b *testing.B)   { benchGet(b, "/o/primary/login") }
func BenchmarkLoginPageNext(b *testing.B) {
	benchGet(b, "/o/primary/login?next=%2Foauth%2Fauthorize%3Fflow%3Dabc")
}

func BenchmarkLandingPageParallel(b *testing.B) {
	e := benchEnv(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			e.Server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != 200 {
				b.Fatalf("%d", rec.Code)
			}
		}
	})
}
