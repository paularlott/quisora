package oidc

import (
	"context"
	"net/http"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// BenchmarkAuthorizeConsented is an authorization request of a signed-in user who has consented to a third-party,
// confidential client (consent checked, a code issued): the path the consent check is on.
func BenchmarkAuthorizeConsented(b *testing.B) { benchAuthorizeConsented(b, false) }

// BenchmarkAuthorizeRemembered is BenchmarkAuthorizeConsented for a client that remembers consent (model.Consent).
func BenchmarkAuthorizeRemembered(b *testing.B) { benchAuthorizeConsented(b, true) }

func benchAuthorizeConsented(b *testing.B, remember bool) {
	h := setup(b, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.FirstParty, in.Name, in.RememberConsent = ptr(false), ptr("Bench App"), ptr(remember)
	})
	c, csrf := h.session(h.user)
	v, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, nil))
	if u.Path != h.orgBase+"/oauth/consent" {
		b.Fatalf("expected consent: %s", u)
	}
	_, redirect := h.decideConsent(c, csrf, u.Query().Get("flow"), true)
	code := loc(b, h.get(c, redirect)).Query().Get("code")
	if r := h.exchangeCode(cl, secret, code, v); r.status != 200 {
		b.Fatal(r.m)
	}
	_, ch2 := pkce()
	q := authzQuery(cl, ch2, nil)
	// the per-address limit (authorizePerIPMin) is reset outside the timing
	local := &http.Request{RemoteAddr: "127.0.0.1:1", Header: http.Header{}}
	key := "authorize|" + web.RateKeyIP(local)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%200 == 0 {
			b.StopTimer()
			_ = h.p.s.Eph.Delete(context.Background(), nsRateOIDC, key)
			b.StartTimer()
		}
		if u := h.authorize(c, q); u.Query().Get("code") == "" {
			b.Fatalf("no code: %s", u)
		}
	}
}
