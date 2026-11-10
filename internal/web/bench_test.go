package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// BenchmarkSessionCheck is the session check of an authenticated browser request under /o/{org} (cookie -> session,
// user, sign-out counters, and the passkey of a session signed in with one), with the session in the node's cache
// as it is for every request after the first within sessionCacheTTL.
func BenchmarkSessionCheck(b *testing.B) {
	for _, tc := range []struct {
		name    string
		passkey bool
	}{{"password", false}, {"passkey", true}} {
		b.Run(tc.name, func(b *testing.B) {
			ctx := context.Background()
			svc, u, _ := sessionFixture(b, memstore.New(), time.Now().UTC())
			org, err := svc.Orgs.Get(ctx, u.OrgID)
			if err != nil {
				b.Fatal(err)
			}
			opt := SessionOptions{AMR: []string{"pwd"}}
			if tc.passkey {
				pk := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: "bench", CredentialID: []byte("cred"), UserVerified: true}
				if err := svc.Passkeys.Create(ctx, pk); err != nil {
					b.Fatal(err)
				}
				opt.Passkey, opt.AMR = pk.ID, []string{"hwk", "user"}
			}
			m := NewSessions(svc)
			rec := httptest.NewRecorder()
			if _, err := m.CreateWith(ctx, rec, httptest.NewRequest(http.MethodGet, "/", nil), u, org, opt); err != nil {
				b.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/o/"+org.ID+"/whoami", nil)
			for _, c := range rec.Result().Cookies() {
				req.AddCookie(c)
			}
			req = req.WithContext(context.WithValue(req.Context(), ctxOrgKey{}, org))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				s, got, err := m.Check(req)
				if err != nil || s == nil || got == nil || (tc.passkey && s.Passkey == "") {
					b.Fatal("session not found", err)
				}
			}
		})
	}
}
