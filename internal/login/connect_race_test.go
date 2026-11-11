package login_test

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// connectGate makes change once, between a provider connection's check of the account's security generation and the
// write that links the identity: at the connection's read of the identity by its subject, or (atCommit) as the
// transaction that writes it is sent, after it read the account it writes.
type connectGate struct {
	store.Store
	atCommit bool
	armed    atomic.Bool
	change   func()
}

func (s *connectGate) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	if kind == model.KindIdentity && !s.atCommit && s.armed.CompareAndSwap(true, false) {
		s.change()
	}
	return s.Store.GetByUnique(ctx, kind, value)
}

func (s *connectGate) Tx(ctx context.Context, ops []store.Op) error {
	if s.atCommit && slices.ContainsFunc(ops, func(op store.Op) bool { return op.Rec.Kind == model.KindIdentity }) &&
		s.armed.CompareAndSwap(true, false) {
		s.change()
	}
	return s.Store.Tx(ctx, ops)
}

// A connection begun before the account's security changed (here an authenticator enrolled from another browser) is
// refused when it finishes, even when the change lands after the callback checked the generation, up to the write that
// links: nothing is linked or replaced, the account keeps the generation the change gave it, and the refusal is audited. Otherwise
// the provider, trusted for the second factor, would sign a fresh browser in without the code. A change that leaves the
// generation alone (the profile) does not fail the link, and is kept.
func TestConnectRefusedAfterConcurrentSecurityChange(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name           string
		atCommit, totp bool
		wantLoc        string
		wantLinked     bool
	}{
		{name: "totp at read", totp: true, wantLoc: "failed"},
		{name: "totp at commit", atCommit: true, totp: true, wantLoc: "failed"},
		{name: "profile at commit", atCommit: true, wantLoc: "connected", wantLinked: true},
		{name: "nothing", wantLoc: "connected", wantLinked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newUpEnv(t, nil)
			p := u.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false); in.TrustMFA = ptr(true) })
			kim := u.user(t, u.org, "kim", model.RoleUser)
			// an earlier link to the provider, which a connection that is made replaces
			if err := u.Svc.Identities.Create(ctx, model.NewIdentity(kim, p, "kim-old", "", "admin")); err != nil {
				t.Fatal(err)
			}
			b := u.signedIn(t, kim)
			gate := &connectGate{Store: u.Svc.Users.S, atCommit: tc.atCommit}
			u.Svc.Users.S, u.Svc.Identities.S = gate, gate
			gate.change = func() {
				cur, err := u.Svc.Users.Get(ctx, kim.ID)
				if err != nil {
					t.Error(err)
					return
				}
				if tc.totp {
					err = u.Svc.SetTOTP(ctx, cur, []byte("12345678901234567890"), 1)
				} else {
					cur.GivenName = "Kimberly"
					err = u.Svc.Users.Update(ctx, cur)
				}
				if err != nil {
					t.Error(err)
				}
			}
			authURL := u.connectURL(t, b, p)
			start, err := u.Svc.Users.Get(ctx, kim.ID)
			if err != nil {
				t.Fatal(err)
			}
			gate.armed.Store(tc.name != "nothing")
			if loc := u.connectCallback(t, b, p, authURL, claims("kim-sub", kim.Email)); loc != u.at("/account?provider="+tc.wantLoc+"#providers") {
				t.Fatalf("connect callback: %q", loc)
			}
			if gate.armed.Load() {
				t.Fatal("the concurrent change was not made")
			}
			want := map[bool]string{true: "kim-sub", false: "kim-old"}[tc.wantLinked] // a refusal replaces nothing
			if ids, err := u.Svc.Identities.All(ctx, kim.ID); err != nil || len(ids) != 1 || ids[0].Subject != want {
				t.Fatalf("identities (want only %s): %+v %v", want, ids, err)
			}
			now, err := u.Svc.Users.Get(ctx, kim.ID)
			if err != nil {
				t.Fatal(err)
			}
			// one step on: the authenticator's (and no link's), or the link's
			if now.SecurityGen != start.SecurityGen+1 {
				t.Fatalf("security generation %d, began at %d", now.SecurityGen, start.SecurityGen)
			}
			if tc.totp != (now.TOTPSecret != "") || !tc.totp && tc.name != "nothing" && now.GivenName != "Kimberly" {
				t.Fatalf("the concurrent change was lost: %+v", now)
			}
			refused := 0
			for _, a := range u.audits(t, "account.provider.connect_refused") {
				if a.Detail["reason"] == "account security changed" {
					refused++
				}
			}
			if want := map[bool]int{true: 0, false: 1}[tc.wantLinked]; refused != want || len(u.audits(t, "account.provider.connect")) != 1-want {
				t.Fatalf("audits: %d refusals", refused)
			}
			// a fresh browser signs in through the provider only when the link was made
			br := u.browser(t)
			br.via(t, u, p, "acme", "/x", claims("kim-sub", kim.Email))
			if br.hasSession() != tc.wantLinked {
				t.Fatalf("fresh browser through the provider: session=%v", br.hasSession())
			}
		})
	}
}
