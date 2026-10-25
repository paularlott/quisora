package service_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestProviderAdministrationAuthorization(t *testing.T) {
	c := newCast(t)
	p, err := c.svc.CreateProvider(c.ctx, actor(c.aAdmin), c.a.ID, goodProvider("sso"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		u    *model.User
		want string
	}{
		{"admin", c.aAdmin, "ok"}, {"manager", c.aManager, "forbidden"}, {"user", c.aUser, "forbidden"}, {"foreign admin", c.bAdmin, "forbidden"},
	} {
		_, _, err := c.svc.ListProviders(c.ctx, actor(tc.u), c.a.ID, store.ListQuery{})
		c.check(t, tc.name+" list", err, tc.want)
		_, err = c.svc.CreateProvider(c.ctx, actor(tc.u), c.a.ID, goodProvider(c.next("p")))
		c.check(t, tc.name+" create", err, tc.want)
	}
	for name, a := range map[string]*model.User{"manager": c.aManager, "foreign admin": c.bAdmin} {
		if _, err := c.svc.GetProvider(c.ctx, actor(a), p.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s get: %v", name, err)
		}
		if _, err := c.svc.UpdateProvider(c.ctx, actor(a), p.ID, service.ProviderInput{Name: ptr("x")}); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s update: %v", name, err)
		}
		if err := c.svc.DeleteProvider(c.ctx, actor(a), p.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s delete: %v", name, err)
		}
	}
	if got, _ := c.svc.GetProvider(c.ctx, nil, p.ID); got == nil || got.Name != "sso" {
		t.Error("provider changed or deleted by a foreign actor")
	}
	// Trusting a provider's second factor is a super admin's decision.
	if _, err := c.svc.UpdateProvider(c.ctx, actor(c.aAdmin), p.ID, service.ProviderInput{TrustMFA: ptr(true)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin trusting MFA: %v", err)
	}
	if got, err := c.svc.UpdateProvider(c.ctx, actor(c.super), p.ID, service.ProviderInput{TrustMFA: ptr(true)}); err != nil || !got.TrustMFA {
		t.Errorf("super trusting MFA: %v", err)
	}
	if _, err := c.svc.UpdateProvider(c.ctx, actor(c.aAdmin), p.ID, service.ProviderInput{TrustMFA: ptr(true)}); err != nil {
		t.Errorf("unchanged TrustMFA by admin: %v", err)
	}
}

func TestProviderInputValidation(t *testing.T) {
	c := newCast(t)
	sys := service.System
	guid := "72f988bf-86f1-41af-91ab-2d7cd011db47"
	cases := map[string]service.ProviderInput{
		"bad id":          {ID: ptr("NOT-A-UUID"), Name: ptr("x"), Issuer: ptr("https://i.example.com"), ClientID: ptr("c"), ClientSecret: ptr("s")},
		"bad type":        {Type: ptr("saml"), Name: ptr("x")},
		"long name":       {Name: ptr(strings.Repeat("n", 101)), Issuer: ptr("https://i.example.com"), ClientID: ptr("c"), ClientSecret: ptr("s")},
		"http issuer":     {Name: ptr("x"), Issuer: ptr("http://i.example.com"), ClientID: ptr("c"), ClientSecret: ptr("s")},
		"no client id":    {Name: ptr("x"), Issuer: ptr("https://i.example.com"), ClientSecret: ptr("s")},
		"no secret":       {Name: ptr("x"), Issuer: ptr("https://i.example.com"), ClientID: ptr("c")},
		"scope space":     {Name: ptr("x"), Issuer: ptr("https://i.example.com"), ClientID: ptr("c"), ClientSecret: ptr("s"), Scopes: &[]string{"a b"}},
		"bad domain":      {Name: ptr("x"), Issuer: ptr("https://i.example.com"), ClientID: ptr("c"), ClientSecret: ptr("s"), AllowedDomains: &[]string{"not a domain"}},
		"ms no tenant":    {Type: ptr(model.ProviderMicrosoft), Name: ptr("x"), ClientID: ptr("c"), ClientSecret: ptr("s")},
		"ms personal":     {Type: ptr(model.ProviderMicrosoft), Name: ptr("x"), ClientID: ptr("c"), ClientSecret: ptr("s"), Tenant: ptr("consumers")},
		"ms orgs no list": {Type: ptr(model.ProviderMicrosoft), Name: ptr("x"), ClientID: ptr("c"), ClientSecret: ptr("s"), Tenant: ptr("organizations")},
		"ms bad allowed":  {Type: ptr(model.ProviderMicrosoft), Name: ptr("x"), ClientID: ptr("c"), ClientSecret: ptr("s"), Tenant: ptr("organizations"), AllowedTenants: &[]string{"nope"}},
		"auth0 no domain": {Type: ptr(model.ProviderAuth0), Name: ptr("x"), ClientID: ptr("c"), ClientSecret: ptr("s")},
	}
	for name, in := range cases {
		if _, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, in); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n, _ := c.svc.Providers.Count(c.ctx, c.a.ID); n != 0 {
		t.Errorf("%d providers stored by refused requests", n)
	}
	ms, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, service.ProviderInput{Type: ptr(model.ProviderMicrosoft), ClientID: ptr("c"), ClientSecret: ptr("s"),
		Tenant: ptr(strings.ToUpper(guid)), AllowedTenants: &[]string{guid}})
	if err != nil {
		t.Fatal(err)
	}
	if ms.Name == "" || ms.Tenant != guid || ms.AllowedTenants != nil {
		t.Errorf("microsoft single tenant: %+v", ms)
	}
	gh, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, service.ProviderInput{Type: ptr(model.ProviderGitHub), Name: ptr("gh"), ClientID: ptr("c"), ClientSecret: ptr("s"),
		AllowedDomains: &[]string{"@Example.com", "example.com"}})
	if err != nil || gh.Issuer != "" || len(gh.Scopes) != 2 || len(gh.AllowedDomains) != 1 || gh.AllowedDomains[0] != "example.com" {
		t.Errorf("github %+v %v", gh, err)
	}
	if sealed := gh.ClientSecret; sealed == "s" || sealed == "" {
		t.Error("client secret not sealed")
	}
	id := "0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b"
	custom := goodProvider("custom")
	custom.ID = &id
	if p, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, custom); err != nil || p.ID != id {
		t.Fatalf("chosen id: %v", err)
	}
	dup := goodProvider("other")
	dup.ID = &id
	if _, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, dup); !errors.Is(err, service.ErrConflict) {
		t.Errorf("reused id: %v", err)
	}
	if _, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, goodProvider("custom")); !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate name: %v", err)
	}
	if _, err := c.svc.UpdateProvider(c.ctx, sys, gh.ID, service.ProviderInput{Name: ptr("custom")}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("rename onto another: %v", err)
	}
}

// Pointing a provider at another issuer makes its subjects mean other people: every link goes, a new secret is
// needed, and the audit event records it (without the secret).
func TestUpdateProviderAuthorityChangeUnlinksIdentities(t *testing.T) {
	c := newCast(t)
	sys := service.System
	p, _ := c.svc.CreateProvider(c.ctx, sys, c.a.ID, goodProvider("sso"))
	q, _ := c.svc.CreateProvider(c.ctx, sys, c.a.ID, goodProvider("other"))
	c.link(c.aUser, p, "s1")
	c.link(c.aManager, p, "s2")
	c.link(c.aAdmin, q, "s3")

	if _, err := c.svc.UpdateProvider(c.ctx, sys, p.ID, service.ProviderInput{Issuer: ptr("https://evil.example.com")}); !isInvalid(err) {
		t.Fatalf("new issuer without a new secret: %v", err)
	}
	if n, _ := c.svc.Identities.Count(c.ctx, c.aUser.ID); n != 1 {
		t.Fatal("links removed by a refused update")
	}
	got, err := c.svc.UpdateProvider(c.ctx, sys, p.ID, service.ProviderInput{Issuer: ptr("https://other-issuer.example.com"), ClientSecret: ptr("new-secret")})
	if err != nil || got.Issuer != "https://other-issuer.example.com" {
		t.Fatalf("update: %v", err)
	}
	for _, u := range []*model.User{c.aUser, c.aManager} {
		if n, _ := c.svc.Identities.Count(c.ctx, u.ID); n != 0 {
			t.Errorf("%s keeps a link to the repointed provider", u.Username)
		}
	}
	if n, _ := c.svc.Identities.Count(c.ctx, c.aAdmin.ID); n != 1 {
		t.Error("another provider's link removed")
	}
	ev := c.audited(c.a.ID, "provider.update")
	if len(ev) != 1 {
		t.Fatalf("audit events %d", len(ev))
	}
	if d := ev[0].Detail; d["identities_unlinked"] != "2" || d["client_secret"] != "replaced" {
		t.Errorf("audit detail %v", d)
	}
	for _, v := range ev[0].Detail {
		if strings.Contains(v, "new-secret") {
			t.Error("secret in audit detail")
		}
	}
	// a rename alone keeps the links
	if _, err := c.svc.UpdateProvider(c.ctx, sys, q.ID, service.ProviderInput{Name: ptr("renamed")}); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.svc.Identities.Count(c.ctx, c.aAdmin.ID); n != 1 {
		t.Error("link lost on rename")
	}
	if err := c.svc.DeleteProvider(c.ctx, actor(c.aAdmin), q.ID); err != nil {
		t.Fatal(err)
	}
	if len(c.audited(c.a.ID, "provider.delete")) != 1 {
		t.Error("delete not audited")
	}
	en, err := c.svc.EnabledProviders(c.ctx, c.a.ID)
	if err != nil || len(en) != 1 || en[0].ID != p.ID {
		t.Errorf("enabled providers %v %v", en, err)
	}
}

func TestMasterKeyAgreementAndStatusStates(t *testing.T) {
	e := newEnv(t)
	st, err := e.svc.RotationStatus(e.ctx)
	if err != nil || st.State != "none" || st.Removable || !st.NodesAgree {
		t.Fatalf("no previous keys: %+v %v", st, err)
	}
	if ok, others, err := e.svc.MasterKeyAgreed(e.ctx); err != nil || !ok || len(others) != 0 {
		t.Errorf("no reports: %v %v %v", ok, others, err)
	}
	if err := e.svc.ReportMasterKey(e.ctx, "node-a"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ReportMasterKey(e.ctx, "node-a"); err != nil { // renewed in place
		t.Fatal(err)
	}
	if ok, _, _ := e.svc.MasterKeyAgreed(e.ctx); !ok {
		t.Error("a node on this key disagrees")
	}

	// Another node reports a different active key: the rotation waits for it, and nothing is declared removable.
	foreign := mustSealer(t)
	if err := e.svc.Locks.Create(e.ctx, &model.Lock{Meta: model.Meta{ID: "master-key/node-b"}, Holder: foreign.KeyIDs()[0], Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	ok, others, err := e.svc.MasterKeyAgreed(e.ctx)
	if err != nil || ok || others["node-b"] != foreign.KeyIDs()[0] {
		t.Fatalf("disagreement: %v %v %v", ok, others, err)
	}
	st, err = e.svc.RotationStatus(e.ctx)
	if err != nil || st.State != "waiting_for_nodes" || st.NodesAgree || st.Removable || !strings.Contains(st.Detail, "node-b") {
		t.Fatalf("waiting: %+v %v", st, err)
	}
	// An expired report stops counting.
	if l, err := e.svc.Locks.Get(e.ctx, "master-key/node-b"); err == nil {
		l.Until = time.Now().Add(-time.Minute)
		if err := e.svc.Locks.Update(e.ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _, _ := e.svc.MasterKeyAgreed(e.ctx); !ok {
		t.Error("expired report still counts")
	}
}

func mustSealer(t *testing.T) *secure.Sealer {
	t.Helper()
	s, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRotationStatusStates(t *testing.T) {
	e := newEnv(t)
	oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
	old, _ := secure.NewSealer(oldKey)
	e.svc.Sealer.Replace(old)
	u := e.user(e.primary.ID, "alan", model.RoleUser)
	u.TOTPSecret = old.SealFor(service.TOTPBinding(u.ID), []byte("totp"))
	if err := e.svc.Users.Update(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	ring, _ := secure.NewKeyring(newKey, oldKey)
	e.svc.Sealer.Replace(ring)
	if err := e.svc.ReportMasterKey(e.ctx, "n1"); err != nil {
		t.Fatal(err)
	}
	st, err := e.svc.RotationStatus(e.ctx)
	if err != nil || st.State != "resealing" || st.Stale == 0 || st.Removable {
		t.Fatalf("resealing: %+v %v", st, err)
	}
	// an unopenable secret outranks the rest
	foreign := mustSealer(t)
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	u.TOTPSecret = foreign.SealFor(service.TOTPBinding(u.ID), []byte("x"))
	_ = e.svc.Users.Update(e.ctx, u)
	if st, _ = e.svc.RotationStatus(e.ctx); st.State != "unopenable" || st.Unopenable != 1 {
		t.Fatalf("unopenable: %+v", st)
	}
}

// A grant's refresh token key is random and bound to the grant: it opens for that grant only; a grant without one
// has none.
func TestGrantKeys(t *testing.T) {
	e := newEnv(t)
	none := &model.Grant{Meta: model.Meta{ID: "g0"}}
	if k, err := e.svc.GrantRefreshKey(none); k != nil || err != nil {
		t.Errorf("grant without a key: %v %v", k, err)
	}
	n1, n2 := &model.Grant{Meta: model.Meta{ID: "n1"}}, &model.Grant{Meta: model.Meta{ID: "n2"}}
	e.svc.NewGrantKey(n1)
	e.svc.NewGrantKey(n2)
	k1, err1 := e.svc.GrantRefreshKey(n1)
	k2, _ := e.svc.GrantRefreshKey(n2)
	if err1 != nil || len(k1) != 32 || string(k1) == string(k2) {
		t.Errorf("new keys: %v", err1)
	}
	n1.ID = "n2" // moved onto another grant: it no longer opens
	if _, err := e.svc.GrantRefreshKey(n1); err == nil {
		t.Error("a grant key opened under another grant's id")
	}
}

func TestResealIdentityRefreshTokens(t *testing.T) {
	e := newEnv(t)
	oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
	old, _ := secure.NewSealer(oldKey)
	e.svc.Sealer.Replace(old)
	u := e.user(e.primary.ID, "alan", model.RoleUser)
	p, _ := e.svc.CreateProvider(e.ctx, service.System, e.primary.ID, goodProvider("sso"))
	id := model.NewIdentity(u, p, "sub", "", "admin")
	if err := e.svc.Identities.Create(e.ctx, id); err != nil {
		t.Fatal(err)
	}
	id.Refresh = old.SealFor(service.IdentityRefreshBinding(id.ID), []byte("upstream-refresh"))
	if err := e.svc.Identities.Update(e.ctx, id); err != nil {
		t.Fatal(err)
	}
	ring, _ := secure.NewKeyring(newKey, oldKey)
	e.svc.Sealer.Replace(ring)
	// a dry run (status) only counts
	st, _ := e.svc.RotationStatus(e.ctx)
	if st.Stale < 1 {
		t.Fatalf("stale not counted: %+v", st)
	}
	if got, _ := e.svc.Identities.Get(e.ctx, id.ID); got.Refresh != id.Refresh {
		t.Error("status rewrote a secret")
	}
	if r, err := e.svc.ResealSecrets(e.ctx, 100); err != nil || r.Resealed < 1 || !r.Done() {
		t.Fatalf("reseal %+v %v", r, err)
	}
	only, _ := secure.NewSealer(newKey)
	got, _ := e.svc.Identities.Get(e.ctx, id.ID)
	if v, err := only.OpenFor(service.IdentityRefreshBinding(id.ID), got.Refresh); err != nil || string(v) != "upstream-refresh" {
		t.Errorf("identity refresh token: %q %v", v, err)
	}
}

func TestBreakGlassInviteAndMarkLinkSent(t *testing.T) {
	c := newCast(t)
	// a disabled super admin locked out: the break-glass invite works where CreateInvite refuses, and enables again
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.pAdmin.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, actor(c.super), c.pAdmin.ID); !isInvalid(err) {
		t.Fatalf("normal invite of a disabled account: %v", err)
	}
	link, exp, err := c.svc.CreateBreakGlassInvite(c.ctx, c.pAdmin.ID)
	if err != nil || !exp.After(time.Now()) {
		t.Fatalf("break glass: %v", err)
	}
	if _, _, err := c.svc.CreateBreakGlassInvite(c.ctx, "nobody"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	ev := c.audited(c.pAdmin.OrgID, "user.invite.break_glass")
	if len(ev) != 1 || !strings.Contains(ev[0].Detail["account"], "disabled") {
		t.Fatalf("audit %+v", ev)
	}
	token := link[strings.Index(link, "token=")+6:]
	if err := c.svc.MarkLinkSent(c.ctx, link, c.pAdmin.Email); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.MarkLinkSent(c.ctx, "not-a-token", "x@example.com"); err == nil {
		t.Error("unknown link marked sent")
	}
	if _, _, err := c.svc.UseSignInLink(c.ctx, token, service.LinkInvite, "correct horse battery", service.NewCredEpoch()); err != nil {
		t.Fatal(err)
	}
	got := c.fresh(c.pAdmin)
	if !got.Active || !got.EmailVerified {
		t.Errorf("after break-glass use: active %v verified %v", got.Active, got.EmailVerified)
	}
	// the token by itself (not the URL) marks too
	l2, _, err := c.svc.CreateInvite(c.ctx, actor(c.super), c.pAdmin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.svc.MarkLinkSent(c.ctx, l2[strings.Index(l2, "token=")+6:], "other@example.com"); err != nil {
		t.Errorf("bare token: %v", err)
	}
}
