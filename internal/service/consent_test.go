package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// consentClient is a confidential client of org that remembers consent.
func (e *env) consentClient(orgID, name string) *model.Client {
	e.t.Helper()
	c, _, err := e.svc.CreateClient(e.ctx, service.System, orgID, service.ClientInput{Name: &name,
		RedirectURIs: &[]string{"https://app.example/cb"}, GrantTypes: &[]string{"authorization_code"},
		Scopes: &[]string{"openid"}, RememberConsent: ptr(true)})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// A client that stops remembering consent forgets what its users allowed (turning it on again asks everyone afresh),
// and the Connected apps list leaves it out meanwhile.
func TestClientForgetsConsentWhenItStopsRemembering(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	alan := e.user(acme.ID, "alan", model.RoleUser)
	ada := e.user(acme.ID, "ada", model.RoleUser)
	cl := e.consentClient(acme.ID, "App")
	other := e.consentClient(acme.ID, "Other")
	for _, u := range []*model.User{alan, ada} {
		for _, c := range []*model.Client{cl, other} {
			if err := e.svc.RememberConsent(e.ctx, u, c.ID, []string{"openid"}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	apps, err := e.svc.ConnectedApps(e.ctx, alan.ID)
	if err != nil || len(apps) != 2 || !apps[0].Remembered {
		t.Fatalf("connected apps %+v %v", apps, err)
	}
	// an update that leaves the setting alone forgets nothing
	if _, err := e.svc.UpdateClient(e.ctx, service.System, cl.ID, service.ClientInput{Name: ptr("App 2")}); err != nil {
		t.Fatal(err)
	}
	if !e.svc.ConsentCovers(e.ctx, alan.ID, cl.ID, []string{"openid"}, nil) {
		t.Fatal("consent forgotten by an unrelated change")
	}
	if _, err := e.svc.UpdateClient(e.ctx, service.System, cl.ID, service.ClientInput{RememberConsent: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*model.User{alan, ada} {
		if e.svc.ConsentCovers(e.ctx, u.ID, cl.ID, []string{"openid"}, nil) {
			t.Errorf("%s: consent kept after the client stopped remembering", u.Username)
		}
		if !e.svc.ConsentCovers(e.ctx, u.ID, other.ID, []string{"openid"}, nil) {
			t.Errorf("%s: another client's consent forgotten", u.Username)
		}
	}
	if _, err := e.svc.UpdateClient(e.ctx, service.System, cl.ID, service.ClientInput{RememberConsent: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if e.svc.ConsentCovers(e.ctx, alan.ID, cl.ID, []string{"openid"}, nil) {
		t.Fatal("turning it on again brought old consent back")
	}
	// a stored consent the client does not honour (one left behind) is not listed
	if _, err := e.svc.UpdateClient(e.ctx, service.System, cl.ID, service.ClientInput{RememberConsent: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Consents.Create(e.ctx, &model.Consent{Meta: model.Meta{ID: model.ConsentID(alan.ID, cl.ID)}, UserID: alan.ID,
		OrgID: acme.ID, ClientID: cl.ID, Allowed: []model.ConsentSet{{Scopes: []string{"openid"}}}}); err != nil {
		t.Fatal(err)
	}
	apps, err = e.svc.ConnectedApps(e.ctx, alan.ID)
	if err != nil || len(apps) != 1 || apps[0].ClientID != other.ID {
		t.Fatalf("connected apps %+v %v", apps, err)
	}
}

// The orphan sweep removes a remembered consent once its user or its client is gone.
func TestSweepRemovesConsentOfAGoneUserOrClient(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	alan := e.user(acme.ID, "alan", model.RoleUser)
	ada := e.user(acme.ID, "ada", model.RoleUser)
	kept, gone := e.consentClient(acme.ID, "Kept"), e.consentClient(acme.ID, "Gone")
	for _, u := range []*model.User{alan, ada} {
		for _, c := range []*model.Client{kept, gone} {
			if err := e.svc.RememberConsent(e.ctx, u, c.ID, []string{"openid"}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := e.svc.DeleteUser(e.ctx, service.System, ada.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteClient(e.ctx, service.System, gone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SweepAll(e.ctx); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		user, client string
		want         bool
	}{{alan.ID, kept.ID, true}, {alan.ID, gone.ID, false}, {ada.ID, kept.ID, false}, {ada.ID, gone.ID, false}} {
		_, err := e.svc.Consents.Get(e.ctx, model.ConsentID(tc.user, tc.client))
		if got := err == nil; got != tc.want {
			t.Errorf("consent of %s for %s kept %v, want %v", tc.user, tc.client, got, tc.want)
		}
	}
}

// After the user removes an application, approving it again is remembered again.
func TestConsentAgainAfterRevoke(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	alan := e.user(acme.ID, "alan", model.RoleUser)
	cl := e.consentClient(acme.ID, "App")
	if err := e.svc.RememberConsent(e.ctx, alan, cl.ID, []string{"openid"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RevokeAppAccess(e.ctx, alan.ID, cl.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RememberConsent(e.ctx, alan, cl.ID, []string{"openid"}, nil); err != nil {
		t.Fatalf("again: %v", err)
	}
	if !e.svc.ConsentCovers(e.ctx, alan.ID, cl.ID, []string{"openid"}, nil) {
		t.Fatal("not remembered again")
	}
}
