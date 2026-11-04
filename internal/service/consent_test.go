package service_test

import (
	"fmt"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
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

// covers reports whether user userID's remembered consent covers openid for client clientID, as the client now is.
func (e *env) covers(userID, clientID string) bool {
	e.t.Helper()
	c, err := e.svc.Clients.Get(e.ctx, clientID)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.svc.ConsentCovers(e.ctx, userID, c, []string{"openid"}, nil)
}

// consentStored reports whether a consent record of user userID for client clientID exists, honoured or not.
func (e *env) consentStored(userID, clientID string) bool {
	_, err := e.svc.Consents.Get(e.ctx, model.ConsentID(userID, clientID))
	return err == nil
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
			if err := e.svc.RememberConsent(e.ctx, u, c, []string{"openid"}, nil); err != nil {
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
	if !e.covers(alan.ID, cl.ID) {
		t.Fatal("consent forgotten by an unrelated change")
	}
	if _, err := e.svc.UpdateClient(e.ctx, service.System, cl.ID, service.ClientInput{RememberConsent: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*model.User{alan, ada} {
		if e.covers(u.ID, cl.ID) || e.consentStored(u.ID, cl.ID) {
			t.Errorf("%s: consent kept after the client stopped remembering", u.Username)
		}
		if !e.covers(u.ID, other.ID) {
			t.Errorf("%s: another client's consent forgotten", u.Username)
		}
	}
	if _, err := e.svc.UpdateClient(e.ctx, service.System, cl.ID, service.ClientInput{RememberConsent: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if e.covers(alan.ID, cl.ID) {
		t.Fatal("turning it on again brought old consent back")
	}
	// a consent left behind (its removal failed) is neither listed nor honoured, even once the client remembers again
	if _, err := e.svc.UpdateClient(e.ctx, service.System, cl.ID, service.ClientInput{RememberConsent: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	stale, _ := e.svc.Clients.Get(e.ctx, cl.ID)
	if err := e.svc.Consents.Create(e.ctx, &model.Consent{Meta: model.Meta{ID: model.ConsentID(alan.ID, cl.ID)}, UserID: alan.ID,
		OrgID: acme.ID, ClientID: cl.ID, Allowed: []model.ConsentSet{{Scopes: []string{"openid"}}}, Gen: stale.RememberGen}); err != nil {
		t.Fatal(err)
	}
	listed := func() []service.AppGrant {
		t.Helper()
		apps, err := e.svc.ConnectedApps(e.ctx, alan.ID)
		if err != nil {
			t.Fatal(err)
		}
		return apps
	}
	if apps := listed(); len(apps) != 1 || apps[0].ClientID != other.ID {
		t.Fatalf("connected apps while off %+v", apps)
	}
	if _, err := e.svc.UpdateClient(e.ctx, service.System, cl.ID, service.ClientInput{RememberConsent: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if e.covers(alan.ID, cl.ID) {
		t.Fatal("a consent left behind came back into effect")
	}
	if apps := listed(); len(apps) != 1 || apps[0].ClientID != other.ID {
		t.Fatalf("connected apps after turning it on again %+v", apps)
	}
	// approving again starts the consent afresh: honoured from then on
	fresh, _ := e.svc.Clients.Get(e.ctx, cl.ID)
	if err := e.svc.RememberConsent(e.ctx, alan, fresh, []string{"openid"}, nil); err != nil {
		t.Fatal(err)
	}
	if !e.covers(alan.ID, cl.ID) {
		t.Fatal("approving again is not remembered")
	}
}

// Turning remembering off removes every user's consent for the client, however many there are (read a page at a
// time), and no other client's.
func TestForgetManyConsents(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	cl, other := e.consentClient(acme.ID, "App"), e.consentClient(acme.ID, "Other")
	const n = 1234 // over two pages
	for i := range n {
		uid := fmt.Sprintf("user-%04d", i)
		for _, c := range []*model.Client{cl, other} {
			if err := e.svc.Consents.Create(e.ctx, &model.Consent{Meta: model.Meta{ID: model.ConsentID(uid, c.ID)},
				UserID: uid, OrgID: acme.ID, ClientID: c.ID, Allowed: []model.ConsentSet{{Scopes: []string{"openid"}}}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := e.svc.UpdateClient(e.ctx, service.System, cl.ID, service.ClientInput{RememberConsent: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	count := func(clientID string) int {
		ids, _, err := e.svc.Consents.IDs(e.ctx, store.ListQuery{Filters: []store.Filter{{Field: "client_id", Value: clientID}}})
		if err != nil {
			t.Fatal(err)
		}
		return len(ids)
	}
	if got := count(cl.ID); got != 0 {
		t.Errorf("%d consents left", got)
	}
	if got := count(other.ID); got != n {
		t.Errorf("other client has %d consents, want %d", got, n)
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
			if err := e.svc.RememberConsent(e.ctx, u, c, []string{"openid"}, nil); err != nil {
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
	if err := e.svc.RememberConsent(e.ctx, alan, cl, []string{"openid"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RevokeAppAccess(e.ctx, alan.ID, cl.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RememberConsent(e.ctx, alan, cl, []string{"openid"}, nil); err != nil {
		t.Fatalf("again: %v", err)
	}
	if !e.covers(alan.ID, cl.ID) {
		t.Fatal("not remembered again")
	}
}
