package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestFreshReviewAccessIntrospectionReflectsRemovedTenantAccess(t *testing.T) {
	h := setup(t, nil)
	tn := h.tenant("fresh-introspection", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	entry := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	tokens, _ := h.login(cl, secret, orgScope)
	at := tokens.str("access_token")
	if tokens.status != 200 || at == "" {
		t.Fatalf("login: %d %v", tokens.status, tokens.m)
	}
	if err := h.env.Svc.RemoveAccess(context.Background(), h.admin, tn.ID, entry.ID); err != nil {
		t.Fatal(err)
	}
	ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	text := body(ui)
	if ui.StatusCode != http.StatusUnauthorized {
		t.Fatalf("control: userinfo after removal: %d %s", ui.StatusCode, text)
	}
	if introspection := h.introspect(cl, secret, at); introspection["active"] != false {
		t.Fatalf("access token remains active after tenant access removed: %v", introspection)
	}
}

type freshReviewAccessReadFailure struct{ store.Store }

func (s freshReviewAccessReadFailure) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindAccess {
		return nil, errors.New("review: tenant access read failed")
	}
	return s.Store.Get(ctx, kind, id)
}
func TestFreshReviewUserinfoFailsClosedOnAccessReadFailure(t *testing.T) {
	h := setup(t, nil)
	tn := h.tenant("fresh-userinfo", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	tokens, _ := h.login(cl, secret, orgScope)
	at := tokens.str("access_token")
	if tokens.status != 200 || at == "" {
		t.Fatalf("login: %d %v", tokens.status, tokens.m)
	}
	h.env.Svc.Access.S = freshReviewAccessReadFailure{Store: h.env.Svc.Access.S}
	ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	text := body(ui)
	if ui.StatusCode == http.StatusOK {
		t.Fatalf("userinfo released profile despite access-check storage failure: %s", text)
	}
}

type freshReviewGrantDeleteFailure struct{ store.Store }

func (s freshReviewGrantDeleteFailure) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindGrant && r.Deleted {
		return errors.New("review: grant deletion failed")
	}
	return s.Store.Put(ctx, r)
}
func TestFreshReviewRevocationDoesNotReportSuccessWhenDeletionFails(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	tokens, _ := h.login(cl, secret, nil)
	rt := tokens.str("refresh_token")
	if tokens.status != 200 || rt == "" {
		t.Fatalf("login: %d %v", tokens.status, tokens.m)
	}
	h.env.Svc.Grants.S = freshReviewGrantDeleteFailure{Store: h.env.Svc.Grants.S}
	revoked := h.post("/oauth/revoke", url.Values{"token": {rt}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
	if revoked.status == 200 {
		refreshed := h.refreshWith(cl, secret, rt)
		t.Fatalf("revocation reported 200 while storage deletion failed; refresh afterward status=%d", refreshed.status)
	}
}
