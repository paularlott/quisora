package admin_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

func TestInviteEndpoint(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	id := w.users["user"].ID
	m := &fakeMailer{}
	w.mod.Mailer = m

	// plain link: url + expiry, nothing emailed
	r := ad.post(AU+"/"+id+"/invite", map[string]any{})
	want(t, r, 200)
	first := r.str("url")
	exp, err := time.Parse(time.RFC3339, r.str("expires"))
	if !strings.Contains(first, "/invite?token=") || err != nil || time.Until(exp) < 6*24*time.Hour || len(m.sent) != 0 {
		t.Fatalf("invite: %s", r.Raw)
	}
	// no body at all works too
	want(t, ad.do("POST", AU+"/"+id+"/invite", nil), 200)

	// emailing; a newer link replaces the older one
	r = ad.post(AU+"/"+id+"/invite", map[string]any{"email": true})
	want(t, r, 200)
	second := r.str("url")
	if second == first || r.JSON["emailed"] != true || len(m.sent) != 1 || m.sent[0] != "alan "+second {
		t.Fatalf("emailed invite: %s %v", r.Raw, m.sent)
	}
	tok := func(u string) string { return u[strings.Index(u, "token=")+6:] }
	if _, _, err := w.env.Svc.PeekLink(context.Background(), tok(first), service.LinkInvite); err == nil {
		t.Error("the first link still works")
	}
	if _, _, err := w.env.Svc.PeekLink(context.Background(), tok(second), service.LinkInvite); err != nil {
		t.Errorf("the newest link does not work: %v", err)
	}

	// unknown fields are rejected; a user without an address cannot be emailed (and no link is spent)
	want(t, ad.post(AU+"/"+id+"/invite", map[string]any{"password": "x"}), 400)

	// disabled users cannot be invited; you cannot invite or de-password yourself here
	want(t, ad.patch(AU+"/"+id, map[string]any{"active": false}), 200)
	want(t, ad.post(AU+"/"+id+"/invite", map[string]any{}), 422)
	self := w.users["admin"].ID
	want(t, ad.post(AU+"/"+self+"/invite", map[string]any{}), 422)
	want(t, ad.delete(AU+"/"+self+"/password"), 422)

	// unknown user, other organization
	want(t, ad.post(AU+"/nope/invite", map[string]any{}), 404)
	want(t, ad.delete(AU+"/nope/password"), 404)
	want(t, ad.post(AU+"/"+w.users["other"].ID+"/invite", map[string]any{}), 404)
	want(t, ad.delete(AU+"/"+w.users["other"].ID+"/password"), 404)
}

func TestInvitePermissions(t *testing.T) {
	w := newWorld(t)
	uid, mid, aid := w.users["user"].ID, w.users["manager"].ID, w.users["admin"].ID
	inv := func(c *caller, id string) int { return c.post(AU+"/"+id+"/invite", map[string]any{}).Status }
	rm := func(c *caller, id string) int { return c.delete(AU + "/" + id + "/password").Status }

	// super admin and admin: anyone below them (admins can also manage managers), not themselves
	su := w.as("super")
	for _, id := range []string{uid, mid, aid} {
		if s := inv(su, id); s != 200 {
			t.Errorf("super invites %s: %d", id, s)
		}
		if s := rm(su, id); s != 204 {
			t.Errorf("super removes password of %s: %d", id, s)
		}
	}
	ad := w.as("admin")
	// the manager holds the super admin's unused invitation: an admin cannot replace it (and accept the new one as
	// the manager); its issuer can
	if s := inv(ad, mid); s != 422 {
		t.Errorf("admin replaces the super admin's pending invitation: %d", s)
	}
	if s := inv(su, mid); s != 200 {
		t.Errorf("super replaces its own invitation: %d", s)
	}
	if s := rm(ad, mid); s != 204 {
		t.Errorf("admin removes manager password: %d", s)
	}

	// managers: plain users only
	mg := w.as("manager")
	if s := inv(mg, uid); s != 200 {
		t.Errorf("manager invites user: %d", s)
	}
	if s := rm(mg, uid); s != 204 {
		t.Errorf("manager removes user password: %d", s)
	}
	for _, id := range []string{aid} {
		if s := inv(mg, id); s != 403 {
			t.Errorf("manager invites admin: %d", s)
		}
		if s := rm(mg, id); s != 403 {
			t.Errorf("manager removes admin password: %d", s)
		}
	}
	if s := inv(mg, mid); s != 403 { // their own role is above what they manage
		t.Errorf("manager invites self: %d", s)
	}
	if s := rm(mg, mid); s != 403 {
		t.Errorf("manager removes own password: %d", s)
	}

	// plain users and other organizations
	us := w.as("user")
	if s := inv(us, uid); s != 404 { // the service hides users from those who cannot manage any
		t.Errorf("user invites: %d", s)
	}
	if s := rm(us, uid); s != 404 {
		t.Errorf("user removes password: %d", s)
	}
	ot := w.as("other")
	if s := inv(ot, uid); s != 404 {
		t.Errorf("other org invites: %d", s)
	}
	if s := rm(ot, uid); s != 404 {
		t.Errorf("other org removes password: %d", s)
	}

	// bearer tokens: the owner's role limits them; admin scope is required
	bt := w.withBearer("manager", service.ScopeAdmin)
	if s := inv(bt, uid); s != 200 {
		t.Errorf("bearer invite: %d", s)
	}
	if s := rm(bt, aid); s != 403 {
		t.Errorf("bearer remove admin password: %d", s)
	}
	if s := w.anon().post(AU+"/"+uid+"/invite", map[string]any{}).Status; s != 401 {
		t.Errorf("anonymous invite: %d", s)
	}
}
