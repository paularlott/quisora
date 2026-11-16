package oidc

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// logoutFor waits for a back-channel logout token for user from rp (failing after a while when want, or expecting none
// shortly when not).
func logoutFor(t *testing.T, rp *rpServer, userID string, want bool) {
	t.Helper()
	wait := 5 * time.Second
	if !want {
		wait = 300 * time.Millisecond
	}
	select {
	case lt := <-rp.got:
		if !want {
			t.Fatalf("a back-channel logout was sent: %v", claimsOf(t, lt))
		}
		if sub := claimsOf(t, lt)["sub"]; sub != userID {
			t.Fatalf("logout for %v, want %v", sub, userID)
		}
	case <-time.After(wait):
		if want {
			t.Fatal("no back-channel logout received")
		}
	}
}

// pastEnd moves access entry id's end into the past, as time passing does: the API sets no end there.
func (h *harness) pastEnd(id string) {
	h.t.Helper()
	ctx := context.Background()
	acc, err := h.env.Svc.Access.Get(ctx, id)
	if err != nil {
		h.t.Fatal(err)
	}
	acc.Expires = time.Now().Add(-time.Second).UTC().Truncate(time.Second)
	if err := h.env.Svc.Access.Update(ctx, acc); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) grantsFor(clientID string) int {
	h.t.Helper()
	gs, err := h.env.Svc.Grants.All(context.Background(), h.user.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	n := 0
	for _, g := range gs {
		if g.ClientID == clientID {
			n++
		}
	}
	return n
}

// An access entry with an end admits its user until then, and the access tokens issued under it expire by that end;
// once it passes, refresh, introspection, userinfo and sign-in refuse at once, and the housekeeping sweep removes the
// entry, signs the user out of the application (back-channel logout) and removes their refresh grants.
func TestTimedAccessBoundsTokensAndEnds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rp := newRP()
	defer rp.Close()
	h := setup(t, nil)
	tn := h.tenant("ops", membersOnly())
	cl, secret := h.tenantClient(tn, func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL + "/logout") })
	c, _ := h.session(h.user)
	_, ch := pkce()
	if code, st, _ := h.tryCode(c, cl, ch, nil); code != "" || st != http.StatusForbidden {
		t.Fatalf("before the access: %d", st)
	}
	end := time.Now().Add(2 * time.Minute).In(time.FixedZone("AWST", 8*3600)).Truncate(time.Second)
	e := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{Roles: &[]string{"oncall"}, Expires: ptr(end.Format(time.RFC3339))})
	if !e.Expires.Equal(end) || e.Expires.Location() != time.UTC {
		t.Fatalf("end %v, want %v in UTC", e.Expires, end)
	}
	r, _ := h.login(cl, secret, orgScope)
	cm := claimsOf(t, r.str("access_token"))
	exp, _ := cm["exp"].(float64)
	if !equalStrs(strsOf(cm["roles"]), []string{"oncall"}) || int64(exp) > end.Unix() {
		t.Fatalf("the access token outlives the access (exp %v, end %v) or lacks its roles: %v", int64(exp), end.Unix(), cm)
	}
	if n, _ := r.m["expires_in"].(float64); n > 120 {
		t.Fatalf("expires_in %v past the access's end", n)
	}
	r2 := h.refreshWith(cl, secret, r.str("refresh_token"))
	if r2.status != 200 {
		t.Fatalf("refresh under the access: %d %v", r2.status, r2.m)
	}
	if exp, _ := claimsOf(t, r2.str("access_token"))["exp"].(float64); int64(exp) > end.Unix() {
		t.Fatalf("a refreshed access token outlives the access: %v > %v", int64(exp), end.Unix())
	}
	if h.grantsFor(cl.ID) == 0 {
		t.Fatal("no refresh grant to end")
	}

	// The end passes: everything refuses at once, before any sweep.
	h.pastEnd(e.ID)
	if m := h.introspect(cl, secret, r2.str("access_token")); m["active"] != false {
		t.Fatalf("introspect after the end: %v", m)
	}
	ui := h.get(&http.Client{Transport: h.http.Transport}, h.orgBase+"/oauth/userinfo", "Authorization", "Bearer "+r2.str("access_token"))
	if ui.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo after the end: %d", ui.StatusCode)
	}
	if code, st, _ := h.tryCode(c, cl, ch, nil); code != "" || st != http.StatusForbidden {
		t.Fatalf("sign-in after the end: %d", st)
	}

	// The sweep: the entry goes, the application is told, the grants go.
	n, err := h.env.Svc.ExpireAccess(ctx)
	if err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	logoutFor(t, rp, h.user.ID, true)
	if _, err := h.env.Svc.Access.Get(ctx, e.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the entry is still there: %v", err)
	}
	if n := h.grantsFor(cl.ID); n != 0 {
		t.Fatalf("%d refresh grants left", n)
	}
	if r := h.refreshWith(cl, secret, r2.str("refresh_token")); r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("refresh after the sweep: %d %v", r.status, r.m)
	}
	if n, err := h.env.Svc.ExpireAccess(ctx); err != nil || n != 0 {
		t.Fatalf("a second sweep: %d %v", n, err)
	}
}

// Standing access (an entry without an end) and a timed one together: tokens get their usual lifetime, and the timed
// entry's end signs nobody out, as the standing entry still lets them in.
func TestTimedAccessWithStandingAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rp := newRP()
	defer rp.Close()
	h := setup(t, nil)
	tn := h.tenant("ops", membersOnly())
	cl, secret := h.tenantClient(tn, func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL + "/logout") })
	g, err := h.env.Svc.CreateGroupWithMembers(ctx, service.System, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("Support")},
		[]string{h.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	h.grant(tn, model.SubjectGroup, g.ID, service.AccessInput{})
	end := time.Now().Add(2 * time.Minute)
	e := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{Roles: &[]string{"oncall"}, Expires: ptr(end.Format(time.RFC3339))})
	r, _ := h.login(cl, secret, orgScope)
	if exp, _ := claimsOf(t, r.str("access_token"))["exp"].(float64); int64(exp) <= end.Unix() {
		t.Fatalf("standing access, yet the access token ends with the timed entry: %v", int64(exp))
	}
	h.pastEnd(e.ID)
	if n, err := h.env.Svc.ExpireAccess(ctx); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	logoutFor(t, rp, h.user.ID, false)
	r2 := h.refreshWith(cl, secret, r.str("refresh_token"))
	if r2.status != 200 || len(strsOf(claimsOf(t, r2.str("access_token"))["roles"])) != 0 {
		t.Fatalf("refresh through the group after the timed entry ended: %d %v", r2.status, r2.m)
	}
}

// Removing access, or narrowing it, signs the people who lost an application out of it (back-channel logout, refresh
// grants removed): a group's entry its members, unless something else still lets them in.
func TestRemovingAccessSignsOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rp := newRP()
	defer rp.Close()
	h := setup(t, nil)
	tn := h.tenant("ops", membersOnly())
	cl, secret := h.tenantClient(tn, func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL + "/logout") })
	other, _ := h.tenantClient(tn, nil)
	g, err := h.env.Svc.CreateGroupWithMembers(ctx, service.System, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("Support")},
		[]string{h.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	ge := h.grant(tn, model.SubjectGroup, g.ID, service.AccessInput{})
	ue := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	r, _ := h.login(cl, secret, orgScope)

	// The group's entry goes, the user's own still lets them in: nobody is signed out.
	if err := h.env.Svc.RemoveAccess(ctx, h.admin, tn.ID, ge.ID); err != nil {
		t.Fatal(err)
	}
	h.env.Svc.WaitBackground()
	logoutFor(t, rp, h.user.ID, false)
	if h.grantsFor(cl.ID) == 0 {
		t.Fatal("signed out while still allowed")
	}

	// Narrowed to the other application: signed out of this one.
	if _, err := h.env.Svc.UpdateAccess(ctx, h.admin, tn.ID, ue.ID, service.AccessInput{AllClients: ptr(false), Clients: &[]string{other.ID}}); err != nil {
		t.Fatal(err)
	}
	h.env.Svc.WaitBackground()
	logoutFor(t, rp, h.user.ID, true)
	if n := h.grantsFor(cl.ID); n != 0 {
		t.Fatalf("%d refresh grants left after narrowing", n)
	}
	if r := h.refreshWith(cl, secret, r.str("refresh_token")); r.status != 400 {
		t.Fatalf("refresh after narrowing: %d", r.status)
	}

	// Back to every application through the group, signed in again, then the group's entry removed: signed out.
	if _, err := h.env.Svc.UpdateAccess(ctx, h.admin, tn.ID, ue.ID, service.AccessInput{AllClients: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.RemoveAccess(ctx, h.admin, tn.ID, ue.ID); err != nil {
		t.Fatal(err)
	}
	h.env.Svc.WaitBackground()
	ge = h.grant(tn, model.SubjectGroup, g.ID, service.AccessInput{})
	h.login(cl, secret, orgScope)
	if err := h.env.Svc.RemoveAccess(ctx, h.admin, tn.ID, ge.ID); err != nil {
		t.Fatal(err)
	}
	h.env.Svc.WaitBackground()
	logoutFor(t, rp, h.user.ID, true)
	if n := h.grantsFor(cl.ID); n != 0 {
		t.Fatalf("%d refresh grants left after the group's access went", n)
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
