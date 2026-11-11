package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestRefreshDefaultMode(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	if parts := strings.Split(rt, "."); len(parts) != 2 {
		t.Fatalf("default refresh token should be grantID.secret: %s", rt)
	}
	if n := claimsOf(t, r.str("id_token"))["nonce"]; n != "n1" {
		t.Fatalf("the code exchange's ID token nonce: %v", n)
	}
	for range 3 { // a pure read: same token keeps working and no new one is returned
		r2 := h.refreshWith(cl, secret, rt)
		if r2.status != 200 || r2.str("refresh_token") != "" || r2.str("access_token") == "" || r2.str("id_token") == "" {
			t.Fatalf("%v", r2)
		}
		if n, ok := claimsOf(t, r2.str("id_token"))["nonce"]; ok {
			t.Fatalf("a refreshed ID token carries a nonce: %v", n)
		}
	}
	// wrong secret part, wrong grant, garbage
	gid := strings.Split(rt, ".")[0]
	for _, bad := range []string{gid + "." + b64.EncodeToString(randBytes(32)), "x." + b64.EncodeToString(randBytes(32)), "garbage", "", gid, gid + ".!!!"} {
		if r := h.refreshWith(cl, secret, bad); r.status != 400 || r.m["error"] != "invalid_grant" {
			t.Errorf("%q: %v", bad, r)
		}
	}
	// another client cannot use it
	other, os := h.newClient(nil)
	if r := h.refreshWith(other, os, rt); r.status != 400 {
		t.Fatal("cross-client refresh")
	}
	// scope escalation
	if r := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "scope": {"openid groups"}}, cl, secret); r.m["error"] != "invalid_scope" {
		t.Fatalf("%v", r.m)
	}
	// narrower scope
	if r := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "scope": {"openid"}}, cl, secret); r.status != 200 || r.str("scope") != "openid" {
		t.Fatalf("%v", r.m)
	}
	// disabled user
	if _, err := h.env.Svc.UpdateUser(context.Background(), h.admin, h.user.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	if r := h.refreshWith(cl, secret, rt); r.status != 400 {
		t.Fatal("disabled user refreshed")
	}
	if m := h.introspect(cl, secret, r.str("access_token")); m["active"] != false {
		t.Fatal("disabled user's access token active")
	}
	resp := h.get(h.http, h.orgBase+"/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token"))
	if resp.StatusCode != 401 {
		t.Fatal("userinfo for disabled user", resp.StatusCode)
	}
	// disabling the user also ended their grants: re-enabling does not bring the token back
	h.env.Svc.UpdateUser(context.Background(), h.admin, h.user.ID, service.UserInput{Active: ptr(true)})
	h.p.InvalidateUser(h.user.ID)
	if r := h.refreshWith(cl, secret, rt); r.status != 400 {
		t.Fatal("grant survived disabling the user")
	}
}

func TestRefreshRotation(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	rt0 := r.str("refresh_token")
	if len(strings.Split(rt0, ".")) != 3 {
		t.Fatalf("rotating token format: %s", rt0)
	}
	r1 := h.refreshWith(cl, secret, rt0)
	rt1 := r1.str("refresh_token")
	if r1.status != 200 || rt1 == "" || rt1 == rt0 {
		t.Fatalf("%v", r1)
	}
	r2 := h.refreshWith(cl, secret, rt1)
	rt2 := r2.str("refresh_token")
	if r2.status != 200 || rt2 == "" {
		t.Fatal(r2)
	}
	// replaying an old token kills the whole family, including the newest token
	if r := h.refreshWith(cl, secret, rt0); r.status != 400 {
		t.Fatal("old token accepted")
	}
	if r := h.refreshWith(cl, secret, rt2); r.status != 400 {
		t.Fatal("newest token survived reuse detection")
	}
	// forged MAC / counter never revoke anything
	r, _ = h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	parts := strings.Split(rt, ".")
	forged := parts[0] + ".5." + parts[2]
	if r := h.refreshWith(cl, secret, forged); r.status != 400 {
		t.Fatal("forged counter accepted")
	}
	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatal("forgery revoked the grant")
	}
}

// One token presented many times at once rotates the grant once: the presentations that succeed all get the same
// next token (a confidential client retrying within refreshRetryGrace is answered again, not forked), so there is
// never more than one live token of the family.
func TestRefreshRotationRace(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	var mu sync.Mutex
	next := map[string]int{}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if x := h.refreshWith(cl, secret, rt); x.status == 200 {
				mu.Lock()
				next[x.str("refresh_token")]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(next) != 1 {
		t.Fatalf("one token rotated into %d different tokens: %v", len(next), next)
	}
	gid, _, _ := strings.Cut(rt, ".")
	if g, err := h.env.Svc.Grants.Get(context.Background(), gid); err != nil || g.Counter != 1 {
		t.Fatalf("the grant rotated %v times (%v)", g, err)
	}
}

func TestRotateFlagUpgradesStaticToken(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	static := r.str("refresh_token")
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{RotateRefresh: ptr(true)})
	h.p.InvalidateClient(cl.ID)
	r2 := h.refreshWith(cl, secret, static)
	if r2.status != 200 || len(strings.Split(r2.str("refresh_token"), ".")) != 3 {
		t.Fatal(r2)
	}
	if r := h.refreshWith(cl, secret, static); r.status != 400 {
		t.Fatal("static token still valid after rotation began")
	}
	// presenting the pre-rotation token again is reuse: the family dies, including the newest token
	if r := h.refreshWith(cl, secret, r2.str("refresh_token")); r.status != 400 {
		t.Fatal("grant survived replay of a pre-rotation static token")
	}
}

// A grant lives with its session unless it was given offline_access, which lets it outlive the session's expiry; the
// deletion of the session (a sign-out) ends both.
func TestRefreshNeedsOfflineAccessToOutliveSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, offline := range []bool{false, true} {
		scope := "openid profile"
		if offline {
			scope += " offline_access"
		}
		login := func(t *testing.T) (h *harness, cl *model.Client, secret, rt, sid string) {
			h = setup(t, nil)
			cl, secret = h.newClient(nil)
			r, _ := h.login(cl, secret, url.Values{"scope": {scope}})
			rt = r.str("refresh_token")
			if rt == "" {
				t.Fatal("no refresh token")
			}
			if r := h.refreshWith(cl, secret, rt); r.status != 200 {
				t.Fatalf("refresh while signed in: %d %v", r.status, r.m)
			}
			return h, cl, secret, rt, claimsOf(t, r.str("access_token"))["sid"].(string)
		}
		t.Run(fmt.Sprintf("expired session, offline=%v", offline), func(t *testing.T) {
			h, cl, secret, rt, sid := login(t)
			s, err := h.env.Svc.Sessions.Get(ctx, sid)
			if err != nil {
				t.Fatal(err)
			}
			s.LastSeen, s.IdleTTL = time.Now().Add(-48*time.Hour), 60 // idle for two days: expired
			if err := h.env.Svc.Sessions.Update(ctx, s); err != nil {
				t.Fatal(err)
			}
			want := 400
			if offline {
				want = 200
			}
			if got := h.refreshWith(cl, secret, rt).status; got != want {
				t.Errorf("refresh after the session expired: %d, want %d", got, want)
			}
		})
		t.Run(fmt.Sprintf("signed out, offline=%v", offline), func(t *testing.T) {
			h, cl, secret, rt, sid := login(t)
			if err := h.env.Server.Sessions.Delete(ctx, sid); err != nil {
				t.Fatal(err)
			}
			tokenErr(t, h.refreshWith(cl, secret, rt), 400, "invalid_grant")
		})
		if !offline { // a session gone from the store ends the grant that lives with it, whatever removed it
			t.Run("session record gone", func(t *testing.T) {
				h, cl, secret, rt, sid := login(t)
				if err := h.env.Svc.Sessions.Delete(ctx, sid); err != nil {
					t.Fatal(err)
				}
				tokenErr(t, h.refreshWith(cl, secret, rt), 400, "invalid_grant")
			})
		}
	}
}

// The stored grant key is sealed with the master key: a refresh token built from the stored value (a database copy
// without the master key) is refused.
func TestRefreshNotForgeableFromDatabase(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	gid, _, _ := strings.Cut(r.str("refresh_token"), ".")
	g, err := h.env.Svc.Grants.Get(context.Background(), gid)
	if err != nil {
		t.Fatal(err)
	}
	forged := gid + "." + base64.RawURLEncoding.EncodeToString([]byte(g.Key))
	if x := h.refreshWith(cl, secret, forged); x.status != 400 {
		t.Errorf("forged from the stored key: %d", x.status)
	}
	if x := h.refreshWith(cl, secret, r.str("refresh_token")); x.status != 200 {
		t.Errorf("genuine: %d %v", x.status, x.m)
	}
}

// Master key rotation: a refresh token stays the same across a rotation and keeps working once the old key is
// removed, because the grant's own key is re-sealed with the new one; the old key alone opens nothing any more.
func TestRefreshTokenAcrossMasterKeyRotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	k0, k1 := secure.RandomBytes(32), secure.RandomBytes(32)
	h := setupKey(t, nil, k0)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}})
	rt := r.str("refresh_token")
	if rt == "" {
		t.Fatal("no refresh token")
	}
	rotating, rsecret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ = h.login(rotating, rsecret, url.Values{"scope": {"openid profile offline_access"}})
	rrt := r.str("refresh_token")

	ring, _ := secure.NewKeyring(k1, k0)
	h.env.Svc.Sealer = ring
	if r := h.refreshWith(cl, secret, rt); r.status != 200 || r.str("refresh_token") != "" {
		t.Fatalf("during the rotation: %d %v", r.status, r.m)
	}
	if res, err := h.env.Svc.ResealSecrets(ctx, time.Minute); err != nil || !res.Done() {
		t.Fatalf("reseal: %+v %v", res, err)
	}

	only1, _ := secure.NewSealer(k1)
	h.env.Svc.Sealer = only1
	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatalf("the same token after the old key was removed: %d %v", r.status, r.m)
	}
	r = h.refreshWith(rotating, rsecret, rrt)
	if r.status != 200 || r.str("refresh_token") == "" {
		t.Fatalf("rotating token after the old key was removed: %d %v", r.status, r.m)
	}
	if r := h.refreshWith(rotating, rsecret, r.str("refresh_token")); r.status != 200 {
		t.Fatalf("the next rotating token: %d %v", r.status, r.m)
	}

	// nothing stored opens with the old key any more
	old, _ := secure.NewSealer(k0)
	gs, _, _ := h.env.Svc.Grants.List(ctx, store.ListQuery{})
	for _, g := range gs {
		if _, err := old.OpenFor(service.GrantKeyBinding(g.ID), g.Key); err == nil {
			t.Fatalf("grant %s still opens with the old key", g.ID)
		}
	}
}

// OIDC Core §12.2: an ID token issued at a refresh has no nonce (it answers no authentication request), while the
// one of the code exchange carries the request's. Pinned so that no one carries the nonce over to refreshes.
// A refresh whose rotation committed (the counter moved) but whose response never reached the client: the client
// retries with the token it still has. A confidential client (it authenticates, so a copied token alone is not
// enough) retrying within refreshRetryGrace gets the token it missed, and nothing rotates again; a public client
// without DPoP has only the token, so its retry is reuse and the grant ends.
func TestRefreshLostResponseRetry(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	old := r.str("refresh_token")
	gid := strings.SplitN(old, ".", 2)[0]
	lost := h.refreshWith(cl, secret, old)
	if lost.status != 200 {
		t.Fatalf("%v", lost.m)
	}
	retry := h.refreshWith(cl, secret, old)
	if retry.status != 200 || retry.str("refresh_token") != lost.str("refresh_token") {
		t.Fatalf("the retry: %d, same token %v", retry.status, retry.str("refresh_token") == lost.str("refresh_token"))
	}
	if g, err := h.env.Svc.Grants.Get(context.Background(), gid); err != nil || g.Counter != 1 {
		t.Fatalf("after the retry: %+v %v", g, err)
	}
	if next := h.refreshWith(cl, secret, retry.str("refresh_token")); next.status != 200 {
		t.Fatalf("the token the retry got: %d", next.status)
	}
	if len(h.auditEvents("oauth.refresh.reuse")) != 0 {
		t.Fatal("a retry was recorded as reuse")
	}
}

// A refresh token that is malformed, forged, or beyond the grant is refused without ending the grant.
func TestRefreshTokenFormatRefusals(t *testing.T) {
	t.Parallel()
	t.Run("rotating client", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
		r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}, "resource": {"https://api.example/a"}})
		rt := r.str("refresh_token")
		parts := strings.Split(rt, ".")

		for _, bad := range []string{"", "nodot", ".x", "a.b.c", "a.x.!!", "g.1.x" + strings.Repeat("y", 400), parts[0] + ".!!!"} {
			tokenErr(t, h.refreshWith(cl, secret, bad), 400, "invalid_grant")
		}
		// unknown grant
		tokenErr(t, h.refreshWith(cl, secret, "nosuchgrant."+parts[1]+"."+parts[2]), 400, "invalid_grant")
		// forged MAC
		tokenErr(t, h.refreshWith(cl, secret, parts[0]+".0."+b64.EncodeToString([]byte("forged-mac-forged-mac-forged-mac!"))), 400, "invalid_grant")
		// a malformed resource
		tokenErr(t, h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {"%%"}}, cl, secret), 400, "invalid_target")

		// a narrowed refresh works and rotates
		ok := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "scope": {"openid"}, "resource": {"https://api.example/a"}}, cl, secret)
		if ok.status != 200 || ok.str("scope") != "openid" || ok.str("refresh_token") == rt {
			t.Fatalf("%d %v", ok.status, ok.m)
		}
	})

	t.Run("static client", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		r, _ := h.login(cl, secret, nil)
		rt := r.str("refresh_token")
		// a counted token for a static client whose counter is not the grant's is refused
		g := strings.SplitN(rt, ".", 2)[0]
		tokenErr(t, h.refreshWith(cl, secret, g+".3."+b64.EncodeToString([]byte("x"))), 400, "invalid_grant")
		if h.refreshWith(cl, secret, rt).status != 200 {
			t.Fatal("static refresh")
		}
	})
}

// A refresh that cannot write the grant's new state answers by cause: this node cannot write (retry), another write error
// (server error), the write kept going stale (give up), or the grant changed meanwhile (revoked, reused, or an
// unrelated rewrite that lets the refresh go ahead on the new copy).
func TestRefreshWriteConflicts(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	good := h.env.Svc.Grants.S
	// failGrants makes the grant compare-and-puts answer err() until the subtest ends
	failGrants := func(t *testing.T, err func() error) {
		h.env.Svc.Grants.S = failCAS(good, model.KindGrant, err)
		t.Cleanup(func() { h.env.Svc.Grants.S = good })
	}
	fresh := func() (rt, gid string) {
		r, _ := h.login(cl, secret, nil)
		rt = r.str("refresh_token")
		return rt, strings.SplitN(rt, ".", 2)[0]
	}
	t.Run("not writable", func(t *testing.T) {
		rt, _ := fresh()
		failGrants(t, func() error { return store.ErrUnavailable })
		expectUnavailable(t, "not writable", h.refreshWith(cl, secret, rt))
	})
	t.Run("other write error", func(t *testing.T) {
		rt, _ := fresh()
		failGrants(t, func() error { return errors.New("disk full") })
		if x := h.refreshWith(cl, secret, rt); x.status != 500 || x.m["error"] != "server_error" {
			t.Fatalf("%d %v", x.status, x.m)
		}
	})
	t.Run("stale writes that never end", func(t *testing.T) {
		rt, _ := fresh()
		var n atomic.Int32
		failGrants(t, func() error { n.Add(1); return store.ErrStale })
		tokenErr(t, h.refreshWith(cl, secret, rt), 400, "invalid_grant")
		if n.Load() != 3 {
			t.Fatalf("attempts: %d", n.Load())
		}
	})
	t.Run("stale because the grant was revoked", func(t *testing.T) {
		rt, gid := fresh()
		var once atomic.Bool
		failGrants(t, func() error {
			if once.CompareAndSwap(false, true) {
				_ = h.env.Svc.Grants.Delete(context.Background(), gid) // via the failing store: Put is not intercepted
			}
			return store.ErrStale
		})
		tokenErr(t, h.refreshWith(cl, secret, rt), 400, "invalid_grant")
	})
	t.Run("stale because another presentation of the token won", func(t *testing.T) {
		rt, gid := fresh()
		var once atomic.Bool
		failGrants(t, func() error {
			if once.CompareAndSwap(false, true) {
				tbl := *h.env.Svc.Grants
				tbl.S = good
				g, err := tbl.Get(context.Background(), gid)
				if err != nil {
					t.Error(err)
					return store.ErrStale
				}
				g.Counter++
				if err := tbl.Update(context.Background(), g); err != nil {
					t.Error(err)
				}
			}
			return store.ErrStale
		})
		tokenErr(t, h.refreshWith(cl, secret, rt), 400, "invalid_grant")
		if got := h.auditEvents("oauth.refresh.reuse"); len(got) != 1 || !strings.Contains(got[0].Detail["reason"], "twice at once") {
			t.Fatalf("audit: %+v", got)
		}
	})
	t.Run("stale and the grant cannot be read again", func(t *testing.T) {
		rt, _ := fresh()
		var once atomic.Bool
		failGrants(t, func() error {
			if once.CompareAndSwap(false, true) {
				h.env.Svc.Grants.S = failReads(good, model.KindGrant) // the re-read after this answer
			}
			return store.ErrStale
		})
		// Not known to be revoked: a 400 would make the client throw away a refresh token that is still good.
		expectUnavailable(t, "re-read after a stale write", h.refreshWith(cl, secret, rt))
		h.env.Svc.Grants.S = good
		if x := h.refreshWith(cl, secret, rt); x.status != 200 {
			t.Fatalf("the token was lost: %d %v", x.status, x.m)
		}
	})
	t.Run("stale for an unrelated change", func(t *testing.T) {
		rt, gid := fresh()
		var once atomic.Bool
		failGrants(t, func() error {
			if once.CompareAndSwap(false, true) {
				tbl := *h.env.Svc.Grants
				tbl.S = good
				g, _ := tbl.Get(context.Background(), gid)
				_ = tbl.Update(context.Background(), g) // a rewrite without a counter change
				return store.ErrStale
			}
			return nil
		})
		if x := h.refreshWith(cl, secret, rt); x.status != 200 {
			t.Fatalf("%d %v", x.status, x.m)
		}
	})
}

// A credentials reset ends the grants of the user's earlier sign-ins.
func TestRefreshEndsWithCredentialsReset(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid offline_access"}})
	if err := h.env.Svc.ResetCredentials(context.Background(), h.user.ID); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	tokenErr(t, h.refreshWith(cl, secret, r.str("refresh_token")), 400, "invalid_grant")
}

func TestRefreshAfterRotationDisabled(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	rt0 := r.str("refresh_token")
	rt1 := h.refreshWith(cl, secret, rt0).str("refresh_token")
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{RotateRefresh: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	// the rotation has moved on: a counted token of an earlier step is refused, the current one still works
	tokenErr(t, h.refreshWith(cl, secret, rt0), 400, "invalid_grant")
	if x := h.refreshWith(cl, secret, rt1); x.status != 200 {
		t.Fatalf("%d %v", x.status, x.m)
	}
}

func TestGrantMaintenanceDoesNotReopenRefreshGrace(t *testing.T) {
	t.Parallel()
	for _, maintenance := range []bool{false, true} {
		name := "expired grace"
		if maintenance {
			name = "expired grace after maintenance"
		}
		t.Run(name, func(t *testing.T) {
			h := setup(t, nil)
			ctx := context.Background()
			cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
			initial, _ := h.login(cl, secret, nil)
			old := initial.str("refresh_token")
			if r := h.refreshWith(cl, secret, old); r.status != 200 {
				t.Fatalf("rotation: %d %v", r.status, r.m)
			}
			g, err := h.env.Svc.Grants.Get(ctx, strings.SplitN(old, ".", 2)[0])
			if err != nil {
				t.Fatal(err)
			}
			// Model an otherwise identical rotation whose response was lost more than a grace interval ago.
			g.Updated = time.Now().Add(-2 * refreshRetryGrace)
			g.Rotated = g.Updated
			raw, err := store.EncodeAsIs(g)
			if err != nil {
				t.Fatal(err)
			}
			raw.Version = store.Clock.Now()
			if err := h.env.Svc.Store.Put(ctx, raw); err != nil {
				t.Fatal(err)
			}
			g, err = h.env.Svc.Grants.Get(ctx, g.ID)
			if err != nil {
				t.Fatal(err)
			}
			if maintenance {
				// Resealing g.Key calls this same update without changing the rotation counter (service/reseal.go).
				if err := h.env.Svc.Grants.Update(ctx, g); err != nil {
					t.Fatal(err)
				}
			}
			if r := h.refreshWith(cl, secret, old); r.status == 200 {
				t.Fatalf("expired previous refresh token accepted after non-rotation grant update: counter=%d status=%d", g.Counter, r.status)
			}
		})
	}
}

// landThenUnknown lets the compare-and-puts of live records of one kind through and then answers store.ErrUnconfirmed
// while armed: the write landed, but the node that decided it was lost before it answered.
type landThenUnknown struct {
	store.Store
	kind  model.Kind
	armed atomic.Bool
}

func (s *landThenUnknown) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	err := s.Store.CompareAndPut(ctx, r, expect)
	if err == nil && r.Kind == s.kind && !r.Deleted && s.armed.Load() {
		return store.ErrUnconfirmed
	}
	return err
}

// A rotation that landed but was not confirmed answers 503 with a Retry-After that fits inside refreshRetryGrace: the
// client's retry with the same token is then a retry of the last rotation (it gets the new token), not an old token
// presented again (reuse: the grant revoked and a false alarm audited). The unknown rotation is audited as such.
func TestRefreshRotationUnknownOutcomeRetry(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	gid := strings.SplitN(rt, ".", 2)[0]
	good := h.env.Svc.Grants.S
	flaky := &landThenUnknown{Store: good, kind: model.KindGrant}
	h.env.Svc.Grants.S = flaky
	t.Cleanup(func() { h.env.Svc.Grants.S = good })
	flaky.armed.Store(true)
	lost := h.refreshWith(cl, secret, rt)
	expectUnavailable(t, "rotation of unknown outcome", lost)
	after, err := strconv.Atoi(lost.hdr.Get("Retry-After"))
	if err != nil || time.Duration(after)*time.Second >= refreshRetryGrace {
		t.Fatalf("Retry-After %q must fit inside the %v retry grace", lost.hdr.Get("Retry-After"), refreshRetryGrace)
	}
	flaky.armed.Store(false)
	retry := h.refreshWith(cl, secret, rt)
	if retry.status != 200 || retry.str("refresh_token") == "" {
		t.Fatalf("the retry of a rotation that landed: %d %v", retry.status, retry.m)
	}
	if g, err := h.env.Svc.Grants.Get(context.Background(), gid); err != nil || g.Counter != 1 {
		t.Fatalf("after the retry: %+v %v", g, err)
	}
	if n := len(h.auditEvents("oauth.refresh.reuse")); n != 0 {
		t.Fatalf("the retry was audited as reuse (%d events)", n)
	}
	ev := h.auditEvents("oauth.refresh")
	if len(ev) != 1 || ev[0].Outcome != service.OutcomeUnknown {
		t.Fatalf("the unknown rotation should be audited once with outcome unknown: %+v", ev)
	}
}

// A revocation whose deletion has an unknown outcome answers 503 and is audited as unknown (not as done, not silently),
// as are the reuse alarms that end a grant: grant_revoked says "unknown", not "false".
func TestRevokeUnknownOutcomeIsAudited(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	tokens, _ := h.login(cl, secret, nil)
	rt := tokens.str("refresh_token")
	good := h.env.Svc.Grants.S
	h.env.Svc.Grants.S = &deleteUnknown{Store: good}
	t.Cleanup(func() { h.env.Svc.Grants.S = good })
	expectUnavailable(t, "revoke", h.post(h.orgBase+"/oauth/revoke", url.Values{"token": {rt}, "client_id": {cl.ID}, "client_secret": {secret}}, "", ""))
	ev := h.auditEvents("oauth.revoke")
	if len(ev) != 1 || ev[0].Outcome != service.OutcomeUnknown {
		t.Fatalf("revocation of unknown outcome: %+v", ev)
	}
	if got := revokedText(store.ErrUnconfirmed); got != service.OutcomeUnknown {
		t.Fatalf("revokedText(unknown) = %q", got)
	}
	if revokedText(nil) != "true" || revokedText(errFault) != "false" {
		t.Fatal("revokedText")
	}
}

// deleteUnknown applies a deletion (tombstone Put) and answers that its outcome is unknown.
type deleteUnknown struct{ store.Store }

func (s *deleteUnknown) Put(ctx context.Context, r *store.Record) error {
	err := s.Store.Put(ctx, r)
	if err == nil && r.Deleted {
		return store.ErrUnconfirmed
	}
	return err
}

// Revoking a refresh token that a rotation has replaced ends the grant, as presenting it at the token endpoint does:
// an attacker who rotated a stolen token must not outlive the revocation the application makes with the token it kept.
// Another client's token and a forged one revoke nothing.
func TestRevokeSupersededRefreshToken(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	other, otherSecret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}})
	old := r.str("refresh_token")
	stolen := h.refreshWith(cl, secret, old) // the attacker rotates the stolen token
	if stolen.status != 200 {
		t.Fatalf("rotation: %d", stolen.status)
	}
	current := stolen.str("refresh_token")
	parts := strings.Split(old, ".")
	forged := parts[0] + ".0." + b64.EncodeToString([]byte("forged-mac-forged-mac-forged-mac!"))
	revoke := func(c *model.Client, secret, tok string) {
		t.Helper()
		if x := h.clientPost(h.orgBase+"/oauth/revoke", url.Values{"token": {tok}}, c, secret); x.status != 200 {
			t.Fatalf("revoke: %d %v", x.status, x.m)
		}
	}

	revoke(other, otherSecret, old)
	revoke(cl, secret, forged)
	if x := h.refreshWith(cl, secret, current); x.status != 200 {
		t.Fatalf("the grant ended without an authentic token of its client: %d %v", x.status, x.m)
	}
	if n := len(h.auditEvents("oauth.revoke")); n != 0 {
		t.Fatalf("revocations audited for tokens that revoked nothing: %d", n)
	}

	revoke(cl, secret, old) // the victim's application, at logout, with the token it kept
	tokenErr(t, h.refreshWith(cl, secret, current), 400, "invalid_grant")
	if ev := h.auditEvents("oauth.revoke"); len(ev) != 1 || ev[0].Detail["token"] != "refresh" || ev[0].Detail["superseded"] != "true" {
		t.Fatalf("oauth.revoke: %+v", ev)
	}
}

// A user's refresh grants are capped: past the cap, the grants without offline_access go first, the oldest first, then
// those with it, the least recently used first, never the grant just made. Each ends as a revocation ends it (its
// refresh token refused, its SSH certificates revoked) and is audited; the user's sessions and other grants stay.
func TestUserGrantsCapped(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	svc := h.env.Svc
	cl, secret := h.newClient(nil)
	gidOf := func(rt string) string { return strings.SplitN(rt, ".", 2)[0] }
	// age sets when grant id was made and last rotated.
	age := func(id string, created, rotated time.Duration) {
		t.Helper()
		g, err := svc.Grants.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		g.Created, g.Rotated = time.Now().Add(-created), time.Time{}
		if rotated > 0 {
			g.Rotated = time.Now().Add(-rotated)
		}
		if err := svc.Grants.Update(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	login := func(scope string) (rt, sid string) {
		t.Helper()
		r, _ := h.login(cl, secret, url.Values{"scope": {scope}})
		return r.str("refresh_token"), claimsOf(t, r.str("id_token"))["sid"].(string)
	}

	// The SSH application's grant, the oldest of all, with a certificate signed under it.
	e := h.sshTenant("prod", service.SSHSettingsInput{CertTTL: ptr(3600)})
	key, _ := sshKey(t)
	st, m, _ := e.sign(e.mfaToken(h.user), map[string]any{"public_key": key})
	if st != 200 {
		t.Fatalf("sign: %d %v", st, m)
	}
	certs, err := svc.SSHCertsOf(ctx, h.user)
	if err != nil || len(certs) != 1 {
		t.Fatalf("certificates: %v %v", certs, err)
	}
	sshGrant, serial := certs[0].SignIn, strconv.FormatUint(certs[0].Serial, 10)
	age(sshGrant, 30*time.Hour, 0)
	// One grant lasting as long as its session, older than every grant with offline access.
	session, sessionSID := login("openid")
	age(gidOf(session), 20*time.Hour, 0)
	// Nine with offline access: the oldest made is the most recently used; the next oldest, never used, goes.
	var offline []string
	for i := range 9 {
		rt, _ := login("openid offline_access")
		offline = append(offline, rt)
		age(gidOf(rt), time.Duration(15-i)*time.Hour, 0)
	}
	age(gidOf(offline[0]), 15*time.Hour, time.Hour)
	svc.WaitBackground()
	// The organization's own cap, the least it may set: past it, down to 9.
	org, err := svc.Orgs.Get(ctx, h.env.Primary.ID)
	if err != nil {
		t.Fatal(err)
	}
	org.Settings.GrantsPerUser = 10
	if _, err := svc.UpdateOrg(ctx, service.System, org.ID, service.OrgInput{Settings: &org.Settings}); err != nil {
		t.Fatal(err)
	}
	h.p.grantRoom.Clear() // as once this node's count of them has expired

	// The twelfth grant, the newest, lasting as long as its session: it stays, three go.
	newest, _ := login("openid")
	svc.WaitBackground()
	gone := map[string]bool{sshGrant: true, gidOf(session): true, gidOf(offline[1]): true}
	all, err := svc.Grants.All(ctx, h.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 9 {
		t.Errorf("%d grants left, want 9", len(all))
	}
	for _, g := range all {
		if gone[g.ID] {
			t.Errorf("grant %s (scopes %v) kept", g.ID, g.Scopes)
		}
	}
	tokenErr(t, h.refreshWith(cl, secret, session), 400, "invalid_grant")
	tokenErr(t, h.refreshWith(cl, secret, offline[1]), 400, "invalid_grant")
	for _, rt := range append([]string{newest, offline[0]}, offline[2:]...) {
		if r := h.refreshWith(cl, secret, rt); r.status != 200 {
			t.Errorf("a kept grant's refresh: %d %v", r.status, r.m)
		}
	}
	list, err := svc.SSHRevoked(ctx, e.tn.ID)
	if err != nil || len(list) != 1 || strconv.FormatUint(list[0].Cert.Serial, 10) != serial || list[0].Reason != service.SSHReasonSignInEnded {
		t.Errorf("the ended grant's certificate: %+v %v", list, err)
	}
	// The ended grant's session is not: the user is still signed in there.
	if _, err := svc.Sessions.Get(ctx, sessionSID); err != nil {
		t.Errorf("the session of an ended grant: %v", err)
	}
	if u, err := svc.Users.Get(ctx, h.user.ID); err != nil || u.SessionEpoch != h.user.SessionEpoch {
		t.Errorf("the user: %v, %v", u, err)
	}
	ev := h.auditEvents("oauth.grant.evict")
	if len(ev) != 3 {
		t.Fatalf("oauth.grant.evict: %+v", ev)
	}
	for _, e := range ev {
		if !gone[e.Detail["grant"]] || e.Detail["grant_revoked"] != "true" || e.Target != "alice" {
			t.Errorf("oauth.grant.evict: %+v", e)
		}
	}
}

// The organization's cap of grants that cannot be read ends nothing: the server's default may be far below an
// organization that raised its own, and ending grants by it would sign people out of applications they still use.
func TestGrantCapUnreadableEndsNothing(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	svc := h.env.Svc
	cl, secret := h.newClient(nil)
	org, err := svc.Orgs.Get(ctx, h.env.Primary.ID)
	if err != nil {
		t.Fatal(err)
	}
	org.Settings.GrantsPerUser = 50 // the organization's own, above the server's lowered below
	if _, err := svc.UpdateOrg(ctx, service.System, org.ID, service.OrgInput{Settings: &org.Settings}); err != nil {
		t.Fatal(err)
	}
	svc.Cfg.Limits.GrantsPerUser = 10
	for range 15 {
		h.login(cl, secret, url.Values{"scope": {"openid offline_access"}})
	}
	svc.WaitBackground()
	before, err := svc.Grants.All(ctx, h.user.ID)
	if err != nil || len(before) != 15 {
		t.Fatalf("set-up: %d grants, %v", len(before), err)
	}
	good := svc.Orgs.S
	svc.Orgs.S = failReads(good, model.KindOrg)
	if _, _, err := h.p.capGrants(ctx, org.ID, h.user.ID, ""); err == nil {
		t.Fatal("the cap counted without the organization's policy")
	}
	svc.Orgs.S = good
	if after, _ := svc.Grants.All(ctx, h.user.ID); len(after) != 15 {
		t.Fatalf("%d grants left of 15: ended by the server's cap", len(after))
	}
}
