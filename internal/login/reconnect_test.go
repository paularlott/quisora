package login_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Reconnecting a provider whose link is left from before the account's sign-in was reset (a passed credential epoch)
// makes a link that counts: "connected" is said only when the account has one.
func TestReconnectReplacesPassedEpochLink(t *testing.T) {
	ctx := context.Background()
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	kim := u.user(t, u.org, "kim", model.RoleUser)
	if err := u.Svc.Identities.Create(ctx, model.NewIdentity(kim, p, "kim-sub", "", "admin")); err != nil {
		t.Fatal(err)
	}
	fresh, err := u.Svc.Users.Get(ctx, kim.ID)
	if err != nil {
		t.Fatal(err)
	}
	fresh.CredEpoch = service.NewCredEpoch() // the sign-in was reset: the link counts no more
	if err := u.Svc.Users.Update(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	b := u.signedIn(t, fresh)
	b.markReauth()
	res, out := b.post("/api-internal/account/providers/"+p.ID+"/connect", nil)
	wantStatus(t, res, out, 200)
	code := u.oidc.Authorize(str(out, "url"), claims("kim-sub", kim.Email))
	lu, _ := url.Parse(str(out, "url"))
	res, _ = b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + url.QueryEscape(code))
	if res.StatusCode != 303 || res.Header.Get("Location") != "/account?provider=connected#providers" {
		t.Fatalf("reconnect callback: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	now, err := u.Svc.Users.Get(ctx, kim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ids, err := u.Svc.CurrentIdentities(ctx, now); err != nil || len(ids) != 1 {
		t.Fatalf("no link that counts after reconnecting: %v %v", ids, err)
	}
}
