package login_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/web"
)

// The management API's changes to your own account decide a recent sign-in as the account page does: one that did
// not use the account's own second factor (a password alone, signed in before the account had one) cannot remove it
// there either, while a sign-in that used it can, on both.
func TestManagementSelfServiceReauthMatchesTheAccountPage(t *testing.T) {
	e := newEnvModules(t, false, func(*web.Server) []web.Module { return []web.Module{admin.New()} })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	api := "/api/orgs/acme/users/" + pat.ID + "/totp"
	removeTOTP := func(b *browser) int {
		t.Helper()
		base := b.base
		b.base = "" // the management API is at the root
		defer func() { b.base = base }()
		res, _ := b.api("DELETE", api, nil)
		return res.StatusCode
	}

	pwd := e.signedIn(t, pat) // the password alone
	pwd.fresh()
	e.giveTOTP(t, pat) // then the account gains an authenticator app (written to the store only, as on another node)
	if res, out := pwd.api("DELETE", "/api-internal/account/totp", nil); res.StatusCode != http.StatusForbidden {
		t.Fatalf("the account page: %d %v", res.StatusCode, out["_raw"])
	}
	if st := removeTOTP(pwd); st != http.StatusForbidden {
		t.Fatalf("the management API removed the authenticator app for a password-only sign-in: %d", st)
	}
	if u, _ := e.Svc.Users.Get(context.Background(), pat.ID); !u.HasTOTP() {
		t.Fatal("the authenticator app is gone")
	}

	code := e.signedInMFA(t, pat) // signed in with the authenticator code
	code.fresh()
	if st := removeTOTP(code); st != http.StatusNoContent {
		t.Fatalf("a sign-in that used the code: %d", st)
	}
}
