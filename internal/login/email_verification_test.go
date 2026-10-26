package login_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Verification mails are limited to five an hour per account, shared by the primary address and linked ones.
func TestEmailVerificationMailLimit(t *testing.T) {
	e, org := accountEnv(t, 0)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	for i := range 5 {
		res, out := b.api("POST", "/api-internal/account/email/verify", nil)
		if res.StatusCode != 200 {
			t.Fatalf("mail %d: %d %v", i, res.StatusCode, out["_raw"])
		}
		e.nextMail(t)
	}
	res, out := b.api("POST", "/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") != "3600" {
		t.Fatalf("Retry-After %q", res.Header.Get("Retry-After"))
	}
	res, out = b.api("POST", "/api-internal/account/emails/"+pat.Email+"/verify", nil)
	wantStatus(t, res, out, 429)
	e.noMail(t)

	// an account with no address, and one already verified (an address the account does not have gets no mail:
	// TestAccountLinkedEmails)
	nu := e.user(t, org, "noaddr", model.RoleUser)
	nf, _ := e.Svc.Users.Get(context.Background(), nu.ID)
	nf.Email = ""
	if err := e.Svc.Users.Update(context.Background(), nf); err != nil {
		t.Fatal(err)
	}
	nb := e.signedIn(t, nu)
	res, out = nb.api("POST", "/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 422)
	v := e.verifiedUser(t, org, "vera", model.RoleUser)
	vb := e.signedIn(t, v)
	res, out = vb.api("POST", "/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 409)
	e.noMail(t)
}

func TestEmailVerification(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	signed := e.signedIn(t, pat)
	res, out := signed.post("/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 200)
	link := linkPath(t, e.nextMail(t))
	if !strings.HasPrefix(link, "/verify-email?token=") {
		t.Fatal(link)
	}
	anon := e.browser(t)
	res, _ = anon.verifyLink(link)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/account?email=verified#profile" {
		t.Fatalf("verify: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	fresh, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	if !fresh.EmailVerified {
		t.Fatal("not verified")
	}
	res, _ = anon.verifyLink(link)
	if res.Header.Get("Location") != "/account?email=invalid#profile" {
		t.Fatalf("reused link: %q", res.Header.Get("Location"))
	}
	res, out = signed.post("/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 409)

	// A token for an address the user has since changed is refused.
	other := "other@example.com"
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, pat.ID, service.UserInput{Email: &other}); err != nil {
		t.Fatal(err)
	}
	signed2 := e.signedIn(t, pat)
	signed2.post("/api-internal/account/email/verify", nil)
	link2 := linkPath(t, e.nextMail(t))
	third := "third@example.com"
	e.Svc.UpdateUser(context.Background(), service.System, pat.ID, service.UserInput{Email: &third})
	res, _ = anon.verifyLink(link2)
	if res.Header.Get("Location") != "/account?email=invalid#profile" {
		t.Fatalf("stale address verified: %q", res.Header.Get("Location"))
	}
}

// Opening a verification link (a mail scanner, a link preview) verifies nothing and uses nothing up; pressing the
// button on its page does.
func TestVerifyLinkOpenedIsNotUsed(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", "user")
	res, out := e.signedIn(t, pat).post("/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 200)
	link := linkPath(t, e.nextMail(t))
	for range 3 { // a scanner, a preview, the person
		if res, _ := e.browser(t).get(link); res.StatusCode != http.StatusOK {
			t.Fatalf("open: %d", res.StatusCode)
		}
	}
	if u, _ := e.Svc.Users.Get(t.Context(), pat.ID); u.EmailVerified {
		t.Fatal("opening the link verified the address")
	}
	if res, _ := e.browser(t).verifyLink(link); res.Header.Get("Location") != "/account?email=verified#profile" {
		t.Fatalf("confirm: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// A press from another site (no matching CSRF cookie) is refused.
	form := url.Values{"token": {tokenOf(link)}, "csrf": {"x"}}
	if res, err := e.browser(t).c.PostForm(e.URL+"/verify-email", form); err != nil || res.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site press: %v %v", res, err)
	}
}
