package login_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// The account page shows the addresses someone else linked: the user verifies them from the link mailed to each
// (resending it when needed) and makes a verified one primary (re-authenticated). Adding and removing are not theirs.
func TestAccountLinkedEmails(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleManager) // whatever the role
	b := e.signedIn(t, pat)
	ctx := context.Background()
	for _, a := range []string{"Paul@The7thDream.com", "second@example.org"} {
		if _, err := e.Svc.AddLinkedEmail(ctx, service.System, pat.ID, a, false); err != nil {
			t.Fatal(err)
		}
	}

	// adding and removing are gone from the account page
	for _, c := range []struct {
		method, path string
		want         int
	}{{"POST", "/api-internal/account/emails", 404}, {"DELETE", "/api-internal/account/emails/second@example.org", 404}} {
		if res, out := b.api(c.method, c.path, map[string]any{"address": "gh@example.org"}); res.StatusCode != c.want {
			t.Fatalf("%s %s: %d, want %d: %v", c.method, c.path, res.StatusCode, c.want, out)
		}
	}
	// making one primary asks to re-authenticate first, in the shape the page turns into its dialog
	res, out := b.api("POST", "/api-internal/account/emails/Paul@The7thDream.com/primary", nil)
	wantStatus(t, res, out, 403)
	if str(out, "field") != "reauth" {
		t.Fatalf("primary without re-authentication: %v", out)
	}
	e.noMail(t)

	// the verification link goes to that address and verifies only it
	res, out = b.api("POST", "/api-internal/account/emails/Paul@The7thDream.com/verify", nil)
	wantStatus(t, res, out, 200)
	m := e.nextMail(t)
	if m.To != "Paul@The7thDream.com" {
		t.Fatalf("mailed %q", m.To)
	}
	link := linkPath(t, m)
	anon := e.browser(t)
	res, _ = anon.verifyLink(link)
	if res.StatusCode != 303 || res.Header.Get("Location") != web.OrgPath(pat.OrgID, "")+"/account?email=verified#emails" {
		t.Fatalf("verify: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	fresh, _ := e.Svc.Users.Get(ctx, pat.ID)
	if l, _ := fresh.LinkedEmail("paul@the7thdream.com"); !l.Verified {
		t.Fatalf("verified state %+v", fresh.LinkedEmails)
	}
	if res, _ = anon.verifyLink(link); res.Header.Get("Location") != web.OrgPath(pat.OrgID, "")+"/account?email=invalid#emails" && res.Header.Get("Location") != web.OrgPath(pat.OrgID, "")+"/account?email=invalid#profile" {
		t.Fatalf("link reused: %q", res.Header.Get("Location"))
	}

	// the account summary carries the list
	res, out = b.api("GET", "/api-internal/account", nil)
	wantStatus(t, res, out, 200)
	if got := out["user"].(map[string]any)["linked_emails"].([]any); len(got) != 2 {
		t.Fatalf("summary: %v", out["_raw"])
	}

	// resend: unverified only, and only the user's own addresses
	res, out = b.api("POST", "/api-internal/account/emails/second@example.org/verify", nil)
	wantStatus(t, res, out, 200)
	if m := e.nextMail(t); m.To != "second@example.org" {
		t.Fatalf("resend to %q", m.To)
	}
	res, out = b.api("POST", "/api-internal/account/emails/Paul@The7thDream.com/verify", nil)
	wantStatus(t, res, out, 409)
	res, out = b.api("POST", "/api-internal/account/emails/stranger@example.org/verify", nil)
	wantStatus(t, res, out, 404)

	// make primary: verified only
	b.markReauth()
	res, out = b.api("POST", "/api-internal/account/emails/second@example.org/primary", nil)
	wantStatus(t, res, out, 422)
	res, out = b.api("POST", "/api-internal/account/emails/Paul@The7thDream.com/primary", nil)
	wantStatus(t, res, out, 200)
	if out["user"].(map[string]any)["email"] != "Paul@The7thDream.com" {
		t.Fatalf("primary: %v", out["_raw"])
	}
	for _, a := range []string{"user.email.add", "user.email.primary", "user.email.verify"} {
		if len(e.audits(t, a)) == 0 {
			t.Errorf("no audit entry %s", a)
		}
	}
}

func TestAccountLinkedEmailsPageAndMailOff(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	res, body := b.get("/account")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("account page %d", res.StatusCode)
	}
	for _, want := range []string{`id="emails"`, `x-data="accountEmails"`, "Sign-ins from GitHub, Google and other providers that use one of your verified addresses find your account.", `x-data="accountHeader"`} {
		if !strings.Contains(body, want) {
			t.Errorf("account page lacks %q", want)
		}
	}
	// the address is shown in the page's header, not as a read-only field of the profile
	if strings.Contains(body, `id="f-email-ro"`) {
		t.Error("account page still has the read-only address field")
	}
}

// A user's addresses are set for them: they cannot add, remove or change one, account page or not, but they verify
// the ones a manager added, resend the link and make a verified one primary.
func TestAccountEmailsLocked(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	b.markReauth()

	res, out := b.api("POST", "/api-internal/account/emails", map[string]any{"address": "ceo@example.org"})
	if res.StatusCode != 404 {
		t.Fatalf("add own address: %d %v", res.StatusCode, out)
	}
	res, out = b.api("PATCH", "/api-internal/account", map[string]any{"email": "ceo@example.org"})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "email" {
		t.Fatalf("field %v", out)
	}
	if _, err := e.Svc.Users.GetByUnique(context.Background(), model.UserEmailKey(org.ID, "ceo@example.org")); err == nil {
		t.Fatal("the address was reserved")
	}
	e.noMail(t)

	// a manager links one, unverified; the user verifies it from the link and makes it primary
	if _, err := e.Svc.AddLinkedEmail(context.Background(), service.System, pat.ID, "pat.work@example.org", false); err != nil {
		t.Fatal(err)
	}
	res, out = b.api("POST", "/api-internal/account/emails/pat.work@example.org/primary", nil)
	wantStatus(t, res, out, 422)
	res, out = b.api("POST", "/api-internal/account/emails/pat.work@example.org/verify", nil)
	wantStatus(t, res, out, 200)
	if res, _ = e.browser(t).verifyLink(linkPath(t, e.nextMail(t))); res.StatusCode != 303 {
		t.Fatalf("verify: %d", res.StatusCode)
	}
	res, out = b.api("POST", "/api-internal/account/emails/pat.work@example.org/primary", nil)
	wantStatus(t, res, out, 200)
	if out["user"].(map[string]any)["email"] != "pat.work@example.org" {
		t.Fatalf("primary: %v", out["_raw"])
	}
	// removing is someone else's job, the old primary included
	if res, out = b.api("DELETE", "/api-internal/account/emails/"+pat.Email, nil); res.StatusCode != 404 {
		t.Fatalf("remove own address: %d %v", res.StatusCode, out)
	}
}
