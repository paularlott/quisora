package login_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// A browser holds one session per organization: the session of one organization is not a session at another's pages,
// whether it is sent as its own cookie or as the other's.
func TestSessionOfAnotherOrganizationIsNotASessionHere(t *testing.T) {
	e := newEnv(t, noIPLimit)
	acme := e.org(t, "acme", nil)
	other := e.org(t, "other", nil)
	pat := e.user(t, acme, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	sid := b.sessionID()

	if res, body := b.get("/o/acme/account"); res.StatusCode != 200 || !strings.Contains(body, "Your account") {
		t.Fatalf("own account page: %d", res.StatusCode)
	}
	for _, ref := range []string{other.ID, "other"} {
		// the account page sends the visitor to this organization's sign-in page, back to the account page afterwards
		res, _ := b.get("/o/" + ref + "/account")
		want := web.OrgPath(other.ID, "/login?next="+url.QueryEscape("/o/"+ref+"/account"))
		if res.StatusCode != 303 || res.Header.Get("Location") != want {
			t.Fatalf("account page of another organization (%s): %d %q, want %q", ref, res.StatusCode, res.Header.Get("Location"), want)
		}
		// its sign-in page does not take the visitor for signed in
		if res, body := b.get("/o/" + ref + "/login"); res.StatusCode != 200 || !strings.Contains(body, `id="f-email"`) {
			t.Fatalf("sign-in page of another organization (%s): %d", ref, res.StatusCode)
		}
		// nor does its account API
		if res, out := b.do("GET", "/o/"+ref+"/api-internal/account", nil, nil); res.StatusCode != 401 {
			t.Fatalf("account API of another organization (%s): %d %v", ref, res.StatusCode, out["_raw"])
		}
		// signing out there ends nothing of the session at acme
		if res, _ := b.get("/o/" + ref + "/logout"); res.StatusCode != 303 {
			t.Fatalf("logout page of another organization (%s): %d", ref, res.StatusCode)
		}
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("the session of acme ended: %v", err)
	}

	// The cookie of acme's session sent as the other organization's is not a session there either.
	raw := b.cookie()
	if raw == "" {
		t.Fatal("no session cookie")
	}
	u, _ := url.Parse(e.URL)
	b.c.Jar.SetCookies(u, []*http.Cookie{{Name: web.SessionCookieFor(other.ID), Value: raw, Path: "/", Secure: true}})
	if res, _ := b.get("/o/" + other.ID + "/account"); res.StatusCode != 303 {
		t.Fatalf("a session of acme under the cookie of another organization: %d", res.StatusCode)
	}
	if res, _ := b.get("/o/" + acme.ID + "/account"); res.StatusCode != 200 {
		t.Fatalf("own account page after that: %d", res.StatusCode)
	}

	// Signing in at the other organization leaves two sessions, one per organization.
	e.user(t, other, "sam", model.RoleUser)
	b.base = web.OrgPath(other.ID, "")
	b.refresh() // the anonymous sign-in token of the sign-in page
	res, out := b.login(other.ID, "sam", userPassword)
	wantStatus(t, res, out, 200)
	for _, o := range []*model.Org{acme, other} {
		if res, _ := b.get(web.OrgPath(o.ID, "/account")); res.StatusCode != 200 {
			t.Fatalf("account page of %s with a session at each: %d", o.Name, res.StatusCode)
		}
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("signing in at the other organization ended the session of acme: %v", err)
	}
}

// A ticket of a sign-in at one organization is dead at another's endpoints, as an expired one is.
func TestSignInTicketOfAnotherOrganizationIsDead(t *testing.T) {
	e := newEnv(t, noIPLimit)
	acme := e.org(t, "acme", nil)
	e.org(t, "other", nil)
	pat := e.user(t, acme, "pat", model.RoleUser)
	secret := e.giveTOTP(t, pat)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	tk := str(out, "ticket")
	code := totpAt(secret, time.Now())

	res, out = b.post("/o/other/api-internal/login/totp", map[string]any{"ticket": tk, "code": code})
	wantStatus(t, res, out, 401)
	if b.hasSession() {
		t.Fatal("a ticket of acme signed in at the other organization")
	}
	res, out = b.post("/o/"+acme.ID+"/api-internal/login/totp", map[string]any{"ticket": tk, "code": code})
	wantStatus(t, res, out, 200)
	if str(out, "next") != web.OrgPath(acme.ID, "/account") {
		t.Fatalf("next %v", out)
	}
}

// An invitation, a password reset and an address verification belong to the organization of their account: opened at
// another organization's address they are invalid, and are not used up by it.
func TestLinkOfAnotherOrganizationIsRefused(t *testing.T) {
	e := newEnv(t, withSMTP, noIPLimit)
	acme := e.org(t, "acme", nil)
	other := e.org(t, "other", nil)
	acmeBase, otherBase := web.OrgPath(acme.ID, ""), web.OrgPath(other.ID, "")

	t.Run("invitation", func(t *testing.T) {
		u, link := e.invitee(t, acme, "newbie")
		tok := tokenOf(link)
		for _, ref := range []string{other.ID, "other"} {
			b := e.browserAt(t, other)
			if res, body := b.get("/o/" + ref + "/invite?token=" + tok); res.StatusCode != http.StatusGone || strings.Contains(body, "invitePage") {
				t.Fatalf("invitation page at %s: %d", ref, res.StatusCode)
			}
			res, out := b.post("/o/"+ref+"/api-internal/invite/passkey/begin", map[string]any{"token": tok})
			wantStatus(t, res, out, http.StatusGone)
			res, out = b.post("/o/"+ref+"/api-internal/invite/complete", map[string]any{"token": tok, "password": "my first password"})
			wantStatus(t, res, out, http.StatusGone)
			if b.hasSession() {
				t.Fatal("signed in by an invitation of another organization")
			}
		}
		if got, _ := e.Svc.Users.Get(context.Background(), u.ID); got.PasswordHash != "" {
			t.Fatal("the invitation set a password at another organization")
		}
		// it was not used up: at its own address it works
		b := e.browserAt(t, acme)
		if res, body := b.get(link); res.StatusCode != 200 || !strings.Contains(body, "Welcome, newbie") {
			t.Fatalf("invitation page at its own address: %d", res.StatusCode)
		}
		res, out := b.post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "my first password"})
		wantStatus(t, res, out, 200)
		if str(out, "next") != acmeBase+"/account" || !b.hasSession() {
			t.Fatalf("invitation at its own address: %v", out)
		}
	})

	t.Run("reset", func(t *testing.T) {
		pat := e.user(t, acme, "pat", model.RoleUser)
		if err := e.Mailer.SendReset(context.Background(), pat, acme); err != nil {
			t.Fatal(err)
		}
		link := linkPath(t, e.nextMail(t))
		if !strings.HasPrefix(link, acmeBase+"/reset?token=") {
			t.Fatalf("reset link %q is not in the organization's address space", link)
		}
		tok := tokenOf(link)
		for _, ref := range []string{other.ID, "other"} {
			b := e.browserAt(t, other)
			if res, body := b.get("/o/" + ref + "/reset?token=" + tok); res.StatusCode != http.StatusGone || strings.Contains(body, "passwordSetup") {
				t.Fatalf("reset page at %s: %d", ref, res.StatusCode)
			}
			res, out := b.post("/o/"+ref+"/api-internal/password/reset", map[string]any{"token": tok, "password": "a brand new password"})
			wantStatus(t, res, out, http.StatusGone)
		}
		if res, out := e.browserAt(t, acme).login("acme", "pat", "a brand new password"); res.StatusCode == 200 {
			t.Fatalf("the password was reset at another organization: %v", out)
		}
		b := e.browserAt(t, acme)
		if res, _ := b.get(link); res.StatusCode != 200 {
			t.Fatalf("reset page at its own address: %d", res.StatusCode)
		}
		res, out := b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "a brand new password"})
		wantStatus(t, res, out, 200)
		if str(out, "next") != acmeBase+"/login" {
			t.Fatalf("reset response %v", out)
		}
	})

	t.Run("verification", func(t *testing.T) {
		sam := e.user(t, acme, "sam", model.RoleUser)
		signed := e.signedIn(t, sam)
		res, out := signed.post("/api-internal/account/email/verify", nil)
		wantStatus(t, res, out, 200)
		link := linkPath(t, e.nextMail(t))
		if !strings.HasPrefix(link, acmeBase+"/verify-email?token=") {
			t.Fatalf("verification link %q is not in the organization's address space", link)
		}
		for _, ref := range []string{other.ID, "other"} {
			b := e.browserAt(t, other)
			res, _ := b.verifyLink("/o/" + ref + "/verify-email?token=" + tokenOf(link))
			if res.StatusCode != 303 || res.Header.Get("Location") != otherBase+"/account?email=invalid#profile" {
				t.Fatalf("verification at %s: %d %q", ref, res.StatusCode, res.Header.Get("Location"))
			}
		}
		if got, _ := e.Svc.Users.Get(context.Background(), sam.ID); got.EmailVerified {
			t.Fatal("the address was verified by a link of another organization")
		}
		res2, _ := e.browserAt(t, acme).verifyLink(link)
		if res2.Header.Get("Location") != acmeBase+"/account?email=verified#profile" {
			t.Fatalf("verification at its own address: %d %q", res2.StatusCode, res2.Header.Get("Location"))
		}
	})
}

// The sign-in page and every JSON sign-in endpoint work at the organization's address by id (the form every generated
// link uses) and by name, and what they answer is by id either way.
func TestSignInEndpointsWorkAtTheOrganizationsIdAndName(t *testing.T) {
	e := newEnv(t, withSMTP, noIPLimit)
	plain := e.org(t, "acme", nil)
	strict := e.org(t, "strict", func(s *model.OrgSettings) { s.RequireMFA = true; s.EmailCodes = true })
	for _, kind := range []string{"id", "name"} {
		t.Run(kind, func(t *testing.T) {
			ref := func(o *model.Org) string {
				if kind == "id" {
					return o.ID
				}
				return o.Name
			}
			base := func(o *model.Org) string { return "/o/" + ref(o) }
			account := func(o *model.Org) string { return web.OrgPath(o.ID, "/account") }
			name := func(s string) string { return s + "-" + kind }

			// the page
			b := e.browser(t)
			res, body := b.get(base(plain) + "/login")
			if res.StatusCode != 200 || !strings.Contains(body, `id="f-email"`) || !strings.Contains(body, `data-org-base="`+web.OrgPath(plain.ID, "")+`"`) {
				t.Fatalf("sign-in page: %d", res.StatusCode)
			}

			// password
			e.user(t, plain, name("pw"), model.RoleUser)
			res, out := b.login(ref(plain), name("pw"), userPassword)
			wantStatus(t, res, out, 200)
			if str(out, "next") != account(plain) || !b.hasSession() {
				t.Fatalf("password sign-in: %v", out)
			}

			// authenticator code, and a recovery code in its place
			tu := e.user(t, plain, name("totp"), model.RoleUser)
			secret := e.giveTOTP(t, tu)
			tu, _ = e.Svc.Users.Get(context.Background(), tu.ID)
			codes, err := e.Svc.CreateRecoveryCodes(context.Background(), service.System, tu)
			if err != nil {
				t.Fatal(err)
			}
			b = e.browser(t)
			_, out = b.login(ref(plain), name("totp"), userPassword)
			res, out = b.post(base(plain)+"/api-internal/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": totpAt(secret, time.Now())})
			wantStatus(t, res, out, 200)
			if str(out, "next") != account(plain) {
				t.Fatalf("totp: %v", out)
			}
			b = e.browser(t)
			_, out = b.login(ref(plain), name("totp"), userPassword)
			res, out = b.post(base(plain)+"/api-internal/login/recovery", map[string]any{"ticket": str(out, "ticket"), "code": codes[0]})
			wantStatus(t, res, out, 200)
			e.nextMail(t) // the notice that a recovery code was used

			// passkey: registered through the account API, signed in with at the page
			pk := e.user(t, plain, name("key"), model.RoleUser)
			signed := e.signedIn(t, pk)
			signed.registerPasskey("Laptop")
			b = e.browser(t)
			b.auth = signed.auth
			status, out := b.passkeyLogin(map[string]any{"org": ref(plain), "next": web.OrgPath(plain.ID, "/x")})
			if status != 200 || str(out, "next") != web.OrgPath(plain.ID, "/x") {
				t.Fatalf("passkey sign-in: %d %v", status, out)
			}

			// a code by email, in an organization that asks for a second factor and takes a code
			e.verifiedUser(t, strict, name("mail"), model.RoleUser)
			b = e.browser(t)
			_, out = b.login(ref(strict), name("mail"), userPassword)
			if str(out, "step") != "email_code" {
				t.Fatalf("email step: %v", out)
			}
			tk := str(out, "ticket")
			code := codeFrom(t, e)
			e.Mod.AgeEmailCode(tk)
			res, out = b.post(base(strict)+"/api-internal/login/email/send", map[string]any{"ticket": tk})
			wantStatus(t, res, out, 200)
			code = codeFrom(t, e)
			res, out = b.post(base(strict)+"/api-internal/login/email", map[string]any{"ticket": tk, "code": code})
			wantStatus(t, res, out, 200)
			if str(out, "next") != account(strict) {
				t.Fatalf("email code: %v", out)
			}

			// enrolment of an authenticator app, and of a passkey, where the account has no verified address to mail
			en := e.user(t, strict, name("enrol"), model.RoleUser)
			tk, err = e.Mod.PutEnrolTicket(en.ID)
			if err != nil {
				t.Fatal(err)
			}
			b = e.browser(t)
			res, out = b.post(base(strict)+"/api-internal/login/enrol/totp/begin", map[string]any{"ticket": tk})
			wantStatus(t, res, out, 200)
			res, out = b.post(base(strict)+"/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": tk, "code": totpAt(str(out, "secret"), time.Now())})
			wantStatus(t, res, out, 200)
			if str(out, "next") != account(strict) {
				t.Fatalf("totp enrolment: %v", out)
			}
			en2 := e.user(t, strict, name("enrol2"), model.RoleUser)
			tk, err = e.Mod.PutEnrolTicket(en2.ID)
			if err != nil {
				t.Fatal(err)
			}
			b = e.browser(t)
			res, begin := b.post(base(strict)+"/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": tk})
			wantStatus(t, res, begin, 200)
			opts, _ := json.Marshal(begin["options"])
			cred, _, err := b.auth.Create(opts)
			if err != nil {
				t.Fatal(err)
			}
			res, out = b.post(base(strict)+"/api-internal/login/enrol/passkey/finish",
				map[string]any{"ticket": tk, "challenge": begin["challenge"], "name": "Key", "credential": json.RawMessage(cred)})
			wantStatus(t, res, out, 200)
			if str(out, "next") != account(strict) {
				t.Fatalf("passkey enrolment: %v", out)
			}

			// forgotten password: the mail's link is by id, the endpoints take either form
			fg := e.user(t, plain, name("forgot"), model.RoleUser)
			b = e.browser(t)
			res, out = b.post(base(plain)+"/api-internal/password/forgot", map[string]any{"email": fg.Email})
			wantStatus(t, res, out, 200)
			link := linkPath(t, e.nextMail(t))
			if !strings.HasPrefix(link, web.OrgPath(plain.ID, "/reset?token=")) {
				t.Fatalf("reset link %q", link)
			}
			res, out = b.post(base(plain)+"/api-internal/password/reset", map[string]any{"token": tokenOf(link), "password": "a brand new password"})
			wantStatus(t, res, out, 200)
			if str(out, "next") != web.OrgPath(plain.ID, "/login") {
				t.Fatalf("reset: %v", out)
			}

			// invitations
			_, link = e.invitee(t, plain, name("inv"))
			b = e.browser(t)
			res, out = b.post(base(plain)+"/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "my first password"})
			wantStatus(t, res, out, 200)
			if str(out, "next") != account(plain) {
				t.Fatalf("invitation with a password: %v", out)
			}
			_, link = e.invitee(t, plain, name("inv2"))
			b = e.browser(t)
			b.base = base(plain)
			body2, st, out2 := b.invitePasskeyBody(tokenOf(link), nil)
			if st != 200 {
				t.Fatalf("invitation passkey begin: %d %v", st, out2)
			}
			res, out = b.post(base(plain)+"/api-internal/invite/complete", body2)
			wantStatus(t, res, out, 200)
			if str(out, "next") != account(plain) {
				t.Fatalf("invitation with a passkey: %v", out)
			}
		})
	}
}
