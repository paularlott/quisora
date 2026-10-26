package login_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
	"github.com/paularlott/quisora/internal/service"
)

func TestPasskeyRegisterAndLogin(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)

	signed := e.signedIn(t, pat)
	signed.registerPasskey("Laptop")
	list, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
	if len(list) != 1 || list[0].Name != "Laptop" || list[0].UserID != pat.ID || list[0].OrgID != org.ID {
		t.Fatalf("stored passkeys %+v", list)
	}

	// Sign in at the organization page (discoverable credential).
	b := e.browser(t)
	b.auth = signed.auth
	status, out := b.passkeyLogin(map[string]any{"org": "acme", "next": "/admin"})
	if status != 200 || str(out, "next") != "/admin" || !b.hasSession() {
		t.Fatalf("passkey login: %d %v", status, out)
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), pat.ID)
	var got []string
	for _, s := range sess {
		if len(s.AMR) > 0 && s.AMR[0] == "hwk" {
			got = s.AMR
		}
	}
	if strings.Join(got, ",") != "hwk,user" {
		t.Fatalf("passkey amr %v (sessions %+v)", got, sess)
	}
	if n := len(e.audits(t, "login.success")); n != 1 {
		t.Fatalf("audits %d", n)
	}
	if res, body := b.get("/account"); res.StatusCode != 200 || !strings.Contains(body, "Your account") {
		t.Fatalf("account after passkey login: %d", res.StatusCode)
	}

	// From the landing page: no org given at all.
	b2 := e.browser(t)
	b2.auth = signed.auth
	status, out = b2.passkeyLogin(map[string]any{})
	if status != 200 || str(out, "next") != "/account" {
		t.Fatalf("landing passkey login: %d %v", status, out)
	}
	// Hostile next is dropped.
	b3 := e.browser(t)
	b3.auth = signed.auth
	status, out = b3.passkeyLogin(map[string]any{"next": "//evil.example"})
	if status != 200 || str(out, "next") != "/account" {
		t.Fatalf("hostile next: %d %v", status, out)
	}
	// The discoverable options never list credentials.
	res, o := b3.post("/api-internal/login/passkey/begin", map[string]any{})
	wantStatus(t, res, o, 200)
	if strings.Contains(str(o, "_raw"), "allowCredentials") && !strings.Contains(str(o, "_raw"), `"allowCredentials":null`) {
		if !strings.Contains(str(o, "_raw"), `"allowCredentials":[]`) {
			t.Fatalf("discoverable options leak credentials: %s", o["_raw"])
		}
	}
}

func TestPasskeyLoginFailures(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	e.org(t, "other", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	signed := e.signedIn(t, pat)
	cred := signed.registerPasskey("Laptop")

	// A stranger's authenticator holding a credential the server never registered.
	b := e.browser(t)
	_, ropts := signed.post("/api-internal/account/passkeys/register/begin", nil)
	stranger := virtualauth.New(e.Cfg.Server.PublicURL)
	raw, _ := json.Marshal(ropts["options"])
	if _, _, err := stranger.Create(raw); err != nil {
		t.Fatal(err)
	}
	b.auth = stranger
	status, out := b.passkeyLogin(map[string]any{"org": "acme"})
	if status != 401 || b.hasSession() {
		t.Fatalf("unknown credential: %d %v", status, out)
	}
	if n := len(e.audits(t, "login.failure")); n != 1 {
		t.Fatalf("failure not audited: %d", n)
	}

	// Replayed challenge.
	b = e.browser(t)
	b.auth = signed.auth
	res, begin := b.post("/api-internal/login/passkey/begin", map[string]any{"org": "acme"})
	wantStatus(t, res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	assertion, _, _ := b.auth.Get(opts)
	body := map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(assertion)}
	res, out = b.post("/api-internal/login/passkey/finish", body)
	wantStatus(t, res, out, 200)
	res, out = e.browser(t).post("/api-internal/login/passkey/finish", body)
	wantStatus(t, res, out, 401)

	// Organization mismatch: the passkey belongs to acme.
	b = e.browser(t)
	b.auth = signed.auth
	status, out = b.passkeyLogin(map[string]any{"org": "other"})
	if status != 401 || b.hasSession() {
		t.Fatalf("passkey accepted for another org: %d %v", status, out)
	}
	// Unknown organization at begin.
	res, out = b.post("/api-internal/login/passkey/begin", map[string]any{"org": "nope"})
	wantStatus(t, res, out, 403)

	// Org that disabled passkeys: begin is refused; a landing-page ceremony is refused at finish.
	e.setSettings(t, org, func(s *model.OrgSettings) { s.PasskeyLogin = false })
	b = e.browser(t)
	b.auth = signed.auth
	status, out = b.passkeyLogin(map[string]any{"org": "acme"})
	if status != 403 {
		t.Fatalf("begin for org without passkeys: %d", status)
	}
	status, out = b.passkeyLogin(map[string]any{})
	if status != 403 || b.hasSession() {
		t.Fatalf("finish for org without passkeys: %d %v", status, out)
	}
	e.setSettings(t, org, func(s *model.OrgSettings) { s.PasskeyLogin = true })

	// Sign counter regression (cloned authenticator) is refused and audited.
	b = e.browser(t)
	b.auth = signed.auth
	for range 2 {
		if status, out := b.passkeyLogin(map[string]any{"org": "acme"}); status != 200 {
			t.Fatalf("normal login %d %v", status, out)
		}
	}
	res, begin = b.post("/api-internal/login/passkey/begin", map[string]any{"org": "acme"})
	opts, _ = json.Marshal(begin["options"])
	stale, err := signed.auth.GetWith(opts, cred, 1, e.Cfg.Server.PublicURL)
	if err != nil {
		t.Fatal(err)
	}
	b2 := e.browser(t)
	res, out = b2.post("/api-internal/login/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(stale)})
	wantStatus(t, res, out, 401)
	if b2.hasSession() {
		t.Fatal("cloned credential signed in")
	}
	if n := len(e.audits(t, "passkey.clone")); n != 1 {
		t.Fatalf("clone audits %d", n)
	}

	// A second-factor passkey sign-in begins only from a ticket at a second-factor step: not from one at the
	// enrolment step, not from one that does not exist.
	mfa := e.org(t, "mfa", func(s *model.OrgSettings) { s.RequireMFA = true })
	e.user(t, mfa, "quinn", model.RoleUser)
	eb := e.browser(t)
	_, out = eb.login("mfa", "quinn", userPassword)
	if str(out, "step") != "enrol" {
		t.Fatalf("step %v", out)
	}
	res, out = eb.post("/api-internal/login/passkey/begin", map[string]any{"ticket": str(out, "ticket")})
	wantStatus(t, res, out, 401)
	res, out = eb.post("/api-internal/login/passkey/begin", map[string]any{"ticket": "n1.nope"})
	wantStatus(t, res, out, 401)

	// Garbage never signs in.
	res, out = b.post("/api-internal/login/passkey/finish", map[string]any{"challenge": "n1.x", "credential": map[string]any{}})
	wantStatus(t, res, out, 401)
	res, out = b.post("/api-internal/login/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": "junk"})
	wantStatus(t, res, out, 401)
}

func TestPasskeysDisabledOnIPHost(t *testing.T) {
	e := newEnvWith(t, true)
	b := e.browser(t)
	res, out := b.post("/api-internal/login/passkey/begin", map[string]any{})
	wantStatus(t, res, out, 503)
	_, body := b.get("/")
	if strings.Contains(body, `data-passkeys="1"`) {
		t.Fatal("landing page offers passkeys on an IP host")
	}
	// password login still works
	res, out = b.login("primary", "admin", e.Password)
	wantStatus(t, res, out, 200)
}

// A ceremony begun for one purpose cannot finish another (a reauth assertion must not become a sign-in).
func TestPasskeyCeremoniesArePurposeBound(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	signed := e.signedIn(t, pat)
	signed.registerPasskey("Laptop")
	auth := signed.auth
	signed = e.signedIn(t, pat) // new session, not yet re-authenticated
	signed.auth = auth
	assert := func(b *browser, begin map[string]any) (string, json.RawMessage) {
		opts, _ := json.Marshal(begin["options"])
		cred, _, err := b.auth.Get(opts)
		if err != nil {
			t.Fatal(err)
		}
		return str(begin, "challenge"), cred
	}

	// reauth ceremony -> anonymous sign-in finish
	res, begin := signed.post("/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, begin, 200)
	ch, cred := assert(signed, begin)
	anon := e.browser(t)
	res, out := anon.post("/api-internal/login/passkey/finish", map[string]any{"challenge": ch, "credential": cred})
	wantStatus(t, res, out, 401)
	if anon.hasSession() {
		t.Fatal("a reauth ceremony created a session")
	}

	// sign-in ceremony -> reauth finish
	anon.auth = signed.auth
	res, begin = anon.post("/api-internal/login/passkey/begin", map[string]any{"org": "acme"})
	wantStatus(t, res, begin, 200)
	ch, cred = assert(anon, begin)
	res, out = signed.post("/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": ch, "credential": cred})
	wantStatus(t, res, out, 422)
	res, out = signed.api("GET", "/api-internal/account/reauth", nil)
	if out["valid"] == true {
		t.Fatal("a sign-in ceremony re-authenticated the session")
	}

	// the matching purposes work
	res, begin = signed.post("/api-internal/account/reauth/passkey/begin", nil)
	ch, cred = assert(signed, begin)
	res, out = signed.post("/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": ch, "credential": cred})
	wantStatus(t, res, out, 200)
	signed.markReauth()

	// a ceremony begun for re-authentication cannot register a passkey
	res, reauthBegin := signed.post("/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, reauthBegin, 200)
	res, regBegin := signed.post("/api-internal/account/passkeys/register/begin", nil)
	wantStatus(t, res, regBegin, 200)
	regOpts, _ := json.Marshal(regBegin["options"])
	regOnly, _, err := virtualauth.New(e.Cfg.Server.PublicURL).Create(regOpts)
	if err != nil {
		t.Fatal(err)
	}
	res, out = signed.post("/api-internal/account/passkeys/register/finish", map[string]any{"challenge": reauthBegin["challenge"], "name": "x",
		"credential": json.RawMessage(regOnly)})
	wantStatus(t, res, out, 422)

	// registration ceremonies: sign-in-time enrolment cannot finish at the account endpoint. The enrolment step
	// exists only for an account with no second factor yet (pat has a passkey, so pat's would be refused): quinn's
	// ticket begins the ceremony, and pat's session must not be able to finish it.
	quinn := e.user(t, org, "quinn", model.RoleUser)
	tid, _ := e.Mod.PutEnrolTicket(quinn.ID)
	res, begin = e.browser(t).post("/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": tid})
	wantStatus(t, res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	regCred, _, err := virtualauth.New(e.Cfg.Server.PublicURL).Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	res, out = signed.post("/api-internal/account/passkeys/register/finish", map[string]any{"challenge": begin["challenge"], "name": "x",
		"credential": json.RawMessage(regCred)})
	wantStatus(t, res, out, 422)
	if l, _ := e.Svc.Passkeys.All(context.Background(), pat.ID); len(l) != 1 {
		t.Fatalf("passkeys %d", len(l))
	}
}

// A copied authenticator caught while confirming it is the user (re-authentication) is refused, its passkey disabled,
// and recorded as passkey.clone, as at sign-in.
func TestReauthPasskeyClone(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	setup := e.signedIn(t, pat)
	setup.fresh()
	cred := setup.registerPasskey("Key")
	c := e.signedIn(t, pat) // another browser, signed in an hour ago
	c.auth = setup.auth
	reauth := func(stale bool) (int, map[string]any) {
		res, begin := c.api("POST", "/api-internal/account/reauth/passkey/begin", nil)
		wantStatus(t, res, begin, 200)
		opts, _ := json.Marshal(begin["options"])
		var assertion []byte
		var err error
		if stale {
			assertion, err = c.auth.GetWith(opts, cred, 1, e.Cfg.Server.PublicURL)
		} else {
			assertion, _, err = c.auth.Get(opts)
		}
		if err != nil {
			t.Fatal(err)
		}
		res, out := c.api("POST", "/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": begin["challenge"],
			"credential": json.RawMessage(assertion)})
		return res.StatusCode, out
	}
	for range 2 {
		if status, out := reauth(false); status != 200 {
			t.Fatalf("confirming: %d %v", status, out)
		}
	}
	if status, out := reauth(true); status != 422 {
		t.Fatalf("a copied authenticator confirmed: %d %v", status, out)
	}
	audits := e.audits(t, "passkey.clone")
	if len(audits) != 1 || audits[0].Detail["passkey"] != "Key" || audits[0].Detail["during"] != "reauth" {
		t.Fatalf("clone audits %+v", audits)
	}
	list, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
	if len(list) != 1 || !list[0].Disabled {
		t.Fatalf("the passkey is not disabled: %+v", list)
	}
}

// Sign-in with a passkey whose authenticator did not verify the user, whose response came from another origin, whose
// account has been switched off or whose passkey was disabled gives no session and is audited as a failure.
func TestPasskeyLoginRefused(t *testing.T) {
	e, pat, signed := passkeyEnv(t)
	signIn := func() (int, *browser) {
		b := e.browser(t)
		b.auth = signed.auth
		status, _ := b.passkeyLogin(map[string]any{"org": "acme"})
		return status, b
	}
	setActive := func(on bool) {
		t.Helper()
		if _, err := e.Svc.UpdateUser(context.Background(), service.System, pat.ID, service.UserInput{Active: &on}); err != nil {
			t.Fatal(err)
		}
	}
	if status, b := signIn(); status != 200 || !b.hasSession() {
		t.Fatalf("control: %d", status)
	}

	for _, tc := range []struct {
		name string
		// refuse makes the sign-in fail and returns how to undo it.
		refuse func(t *testing.T) (undo func())
		// attempt signs in (nil: signIn).
		attempt func(t *testing.T) (int, *browser)
	}{
		{"authenticator did not verify the user", func(t *testing.T) func() {
			signed.auth.UserVerified = false
			return func() { signed.auth.UserVerified = true }
		}, nil},
		{"response from another origin", nil, func(t *testing.T) (int, *browser) {
			b := e.browser(t)
			res, begin := b.post("/api-internal/login/passkey/begin", map[string]any{"org": "acme"})
			wantStatus(t, res, begin, 200)
			opts, _ := json.Marshal(begin["options"])
			evil, err := signed.auth.GetWith(opts, signed.auth.Creds[0], 99, "https://evil.example")
			if err != nil {
				t.Fatal(err)
			}
			res, _ = b.post("/api-internal/login/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(evil)})
			return res.StatusCode, b
		}},
		{"account switched off", func(t *testing.T) func() {
			setActive(false)
			return func() {
				setActive(true)
				if status, _ := signIn(); status != 200 {
					t.Fatalf("re-enabled account: %d", status)
				}
			}
		}, nil},
		{"passkey disabled", func(t *testing.T) func() {
			list, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
			list[0].Disabled = true
			if err := e.Svc.Passkeys.Update(context.Background(), list[0]); err != nil {
				t.Fatal(err)
			}
			return func() {}
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.refuse != nil {
				defer tc.refuse(t)()
			}
			attempt := tc.attempt
			if attempt == nil {
				attempt = func(*testing.T) (int, *browser) { return signIn() }
			}
			status, b := attempt(t)
			if status != 401 || b.hasSession() {
				t.Fatalf("status %d, session=%v", status, b.hasSession())
			}
		})
	}
	if n := len(e.audits(t, "login.failure")); n < 4 {
		t.Fatalf("failures audited: %d", n)
	}
}
