package login_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
)

// registerPasskey enrols a passkey for the signed-in browser's user through the account API.
func (b *browser) registerPasskey(name string) *virtualauth.Credential {
	b.t.Helper()
	b.markReauth() // registering a passkey needs a recent re-authentication
	res, out := b.post("/api-internal/account/passkeys/register/begin", nil)
	wantStatus(b.t, res, out, 200)
	opts, _ := json.Marshal(out["options"])
	cred, c, err := b.auth.Create(opts)
	if err != nil {
		b.t.Fatal(err)
	}
	res, out = b.post("/api-internal/account/passkeys/register/finish", map[string]any{"challenge": out["challenge"], "name": name,
		"credential": json.RawMessage(cred)})
	wantStatus(b.t, res, out, 201)
	return c
}

// passkeyLogin runs begin+finish on an anonymous browser and returns the finish response.
func (b *browser) passkeyLogin(begin map[string]any) (int, map[string]any) {
	b.t.Helper()
	res, out := b.post("/api-internal/login/passkey/begin", begin)
	if res.StatusCode != 200 {
		return res.StatusCode, out
	}
	opts, _ := json.Marshal(out["options"])
	cred, _, err := b.auth.Get(opts)
	if err != nil {
		b.t.Fatal(err)
	}
	res, out2 := b.post("/api-internal/login/passkey/finish", map[string]any{"challenge": out["challenge"], "credential": json.RawMessage(cred)})
	return res.StatusCode, out2
}

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
	other := e.org(t, "other", nil)
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
	_ = other
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

	// Garbage never signs in.
	res, out = b.post("/api-internal/login/passkey/finish", map[string]any{"challenge": "n1.x", "credential": map[string]any{}})
	wantStatus(t, res, out, 401)
	res, out = b.post("/api-internal/login/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": "junk"})
	if res.StatusCode != 401 && res.StatusCode != 400 {
		t.Fatalf("junk credential: %d", res.StatusCode)
	}
}

func TestPasskeysDisabledOnIPHost(t *testing.T) {
	e := newEnvWith(t, nil, true)
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

	// registration ceremonies: sign-in-time enrolment cannot finish at the account endpoint
	tid, _ := e.Mod.PutEnrolTicket(pat.ID)
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

// Deleting a passkey ends the sessions that signed in with it, but not the session deleting it.
func TestDeletingPasskeyEndsItsSessions(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	b.registerPasskey("Laptop")
	other := e.browser(t)
	other.auth = b.auth // the same authenticator, on another device
	if st, out := other.passkeyLogin(map[string]any{"org": "acme"}); st != 200 {
		t.Fatalf("passkey sign-in: %d %v", st, out)
	}
	if res, _ := other.api("GET", "/api-internal/account", nil); res.StatusCode != 200 {
		t.Fatalf("not signed in: %d", res.StatusCode)
	}
	// a session signed in another way is not touched
	pwd := e.signedIn(t, pat)
	list, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
	b.markReauth()
	res, out := b.api("DELETE", "/api-internal/account/passkeys/"+list[0].ID, nil)
	wantStatus(t, res, out, 204)
	if res, _ := other.api("GET", "/api-internal/account", nil); res.StatusCode != 401 {
		t.Errorf("the passkey's session survived: %d", res.StatusCode)
	}
	for name, br := range map[string]*browser{"deleting": b, "password": pwd} {
		if res, _ := br.api("GET", "/api-internal/account", nil); res.StatusCode != 200 {
			t.Errorf("%s session ended: %d", name, res.StatusCode)
		}
	}
}

// "Try another way" at the authenticator-code step: the step lists the account's other ways (a passkey, recovery
// codes left), and a passkey is accepted there in place of the code.
func TestSecondFactorAlternatives(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	e.giveTOTP(t, pat)
	alts := func() ([]any, string) {
		res, out := e.browser(t).login("acme", "pat", userPassword)
		wantStatus(t, res, out, 200)
		a, _ := out["alternatives"].([]any)
		return a, str(out, "step")
	}
	if a, step := alts(); step != "totp" || len(a) != 0 {
		t.Fatalf("no other way: %s %v", step, a)
	}

	signed := e.signedIn(t, pat)
	signed.registerPasskey("Laptop")
	u, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	if _, err := e.Svc.CreateRecoveryCodes(context.Background(), nil, u); err != nil {
		t.Fatal(err)
	}
	if a, step := alts(); step != "totp" || len(a) != 2 || a[0] != "passkey" || a[1] != "recovery" {
		t.Fatalf("passkey and codes: %s %v", step, a)
	}

	// the passkey in place of the code, with the authenticator-code step's ticket
	b := e.browser(t)
	b.auth = signed.auth
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	status, done := b.passkeyLogin(map[string]any{"ticket": str(out, "ticket")})
	if status != 200 || !b.hasSession() {
		t.Fatalf("passkey at the code step: %d %v", status, done)
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), pat.ID)
	found := false
	for _, s := range sess {
		if strings.HasPrefix(strings.Join(s.AMR, ","), "pwd,") && strings.HasSuffix(strings.Join(s.AMR, ","), ",mfa") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no two-factor session: %+v", sess)
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
