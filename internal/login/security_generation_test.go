package login_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Every sign-in or set-up in flight is bound to the account's security generation (model.User.SecurityGen) and dies
// when a credential changes under it; a commit that sets a factor is a compare-and-swap, so of two racing completions
// exactly one wins. These tests take each flow through "start, change a credential, continue: refused" and the
// enrolment commits through "two at once: one wins".

// A ticket at the authenticator-code step dies with a password change: the code is right, the sign-in is not.
func TestSecondFactorTicketDiesWithPasswordChange(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	user := e.user(t, org, "pat", model.RoleUser)
	secret := e.giveTOTP(t, user)
	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	ticket := str(out, "ticket")
	if str(out, "step") != "totp" || ticket == "" {
		t.Fatalf("setup: %v", out)
	}
	pw := "another fine password 42"
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, user.ID, service.UserInput{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	res, out := b.post("/api-internal/login/totp", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	refused(t, res, out)
	if b.hasSession() {
		t.Fatal("a ticket from the old password signed in after the password changed")
	}
	// the same sign-in with the new password works
	_, out = b.login("acme", "pat", pw)
	res, out = b.post("/api-internal/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": totpAt(secret, time.Now().Add(30*time.Second))})
	wantStatus(t, res, out, 200)
}

// A ticket dies with the emergency sign-out lever: whatever was mid-sign-in when it was pulled starts again.
func TestSecondFactorTicketDiesWithEmergencySignOut(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	user := e.user(t, org, "pat", model.RoleUser)
	secret := e.giveTOTP(t, user)
	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	ticket := str(out, "ticket")
	if _, err := e.Svc.SignOutOrg(context.Background(), service.System, org.ID, service.SignOutOptions{Reason: "drill"}); err != nil {
		t.Fatal(err)
	}
	res, out := b.post("/api-internal/login/totp", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	refused(t, res, out)
	if b.hasSession() {
		t.Fatal("signed in past the lever")
	}
}

// An emailed code is bound to its sign-in, and the sign-in to the account's credentials.
func TestEmailCodeStepDiesWithPasswordChange(t *testing.T) {
	e, org := emailEnv(t, func(s *model.OrgSettings) { s.RequireMFA, s.EmailCodes = true, true })
	user := e.verifiedUser(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	ticket := str(out, "ticket")
	if str(out, "step") != "email_code" {
		t.Fatalf("setup: %v", out)
	}
	code := codeFrom(t, e)
	pw := "another fine password 42"
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, user.ID, service.UserInput{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	res, out := b.post("/api-internal/login/email", map[string]any{"ticket": ticket, "code": code})
	refused(t, res, out)
	res, out = b.post("/api-internal/login/email/send", map[string]any{"ticket": ticket})
	refused(t, res, out)
	if b.hasSession() {
		t.Fatal("signed in with a code sent before the password changed")
	}
}

// A recovery code stands in for the second factor of a sign-in that is still the account's: new codes (a new
// credential) end the sign-in, even though the code typed is one of the new ones.
func TestRecoveryStepDiesWhenCodesAreRemade(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	user := e.user(t, org, "pat", model.RoleUser)
	e.giveTOTP(t, user)
	ctx := context.Background()
	fresh, _ := e.Svc.Users.Get(ctx, user.ID)
	if _, err := e.Svc.CreateRecoveryCodes(ctx, service.System, fresh); err != nil {
		t.Fatal(err)
	}
	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	ticket := str(out, "ticket")
	fresh, _ = e.Svc.Users.Get(ctx, user.ID)
	codes, err := e.Svc.CreateRecoveryCodes(ctx, service.System, fresh)
	if err != nil {
		t.Fatal(err)
	}
	res, out := b.post("/api-internal/login/recovery", map[string]any{"ticket": ticket, "code": codes[0]})
	refused(t, res, out)
	if b.hasSession() {
		t.Fatal("signed in with a ticket from before the codes were remade")
	}
}

// A sign-in that must enrol a factor cannot replace one the account got meanwhile (its owner set one up elsewhere), with
// the ticket it already held or with one minted now.
func TestEnrolmentRefusedOnceAFactorIsEstablished(t *testing.T) {
	// A factor set up through the sign-in flow moves the account's security generation, which ends the ticket held
	// (401); one written straight to the account leaves the generation, so it is the factor that refuses (409).
	for factor, stale := range map[string]int{"passkey": 401, "totp": 409} {
		t.Run(factor, func(t *testing.T) {
			e := newEnv(t, nil)
			org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
			user := e.user(t, org, "pat", model.RoleUser)
			pending, owner := e.browser(t), e.browser(t)
			_, first := pending.login("acme", "pat", userPassword)
			ticket := str(first, "ticket")
			var secret string
			if factor == "totp" {
				e.giveTOTP(t, user)
				u, _ := e.Svc.Users.Get(context.Background(), user.ID)
				secret = u.TOTPSecret
			} else {
				_, second := owner.login("acme", "pat", userPassword)
				res, begin := owner.post("/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": str(second, "ticket")})
				wantStatus(t, res, begin, 200)
				opts, _ := json.Marshal(begin["options"])
				cred, _, err := owner.auth.Create(opts)
				if err != nil {
					t.Fatal(err)
				}
				res, out := owner.post("/api-internal/login/enrol/passkey/finish", map[string]any{"ticket": str(second, "ticket"),
					"challenge": begin["challenge"], "name": "Laptop", "credential": json.RawMessage(cred)})
				wantStatus(t, res, out, 200)
				if !owner.hasSession() {
					t.Fatal("owner not signed in")
				}
			}
			res, out := pending.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
			wantStatus(t, res, out, stale)
			res, out = pending.post("/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": ticket})
			wantStatus(t, res, out, stale)
			// a ticket minted now, at the current generation: still not for an account with a factor
			tk, err := e.Mod.PutEnrolTicket(user.ID)
			if err != nil {
				t.Fatal(err)
			}
			res, out = pending.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": tk})
			wantStatus(t, res, out, 409)
			res, out = pending.post("/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": tk})
			wantStatus(t, res, out, 409)
			if pending.hasSession() {
				t.Fatal("session")
			}
			now, _ := e.Svc.Users.Get(context.Background(), user.ID)
			if factor == "totp" && now.TOTPSecret != secret {
				t.Fatal("the account's authenticator app was replaced")
			}
			wantPasskeys := 0
			if factor == "passkey" {
				wantPasskeys = 1
			}
			if n, _ := e.Svc.Passkeys.Count(context.Background(), user.ID); n != wantPasskeys {
				t.Fatalf("passkeys %d, want %d", n, wantPasskeys)
			}
		})
	}
}

// Two authenticator-app enrolments racing for the same account (two tickets from the same password): the commit is
// a compare-and-swap on the user, so exactly one wins, and the stored secret is the winner's.
func TestConcurrentTOTPEnrolmentsOneWins(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	user := e.user(t, org, "pat", model.RoleUser)
	const n = 3
	type racer struct {
		b              *browser
		ticket, secret string
		status         int
	}
	racers := make([]*racer, n)
	for i := range racers {
		b := e.browser(t)
		_, out := b.login("acme", "pat", userPassword)
		r := &racer{b: b, ticket: str(out, "ticket")}
		res, begin := b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": r.ticket})
		wantStatus(t, res, begin, 200)
		r.secret = str(begin, "secret")
		racers[i] = r
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	now := time.Now()
	for _, r := range racers {
		wg.Add(1)
		go func(r *racer) {
			defer wg.Done()
			<-start
			res, _ := r.b.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": r.ticket, "code": totpAt(r.secret, now)})
			r.status = res.StatusCode
		}(r)
	}
	close(start)
	wg.Wait()
	var winner *racer
	for _, r := range racers {
		switch {
		case r.status == 200 && winner == nil:
			winner = r
		case r.status == 200:
			t.Fatalf("two enrolments succeeded")
		case r.status != http.StatusUnauthorized && r.status != http.StatusConflict:
			t.Fatalf("loser answered %d", r.status)
		}
		if (r.status == 200) != r.b.hasSession() {
			t.Fatalf("status %d, session %v", r.status, r.b.hasSession())
		}
	}
	if winner == nil {
		t.Fatal("no enrolment succeeded")
	}
	ctx := context.Background()
	current, err := e.Svc.Users.Get(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := e.Svc.Sealer.OpenFor(service.TOTPBinding(user.ID), current.TOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != winner.secret {
		t.Fatal("the stored secret is not the winner's")
	}
	if current.SecurityGen != user.SecurityGen+1 {
		t.Fatalf("generation %d, want %d", current.SecurityGen, user.SecurityGen+1)
	}
}

// The same race with passkeys: the generation moves on before the credential is stored, with a compare-and-swap on
// the user each completion validated against, so exactly one passkey is stored.
func TestConcurrentPasskeyEnrolmentsOneWins(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	user := e.user(t, org, "pat", model.RoleUser)
	type racer struct {
		b         *browser
		ticket    string
		challenge any
		cred      []byte
		status    int
	}
	racers := make([]*racer, 2)
	for i := range racers {
		b := e.browser(t)
		_, out := b.login("acme", "pat", userPassword)
		r := &racer{b: b, ticket: str(out, "ticket")}
		res, begin := b.post("/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": r.ticket})
		wantStatus(t, res, begin, 200)
		opts, _ := json.Marshal(begin["options"])
		cred, _, err := b.auth.Create(opts)
		if err != nil {
			t.Fatal(err)
		}
		r.challenge, r.cred = begin["challenge"], cred
		racers[i] = r
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, r := range racers {
		wg.Add(1)
		go func(r *racer) {
			defer wg.Done()
			<-start
			res, _ := r.b.post("/api-internal/login/enrol/passkey/finish", map[string]any{"ticket": r.ticket,
				"challenge": r.challenge, "name": "Key", "credential": json.RawMessage(r.cred)})
			r.status = res.StatusCode
		}(r)
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, r := range racers {
		if r.status == 200 {
			wins++
		} else if r.status != http.StatusUnauthorized && r.status != http.StatusConflict {
			t.Fatalf("loser answered %d", r.status)
		}
		if (r.status == 200) != r.b.hasSession() {
			t.Fatalf("status %d, session %v", r.status, r.b.hasSession())
		}
	}
	if wins != 1 {
		t.Fatalf("%d enrolments succeeded, want 1", wins)
	}
	if n, _ := e.Svc.Passkeys.Count(context.Background(), user.ID); n != 1 {
		t.Fatalf("passkeys %d, want 1", n)
	}
}

// A password reset link dies when the password changes after it was sent: a reset nobody needs any more must not
// change the new password.
func TestResetLinkDiesWithPasswordChange(t *testing.T) {
	e, org := emailEnv(t, nil)
	user := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.post("/o/acme/api-internal/password/forgot", map[string]any{"email": user.Email})
	wantStatus(t, res, out, 200)
	link := linkPath(t, e.nextMail(t))
	pw := "another fine password 42"
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, user.ID, service.UserInput{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": tokenOf(link), "password": "a reset nobody asked for 9"})
	wantStatus(t, res, out, http.StatusGone)
	if res, _ := b.get(link); res.StatusCode != http.StatusGone {
		t.Fatalf("reset page %d, want 410", res.StatusCode)
	}
	_, out = b.login("acme", "pat", pw)
	if str(out, "next") == "" {
		t.Fatalf("the new password no longer signs in: %v", out)
	}
}

// An invitation dies when a credential of the account changes after it was issued (here: a passkey added by its
// owner); an invitation accepted would replace that credential.
func TestInvitationDiesWithCredentialChange(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	user := e.user(t, org, "pat", model.RoleUser)
	ctx := context.Background()
	link, _, err := e.Svc.CreateInvite(ctx, service.System, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.signedIn(t, user).registerPasskey("Laptop")
	b := e.browser(t)
	res, out := b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "an invitation nobody needs 7"})
	wantStatus(t, res, out, http.StatusGone)
	if n, _ := e.Svc.Passkeys.Count(ctx, user.ID); n != 1 {
		t.Fatalf("passkeys %d, want 1", n)
	}
	if b.hasSession() {
		t.Fatal("a dead invitation signed in")
	}
}

// A re-authentication is a confirmation of the credentials as they were: another browser setting up an authenticator
// app ends it (the account page asks again, now for the code), while the browser that made the change keeps its own.
func TestReauthDiesWithCredentialChangeElsewhere(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	user := e.user(t, org, "pat", model.RoleUser)
	stale, active := e.signedIn(t, user), e.signedIn(t, user)
	stale.markReauth()
	active.markReauth()
	valid := func(b *browser) bool {
		_, out := b.api("GET", "/api-internal/account/reauth", nil)
		return out["valid"] == true
	}
	if !valid(stale) {
		t.Fatal("setup: not re-authenticated")
	}
	res, out := active.post("/api-internal/account/totp/begin", nil)
	wantStatus(t, res, out, 200)
	res, out = active.post("/api-internal/account/totp/confirm", map[string]any{"code": totpAt(str(out, "secret"), time.Now())})
	wantStatus(t, res, out, 200)
	if valid(stale) {
		t.Fatal("a re-authentication from before the authenticator app was set up still counts")
	}
	if !valid(active) {
		t.Fatal("the browser that set up the app lost its own confirmation")
	}
	// and the stale browser cannot use it to remove the new factor
	res, out = stale.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, http.StatusForbidden)
}

// A confirmation that no longer stands is not brought back by the stale session's own change: someone holding only
// the password, with a session confirmed before the owner set up an authenticator app, cannot change the password
// (which now asks for the app as well) and must still not be able to remove the new app.
func TestStaleReauthNotRevivedByPasswordChange(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	user := e.user(t, org, "pat", model.RoleUser)
	attacker, owner := e.signedIn(t, user), e.signedIn(t, user)
	attacker.markReauth()
	owner.markReauth()
	res, out := owner.post("/api-internal/account/totp/begin", nil)
	wantStatus(t, res, out, 200)
	res, out = owner.post("/api-internal/account/totp/confirm", map[string]any{"code": totpAt(str(out, "secret"), time.Now())})
	wantStatus(t, res, out, 200)
	res, out = attacker.api("POST", "/api-internal/account/password", map[string]any{"current": userPassword, "new": "an entirely new passphrase 7731"})
	wantStatus(t, res, out, http.StatusForbidden)
	if _, out := attacker.api("GET", "/api-internal/account/reauth", nil); out["valid"] == true {
		t.Fatal("a stale re-authentication came back with the password change")
	}
	res, out = attacker.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, http.StatusForbidden)
	if u, _ := e.Svc.Users.Get(context.Background(), user.ID); !u.HasTOTP() {
		t.Fatal("the authenticator app was removed")
	}
}

// An authenticator secret shown on the account page is confirmed only against the account as it was when shown.
func TestPendingTOTPDiesWithCredentialChange(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	user := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, user)
	b.markReauth()
	res, out := b.post("/api-internal/account/totp/begin", nil)
	wantStatus(t, res, out, 200)
	secret := str(out, "secret")
	if _, err := e.Svc.AdvanceSecurity(context.Background(), user.ID); err != nil { // a credential changed elsewhere
		t.Fatal(err)
	}
	res, out = b.post("/api-internal/account/totp/confirm", map[string]any{"code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, http.StatusConflict)
	if u, _ := e.Svc.Users.Get(context.Background(), user.ID); u.HasTOTP() {
		t.Fatal("a secret from before the change was stored")
	}
}

// A passkey ceremony begun for a known user is bound to the account's generation too: a response to a challenge
// issued before a credential changed does not re-authenticate.
func TestPasskeyCeremonyDiesWithCredentialChange(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	user := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, user)
	b.registerPasskey("Laptop")
	e.Mod.ClearReauth(b.sessionID())
	res, out := b.post("/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, out, 200)
	opts, _ := json.Marshal(out["options"])
	cred, _, err := b.auth.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Svc.AdvanceSecurity(context.Background(), user.ID); err != nil {
		t.Fatal(err)
	}
	res, out = b.post("/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": out["challenge"], "credential": json.RawMessage(cred)})
	wantStatus(t, res, out, http.StatusUnprocessableEntity)
	_, out = b.api("GET", "/api-internal/account/reauth", nil)
	if out["valid"] == true {
		t.Fatal("a ceremony from before the change re-authenticated")
	}
}

// The generation moves on with each credential change made from the account page, and not with a profile edit.
func TestSecurityGenerationFollowsAccountChanges(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	user := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, user)
	b.markReauth()
	gen := e.securityGen(t, user.ID)
	res, out := b.api("PATCH", "/api-internal/account", map[string]any{"given_name": "Patricia"})
	wantStatus(t, res, out, 200)
	if g := e.securityGen(t, user.ID); g != gen {
		t.Fatalf("a profile edit moved the generation %d -> %d", gen, g)
	}
	b.registerPasskey("Laptop")
	if g := e.securityGen(t, user.ID); g != gen+1 {
		t.Fatalf("passkey: generation %d, want %d", g, gen+1)
	}
	res, out = b.post("/api-internal/account/password", map[string]any{"current": userPassword, "new": "a brand new password 11"})
	wantStatus(t, res, out, 200)
	if g := e.securityGen(t, user.ID); g != gen+2 {
		t.Fatalf("password: generation %d, want %d", g, gen+2)
	}
	_, out = b.api("GET", "/api-internal/account/reauth", nil)
	if out["valid"] != true {
		t.Fatal("own changes spent the re-authentication")
	}
}

// The ticket of a sign-in that must enrol a factor dies with the password it was obtained with: after a password change it
// cannot begin or finish an enrolment.
func TestEnrolmentTicketDiesWithPasswordChange(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	user := e.user(t, org, "pat", model.RoleUser)
	pending := e.browser(t)
	_, first := pending.login("acme", user.Email, userPassword)
	ticket := str(first, "ticket")
	if str(first, "step") != "enrol" || ticket == "" {
		t.Fatalf("setup: %v", first)
	}
	newPassword := "fresh forest orbit lantern 7"
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, user.ID, service.UserInput{Password: &newPassword}); err != nil {
		t.Fatal(err)
	}
	res, body := pending.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	wantStatus(t, res, body, 401)
	res, body = pending.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": "123456"})
	wantStatus(t, res, body, 401)
	if pending.hasSession() {
		t.Fatal("a ticket obtained with the old password started a session after the password changed")
	}
}
