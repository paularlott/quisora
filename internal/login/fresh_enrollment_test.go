package login_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestFreshPendingEnrollmentCannotReplaceEstablishedFactor(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	user := e.user(t, org, "pending-factor", model.RoleUser)
	pending, owner := e.browser(t), e.browser(t)
	_, first := pending.login("acme", user.Email, userPassword)
	ticket := str(first, "ticket")
	if str(first, "step") != "enrol" || ticket == "" {
		t.Fatalf("setup: %v", first)
	}
	_, second := owner.login("acme", user.Email, userPassword)
	ownerTicket := str(second, "ticket")
	res, body := owner.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ownerTicket})
	wantStatus(t, res, body, 200)
	establishedSecret := str(body, "secret")
	res, body = owner.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ownerTicket, "code": totpAt(establishedSecret, time.Now())})
	wantStatus(t, res, body, 200)
	res, body = pending.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusConflict {
		return
	}
	wantStatus(t, res, body, 200)
	newSecret := str(body, "secret")
	res, body = pending.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": totpAt(newSecret, time.Now())})
	current, err := e.Svc.Users.Get(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := e.Svc.Sealer.OpenFor(service.TOTPBinding(user.ID), current.TOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != establishedSecret {
		t.Fatalf("pending first-factor enrollment replaced an established authenticator without verifying it: status=%d session=%v", res.StatusCode, pending.hasSession())
	}
}

func TestFreshPasswordChangeInvalidatesPendingEnrollment(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	user := e.user(t, org, "changed-password", model.RoleUser)
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
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusConflict {
		return
	}
	wantStatus(t, res, body, 200)
	secret := str(body, "secret")
	res, body = pending.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	if res.StatusCode == http.StatusOK && pending.hasSession() {
		t.Fatal("ticket authenticated with old password obtained a session after password change")
	}
}
