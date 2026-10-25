package login_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestFreshReviewPassedEpochPasskeyDoesNotBlockFreshEnrollment(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	u := e.user(t, org, "fresh-start", model.RoleUser)
	u.CredEpoch = service.NewCredEpoch()
	if err := e.Svc.Users.Update(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	// A reset made this old record inert; failed cleanup or a delayed losing invite may leave it stored.
	old := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Epoch: 0, Name: "old epoch", CredentialID: []byte("old-epoch-key"), UserVerified: true}
	if err := e.Svc.Passkeys.Create(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	res, out := e.browser(t).login("acme", u.Email, userPassword)
	if res.StatusCode != 200 || str(out, "step") != "enrol" {
		t.Fatalf("inert passkey blocked fresh MFA enrollment: status=%d step=%q error=%q", res.StatusCode, str(out, "step"), str(out, "error"))
	}
}
