package admin_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Who pulled the last emergency sign-out, and why, is for those who manage the organization's users: a plain user
// reading their organization does not see it.
func TestLastSignOutHiddenFromUsers(t *testing.T) {
	w := newWorld(t)
	if _, err := w.env.Svc.SignOutOrg(context.Background(), service.System, w.acme.ID,
		service.SignOutOptions{Reason: "suspected phishing"}); err != nil {
		t.Fatal(err)
	}
	for who, visible := range map[string]bool{"user": false, "manager": true, "admin": true} {
		r := w.as(who).get(A)
		want(t, r, 200)
		if _, ok := r.JSON["last_sign_out"]; ok != visible {
			t.Errorf("%s: last_sign_out shown=%v, want %v", who, ok, visible)
		}
	}
}

// A backup holds every sealed secret: from a console session it needs a recent re-authentication, as key rotation.
func TestBackupDownloadNeedsReauthFromSession(t *testing.T) {
	w := newWorld(t)
	w.env.Server.Reauthed = func(*http.Request) bool { return false }
	wantField(t, w.as("super").get("/api/backup?plain=1"), 403, "reauth")
}

// A request the service refuses for want of permission is an access-control event: it is audited, like the
// refusals the API makes itself (scope, CSRF, second factor).
func TestForbiddenRequestIsAudited(t *testing.T) {
	w := newWorld(t)
	want(t, w.as("manager").patch(A, map[string]any{"display_name": "Mine now"}), 403)
	evs, _, err := w.env.Svc.Audits.List(context.Background(), store.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Action == "api.request.refused" && e.Detail["reason"] == "not permitted" && e.ActorID == w.users["manager"].ID {
			return
		}
	}
	t.Fatal("the refused request was not audited")
}
