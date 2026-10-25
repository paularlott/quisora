package oidc

// Regression tests from the external code reviews, one per finding: each states the failure it guards against.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// Hold the first PAR read after it took its snapshot, allowing another browser
// request to start and finish the authorization before the delayed read resumes.
type deepReviewPARReadGate struct {
	ephemeral.Store
	captured chan struct{}
	resume   chan struct{}
	held     atomic.Bool
}

func (g *deepReviewPARReadGate) Get(ctx context.Context, ns, id string) ([]byte, error) {
	b, err := g.Store.Get(ctx, ns, id)
	if ns == nsPAR && err == nil && g.held.CompareAndSwap(false, true) {
		close(g.captured)
		<-g.resume
	}
	return b, err
}
func TestDeepReviewDelayedPARStartCannotResurrectConsumedRequest(t *testing.T) {
	ctx := context.Background()
	local := ephemeral.NewLocal("deep-review")
	defer local.Close()
	gate := &deepReviewPARReadGate{Store: local, captured: make(chan struct{}), resume: make(chan struct{})}
	p := &Provider{s: &web.Server{Eph: gate}}
	raw, _ := json.Marshal(pushedRequest{ClientID: "client", Params: "client_id=client&response_type=code"})
	id, err := local.New(ctx, nsPAR, raw, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	loaded := make(chan error, 1)
	go func() { _, _, _, err := p.loadPushed(ctx, "client", parURNPrefix+id); loaded <- err }()
	<-gate.captured
	if _, _, used, err := p.loadPushed(ctx, "client", parURNPrefix+id); err != nil || used {
		t.Fatalf("second visit: used=%v err=%v", used, err)
	}
	if !p.usePushed(ctx, id) {
		t.Fatal("first completion refused")
	}
	close(gate.resume)
	if err := <-loaded; err != nil {
		t.Fatal(err)
	}
	if p.usePushed(ctx, id) {
		t.Fatal("consumed PAR request resurrected by delayed first-visit write; another authorization code can be issued")
	}
}

// An epoch change ends authorization approved by an earlier session even when
// physical deletion of that session fails: deletion is only housekeeping.
func TestFresh3EpochChangeEndsOutstandingAuthorizationCode(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	client, secret := h.newClient(nil)
	browser, _ := h.session(h.user)
	verifier, challenge := pkce()
	code := h.getCode(browser, client, challenge, nil)
	base := h.env.Svc.Store
	h.env.Svc.Store = failDeletes{Store: base, kind: model.KindSession}
	if err := h.env.Svc.ResetCredentials(ctx, h.user.ID); err == nil {
		t.Fatal("setup: expected injected cleanup error")
	}
	h.env.Svc.Store = base
	current, err := h.env.Svc.Users.Get(ctx, h.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.CredEpoch == h.user.CredEpoch {
		t.Fatal("reset did not commit a new epoch")
	}
	h.p.InvalidateUser(h.user.ID) // as the production user-change notification does
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {verifier}}, client, secret)
	if r.status == 200 {
		_, verifyErr := h.p.VerifyAccessToken(ctx, r.str("access_token"))
		refreshed := h.refreshWith(client, secret, r.str("refresh_token"))
		t.Fatalf("authorization from a passed session epoch issued new tokens: access verification=%v refresh status=%d", verifyErr, refreshed.status)
	}
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("unexpected refusal: %d %v", r.status, r.m)
	}
}

// Emergency sign-out invalidates stamps before its background deletion runs.
func TestFresh3SignOutEndsOutstandingAuthorizationCode(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	client, secret := h.newClient(nil)
	browser, _ := h.session(h.user)
	verifier, challenge := pkce()
	code := h.getCode(browser, client, challenge, nil)
	if _, err := h.env.Svc.SignOutOrg(ctx, service.System, h.user.OrgID, service.SignOutOptions{Reason: "review outstanding code"}); err != nil {
		t.Fatal(err)
	}
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {verifier}}, client, secret)
	if r.status == 200 {
		_, verifyErr := h.p.VerifyAccessToken(ctx, r.str("access_token"))
		t.Fatalf("authorization from a signed-out session issued tokens with current counters: access verification=%v", verifyErr)
	}
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("unexpected refusal: %d %v", r.status, r.m)
	}
}

func TestFreshReviewAccessIntrospectionReflectsRemovedTenantAccess(t *testing.T) {
	h := setup(t, nil)
	tn := h.tenant("fresh-introspection", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	entry := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	tokens, _ := h.login(cl, secret, orgScope)
	at := tokens.str("access_token")
	if tokens.status != 200 || at == "" {
		t.Fatalf("login: %d %v", tokens.status, tokens.m)
	}
	if err := h.env.Svc.RemoveAccess(context.Background(), h.admin, tn.ID, entry.ID); err != nil {
		t.Fatal(err)
	}
	ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	text := body(ui)
	if ui.StatusCode != http.StatusUnauthorized {
		t.Fatalf("control: userinfo after removal: %d %s", ui.StatusCode, text)
	}
	if introspection := h.introspect(cl, secret, at); introspection["active"] != false {
		t.Fatalf("access token remains active after tenant access removed: %v", introspection)
	}
}

type freshReviewAccessReadFailure struct{ store.Store }

func (s freshReviewAccessReadFailure) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindAccess {
		return nil, errors.New("review: tenant access read failed")
	}
	return s.Store.Get(ctx, kind, id)
}
func TestFreshReviewUserinfoFailsClosedOnAccessReadFailure(t *testing.T) {
	h := setup(t, nil)
	tn := h.tenant("fresh-userinfo", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	tokens, _ := h.login(cl, secret, orgScope)
	at := tokens.str("access_token")
	if tokens.status != 200 || at == "" {
		t.Fatalf("login: %d %v", tokens.status, tokens.m)
	}
	h.env.Svc.Access.S = freshReviewAccessReadFailure{Store: h.env.Svc.Access.S}
	ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	text := body(ui)
	if ui.StatusCode == http.StatusOK {
		t.Fatalf("userinfo released profile despite access-check storage failure: %s", text)
	}
}

type freshReviewGrantDeleteFailure struct{ store.Store }

func (s freshReviewGrantDeleteFailure) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindGrant && r.Deleted {
		return errors.New("review: grant deletion failed")
	}
	return s.Store.Put(ctx, r)
}
func TestFreshReviewRevocationDoesNotReportSuccessWhenDeletionFails(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	tokens, _ := h.login(cl, secret, nil)
	rt := tokens.str("refresh_token")
	if tokens.status != 200 || rt == "" {
		t.Fatalf("login: %d %v", tokens.status, tokens.m)
	}
	h.env.Svc.Grants.S = freshReviewGrantDeleteFailure{Store: h.env.Svc.Grants.S}
	revoked := h.post("/oauth/revoke", url.Values{"token": {rt}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
	if revoked.status == 200 {
		refreshed := h.refreshWith(cl, secret, rt)
		t.Fatalf("revocation reported 200 while storage deletion failed; refresh afterward status=%d", refreshed.status)
	}
}

// A failure to read the emergency sign-out counters is unavailable state, not proof the session ended.
func TestFreshReviewCodeExchangeDistinguishesSignOutReadFailure(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	browser, _ := h.session(h.user)
	verifier, challenge := pkce()
	code := h.getCode(browser, cl, challenge, nil)
	h.env.Svc.InvalidateSignOut()
	h.env.Svc.Orgs.S = failReads{Store: h.env.Svc.Orgs.S, kind: model.KindOrg}
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]}, "code_verifier": {verifier}}, cl, secret)
	expectUnavailable(t, "code exchange with unreadable sign-out counters", r)
}

func TestFreshReviewApprovedDeviceGrantDiesWithSessionEpoch(t *testing.T) {
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	dc, uc := h.startDevice(cl, "openid profile offline_access")
	browser, csrf := h.session(h.user)
	if status, page := h.consentDevice(browser, csrf, uc, true); status != 200 {
		t.Fatalf("approval: %d %s", status, page)
	}
	base := h.env.Svc.Store
	h.env.Svc.Store = failDeletes{Store: base, kind: model.KindSession}
	err := h.env.Svc.ResetCredentials(context.Background(), h.user.ID)
	h.env.Svc.Store = base
	if err == nil {
		t.Fatal("setup: expected session cleanup failure")
	}
	h.p.InvalidateUser(h.user.ID)
	if r := h.pollDevice(cl, dc); r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("approved device authorization outlived session epoch: %d %v", r.status, r.m)
	}
}

type reviewGateStore struct {
	ephemeral.Store
	taken  chan struct{}
	resume chan struct{}
}

// Set pauses the approval just before it records the decision: the window in which a poll must not see the
// sign-in gone.
func (s *reviewGateStore) Set(ctx context.Context, ns, id string, value []byte, ttl time.Duration) error {
	if ns == nsDevice {
		close(s.taken)
		<-s.resume
	}
	return s.Store.Set(ctx, ns, id, value, ttl)
}
func TestReviewDevicePollDuringApproval(t *testing.T) {
	ctx := context.Background()
	local := ephemeral.NewLocal("review")
	defer local.Close()
	gate := &reviewGateStore{Store: local, taken: make(chan struct{}), resume: make(chan struct{})}
	p := &Provider{s: &web.Server{Eph: gate}}
	raw, _ := json.Marshal(deviceGrant{ClientID: "client", UserCode: "BCDFGHJK", Expires: time.Now().Add(time.Minute).Unix()})
	id, _ := local.New(ctx, nsDevice, raw, time.Minute)
	_ = local.Set(ctx, nsDeviceTurn, id, []byte{1}, time.Minute)
	done := make(chan bool, 1)
	go func() {
		done <- p.decideDevice(ctx, &flow{Device: id}, true, &model.Session{AuthTime: time.Now()}, &model.User{})
	}()
	<-gate.taken
	_, oe := p.deviceToken(ctx, &model.Client{Meta: model.Meta{ID: "client"}}, id, "")
	close(gate.resume)
	if !<-done {
		t.Fatal("approval failed")
	}
	if oe == nil || oe.code != "authorization_pending" {
		t.Fatalf("live device grant returned terminal expiry during approval: %v", oe)
	}
}
