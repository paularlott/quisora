package upstream_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/upstream"
)

// signedInThrough signs a user in with p and gives them a live session signed in through it.
func (e *env) signedInThrough(t *testing.T, p *model.Provider, sub, email string) (*upstream.Result, *model.Session) {
	t.Helper()
	res, err := e.signIn(p, std(sub, email))
	if err != nil {
		t.Fatal(err)
	}
	s := &model.Session{UserID: res.User.ID, OrgID: e.org.ID, Provider: p.ID, AuthTime: time.Now(), LastSeen: time.Now(),
		Expires: time.Now().Add(24 * time.Hour)}
	if err := e.svc.Sessions.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	return res, s
}

func (e *env) refreshCalls() int {
	e.oidc.Mu.Lock()
	defer e.oidc.Mu.Unlock()
	return e.oidc.RefreshCalls
}

func TestCheckSessionsLifecycle(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh, e.oidc.RotateRefresh = true, true
	p := e.oidcProvider(t, nil)
	_, sess := e.signedInThrough(t, p, "lee", "lee@corp.example")
	ident, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "lee"))
	if err != nil || ident.Refresh == "" || len(ident.Scopes) == 0 {
		t.Fatalf("refresh token not kept: %+v %v", ident, err)
	}

	// Not due yet: checked just now.
	if r, err := e.up.CheckSessions(e.ctx, time.Hour, time.Minute); err != nil || r.Checked != 0 {
		t.Fatalf("within interval: %+v %v", r, err)
	}
	e.advance(2 * time.Hour)
	// Due, accepted and rotated.
	before := e.oidc.LiveRefresh()
	if r, err := e.up.CheckSessions(e.ctx, time.Hour, time.Minute); err != nil || r.Checked != 1 || r.Ended != 0 || r.Failed != 0 {
		t.Fatalf("due check: %+v %v", r, err)
	}
	if after := e.oidc.LiveRefresh(); len(after) != 1 || after[0] == before[0] {
		t.Fatalf("rotation: %v -> %v", before, after)
	}
	// The check was recorded, so it is not due again.
	if r, _ := e.up.CheckSessions(e.ctx, time.Hour, time.Minute); r.Checked != 0 {
		t.Fatalf("checked twice: %+v", r)
	}

	// A provider that fails is left alone, and its sessions stay.
	e.advance(2 * time.Hour)
	e.oidc.Mu.Lock()
	e.oidc.RefreshFail = 503
	e.oidc.Mu.Unlock()
	if r, err := e.up.CheckSessions(e.ctx, time.Hour, time.Minute); err != nil || r.Failed != 1 || r.Ended != 0 {
		t.Fatalf("failure: %+v %v", r, err)
	}
	if _, err := e.svc.Sessions.Get(e.ctx, sess.ID); err != nil {
		t.Fatal("a transient failure ended the session")
	}
	e.oidc.Mu.Lock()
	e.oidc.RefreshFail = 0
	e.oidc.Mu.Unlock()

	// Refused with invalid_grant: sessions end, the token is forgotten, an audit record says why.
	e.oidc.RevokeRefresh()
	if r, err := e.up.CheckSessions(e.ctx, time.Hour, time.Minute); err != nil || r.Ended != 1 {
		t.Fatalf("leaver: %+v %v", r, err)
	}
	if _, err := e.svc.Sessions.Get(e.ctx, sess.ID); err == nil {
		t.Fatal("the leaver's session survived")
	}
	if id, _ := e.svc.Identities.Get(e.ctx, ident.ID); id == nil || id.Refresh != "" || id.Scopes != nil {
		t.Fatalf("refused token kept: %+v", id)
	}
	if !e.audited(t, "identity.refresh.refused") {
		t.Fatal("refusal not audited")
	}
	// Nothing left to check.
	calls := e.refreshCalls()
	if r, _ := e.up.CheckSessions(e.ctx, 0, time.Minute); r.Checked != 0 || e.refreshCalls() != calls {
		t.Fatalf("replayed without a token: %+v", r)
	}
}

// Only users with a live session through the provider are checked.
func TestCheckSessionsNeedsLiveProviderSession(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh = true
	p := e.oidcProvider(t, nil)
	res, err := e.signIn(p, std("pat", "pat@corp.example"))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(provider string, expires time.Duration) {
		s := &model.Session{UserID: res.User.ID, OrgID: e.org.ID, Provider: provider, AuthTime: time.Now(), LastSeen: time.Now(),
			Expires: time.Now().Add(expires)}
		if err := e.svc.Sessions.Create(e.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	// No session at all, an expired one, and a live one not signed in through the provider: nothing is replayed.
	if r, err := e.up.CheckSessions(e.ctx, 0, time.Minute); err != nil || r.Checked != 0 {
		t.Fatalf("no session: %+v %v", r, err)
	}
	mk(p.ID, -time.Minute)
	mk("", time.Hour)
	if r, _ := e.up.CheckSessions(e.ctx, 0, time.Minute); r.Checked != 0 || e.refreshCalls() != 0 {
		t.Fatalf("checked without a live provider session: %+v", r)
	}
	// A live session through the provider: checked and accepted; no rotation, so the token stays valid.
	mk(p.ID, time.Hour)
	if r, _ := e.up.CheckSessions(e.ctx, 0, time.Minute); r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("live session: %+v", r)
	}
	if len(e.oidc.LiveRefresh()) != 1 {
		t.Fatal("token lost")
	}
}

// A provider that is off, or a canceled run, is not replayed against.
func TestCheckSessionsProviderOffAndCancel(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh = true
	p := e.oidcProvider(t, nil)
	e.signedInThrough(t, p, "sam", "sam@corp.example")

	if _, err := e.svc.UpdateProvider(e.ctx, service.System, p.ID, service.ProviderInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if r, err := e.up.CheckSessions(e.ctx, 0, time.Minute); err != nil || r.Checked != 0 {
		t.Fatalf("disabled provider replayed: %+v %v", r, err)
	}
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()
	if _, err := e.up.CheckSessions(ctx, 0, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run: %v", err)
	}
}

func TestCheckSessionsBasicAuthProvider(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh, e.oidc.BasicOnly = true, true
	p := e.oidcProvider(t, nil)
	e.signedInThrough(t, p, "bas", "bas@corp.example")
	e.oidc.Mu.Lock()
	e.oidc.GotBasic = false
	e.oidc.Mu.Unlock()
	if r, err := e.up.CheckSessions(e.ctx, 0, time.Minute); err != nil || r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if !e.oidc.GotBasic {
		t.Fatal("refresh did not use client_secret_basic")
	}
}

// Other providers' identities wait for the next run once one provider failed in this one.
func TestCheckSessionsUnreachableProvider(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh = true
	p := e.oidcProvider(t, nil)
	e.signedInThrough(t, p, "a1", "a1@corp.example")
	e.signedInThrough(t, p, "a2", "a2@corp.example")
	e.oidc.Mu.Lock()
	e.oidc.RefreshFail = 500
	e.oidc.Mu.Unlock()
	r, err := e.up.CheckSessions(e.ctx, 0, time.Minute)
	if err != nil || r.Failed != 1 || r.Checked != 1 || e.refreshCalls() != 1 {
		t.Fatalf("one failure must park the provider: %+v %v calls=%d", r, err, e.refreshCalls())
	}
}

// A run is a slice of the work: with a slow provider and many due identities it stops at its time budget, and the next
// run resumes after the identity the last one reached, so every identity is replayed once before any is replayed again.
func TestCheckSessionsBudgetAndResume(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh = true
	p := e.oidcProvider(t, nil)
	const n = 6
	for i := range n {
		e.signedInThrough(t, p, fmt.Sprintf("sub%d", i), fmt.Sprintf("u%d@corp.example", i))
	}
	e.oidc.Mu.Lock()
	e.oidc.RefreshDelay = 100 * time.Millisecond
	e.oidc.Mu.Unlock()

	budget := 150 * time.Millisecond // two replays fit (the budget is looked at before each one)
	runs := 0
	for {
		runs++
		started := time.Now()
		r, err := e.up.CheckSessions(e.ctx, 0, budget)
		if err != nil || r.Checked == 0 || r.Checked > 3 {
			t.Fatalf("run %d: %+v %v", runs, r, err)
		}
		if took := time.Since(started); took > 2*time.Second {
			t.Fatalf("run %d took %v against a budget of %v", runs, took, budget)
		}
		if !r.Unfinished {
			break
		}
		if r.Reached == "" {
			t.Fatalf("run %d stopped without saying how far it got: %+v", runs, r)
		}
		if runs > 2*n {
			t.Fatal("the runs never reach the end")
		}
	}
	if runs < 2 || e.refreshCalls() != n {
		t.Fatalf("one pass over %d identities in %d runs replayed %d tokens (want each exactly once)", n, runs, e.refreshCalls())
	}
	// The pass wrapped: the next run starts again from the first identity.
	e.oidc.Mu.Lock()
	e.oidc.RefreshDelay = 0
	e.oidc.Mu.Unlock()
	if r, err := e.up.CheckSessions(e.ctx, 0, time.Minute); err != nil || r.Checked != n || r.Unfinished {
		t.Fatalf("second pass: %+v %v", r, err)
	}
}

// A run stops replaying as soon as the node no longer leads (Tenure refuses), without an error, and the identity it
// had not replayed is the first of the next run.
func TestCheckSessionsStopsWhenTenureIsLost(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh = true
	p := e.oidcProvider(t, nil)
	const n = 4
	for i := range n {
		e.signedInThrough(t, p, fmt.Sprintf("sub%d", i), fmt.Sprintf("u%d@corp.example", i))
	}
	var asked int
	e.up.Tenure = func(context.Context) error { // lost after the first replay
		asked++
		if asked > 1 {
			return errors.New("housekeeping has passed to another node")
		}
		return nil
	}
	if r, err := e.up.CheckSessions(e.ctx, 0, time.Minute); err != nil || r.Checked != 1 || e.refreshCalls() != 1 {
		t.Fatalf("a deposed run replayed after losing the tenure: %+v %v calls=%d", r, err, e.refreshCalls())
	}
	e.up.Tenure = func(context.Context) error { return nil }
	if r, err := e.up.CheckSessions(e.ctx, 0, time.Minute); err != nil || r.Checked != n-1 || e.refreshCalls() != n {
		t.Fatalf("the next run: %+v %v calls=%d (want the other %d, none twice)", r, err, e.refreshCalls(), n-1)
	}
}

// deposedWrites refuses every identity write made under the fence, as a node's store does once housekeeping has
// passed to another node; a write whose context carries unfenced (the hook the cluster's Unfenced stands for) goes on.
type deposedWrites struct{ store.Store }

type unfenced struct{}

func (d deposedWrites) refuse(ctx context.Context, rec *store.Record) error {
	if rec.Kind == model.KindIdentity && ctx.Value(unfenced{}) == nil {
		return fmt.Errorf("%w: housekeeping has passed to another node", store.ErrUnavailable)
	}
	return nil
}

func (d deposedWrites) Put(ctx context.Context, rec *store.Record) error {
	if err := d.refuse(ctx, rec); err != nil {
		return err
	}
	return d.Store.Put(ctx, rec)
}

func (d deposedWrites) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if err := d.refuse(ctx, rec); err != nil {
		return err
	}
	return d.Store.CompareAndPut(ctx, rec, expect)
}

// The refresh token a provider rotates during a replay is kept even when the tenure passes to another node during that
// replay: keeping it is a compare-and-swap any node may make. Lost, the next check would replay the retired token, the
// provider would refuse it, and a user who never left would be signed out.
func TestRotatedTokenIsKeptWhenTenureIsLostMidReplay(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh, e.oidc.RotateRefresh = true, true
	p := e.oidcProvider(t, nil)
	e.signedInThrough(t, p, "lee", "lee@corp.example")
	e.advance(2 * time.Hour)

	good := e.svc.Identities.S
	e.svc.Identities.S = deposedWrites{good} // the tenure is gone by the time the replay's answer is saved
	e.up.Unfenced = func(ctx context.Context) context.Context { return context.WithValue(ctx, unfenced{}, true) }
	if r, err := e.up.CheckSessions(e.ctx, time.Hour, time.Minute); err != nil || r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("the check: %+v %v", r, err)
	}
	e.svc.Identities.S = good

	// The next check (any node) replays the token the provider rotated to: accepted, nobody signed out.
	e.advance(2 * time.Hour)
	if r, err := e.up.CheckSessions(e.ctx, time.Hour, time.Minute); err != nil || r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("the rotated token was not kept: %+v %v", r, err)
	}
}

// The scopes a refresh token was granted with are kept beside it: those the provider's token response names, else
// (RFC 6749 §5.1) those asked for; sorted. No refresh token, no scopes.
func TestGrantedScopesAreKeptWithTheRefreshToken(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh = true
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.Scopes = &[]string{"email", "offline_access", "profile"} })
	scopesOf := func(sub string) []string {
		t.Helper()
		id, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, sub))
		if err != nil {
			t.Fatal(err)
		}
		return id.Scopes
	}

	// Named by the token response: as granted, which may be less than asked for.
	e.oidc.Mu.Lock()
	e.oidc.GrantScope = "profile openid email profile"
	e.oidc.Mu.Unlock()
	e.signedInThrough(t, p, "named", "named@corp.example")
	if got := scopesOf("named"); !slices.Equal(got, []string{"email", "openid", "profile"}) {
		t.Fatalf("named scopes: %v", got)
	}

	// Not named: those asked for, with openid.
	e.oidc.Mu.Lock()
	e.oidc.GrantScope = ""
	e.oidc.Mu.Unlock()
	e.signedInThrough(t, p, "asked", "asked@corp.example")
	if got := scopesOf("asked"); !slices.Equal(got, []string{"email", "offline_access", "openid", "profile"}) {
		t.Fatalf("requested scopes: %v", got)
	}

	// No refresh token: nothing kept.
	e.oidc.Mu.Lock()
	e.oidc.IssueRefresh, e.oidc.GrantScope = false, "openid email"
	e.oidc.Mu.Unlock()
	e.signedInThrough(t, p, "none", "none@corp.example")
	if got := scopesOf("none"); got != nil {
		t.Fatalf("scopes without a refresh token: %v", got)
	}
}

// Google gives a refresh token only for offline access, which it is asked for with access_type=offline; other
// providers are not sent it.
func TestGoogleIsAskedForOfflineAccess(t *testing.T) {
	e := setup(t)
	e.oidc.IssueRefresh = true
	g, err := e.svc.CreateProvider(e.ctx, service.System, e.org.ID, service.ProviderInput{Type: ptr(model.ProviderGoogle),
		Name: ptr("Google"), ClientID: ptr("cid"), ClientSecret: ptr("s3cret"), AutoProvision: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	g.Issuer = e.oidc.Srv.URL // Google's issuer is fixed: the fake plays it
	if err := e.svc.Providers.Update(e.ctx, g); err != nil {
		t.Fatal(err)
	}
	offline := func(p *model.Provider) string {
		t.Helper()
		authURL, _, err := e.up.BeginTenant(e.ctx, e.org, p, "/next", "")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(authURL)
		return u.Query().Get("access_type")
	}
	if got := offline(g); got != "offline" {
		t.Fatalf("Google access_type %q", got)
	}
	if got := offline(e.oidcProvider(t, nil)); got != "" {
		t.Fatalf("OpenID Connect provider access_type %q", got)
	}

	// The refresh token it gives is kept, for the leaver checks.
	e.signedInThrough(t, g, "goo", "goo@corp.example")
	if id, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(g.ID, "goo")); err != nil || id.Refresh == "" {
		t.Fatalf("Google refresh token not kept: %+v %v", id, err)
	}
}
