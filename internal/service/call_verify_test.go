package service_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// verifyWorld: the primary organization (the vendor) whose Support group verifies callers (sam), a customer
// organization that lets the primary organization's agents verify its users (custa: pat, kim) and one that does not
// (custb: lee).
type verifyWorld struct {
	*env
	vendor, custa, custb *model.Org
	support              *model.Group
	sam, mgr, pat, kim   *model.User
	lee, vendorPlain     *model.User
}

func newVerifyWorld(t *testing.T) *verifyWorld {
	t.Helper()
	e := newEnv(t)
	w := &verifyWorld{env: e, vendor: e.primary, custa: e.org("custa"), custb: e.org("custb")}
	w.sam = e.user(w.vendor.ID, "sam", model.RoleUser)
	w.mgr = e.user(w.vendor.ID, "mgr", model.RoleManager)
	w.vendorPlain = e.user(w.vendor.ID, "plain", model.RoleUser)
	w.pat = e.user(w.custa.ID, "pat", model.RoleUser)
	w.kim = e.user(w.custa.ID, "kim", model.RoleUser)
	w.lee = e.user(w.custb.ID, "lee", model.RoleUser)
	var err error
	if w.support, err = e.svc.CreateGroupWithMembers(e.ctx, service.System, w.vendor.ID, service.GroupInput{DisplayName: ptr("Support")},
		[]string{w.sam.ID}); err != nil {
		t.Fatal(err)
	}
	w.settings(t, w.vendor, func(s *model.OrgSettings) { s.VerifyCallers, s.VerifyAgentGroups = true, []string{w.support.ID} })
	w.settings(t, w.custa, func(s *model.OrgSettings) { s.VerifiedByPrimary = true })
	return w
}

func (w *verifyWorld) settings(t *testing.T, o *model.Org, change func(*model.OrgSettings)) error {
	t.Helper()
	cur, err := w.svc.Orgs.Get(w.ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	set := cur.Settings
	change(&set)
	_, err = w.svc.UpdateOrg(w.ctx, service.System, o.ID, service.OrgInput{Settings: &set})
	if err != nil && !strings.Contains(t.Name(), "Settings") {
		t.Fatal(err)
	}
	return err
}

// The whole of it: the agent finds the customer (in an organization that lets the vendor verify its users), starts a
// verification, and the customer, entering its code on their own account, sees who asks and confirms it is them.
func TestCallVerification(t *testing.T) {
	w := newVerifyWorld(t)
	ctx := w.ctx
	if _, _, agent := w.svc.AccountRoles(ctx, w.sam); !agent {
		t.Fatal("sam, in Support, is not an agent")
	}
	if _, _, agent := w.svc.AccountRoles(ctx, w.vendorPlain); agent {
		t.Fatal("someone outside the agent groups is an agent")
	}

	// whom sam may look for: the vendor and custa, never custb
	orgs, err := w.svc.VerifyOrgs(ctx, actor(w.sam), "", 20)
	if err != nil || len(orgs) != 2 || !orgs[0].Own || orgs[0].ID != w.vendor.ID || orgs[1].ID != w.custa.ID {
		t.Fatalf("sam's organizations: %v %+v", err, orgs)
	}
	if orgs, _ = w.svc.VerifyOrgs(ctx, actor(w.sam), "cus", 20); len(orgs) != 1 || orgs[0].ID != w.custa.ID {
		t.Fatalf("organizations starting cus: %+v", orgs)
	}
	if users, err := w.svc.VerifyUsers(ctx, actor(w.sam), w.custa.ID, "pat", 10); err != nil || len(users) != 1 || users[0].ID != w.pat.ID {
		t.Fatalf("pat in custa: %v %+v", err, users)
	}
	if users, _ := w.svc.VerifyUsers(ctx, actor(w.sam), w.custa.ID, "", 10); len(users) != 0 {
		t.Errorf("an empty search lists the organization's people: %+v", users)
	}
	if _, err := w.svc.VerifyUsers(ctx, actor(w.sam), w.custb.ID, "lee", 10); fieldOf(err) != "org" {
		t.Errorf("custb, which does not allow the vendor: %v", err)
	}
	for _, who := range []*model.User{w.vendorPlain, w.pat} {
		if _, err := w.svc.VerifyOrgs(ctx, actor(who), "", 20); !errors.Is(err, service.ErrForbidden) {
			t.Errorf("%s, not an agent, listed organizations: %v", who.Username, err)
		}
	}
	if _, _, err := w.svc.StartCallVerification(ctx, actor(w.sam), service.VerifyCallInput{Direction: model.VerifyInbound, Org: w.custb.ID, UserID: w.lee.ID}); fieldOf(err) != "org" {
		t.Errorf("started for custb: %v", err)
	}
	if _, _, err := w.svc.StartCallVerification(ctx, actor(w.sam), service.VerifyCallInput{Direction: model.VerifyInbound, Org: w.custa.ID, UserID: w.lee.ID}); fieldOf(err) != "user_id" {
		t.Errorf("started for a person of another organization than named: %v", err)
	}
	// another organization's own agents verify its own people only: never custa's, even though custa lets the primary's
	desk, err := w.svc.CreateGroupWithMembers(ctx, service.System, w.custb.ID, service.GroupInput{DisplayName: ptr("Desk")}, []string{w.lee.ID})
	if err != nil {
		t.Fatal(err)
	}
	w.settings(t, w.custb, func(s *model.OrgSettings) { s.VerifyCallers, s.VerifyAgentGroups = true, []string{desk.ID} })
	if orgs, err := w.svc.VerifyOrgs(ctx, actor(w.lee), "", 20); err != nil || len(orgs) != 1 || orgs[0].ID != w.custb.ID {
		t.Errorf("lee's organizations: %v %+v", err, orgs)
	}
	if _, err := w.svc.VerifyUsers(ctx, actor(w.lee), w.custa.ID, "pat", 10); fieldOf(err) != "org" {
		t.Errorf("an agent of another organization than the primary searched custa: %v", err)
	}

	if _, _, err := w.svc.StartCallVerification(ctx, actor(w.sam), service.VerifyCallInput{Org: "custa", UserID: w.pat.ID}); fieldOf(err) != "direction" {
		t.Errorf("started without saying who placed the call: %v", err)
	}
	// organizations are found by any of the first words of their display name too
	if _, err := w.svc.UpdateOrg(ctx, service.System, w.custa.ID, service.OrgInput{DisplayName: ptr("Contoso Retail Group")}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"custa", "Contoso", "ret", "group"} {
		if orgs, err := w.svc.VerifyOrgs(ctx, actor(w.sam), q, 20); err != nil || len(orgs) != 1 || orgs[0].ID != w.custa.ID {
			t.Errorf("organizations matching %q: %v %+v", q, err, orgs)
		}
	}

	// start: a six-digit code, shown once
	v, code, err := w.svc.StartCallVerification(ctx, actor(w.sam), service.VerifyCallInput{Direction: model.VerifyInbound, Org: "custa", UserID: w.pat.ID, Reason: "Invoice INV-7"})
	if err != nil || len(code) != 6 || v.State != model.VerifyPending || !v.Live || v.CustomerName == "" || v.VerifyPath != "/o/custa/account/verify-call" {
		t.Fatalf("started: %v %q %+v", err, code, v)
	}
	// pat sees who is verifying them now (never the code); kim, nobody
	if l, err := w.svc.WaitingCallVerifications(ctx, actor(w.pat)); err != nil || len(l) != 1 || l[0].AgentName != w.sam.FullName() || l[0].Reason != "Invoice INV-7" ||
		l[0].Direction != model.VerifyInbound {
		t.Errorf("pat's waiting verifications: %v %+v", err, l)
	}
	if l, err := w.svc.WaitingCallVerifications(ctx, actor(w.kim)); err != nil || len(l) != 0 {
		t.Errorf("kim's waiting verifications: %v %d", err, len(l))
	}
	stored, _ := w.svc.Verifications.Get(ctx, v.ID)
	if strings.Contains(stored.CodeKey, code) {
		t.Error("the code is kept as it is")
	}

	// the customer enters it: a wrong one finds nothing, nor does the right one in another account
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if _, err := w.svc.FindCallVerification(ctx, actor(w.pat), wrong); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("a wrong code: %v", err)
	}
	if _, err := w.svc.FindCallVerification(ctx, actor(w.pat), "12ab"); fieldOf(err) != "code" {
		t.Errorf("not six digits: %v", err)
	}
	if _, err := w.svc.FindCallVerification(ctx, actor(w.kim), code); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("the code in kim's account: %v", err)
	}
	found, err := w.svc.FindCallVerification(ctx, actor(w.pat), code[:3]+" "+code[3:])
	if err != nil || found.ID != v.ID || found.AgentName != w.sam.FullName() || found.AgentOrgName != w.vendor.DisplayName || found.Reason != "Invoice INV-7" {
		t.Fatalf("pat's code: %v %+v", err, found)
	}
	// only pat answers it
	if _, err := w.svc.AnswerCallVerification(ctx, actor(w.kim), v.ID, true, true); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("kim answered pat's: %v", err)
	}
	ans, err := w.svc.AnswerCallVerification(ctx, actor(w.pat), v.ID, true, true)
	if err != nil || ans.State != model.VerifyConfirmed || !ans.SecondFactor {
		t.Fatalf("confirmed: %v %+v", err, ans)
	}
	if _, err := w.svc.AnswerCallVerification(ctx, actor(w.pat), v.ID, false, false); fieldOf(err) != "state" {
		t.Errorf("answered twice: %v", err)
	}
	if _, err := w.svc.FindCallVerification(ctx, actor(w.pat), code); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("the code works after it was answered: %v", err)
	}
	if l, _ := w.svc.WaitingCallVerifications(ctx, actor(w.pat)); len(l) != 0 {
		t.Errorf("an answered verification is still waiting: %d", len(l))
	}

	// the agent sees it: theirs only
	if got, err := w.svc.AgentVerification(ctx, actor(w.sam), v.ID); err != nil || got.State != model.VerifyConfirmed || !got.SecondFactor {
		t.Errorf("sam's view: %v %+v", err, got)
	}
	if _, err := w.svc.AgentVerification(ctx, actor(w.vendorPlain), v.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("another person read sam's verification: %v", err)
	}
	if l, err := w.svc.AgentVerifications(ctx, actor(w.sam)); err != nil || len(l) != 1 || l[0].ID != v.ID {
		t.Errorf("sam's day: %v %d", err, len(l))
	}
	if l, n, err := w.svc.CustomerVerifications(ctx, actor(w.pat), store.ListQuery{}); err != nil || n != 1 || l[0].AgentName != w.sam.FullName() {
		t.Errorf("pat's verifications: %v %d", err, n)
	}

	// another: the customer says it is not them; and one the agent stops
	v2, code2, _ := w.svc.StartCallVerification(ctx, actor(w.sam), service.VerifyCallInput{Direction: model.VerifyInbound, UserID: w.vendorPlain.ID})
	if v2 == nil || v2.OrgID != w.vendor.ID {
		t.Fatalf("one of the agent's own organization: %+v", v2)
	}
	if _, err := w.svc.FindCallVerification(ctx, actor(w.vendorPlain), code2); err != nil {
		t.Fatal(err)
	}
	if ans, err := w.svc.AnswerCallVerification(ctx, actor(w.vendorPlain), v2.ID, false, true); err != nil || ans.State != model.VerifyDenied {
		t.Errorf("denied: %v %+v", err, ans)
	}
	v3, _, _ := w.svc.StartCallVerification(ctx, actor(w.sam), service.VerifyCallInput{Direction: model.VerifyInbound, Org: w.custa.ID, UserID: w.kim.ID})
	if _, err := w.svc.CancelCallVerification(ctx, actor(w.vendorPlain), v3.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("someone else cancelled it: %v", err)
	}
	if got, err := w.svc.CancelCallVerification(ctx, actor(w.sam), v3.ID); err != nil || got.State != model.VerifyCancelled {
		t.Errorf("cancelled: %v %+v", err, got)
	}

	// never: yourself, a guest, a personal API token
	if _, _, err := w.svc.StartCallVerification(ctx, actor(w.sam), service.VerifyCallInput{Direction: model.VerifyInbound, UserID: w.sam.ID}); fieldOf(err) != "user_id" {
		t.Errorf("verified themselves: %v", err)
	}
	guest := actor(w.sam)
	guest.Sources = []model.GuestSource{{UserID: "elsewhere"}}
	token := actor(w.pat)
	token.TokenID = "tok"
	if _, err := w.svc.VerifyOrgs(ctx, guest, "", 10); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("a guest session listed: %v", err)
	}
	if _, err := w.svc.FindCallVerification(ctx, token, "123456"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("a personal API token entered a code: %v", err)
	}
}

// A code runs out after model.VerifyCodeFor, and housekeeping marks it expired, then removes it once kept long enough.
func TestCallVerificationRunsOut(t *testing.T) {
	w := newVerifyWorld(t)
	ctx := w.ctx
	v, code, err := w.svc.StartCallVerification(ctx, actor(w.sam), service.VerifyCallInput{Direction: model.VerifyInbound, Org: w.custa.ID, UserID: w.pat.ID})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := w.svc.Verifications.Get(ctx, v.ID)
	rec.Expires = time.Now().Add(-time.Second).UTC()
	if err := w.svc.Verifications.Update(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.FindCallVerification(ctx, actor(w.pat), code); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("a code that ran out: %v", err)
	}
	if got, _ := w.svc.AgentVerification(ctx, actor(w.sam), v.ID); got.State != model.VerifyExpired || got.Live {
		t.Errorf("the agent's view of one that ran out: %+v", got)
	}
	if n, err := w.svc.ExpireCallVerifications(ctx); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	rec, _ = w.svc.Verifications.Get(ctx, v.ID)
	if rec.State != model.VerifyExpired {
		t.Fatalf("after housekeeping: %+v", rec)
	}
	rec.DecidedAt = time.Now().Add(-model.VerifyKeptFor - time.Hour).UTC()
	if err := w.svc.Verifications.Update(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if n, err := w.svc.ExpireCallVerifications(ctx); err != nil || n != 1 {
		t.Fatalf("removal: %d %v", n, err)
	}
	if _, err := w.svc.Verifications.Get(ctx, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an old verification is still kept: %v", err)
	}
}

// The settings: agent groups of the organization (at least one while it verifies callers), other existing
// organizations allowed to verify its users; agent groups are protected; turning it off takes the agents' role away.
func TestCallVerificationSettings(t *testing.T) {
	w := newVerifyWorld(t)
	ctx := w.ctx
	for name, c := range map[string]struct {
		org   *model.Org
		set   func(*model.OrgSettings)
		field string
	}{
		"no agent groups":     {w.custb, func(s *model.OrgSettings) { s.VerifyCallers = true }, "verify_agent_groups"},
		"another org's group": {w.custb, func(s *model.OrgSettings) { s.VerifyCallers, s.VerifyAgentGroups = true, []string{w.support.ID} }, "verify_agent_groups"},
		"the primary itself":  {w.vendor, func(s *model.OrgSettings) { s.VerifiedByPrimary = true }, "verified_by_primary"},
	} {
		if err := w.settings(t, c.org, c.set); fieldOf(err) != c.field {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a manager adds plain users to groups, but not to an agent group
	if err := w.svc.SetMembership(ctx, actor(w.mgr), w.support.ID, w.vendorPlain.ID, true); fieldOf(err) != "members" {
		t.Errorf("a manager added someone to the agent group: %v", err)
	}
	// off: sam is no agent any more (at once: the change drops what the menu keeps)
	w.settings(t, w.vendor, func(s *model.OrgSettings) { s.VerifyCallers = false })
	if _, _, agent := w.svc.AccountRoles(ctx, w.sam); agent {
		t.Error("sam is still an agent with caller verification off")
	}
	if _, _, err := w.svc.StartCallVerification(ctx, actor(w.sam), service.VerifyCallInput{Direction: model.VerifyInbound, Org: w.custa.ID, UserID: w.pat.ID}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("started with caller verification off: %v", err)
	}
	if err := w.svc.SetMembership(ctx, actor(w.mgr), w.support.ID, w.vendorPlain.ID, true); err != nil {
		t.Errorf("an ordinary group again: %v", err)
	}
}
