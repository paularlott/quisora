package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func TestInviteSingleUseExpiryAndRevocation(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "newbie", model.RoleUser)

	first, exp, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 6*24*time.Hour+23*time.Hour || d > service.InviteTTL {
		t.Fatalf("invitation lifetime %v", d)
	}
	if !strings.Contains(first, "/invite?token=") {
		t.Fatalf("link %s", first)
	}
	tok := tokenFrom(first)
	// The link is hashed at rest: the token itself is nowhere in the store.
	if links, _, _ := e.svc.Links.List(e.ctx, store.ListQuery{}); len(links) == 0 {
		t.Fatal("no stored link")
	} else {
		for _, l := range links {
			if strings.Contains(l.ID, tok) {
				t.Fatal("link token stored in the clear")
			}
		}
	}
	// Wrong purpose never redeems.
	if _, _, err := e.svc.UseSignInLink(e.ctx, tok, service.LinkReset, "a fresh long passphrase", 0); !errors.Is(err, service.ErrLink) {
		t.Fatalf("wrong purpose: %v", err)
	}
	// A newer invitation revokes the older one.
	second, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tok, service.LinkInvite); !errors.Is(err, service.ErrLink) {
		t.Fatalf("older invitation survived: %v", err)
	}
	// Single use.
	tok2 := tokenFrom(second)
	if _, got, err := e.svc.UseSignInLink(e.ctx, tok2, service.LinkInvite, "", service.NewCredEpoch()); err != nil || got.ID != u.ID {
		t.Fatalf("redeem: %v", err)
	}
	if _, _, err := e.svc.UseSignInLink(e.ctx, tok2, service.LinkInvite, "", service.NewCredEpoch()); !errors.Is(err, service.ErrLink) {
		t.Fatalf("second redeem: %v", err)
	}
	// Expiry.
	old, _, err := e.svc.IssueLink(e.ctx, u, service.LinkInvite, "", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, old, service.LinkInvite); !errors.Is(err, service.ErrLink) {
		t.Fatalf("expired link: %v", err)
	}
	// Garbage and oversize tokens.
	for _, bad := range []string{"", "nope", strings.Repeat("x", 500)} {
		if _, _, err := e.svc.PeekLink(e.ctx, bad, service.LinkInvite); !errors.Is(err, service.ErrLink) {
			t.Fatalf("token %q: %v", bad, err)
		}
	}
	// Disabled accounts cannot be invited, and an invitation stops working when the account is disabled.
	live, _, _ := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	off := false
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(live), service.LinkInvite); !errors.Is(err, service.ErrLink) {
		t.Fatalf("invitation of a disabled user: %v", err)
	}
	if _, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID); err == nil {
		t.Fatal("invited a disabled user")
	}
}

// Links are durable records: a new Service over the same store (a restart, or another node) honours them.
func TestInviteLinksSurviveRestart(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 2
	key := secure.RandomBytes(32)
	sealer, _ := secure.NewSealer(key)
	st := memstore.New()
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(cfg, st, sealer)
	ctx := t.Context()
	admin, link, err := svc.Bootstrap(ctx, "root@example.com")
	if err != nil || admin == nil || link == "" {
		t.Fatalf("bootstrap: %v %q", err, link)
	}
	reset, _, err := svc.IssueLink(ctx, admin, service.LinkReset, admin.Email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	sealer2, _ := secure.NewSealer(key)
	svc2 := service.New(cfg, st, sealer2) // "restart"
	if _, u, err := svc2.PeekLink(ctx, tokenFrom(link), service.LinkInvite); err != nil || u.ID != admin.ID {
		t.Fatalf("invitation lost across restart: %v", err)
	}
	if _, _, err := svc2.UseSignInLink(ctx, reset, service.LinkReset, "a fresh long passphrase", 0); err != nil {
		t.Fatalf("reset link lost across restart: %v", err)
	}
	if _, _, err := svc.UseSignInLink(ctx, reset, service.LinkReset, "a fresh long passphrase", 0); !errors.Is(err, service.ErrLink) {
		t.Fatal("link redeemed on two services")
	}
	// A second bootstrap creates nothing.
	if u, l, err := svc2.Bootstrap(ctx, "other@example.com"); err != nil || u != nil || l != "" {
		t.Fatalf("second bootstrap: %v %v %q", u, l, err)
	}
}

// Two sign-in links for one user can both be live: two invitations issued at once (each revoking only what it saw),
// or an invitation and a reset link. Using one revokes the rest, so none can reset the account its owner just set up.
// An account has one invitation link: a new one replaces the record, so the earlier token finds nothing. Using an
// invitation uses up every invitation and reset link of the account (their generation has passed); an email
// verification link is not a sign-in link and stays.
func TestOneSignInLinkPerAccount(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "racer", model.RoleUser)

	first, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	links, _, err := e.svc.Links.List(e.ctx, store.ListQuery{Scope: u.ID})
	if err != nil || len(links) != 1 {
		t.Fatalf("links %d: %v", len(links), err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(first), service.LinkInvite); !errors.Is(err, service.ErrLink) {
		t.Fatalf("the replaced invitation still works: %v", err)
	}
	reset, _, err := e.svc.IssueLink(e.ctx, u, service.LinkReset, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verify, _, err := e.svc.IssueLink(e.ctx, u, service.LinkVerify, "racer@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.svc.UseSignInLink(e.ctx, tokenFrom(second), service.LinkInvite, "", service.NewCredEpoch()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(second), service.LinkInvite); !errors.Is(err, service.ErrLink) {
		t.Fatalf("the invitation works after its use: %v", err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, reset, service.LinkReset); !errors.Is(err, service.ErrLink) {
		t.Fatalf("the reset link survived the invitation's use: %v", err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, verify, service.LinkVerify); err != nil {
		t.Fatal(err)
	}
}

// Until its commit an invitation can be tried again: a failed commit (a password the policy refuses) changes nothing
// and uses nothing up.
func TestInviteRecoverableUntilCommit(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "retry", model.RoleUser)
	link, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenFrom(link)
	if _, _, err := e.svc.UseSignInLink(e.ctx, tok, service.LinkInvite, "short", service.NewCredEpoch()); err == nil {
		t.Fatal("a refused password was accepted")
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tok, service.LinkInvite); err != nil {
		t.Fatalf("a failure before the commit used the link up: %v", err)
	}
	_, got, err := e.svc.UseSignInLink(e.ctx, tok, service.LinkInvite, "a fresh long passphrase", service.NewCredEpoch())
	if err != nil || got.PasswordHash == "" || got.SecurityGen == u.SecurityGen {
		t.Fatalf("commit: %v", err)
	}
	if _, _, err := e.svc.UseSignInLink(e.ctx, tok, service.LinkInvite, "another long passphrase", service.NewCredEpoch()); !errors.Is(err, service.ErrLink) {
		t.Fatalf("used twice: %v", err)
	}
}

// An invitation is checked again when used, against its issuer as they are now: one an administrator issued for a
// plain user does not open the account once it is promoted beyond them, one a super admin issued does not outlive
// their demotion or their account, and a refused link is gone. The flows the issue-time rules allow still work.
func TestInviteRecheckedAgainstIssuer(t *testing.T) {
	e := newEnv(t)
	p := e.primary.ID
	admin := e.user(p, "inv-admin", model.RoleAdmin)
	setRole := func(u *model.User, r model.Role) {
		t.Helper()
		if _, err := e.svc.UpdateUser(e.ctx, actor(e.super), u.ID, service.UserInput{Role: &r}); err != nil {
			t.Fatalf("role %s for %s: %v", r, u.Username, err)
		}
	}
	invite := func(by *model.User, u *model.User) string {
		t.Helper()
		link, _, err := e.svc.CreateInvite(e.ctx, actor(by), u.ID)
		if err != nil {
			t.Fatalf("%s invites %s: %v", by.Username, u.Username, err)
		}
		return tokenFrom(link)
	}
	refused := func(name, tok string, u *model.User) {
		t.Helper()
		if _, _, err := e.svc.PeekLink(e.ctx, tok, service.LinkInvite); !errors.Is(err, service.ErrLink) {
			t.Errorf("%s: page shown: %v", name, err)
		}
		if _, _, err := e.svc.UseSignInLink(e.ctx, tok, service.LinkInvite, "", service.NewCredEpoch()); !errors.Is(err, service.ErrLink) {
			t.Errorf("%s: redeemed: %v", name, err)
		}
		if links, _, _ := e.svc.Links.List(e.ctx, store.ListQuery{Scope: u.ID}); len(links) > 0 {
			t.Errorf("%s: a refused invitation is kept", name)
		}
	}
	redeems := func(name, tok string) {
		t.Helper()
		if _, _, err := e.svc.UseSignInLink(e.ctx, tok, service.LinkInvite, "", service.NewCredEpoch()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// promoted beyond the issuer after the invitation: refused
	target := e.user(p, "inv-target", model.RoleUser)
	tok := invite(admin, target)
	setRole(target, model.RoleSuperAdmin)
	refused("admin's invitation after promotion to super admin", tok, target)

	// the issuer demoted after issuing: refused
	super2 := e.user(p, "inv-super", model.RoleSuperAdmin)
	mgr := e.user(p, "inv-mgr", model.RoleManager)
	tok = invite(super2, mgr)
	setRole(super2, model.RoleUser)
	refused("invitation of a demoted super admin", tok, mgr)

	// the issuer disabled after issuing: refused
	plain := e.user(p, "inv-plain", model.RoleUser)
	tok = invite(admin, plain)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, admin.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	refused("invitation of a disabled administrator", tok, plain)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, admin.ID, service.UserInput{Active: ptr(true)}); err != nil {
		t.Fatal(err)
	}

	// still allowed: an administrator invites a plain user, or a brand-new manager (the first invitation)
	redeems("admin invites a plain user", invite(admin, e.user(p, "inv-u2", model.RoleUser)))
	redeems("admin invites a brand-new manager", invite(admin, e.user(p, "inv-mgr2", model.RoleManager)))
	// promoted to the issuer's own rank before it was ever set up: the administrator could invite a new one anyway
	u3 := e.user(p, "inv-u3", model.RoleUser)
	tok = invite(admin, u3)
	setRole(u3, model.RoleAdmin)
	redeems("admin's invitation for an account promoted to admin, never set up", tok)
	// a super admin invites an established manager
	est := e.user(p, "inv-est", model.RoleManager)
	est.PasswordHash = "x"
	if err := e.svc.Users.Update(e.ctx, est); err != nil {
		t.Fatal(err)
	}
	redeems("super admin invites an established manager", invite(e.super, est))
	// no issuer (bootstrap, the mailer): unchanged
	link, _, err := e.svc.CreateInvite(e.ctx, service.System, e.user(p, "inv-sys", model.RoleManager).ID)
	if err != nil {
		t.Fatal(err)
	}
	redeems("system invitation", tokenFrom(link))
}

// Cleanup belongs to the invitation it follows. Redeeming an invitation tidies the sessions of the account after the
// commit; when that is slow, a later invitation may be issued, and even accepted, meanwhile, and the old cleanup must
// leave it alone.
func TestEarlierInviteCleanupLeavesALaterInvitation(t *testing.T) {
	// pausedRedemption redeems the account's invitation and pauses it at the post-commit session cleanup.
	pausedRedemption := func(t *testing.T) (*env, *model.User, *gate, <-chan error) {
		e := newEnv(t)
		u := e.user(e.primary.ID, "cleanup-generation", model.RoleUser)
		first, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		gt := newGate(t)
		e.svc.Store = &faultStore{Store: e.svc.Store, beforeList: func(kind model.Kind, q store.ListQuery) error {
			if kind == model.KindSession && q.Scope == u.ID {
				gt.stall()
			}
			return nil
		}}
		done := make(chan error, 1)
		go func() {
			_, _, err := e.svc.UseSignInLink(e.ctx, tokenFrom(first), service.LinkInvite, "", service.NewCredEpoch())
			done <- err
		}()
		gt.waitEntered(t, "the redemption's session cleanup")
		return e, u, gt, done
	}

	t.Run("later_invite_still_valid", func(t *testing.T) {
		e, u, gt, done := pausedRedemption(t)
		later, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(later), service.LinkInvite); err != nil {
			t.Fatalf("new link invalid before the cleanup: %v", err)
		}
		gt.release()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(later), service.LinkInvite); err != nil {
			t.Fatalf("the old redemption's cleanup deleted a valid invitation issued for the next security generation: %v", err)
		}
	})

	t.Run("later_acceptance_keeps_its_credentials", func(t *testing.T) {
		e, u, gt, done := pausedRedemption(t)
		later, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		epoch := service.NewCredEpoch()
		pk := &model.Passkey{Meta: model.Meta{ID: model.NewID()}, UserID: u.ID, OrgID: u.OrgID, Epoch: epoch, Name: "second acceptance", CredentialID: []byte("later-credential")}
		if err := e.svc.Passkeys.Create(e.ctx, pk); err != nil {
			t.Fatal(err)
		}
		_, current, err := e.svc.UseSignInLink(e.ctx, tokenFrom(later), service.LinkInvite, "", epoch)
		if err != nil {
			t.Fatal(err)
		}
		if !current.Holds(epoch) {
			t.Fatal("the second acceptance did not commit its epoch")
		}
		if _, err := e.svc.Passkeys.Get(e.ctx, pk.ID); err != nil {
			t.Fatalf("credential absent before the old cleanup: %v", err)
		}
		gt.release()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Passkeys.Get(e.ctx, pk.ID); err != nil {
			t.Fatalf("the cleanup after the earlier invitation removed the current epoch's credential: %v", err)
		}
	})
}

// An admin may not replace a privileged user's invitation. When the admin's issue loses a race to another issuer, the
// authority to replace the invitation that won is checked again.
func TestInviteReplacementIsRecheckedAfterAnIssueConflict(t *testing.T) {
	e := newEnv(t)
	admin := e.user(e.primary.ID, "invite-admin", model.RoleAdmin)
	u := e.user(e.primary.ID, "new-manager", model.RoleManager)
	linkID := service.LinkInvite + ":" + u.ID
	gt := newGate(t)
	e.svc.Links.S = &faultStore{Store: e.svc.Store, beforeCAS: func(r *store.Record, expect hlc.Timestamp) error {
		if r.Kind == model.KindLink && r.ID == linkID && expect == 0 {
			gt.stall()
		}
		return nil
	}}
	done := make(chan error, 1)
	go func() { _, _, err := e.svc.CreateInvite(e.ctx, actor(admin), u.ID); done <- err }()
	gt.waitEntered(t, "the admin's first write of the invitation") // the admin passed the replacement check while no invitation existed
	superLink, _, err := e.svc.CreateInvite(e.ctx, actor(e.super), u.ID)
	gt.release()
	adminErr := <-done
	if err != nil {
		t.Fatal(err)
	}
	if adminErr == nil {
		_, _, peekErr := e.svc.PeekLink(e.ctx, tokenFrom(superLink), service.LinkInvite)
		t.Fatalf("the admin replaced a privileged user's invitation from another issuer after a conflict; the original link now: %v", peekErr)
	}
}

func TestBreakGlassInviteAndMarkLinkSent(t *testing.T) {
	c := newCast(t)
	// a disabled super admin locked out: the break-glass invite works where CreateInvite refuses, and enables again
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.pAdmin.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, actor(c.super), c.pAdmin.ID); !isInvalid(err) {
		t.Fatalf("normal invite of a disabled account: %v", err)
	}
	link, exp, err := c.svc.CreateBreakGlassInvite(c.ctx, c.pAdmin.ID, false)
	if err != nil || !exp.After(time.Now()) {
		t.Fatalf("break glass: %v", err)
	}
	if _, _, err := c.svc.CreateBreakGlassInvite(c.ctx, "nobody", false); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	ev := c.audited(c.pAdmin.OrgID, "user.invite.break_glass")
	if len(ev) != 1 || !strings.Contains(ev[0].Detail["account"], "disabled") {
		t.Fatalf("audit %+v", ev)
	}
	token := link[strings.Index(link, "token=")+6:]
	if err := c.svc.MarkLinkSent(c.ctx, link, c.pAdmin.Email); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.MarkLinkSent(c.ctx, "not-a-token", "x@example.com"); err == nil {
		t.Error("unknown link marked sent")
	}
	if _, _, err := c.svc.UseSignInLink(c.ctx, token, service.LinkInvite, "correct horse battery", service.NewCredEpoch()); err != nil {
		t.Fatal(err)
	}
	got := c.fresh(c.pAdmin)
	if !got.Active || !got.EmailVerified {
		t.Errorf("after break-glass use: active %v verified %v", got.Active, got.EmailVerified)
	}
	// the token by itself (not the URL) marks too
	l2, _, err := c.svc.CreateInvite(c.ctx, actor(c.super), c.pAdmin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.svc.MarkLinkSent(c.ctx, l2[strings.Index(l2, "token=")+6:], "other@example.com"); err != nil {
		t.Errorf("bare token: %v", err)
	}
}

// An invitation or reset link is bound to the address the account had when it was issued: once an administrator
// corrects a mistyped address, the link that went to the wrong mailbox opens nothing (it would have set the
// account's credentials). A break-glass invitation goes to whoever runs the command, not to an address.
func TestLinksStopWhenTheAddressChanges(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "bob", model.RoleUser)
	invite, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	reset, _, err := e.svc.IssueLink(e.ctx, u, service.LinkReset, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(invite), service.LinkInvite); err != nil {
		t.Fatalf("invitation before the change: %v", err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Email: ptr("bob.right@example.com")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(invite), service.LinkInvite); !errors.Is(err, service.ErrLink) {
		t.Fatalf("invitation for the old address still opens: %v", err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, reset, service.LinkReset); !errors.Is(err, service.ErrLink) {
		t.Fatalf("reset link for the old address still opens: %v", err)
	}
	// A new invitation, for the address on file now, works.
	invite, _, err = e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(invite), service.LinkInvite); err != nil {
		t.Fatalf("new invitation: %v", err)
	}
	bg, _, err := e.svc.CreateBreakGlassInvite(e.ctx, u.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Email: ptr("bob.again@example.com")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(bg), service.LinkInvite); err != nil {
		t.Fatalf("break-glass invitation: %v", err)
	}
}

// A break-glass invitation with superAdmin makes a user of the primary organization an enabled super admin (an end date
// that has passed is cleared), audited; a user of another organization is refused and left as they were.
func TestBreakGlassInviteMakesASuperAdmin(t *testing.T) {
	c := newCast(t)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), c.pUser.ID, service.UserInput{ValidUntil: ptr(past)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), c.pUser.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.CreateBreakGlassInvite(c.ctx, c.aAdmin.ID, true); !isInvalid(err) || !strings.Contains(err.Error(), "primary organization") {
		t.Fatalf("a user of another organization: %v", err)
	}
	if got := c.fresh(c.aAdmin); got.Role != model.RoleAdmin {
		t.Fatalf("the refused user is now %s", got.Role)
	}
	// an identity linked by a mere email match, and one the user connected: the promotion drops the first, as any
	// promotion to a privileged role does
	for _, via := range []string{"email", "connect"} {
		if err := c.svc.Identities.Create(c.ctx, &model.Identity{UserID: c.pUser.ID, OrgID: c.primary.ID,
			ProviderID: "prov-" + via, Subject: "sub-" + via, Via: via}); err != nil {
			t.Fatal(err)
		}
	}
	link, _, err := c.svc.CreateBreakGlassInvite(c.ctx, c.pUser.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if ids, err := c.svc.Identities.All(c.ctx, c.pUser.ID); err != nil || len(ids) != 1 || ids[0].Via != "connect" {
		t.Fatalf("identities after the promotion: %+v %v", ids, err)
	}
	got := c.fresh(c.pUser)
	if got.Role != model.RoleSuperAdmin || !got.Active || got.ValidUntil != nil {
		t.Fatalf("after recovery: role %s active %v end %v", got.Role, got.Active, got.ValidUntil)
	}
	if _, _, err := c.svc.PeekLink(c.ctx, link[strings.Index(link, "token=")+6:], service.LinkInvite); err != nil {
		t.Fatalf("the invitation does not open: %v", err)
	}
	if ev := c.audited(c.primary.ID, "user.invite.break_glass"); len(ev) != 1 || ev[0].Detail["super_admin"] != "granted" {
		t.Fatalf("invite audit %+v", ev)
	}
	if ev := c.audited(c.primary.ID, "user.update"); len(ev) == 0 {
		t.Fatal("the promotion was not audited")
	}
	// without the flag the role stays as it is
	if _, _, err := c.svc.CreateBreakGlassInvite(c.ctx, c.pManager.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := c.fresh(c.pManager); got.Role != model.RoleManager {
		t.Fatalf("plain break-glass changed the role to %s", got.Role)
	}
}

// unconfirmedUsers lets every compare-and-swap of a user land, then reports it unconfirmed.
type unconfirmedUsers struct{ store.Store }

func (s unconfirmedUsers) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if err := s.Store.CompareAndPut(ctx, r, expect); err != nil || r.Kind != model.KindUser {
		return err
	}
	return store.ErrUnconfirmed
}

// A break-glass promotion whose outcome is unknown (it may have landed) is audited as such before the error returns.
func TestBreakGlassPromotionWithUnknownOutcomeIsAudited(t *testing.T) {
	c := newCast(t)
	good := c.svc.Users.S
	c.svc.Users.S = unconfirmedUsers{good}
	if _, _, err := c.svc.CreateBreakGlassInvite(c.ctx, c.pUser.ID, true); err == nil {
		t.Fatal("an unconfirmed promotion reported success")
	}
	c.svc.Users.S = good
	if got := c.fresh(c.pUser); got.Role != model.RoleSuperAdmin {
		t.Fatalf("setup: the promotion did not land (%s)", got.Role)
	}
	var unknown bool
	for _, ev := range c.audited(c.primary.ID, "user.update") {
		if ev.Target == c.pUser.Username && ev.Outcome == "unknown" {
			unknown = true
		}
	}
	if !unknown {
		t.Fatal("the promotion that landed was not audited")
	}
}

// The live invitation of a privileged account is replaced only by its issuer (or a super admin), a service account
// included: one service account cannot replace another's invitation, or the system's, and take the new link.
func TestServiceAccountReplacesOnlyItsOwnInvite(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	sa := func(name string) *service.Actor {
		t.Helper()
		scopes := []string{"users"}
		c, _, err := e.svc.CreateServiceAccount(e.ctx, actor(e.super), org.ID, service.ServiceAccountInput{Name: ptr(name), Scopes: &scopes})
		if err != nil {
			t.Fatal(err)
		}
		return service.ActorForServiceAccount(c, scopes, "")
	}
	one, two := sa("one"), sa("two")

	mgr := e.user(org.ID, "new-mgr", model.RoleManager) // never set up: whoever may manage it invites it
	if _, _, err := e.svc.CreateInvite(e.ctx, one, mgr.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.CreateInvite(e.ctx, two, mgr.ID); err == nil {
		t.Error("a service account replaced another's live invitation")
	}
	if _, _, err := e.svc.CreateInvite(e.ctx, one, mgr.ID); err != nil {
		t.Errorf("a service account could not replace its own invitation: %v", err)
	}

	sys := e.user(org.ID, "sys-mgr", model.RoleManager)
	if _, _, err := e.svc.CreateInvite(e.ctx, service.System, sys.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.CreateInvite(e.ctx, one, sys.ID); err == nil {
		t.Error("a service account replaced the system's live invitation")
	}
}

// A service account's invitation opens nothing once the account no longer holds a scope it invites with.
func TestServiceAccountInviteNeedsItsScopeWhenUsed(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	scopes := []string{"users", "clients"}
	c, _, err := e.svc.CreateServiceAccount(e.ctx, actor(e.super), org.ID, service.ServiceAccountInput{Name: ptr("inviter"), Scopes: &scopes})
	if err != nil {
		t.Fatal(err)
	}
	u := e.user(org.ID, "invited", model.RoleUser)
	link, _, err := e.svc.CreateInvite(e.ctx, service.ActorForServiceAccount(c, scopes, ""), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	less := []string{"clients"}
	if _, err := e.svc.UpdateServiceAccount(e.ctx, actor(e.super), org.ID, c.ID, service.ServiceAccountInput{Scopes: &less}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(link), service.LinkInvite); !errors.Is(err, service.ErrLink) {
		t.Fatalf("the invitation of a service account without the users scope opened: %v", err)
	}
}
