package service_test

import (
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

func tokenFrom(link string) string { return link[strings.Index(link, "token=")+len("token="):] }

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
	if _, _, err := e.svc.RedeemLink(e.ctx, tok, service.LinkReset); !errors.Is(err, service.ErrLink) {
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
	if _, got, err := e.svc.RedeemLink(e.ctx, tok2, service.LinkInvite); err != nil || got.ID != u.ID {
		t.Fatalf("redeem: %v", err)
	}
	if _, _, err := e.svc.RedeemLink(e.ctx, tok2, service.LinkInvite); !errors.Is(err, service.ErrLink) {
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
	if admin.PasswordHash != "" {
		t.Fatal("the first admin has a password")
	}
	org, _ := svc.PrimaryOrg(ctx)
	if !org.Settings.RequireMFA {
		t.Fatal("the primary org must require MFA")
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
	if _, _, err := svc2.RedeemLink(ctx, reset, service.LinkReset); err != nil {
		t.Fatalf("reset link lost across restart: %v", err)
	}
	if _, _, err := svc.RedeemLink(ctx, reset, service.LinkReset); !errors.Is(err, service.ErrLink) {
		t.Fatal("link redeemed on two services")
	}
	// A second bootstrap creates nothing.
	if u, l, err := svc2.Bootstrap(ctx, "other@example.com"); err != nil || u != nil || l != "" {
		t.Fatalf("second bootstrap: %v %v %q", u, l, err)
	}
}

func TestRemovePasswordEndsAccess(t *testing.T) {
	c := newCast(t)
	u, err := c.svc.CreateUser(c.ctx, service.System, c.a.ID, service.UserInput{GivenName: gn("T"), Username: ptr("pw"), Email: ptr("pw@example.com"), Password: ptr("correct horse battery")})
	if err != nil {
		t.Fatal(err)
	}
	sess := &model.Session{Meta: model.Meta{ID: "sess-" + u.ID}, UserID: u.ID, OrgID: u.OrgID}
	if err := c.svc.Sessions.Create(c.ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.RemovePassword(c.ctx, actor(c.aAdmin), u.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := c.svc.Users.Get(c.ctx, u.ID)
	if got.PasswordHash != "" {
		t.Fatal("password still set")
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess.ID); err == nil {
		t.Fatal("session survived")
	}
	// Idempotent, and nobody removes their own password here.
	if err := c.svc.RemovePassword(c.ctx, actor(c.aAdmin), u.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.RemovePassword(c.ctx, actor(c.aAdmin), c.aAdmin.ID); err == nil {
		t.Fatal("removed own password")
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, actor(c.aAdmin), c.aAdmin.ID); err == nil {
		t.Fatal("invited self")
	}
}

// Two sign-in links for one user can both be live: two invitations issued at once (each revoking only what it saw),
// or an invitation and a reset link. Using one revokes the rest, so none can reset the account its owner just set up.
func TestRedeemRevokesOtherSignInLinks(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "racer", model.RoleUser)

	first, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	links, _, err := e.svc.Links.List(e.ctx, store.ListQuery{Scope: u.ID})
	if err != nil || len(links) != 1 {
		t.Fatalf("links %d: %v", len(links), err)
	}
	survivor := *links[0]
	second, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The race: the second issue's revoke missed the first invitation, which is back as it was.
	var zero hlc.Timestamp
	survivor.Version = zero
	if err := e.svc.Links.Create(e.ctx, &survivor); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(first), service.LinkInvite); err != nil {
		t.Fatalf("set-up: first invitation not live: %v", err)
	}
	reset, _, err := e.svc.IssueLink(e.ctx, u, service.LinkReset, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verify, _, err := e.svc.IssueLink(e.ctx, u, service.LinkVerify, "racer@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.svc.RedeemLink(e.ctx, tokenFrom(second), service.LinkInvite); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(first), service.LinkInvite); !errors.Is(err, service.ErrLink) {
		t.Fatalf("the other invitation survived its sibling's use: %v", err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, reset, service.LinkReset); !errors.Is(err, service.ErrLink) {
		t.Fatalf("the reset link survived the invitation's use: %v", err)
	}
	// An email verification link is not a sign-in link: it stays.
	if _, _, err := e.svc.PeekLink(e.ctx, verify, service.LinkVerify); err != nil {
		t.Fatalf("verification link revoked: %v", err)
	}
}
