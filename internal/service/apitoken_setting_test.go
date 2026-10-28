package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func apiTokenInput() service.APITokenInput {
	return service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAPI}}
}

// An organization starts with nobody allowed to make api tokens (the setting's zero value), whatever the users' roles,
// and so does one saved before the setting existed.
func TestAPITokensOffByDefault(t *testing.T) {
	c := newCast(t)
	o, err := c.svc.CreateOrg(c.ctx, service.System, service.OrgInput{Name: ptr("fresh")}) // as made, not as the helper does
	if err != nil {
		t.Fatal(err)
	}
	if got := model.DefaultOrgSettings().APITokens; got != "" {
		t.Fatalf("the default setting is %q, want nobody (empty)", got)
	}
	for name, role := range map[string]model.Role{"user": model.RoleUser, "manager": model.RoleManager, "admin": model.RoleAdmin} {
		u := c.user(o.ID, name, role)
		if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(u), apiTokenInput()); !isInvalid(err) {
			t.Errorf("%s: %v, want the api scope refused", name, err)
		}
	}
}

// Who may make an api token is the organization's choice: nobody, the members of its chosen groups, or everyone. The
// other scopes are not decided by it.
func TestAPITokenSettingGatesCreation(t *testing.T) {
	c := newCast(t)
	member, outsider := c.user(c.a.ID, "member", model.RoleUser), c.user(c.a.ID, "outsider", model.RoleUser)
	g := c.group(c.a.ID, "Developers", member)

	c.setAPITokens(c.a.ID, model.APITokensOff)
	var fe *service.FieldError
	for _, u := range []*model.User{member, c.aUser, c.aAdmin} {
		if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(u), apiTokenInput()); !errors.As(err, &fe) || fe.Field != "scopes" {
			t.Errorf("off, %s: %v", u.Username, err)
		}
	}
	// scim and admin tokens are gated by role alone
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aAdmin), service.APITokenInput{Name: "t", Scopes: []string{"scim", "admin"}}); err != nil {
		t.Errorf("off, scim and admin: %v", err)
	}

	c.setAPITokens(c.a.ID, model.APITokensGroups, g.ID)
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(member), apiTokenInput()); err != nil {
		t.Errorf("groups, a member: %v", err)
	}
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(outsider), apiTokenInput()); !isInvalid(err) {
		t.Errorf("groups, not a member: %v", err)
	}
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aAdmin), apiTokenInput()); !isInvalid(err) {
		t.Errorf("groups, an administrator who is not a member: %v", err)
	}

	c.setAPITokens(c.a.ID, model.APITokensEveryone)
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(outsider), apiTokenInput()); err != nil {
		t.Errorf("everyone: %v", err)
	}
	// the setting is the user's own organization's: another organization's is another's
	c.setAPITokens(c.b.ID, model.APITokensOff)
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aUser), apiTokenInput()); err != nil {
		t.Errorf("another organization's setting changed this one's: %v", err)
	}
}

// A token is kept when its owner may no longer use it, and lives by the setting as it is at each use: turned off, or
// the owner out of the chosen groups, it is refused (and audited); allowed again, it works again.
func TestAPITokenSettingGovernsUse(t *testing.T) {
	c := newCast(t)
	sink := &auditSink{}
	c.svc.AuditWriter = sink
	owner := c.user(c.a.ID, "owner", model.RoleUser)
	g := c.group(c.a.ID, "Developers", owner)
	tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(owner), apiTokenInput())
	if err != nil {
		t.Fatal(err)
	}
	ok := func(when string) {
		t.Helper()
		if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); err != nil {
			t.Fatalf("%s: %v", when, err)
		}
	}
	refused := func(when string) {
		t.Helper()
		if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); !errors.Is(err, service.ErrBadToken) {
			t.Fatalf("%s: %v, want ErrBadToken", when, err)
		}
	}

	ok("everyone")
	c.setAPITokens(c.a.ID, model.APITokensOff)
	refused("turned off")
	if got, err := c.svc.APITokens.Get(c.ctx, tok.ID); err != nil || got.ID != tok.ID {
		t.Fatalf("the token is kept when the setting is off: %v", err)
	}
	if ev := sink.of("apitoken.refused"); len(ev) != 1 || ev[0].OrgID != c.a.ID ||
		ev[0].Detail["reason"] != "the organization does not let the owner use api tokens" {
		t.Fatalf("the refusal is audited with its reason: %+v", ev)
	}
	c.setAPITokens(c.a.ID, model.APITokensEveryone)
	ok("turned on again")

	c.setAPITokens(c.a.ID, model.APITokensGroups, g.ID)
	ok("owner in the chosen group")
	if err := c.svc.SetMembership(c.ctx, service.System, g.ID, owner.ID, false); err != nil {
		t.Fatal(err)
	}
	refused("owner left the chosen group")
	if err := c.svc.SetMembership(c.ctx, service.System, g.ID, owner.ID, true); err != nil {
		t.Fatal(err)
	}
	ok("owner back in the group")
	c.setAPITokens(c.a.ID, model.APITokensGroups, c.group(c.a.ID, "Others").ID)
	refused("another group chosen")
}

// The setting is for the api scope: scim and admin tokens of the same owners work whatever it says.
func TestAPITokenSettingLeavesOtherScopesAlone(t *testing.T) {
	c := newCast(t)
	_, scim, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "s", Scopes: []string{service.ScopeSCIM}})
	if err != nil {
		t.Fatal(err)
	}
	_, admin, err := c.svc.CreateAPIToken(c.ctx, actor(c.aAdmin), service.APITokenInput{Name: "a", Scopes: []string{service.ScopeAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{model.APITokensOff, model.APITokensGroups, model.APITokensEveryone} {
		var groups []string
		if mode == model.APITokensGroups {
			groups = []string{c.group(c.a.ID, "G").ID}
		}
		c.setAPITokens(c.a.ID, mode, groups...)
		for name, plain := range map[string]string{"scim": scim, "admin": admin} {
			if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); err != nil {
				t.Errorf("%s token with the setting %q: %v", name, mode, err)
			}
		}
	}
}

// A read of the setting or of the owner's groups that fails is no verdict: the token is neither good nor refused
// (503, not a refusal audited as if the setting had changed).
func TestAPITokenUnavailableWhenTheSettingCannotBeRead(t *testing.T) {
	c := newCast(t)
	sink := &auditSink{}
	c.svc.AuditWriter = sink
	owner := c.user(c.a.ID, "owner", model.RoleUser)
	g := c.group(c.a.ID, "Developers", owner)
	c.setAPITokens(c.a.ID, model.APITokensGroups, g.ID)
	_, plain, err := c.svc.CreateAPIToken(c.ctx, actor(owner), apiTokenInput())
	if err != nil {
		t.Fatal(err)
	}
	good := c.svc.Members.S
	c.svc.Members.S = &faultStore{Store: good, beforeList: func(k model.Kind, _ store.ListQuery) error { return failKind(k, model.KindMember) }}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); !errors.Is(err, service.ErrUnavailable) || errors.Is(err, service.ErrBadToken) {
		t.Fatalf("groups unreadable: %v, want ErrUnavailable", err)
	}
	if n := len(sink.of("apitoken.refused")); n != 0 {
		t.Fatalf("%d refusals audited for a token that was not refused", n)
	}
	c.svc.Members.S = good
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); err != nil {
		t.Fatalf("once the store answers again: %v", err)
	}
	// and the groups are not asked for in the other modes: a failing read there decides nothing
	c.setAPITokens(c.a.ID, model.APITokensEveryone)
	c.svc.Members.S = &faultStore{Store: good, beforeList: func(k model.Kind, _ store.ListQuery) error { return failKind(k, model.KindMember) }}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); err != nil {
		t.Fatalf("everyone, groups unreadable: %v", err)
	}
}

// The setting is one of its modes, with groups of the organization for the groups mode only, and at least one there.
func TestOrgAPITokenSettingValidation(t *testing.T) {
	c := newCast(t)
	sys := service.System
	mine := c.group(c.a.ID, "Mine")
	theirs := c.group(c.b.ID, "Theirs")
	set := func(mode string, groups ...string) error {
		st := model.DefaultOrgSettings()
		st.APITokens, st.APITokenGroups = mode, groups
		_, err := c.svc.UpdateOrg(c.ctx, sys, c.a.ID, service.OrgInput{Settings: &st})
		return err
	}
	for name, err := range map[string]error{
		"groups without groups":       set(model.APITokensGroups),
		"a group of another org":      set(model.APITokensGroups, mine.ID, theirs.ID),
		"a group that does not exist": set(model.APITokensGroups, "nope"),
		"groups with everyone":        set(model.APITokensEveryone, mine.ID),
		"groups with off":             set(model.APITokensOff, mine.ID),
		"an unknown mode":             set("admins"),
		"too many groups":             set(model.APITokensGroups, make([]string, 21)...),
	} {
		if !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, err := range map[string]error{
		"groups":   set(model.APITokensGroups, mine.ID),
		"everyone": set(model.APITokensEveryone),
		"off":      set(model.APITokensOff),
		"nobody":   set(""),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a new organization has no groups to choose
	st := model.DefaultOrgSettings()
	st.APITokens, st.APITokenGroups = model.APITokensGroups, []string{mine.ID}
	if _, err := c.svc.CreateOrg(c.ctx, sys, service.OrgInput{Name: ptr("newcomer"), Settings: &st}); !isInvalid(err) {
		t.Errorf("create with groups: %v", err)
	}

	// A group deleted since it was chosen does not stop other settings being saved (only a list being changed is
	// looked up); its members no longer count.
	if err := set(model.APITokensGroups, mine.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.DeleteGroup(c.ctx, sys, mine.ID); err != nil {
		t.Fatal(err)
	}
	o, err := c.svc.GetOrg(c.ctx, sys, c.a.ID)
	if err != nil {
		t.Fatal(err)
	}
	st = o.Settings
	st.RequireMFA = true
	if _, err := c.svc.UpdateOrg(c.ctx, sys, c.a.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatalf("another setting saved with a deleted group chosen: %v", err)
	}
	if ok, err := c.svc.APITokensAllowed(context.Background(), c.aUser); err != nil || ok {
		t.Fatalf("a deleted group lets someone make tokens: %v %v", ok, err)
	}
}

// A public client cannot introspect, so it never accepts api tokens, whatever it is set to.
func TestPublicClientDoesNotAcceptAPITokens(t *testing.T) {
	c := newCast(t)
	pub, _, err := c.svc.CreateClient(c.ctx, service.System, c.a.ID, service.ClientInput{Name: ptr("Spa"), AuthMethod: ptr(model.AuthMethodNone),
		RedirectURIs: ptr([]string{"https://p.example.com/cb"}), AcceptsAPITokens: ptr(true)})
	if err != nil || pub.AcceptsAPITokens {
		t.Fatalf("public client: %+v %v", pub, err)
	}
	conf, _, err := c.svc.CreateClient(c.ctx, service.System, c.a.ID, service.ClientInput{Name: ptr("Api"), GrantTypes: ptr([]string{"client_credentials"})})
	if err != nil || conf.AcceptsAPITokens {
		t.Fatalf("a client accepts api tokens only once chosen: %+v %v", conf, err)
	}
	if conf, err = c.svc.UpdateClient(c.ctx, service.System, conf.ID, service.ClientInput{AcceptsAPITokens: ptr(true)}); err != nil || !conf.AcceptsAPITokens {
		t.Fatalf("chosen: %+v %v", conf, err)
	}
}
