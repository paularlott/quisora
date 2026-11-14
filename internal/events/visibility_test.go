package events

import (
	"strings"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func userRec(id string, role model.Role) *store.Record {
	return &store.Record{Kind: model.KindUser, ID: id, Scope: "o",
		Fields: map[string]any{"role": string(role), "super_admin": role == model.RoleSuperAdmin}}
}

// aboutUser is every kind of record that names a user, and a deletion of each.
func aboutUser(u string) []*store.Record {
	return []*store.Record{
		userRec(u, ""),
		{Kind: model.KindSession, ID: "s-" + u, Scope: u},
		{Kind: model.KindPasskey, ID: "p-" + u, Scope: u},
		{Kind: model.KindAPIToken, ID: "t-" + u, Scope: u},
		{Kind: model.KindIdentity, ID: "i-" + u, Scope: u},
		{Kind: model.KindGrant, ID: "g-" + u, Scope: u},
		{Kind: model.KindConsent, ID: "c-" + u, Scope: u},
		{Kind: model.KindSSHCert, ID: "x-" + u, Scope: "o", Fields: map[string]any{"user_id": u}},
		{Kind: model.KindMember, ID: "grp:" + u, Scope: "o", Fields: map[string]any{"user_id": u}},
		{Kind: model.KindAudit, ID: "a-" + u, Scope: "o", Fields: map[string]any{"super_admin": u == "sa"}},
		{Kind: model.KindSession, ID: "s-" + u, Scope: u, Deleted: true},
	}
}

func kinds(s *subscriber) string {
	var out []string
	for _, e := range strings.Fields(drain(s)) {
		out = append(out, strings.SplitN(e, ":", 2)[0]+":"+e[strings.LastIndex(e, ":")+1:])
	}
	return strings.Join(out, " ")
}

func roleHub(roles map[string]model.Role) *Hub {
	h := NewHub()
	h.UserInfo = func(id string) (string, model.Role) {
		if r, ok := roles[id]; ok {
			return "o", r
		}
		return "", ""
	}
	return h
}

func TestHubRoleVisibility(t *testing.T) {
	h := roleHub(map[string]model.Role{"usr": model.RoleUser, "mgr2": model.RoleManager, "adm": model.RoleAdmin, "sa": model.RoleSuperAdmin})
	mgr := &subscriber{ch: make(chan Event, 64), orgID: "o", actor: actorOf("o", model.RoleManager)}
	adm := &subscriber{ch: make(chan Event, 64), orgID: "o", actor: actorOf("o", model.RoleAdmin)}
	sup := &subscriber{ch: make(chan Event, 64), orgID: "o", super: true, actor: actorOf("o", model.RoleSuperAdmin)}
	for _, s := range []*subscriber{mgr, adm, sup} {
		h.add(s)
	}
	publish := func(u string) {
		for _, r := range aboutUser(u) {
			if r.Kind == model.KindUser {
				r = userRec(u, h.roleFor(u))
			}
			h.Publish(r)
		}
	}
	all := "user:put session:put passkey:put apitoken:put identity:put grant:put consent:put sshcert:put member:put audit:put session:delete"

	// an ordinary user: a manager sees their security records (not the audit log or the SSH certificates, which
	// are administrators'); an administrator sees all
	publish("usr")
	if got := kinds(mgr); got != "user:put session:put passkey:put apitoken:put identity:put grant:put consent:put member:put session:delete" {
		t.Errorf("manager, user: %q", got)
	}
	if got := kinds(adm); got != all {
		t.Errorf("admin, user: %q", got)
	}
	if got := kinds(sup); got != all {
		t.Errorf("super, user: %q", got)
	}
	// a manager: a manager manages plain users only, so a peer's security records are not theirs
	publish("mgr2")
	if got := kinds(mgr); got != "user:put member:put" {
		t.Errorf("manager, manager: %q", got)
	}
	if got := kinds(adm); got != all {
		t.Errorf("admin, manager: %q", got)
	}
	drain(sup)
	// an administrator: the manager sees the directory entry (the user record) and the membership, nothing else
	publish("adm")
	if got := kinds(mgr); got != "user:put member:put" {
		t.Errorf("manager, administrator: %q", got)
	}
	if got := kinds(adm); got != all {
		t.Errorf("admin, administrator: %q", got)
	}
	if got := kinds(sup); got != all {
		t.Errorf("super, administrator: %q", got)
	}
	// a super admin: nothing below super; everything for super
	publish("sa")
	if got := kinds(mgr) + kinds(adm); got != "" {
		t.Errorf("below super got %q about a super admin", got)
	}
	if got := kinds(sup); got != all {
		t.Errorf("super, super admin: %q", got)
	}
}

func (h *Hub) roleFor(u string) model.Role { _, r := h.UserInfo(u); return r }

func TestHubRoleChangeAppliesToNextEvent(t *testing.T) {
	h := roleHub(map[string]model.Role{"u": model.RoleUser})
	mgr := &subscriber{ch: make(chan Event, 8), orgID: "o", actor: actorOf("o", model.RoleManager)}
	h.add(mgr)
	sess := &store.Record{Kind: model.KindSession, ID: "s", Scope: "u"}
	h.Publish(sess)
	if got := kinds(mgr); got != "session:put" {
		t.Fatalf("user: %q", got)
	}
	h.Publish(userRec("u", model.RoleAdmin)) // promoted: the manager still gets the directory entry
	h.Publish(sess)
	if got := kinds(mgr); got != "user:put" {
		t.Fatalf("promoted: %q", got)
	}
	h.Publish(userRec("u", model.RoleUser)) // demoted
	h.Publish(sess)
	if got := kinds(mgr); got != "user:put session:put" {
		t.Fatalf("demoted: %q", got)
	}
}

// A lookup begun before a promotion must not overwrite the role the promotion's record published.
func TestHubStaleLookupDoesNotUndoPromotion(t *testing.T) {
	h := NewHub()
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.UserInfo = func(id string) (string, model.Role) {
		first := false
		once.Do(func() { first = true })
		if first {
			close(started)
			<-release // the old lookup: the user was still plain when it read the store
			return "o", model.RoleUser
		}
		return "o", model.RoleSuperAdmin
	}
	mgr := &subscriber{ch: make(chan Event, 8), orgID: "o", actor: actorOf("o", model.RoleManager)}
	h.add(mgr)
	done := make(chan struct{})
	go func() { // an event about the user triggers the lookup
		h.Publish(&store.Record{Kind: model.KindSession, ID: "s0", Scope: "u"})
		close(done)
	}()
	<-started
	h.Publish(userRec("u", model.RoleSuperAdmin)) // the promotion
	close(release)
	<-done
	drain(mgr)
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s1", Scope: "u"})
	if got := drain(mgr); got != "" {
		t.Fatalf("a stale lookup undid the promotion: manager got %q", got)
	}
}

func TestHubUnknownAndNoActorFailClosed(t *testing.T) {
	h := roleHub(map[string]model.Role{"u": model.RoleUser})
	noActor := &subscriber{ch: make(chan Event, 8), orgID: "o"}
	adm := &subscriber{ch: make(chan Event, 8), orgID: "o", actor: actorOf("o", model.RoleAdmin)}
	h.add(noActor)
	h.add(adm)
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s", Scope: "nobody"})
	if got := drain(noActor) + drain(adm); got != "" {
		t.Errorf("got %q", got)
	}
	h.Publish(&store.Record{Kind: model.KindAudit, ID: "a", Scope: "o"})
	if got := drain(noActor); got != "" {
		t.Errorf("a viewer without an actor got %q", got)
	}
	if got := drain(adm); got != "audit:a:put" {
		t.Errorf("admin got %q", got)
	}
}

// A manager watches the stream for the users and groups they manage, so they hear of nothing the management API keeps
// to administrators (tenants, access entries, applications, providers, SSH CA keys): not even that one changed. An
// administrator hears of all of them but a super admin's access to a tenant; the access entry of a group, which the hub
// cannot tell from a deleted user, comes without its id.
func TestHubAdminOnlyKindsAndHiddenAccess(t *testing.T) {
	h := roleHub(map[string]model.Role{"usr": model.RoleUser, "sa": model.RoleSuperAdmin})
	mgr := &subscriber{ch: make(chan Event, 64), orgID: "o", actor: actorOf("o", model.RoleManager)}
	adm := &subscriber{ch: make(chan Event, 64), orgID: "o", actor: actorOf("o", model.RoleAdmin)}
	sup := &subscriber{ch: make(chan Event, 64), orgID: "o", super: true, actor: actorOf("o", model.RoleSuperAdmin)}
	for _, s := range []*subscriber{mgr, adm, sup} {
		h.add(s)
	}
	for _, r := range []*store.Record{
		{Kind: model.KindTenant, ID: "t1", Scope: "o"},
		{Kind: model.KindClient, ID: "c1", Scope: "o"},
		{Kind: model.KindProvider, ID: "p1", Scope: "o"},
		{Kind: model.KindSSHKey, ID: "k1", Scope: "o"},
		{Kind: model.KindAccess, ID: "t1:usr", Scope: "o"},
		{Kind: model.KindAccess, ID: "t1:grp", Scope: "o"},
		{Kind: model.KindAccess, ID: "t1:sa", Scope: "o"},
		{Kind: model.KindAccess, ID: "t1:sa", Deleted: true},
		{Kind: model.KindGroup, ID: "g1", Scope: "o"},
	} {
		h.Publish(r)
	}
	if got := drain(mgr); got != "group:g1:put" {
		t.Errorf("manager got %q", got)
	}
	if got := drain(adm); got != "tenant:t1:put client:c1:put provider:p1:put sshkey:k1:put access:t1:usr:put access::put group:g1:put" {
		t.Errorf("admin got %q", got)
	}
	if got := drain(sup); got != "tenant:t1:put client:c1:put provider:p1:put sshkey:k1:put access:t1:usr:put access:t1:grp:put "+
		"access:t1:sa:put access::delete group:g1:put" {
		t.Errorf("super got %q", got)
	}
}
