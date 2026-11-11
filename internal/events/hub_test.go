package events

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestHubScoping(t *testing.T) {
	h := NewHub()
	a := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	b := &subscriber{ch: make(chan Event, 8), orgID: "org-b"}
	super := &subscriber{ch: make(chan Event, 8), orgID: "primary", super: true}
	for _, s := range []*subscriber{a, b, super} {
		h.add(s)
	}
	h.UserInfo = func(id string) (string, bool) { return map[string]string{"u1": "org-a"}[id], false }
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindLink, ID: "l1", Scope: "u1"})    // not streamed
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s1", Scope: "u1"}) // a user's own record: their org only
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u2", Deleted: true})  // scope unknown
	h.Publish(&store.Record{Kind: model.KindOrg, ID: "org-b", Scope: ""})    // org record
	if got := drain(a); got != "user:u1:put session:s1:put" {                // the deleted, unknown user is dropped
		t.Errorf("org-a got %q", got)
	}
	if got := drain(b); got != "org:org-b:put" {
		t.Errorf("org-b got %q", got)
	}
	if got := drain(super); got != "user::delete org:org-b:put" { // scoped to the org being viewed, plus org list changes
		t.Errorf("super got %q", got)
	}
}

func TestHubOverflowMarksLagged(t *testing.T) {
	h := NewHub()
	s := &subscriber{ch: make(chan Event, 1), orgID: "o"}
	h.add(s)
	f := map[string]any{"super_admin": false}
	h.Publish(&store.Record{Kind: model.KindUser, ID: "1", Scope: "o", Fields: f})
	h.Publish(&store.Record{Kind: model.KindUser, ID: "2", Scope: "o", Fields: f})
	if !s.lagged {
		t.Fatal("overflow must mark the subscriber lagged")
	}
}

func drain(s *subscriber) string {
	var out []string
	for {
		select {
		case e := <-s.ch:
			out = append(out, e.Kind+":"+e.ID+":"+e.Op)
		default:
			return strings.Join(out, " ")
		}
	}
}

func ptr[T any](v T) *T { return &v }

// A user's own record carries its owner for viewers of their organization (a user page refetches only for its user);
// a viewer of another organization learns only that something of the kind changed; without a lookup the user is
// unknown, so a viewer below super admin gets nothing, and a super admin no id.
func TestHubUserScopedOwner(t *testing.T) {
	h := NewHub()
	a := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	b := &subscriber{ch: make(chan Event, 8), orgID: "org-b"}
	h.add(a)
	h.add(b)
	h.UserInfo = func(id string) (string, bool) { return map[string]string{"u1": "org-a"}[id], false }
	h.Publish(&store.Record{Kind: model.KindPasskey, ID: "pk1", Scope: "u1", Deleted: true})
	if e := <-a.ch; e.User != "u1" || e.ID != "pk1" || e.Op != "delete" {
		t.Errorf("same org: %+v", e)
	}
	select {
	case e := <-b.ch:
		t.Errorf("other org got %+v", e)
	default:
	}
	h2 := NewHub()
	c := &subscriber{ch: make(chan Event, 8), orgID: "org-a", super: true}
	d := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	h2.add(c)
	h2.add(d)
	h2.Publish(&store.Record{Kind: model.KindAPIToken, ID: "t1", Scope: "u1"})
	if e := <-c.ch; e.User != "" || e.ID != "" || e.Kind != "apitoken" {
		t.Errorf("no lookup: %+v", e)
	}
	if got := drain(d); got != "" {
		t.Errorf("unknown user reached a viewer below super admin: %q", got)
	}
}

// One viewer cannot hold more than maxPerUser streams on a node; others are unaffected.
func TestStreamsCappedPerViewer(t *testing.T) {
	h := NewHub()
	for i := 0; i < maxPerUser; i++ {
		if !h.add(&subscriber{ch: make(chan Event, 1), orgID: "o", who: "u:1"}) {
			t.Fatalf("stream %d refused", i)
		}
	}
	extra := &subscriber{ch: make(chan Event, 1), orgID: "o", who: "u:1"}
	if h.add(extra) {
		t.Fatal("cap not enforced")
	}
	other := &subscriber{ch: make(chan Event, 1), orgID: "o", who: "u:2"}
	if !h.add(other) {
		t.Fatal("another viewer refused")
	}
	h.remove(other)
	h.remove(other) // twice is harmless
	for s := range h.subs {
		h.remove(s)
		break
	}
	if !h.add(extra) {
		t.Fatal("a closed stream did not free its slot")
	}
	if !strings.HasPrefix(viewer(&service.Actor{Name: "x"}), "n:") {
		t.Fatal("viewer of an anonymous actor")
	}
}

// A tenant's SSH CA keys and certificates are streamed to their organization (the tenant page's SSH card).
func TestHubSSHKinds(t *testing.T) {
	h := NewHub()
	a := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	b := &subscriber{ch: make(chan Event, 8), orgID: "org-b"}
	h.add(a)
	h.add(b)
	h.Publish(&store.Record{Kind: model.KindSSHKey, ID: "k1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindSSHCert, ID: "c1", Scope: "org-a"})
	if got := drain(a); got != "sshkey:k1:put sshcert:c1:put" {
		t.Errorf("org-a got %q", got)
	}
	if got := drain(b); got != "" {
		t.Errorf("org-b got %q", got)
	}
}

// An SSH certificate is the organization's (the tenant page) and names its user (the admin user page lists theirs).
func TestHubSSHCertsNameTheirUser(t *testing.T) {
	h := NewHub()
	admin := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	h.add(admin)
	h.UserInfo = func(id string) (string, bool) { return "org-a", false }
	h.Publish(&store.Record{Kind: model.KindSSHCert, ID: "c1", Scope: "org-a", Fields: map[string]any{"user_id": "u1"}})
	h.Publish(&store.Record{Kind: model.KindSSHCert, ID: "c2", Scope: "org-a"}) // a host certificate
	h.Publish(&store.Record{Kind: model.KindSSHCert, ID: "c3", Scope: "org-b", Fields: map[string]any{"user_id": "u1"}})
	if e := <-admin.ch; e.ID != "c1" || e.User != "u1" {
		t.Errorf("user certificate: %+v", e)
	}
	if e := <-admin.ch; e.ID != "c2" || e.User != "" {
		t.Errorf("host certificate: %+v", e)
	}
	if got := drain(admin); got != "" {
		t.Errorf("another organization's certificate reached org-a: %q", got)
	}
}

// A viewer below super admin gets no event about a super admin or anything of theirs (nor of a user the hub cannot
// tell), super admins get everything, and a role change applies to the next event.
func TestHubHidesSuperAdmins(t *testing.T) {
	h := NewHub()
	mgr := &subscriber{ch: make(chan Event, 64), orgID: "primary"}
	sup := &subscriber{ch: make(chan Event, 64), orgID: "primary", super: true}
	h.add(mgr)
	h.add(sup)
	h.UserInfo = func(id string) (string, bool) {
		return map[string]string{"sa": "primary", "u1": "primary"}[id], id == "sa"
	}
	userRec := func(id string, super bool) *store.Record {
		return &store.Record{Kind: model.KindUser, ID: id, Scope: "primary", Fields: map[string]any{"super_admin": super}}
	}
	records := func(u string) []*store.Record {
		return []*store.Record{
			userRec(u, u == "sa"),
			{Kind: model.KindSession, ID: "s-" + u, Scope: u},
			{Kind: model.KindPasskey, ID: "p-" + u, Scope: u},
			{Kind: model.KindMember, ID: "g1:" + u, Scope: "primary", Fields: map[string]any{"group_id": "g1", "user_id": u}},
			{Kind: model.KindSSHCert, ID: "c-" + u, Scope: "primary", Fields: map[string]any{"user_id": u}},
			{Kind: model.KindAudit, ID: "a-" + u, Scope: "primary", Fields: map[string]any{"super_admin": u == "sa"}},
			{Kind: model.KindUser, ID: u, Deleted: true},
			{Kind: model.KindMember, ID: "g1:" + u, Deleted: true},
		}
	}
	for _, r := range records("sa") {
		h.Publish(r)
	}
	if got := drain(mgr); got != "" {
		t.Errorf("manager got events about a super admin: %q", got)
	}
	if n := len(sup.ch); n != 8 {
		t.Errorf("super admin got %d events about a super admin, want 8", n)
	}
	drain(sup)
	for _, r := range records("u1") {
		h.Publish(r)
	}
	if n := len(mgr.ch); n != 8 {
		t.Errorf("manager got %d events about an ordinary user, want 8", n)
	}
	if n := len(sup.ch); n != 8 {
		t.Errorf("super admin got %d events about an ordinary user, want 8", n)
	}
	drain(mgr)

	// promoted: the user record carries the new role, and the next event is hidden
	h.Publish(userRec("u1", true))
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s2", Scope: "u1"})
	if got := drain(mgr); got != "" {
		t.Errorf("manager got events about a promoted user: %q", got)
	}
	// demoted: visible again
	h.Publish(userRec("u1", false))
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s3", Scope: "u1"})
	if got := drain(mgr); got != "user:u1:put session:s3:put" {
		t.Errorf("after demotion the manager got %q", got)
	}
	// a deleted user keeps its last known role; an unknown one is dropped
	h.Publish(&store.Record{Kind: model.KindUser, ID: "gone", Deleted: true})
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s4", Scope: "gone"})
	h.Publish(&store.Record{Kind: model.KindSSHCert, ID: "c9", Deleted: true}) // deletion without its user
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s5", Deleted: true})
	if got := drain(mgr); got != "" {
		t.Errorf("manager got events about an unknown user: %q", got)
	}
}
