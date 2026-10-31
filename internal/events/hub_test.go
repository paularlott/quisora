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
	h.OrgOfUser = func(id string) string { return map[string]string{"u1": "org-a"}[id] }
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindLink, ID: "l1", Scope: "u1"})    // not streamed
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s1", Scope: "u1"}) // a user's own record: their org only
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u2", Deleted: true})  // scope unknown
	h.Publish(&store.Record{Kind: model.KindOrg, ID: "org-b", Scope: ""})    // org record
	if got := drain(a); got != "user:u1:put session:s1:put user::delete" {
		t.Errorf("org-a got %q", got)
	}
	if got := drain(b); got != "user::delete org:org-b:put" {
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
	h.Publish(&store.Record{Kind: model.KindUser, ID: "1", Scope: "o"})
	h.Publish(&store.Record{Kind: model.KindUser, ID: "2", Scope: "o"})
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
// a viewer of another organization learns only that something of the kind changed; without a lookup, nobody gets ids.
func TestHubUserScopedOwner(t *testing.T) {
	h := NewHub()
	a := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	b := &subscriber{ch: make(chan Event, 8), orgID: "org-b"}
	h.add(a)
	h.add(b)
	h.OrgOfUser = func(id string) string { return map[string]string{"u1": "org-a"}[id] }
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
	c := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	h2.add(c)
	h2.Publish(&store.Record{Kind: model.KindAPIToken, ID: "t1", Scope: "u1"})
	if e := <-c.ch; e.User != "" || e.ID != "" || e.Kind != "apitoken" {
		t.Errorf("no lookup: %+v", e)
	}
}

// A personal stream (the account page) carries only its user's own changes: their user record, their memberships and
// their own records; nothing about other users, groups or clients.
func TestHubPersonalStream(t *testing.T) {
	h := NewHub()
	h.OrgOfUser = func(id string) string { return map[string]string{"u1": "org-a", "u2": "org-a"}[id] }
	me := &subscriber{ch: make(chan Event, 16), orgID: "org-a", self: "u1"}
	h.add(me)
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u2", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindMember, ID: "g1:u1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindMember, ID: "g1:u2", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s1", Scope: "u1"})
	h.Publish(&store.Record{Kind: model.KindPasskey, ID: "p2", Scope: "u2"})
	h.Publish(&store.Record{Kind: model.KindGroup, ID: "g1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u3", Deleted: true}) // scope unknown
	if got := drain(me); got != "user:u1:put member:g1:u1:put session:s1:put" {
		t.Errorf("personal stream got %q", got)
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

// An SSH certificate is the organization's (the tenant page) and its user's own (the account page): the personal stream
// gets the changes of the user's certificates and no one else's.
func TestHubSSHCertsReachTheirUser(t *testing.T) {
	h := NewHub()
	me := &subscriber{ch: make(chan Event, 8), orgID: "org-a", self: "u1"}
	admin := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	h.add(me)
	h.add(admin)
	cert := func(id, user string) *store.Record {
		return &store.Record{Kind: model.KindSSHCert, ID: id, Scope: "org-a", Fields: map[string]any{"user_id": user}}
	}
	h.Publish(cert("c1", "u1"))
	h.Publish(cert("c2", "u2"))
	h.Publish(cert("c3", "")) // a host certificate
	h.Publish(&store.Record{Kind: model.KindSSHCert, ID: "c4", Scope: "org-b", Fields: map[string]any{"user_id": "u1"}})
	if got := drain(me); got != "sshcert:c1:put" {
		t.Errorf("personal stream got %q", got)
	}
	if got := drain(admin); got != "sshcert:c1:put sshcert:c2:put sshcert:c3:put" {
		t.Errorf("the organization's stream got %q", got)
	}
}
