package scim_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// deepSCIMGroupGate pauses the first write of a group's record: the commit of the request's change, before which
// nothing is written (written against the lease design, it paused the taking of the group's lock, the same point).
type deepSCIMGroupGate struct {
	store.Store
	armed           atomic.Bool
	entered, resume chan struct{}
}

func (s *deepSCIMGroupGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindGroup && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.resume
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A conditional PATCH racing another node must not undo the other node's successful desired membership.
func TestDeepConditionalSCIMRollbackPreservesConcurrentSuccess(t *testing.T) {
	e := newEnv(t)
	uid := e.mk("deep-member", nil)
	id := e.group("Original")
	path := "/scim/v2/acme/Groups/" + id
	tag := e.do("GET", path, e.admA, nil).Header.Get("ETag")
	gate := &deepSCIMGroupGate{Store: e.Svc.Groups.S, entered: make(chan struct{}), resume: make(chan struct{})}
	e.Svc.Groups.S = gate
	gate.armed.Store(true)
	done := make(chan resp, 1)
	go func() {
		done <- e.do("PATCH", path, e.admA, patchBody(op("add", "members", []any{map[string]any{"value": uid}})), "If-Match", tag)
	}()
	<-gate.entered
	g, err := e.Svc.Groups.Get(e.ctx, id)
	if err != nil {
		close(gate.resume)
		<-done
		t.Fatal(err)
	}
	// Another node has its own SCIM lock; call the same service operation directly to model its concurrent PATCH.
	name := "Concurrent success"
	_, err = e.Svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{DisplayName: &name}, []string{uid}, nil)
	close(gate.resume)
	first := <-done
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != 412 {
		t.Fatalf("first conditional request: %d %s", first.Status, first.Raw)
	}
	got := e.do("GET", path, e.admA, nil)
	if len(got.list("members")) != 1 {
		t.Fatalf("concurrent successful change lost member after failed conditional PATCH: %s", got.Raw)
	}
}

// failSCIMRecord fails every compare-and-swap of records whose id ends in suffix.
type failSCIMRecord struct {
	store.Store
	suffix string
}

func (s failSCIMRecord) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if strings.HasSuffix(r.ID, s.suffix) {
		return errors.New("review: membership storage failure")
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A group created with members is one commit: a POST whose membership write fails still created the group with
// every member (seen whole through the record), and one whose member is refused creates nothing, with nothing to
// delete afterwards.
func TestDeepSCIMGroupCreateWithMembersIsOneCommit(t *testing.T) {
	e := newEnv(t)
	u1, u2 := e.mk("c1", nil), e.mk("c2", nil)
	inner := e.Svc.Members.S
	e.Svc.Members.S = failSCIMRecord{Store: inner, suffix: u2}
	r := e.do("POST", "/scim/v2/acme/Groups", e.admA, map[string]any{"displayName": "Committed",
		"members": []any{map[string]any{"value": u1}, map[string]any{"value": u2}}})
	if r.Status != 201 || len(r.list("members")) != 2 {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	if g := e.do("GET", "/scim/v2/acme/Groups/"+id, e.admA, nil); len(g.list("members")) != 2 {
		t.Fatalf("members seen: %s", g.Raw)
	}
	if ug := e.do("GET", "/scim/v2/acme/Users/"+u2, e.admA, nil); len(ug.list("groups")) != 1 {
		t.Fatalf("user's groups: %s", ug.Raw)
	}
	e.Svc.Members.S = inner
	if n, err := e.Svc.FinishGroupChanges(e.ctx, 0); err != nil || n != 1 {
		t.Fatalf("housekeeping: %d %v", n, err)
	}
	if m, err := e.Svc.Members.Get(e.ctx, model.MemberID(id, u2)); err != nil || !m.Active() {
		t.Fatalf("membership not materialized: %v", err)
	}
	// Refused: no group, no memberships, nothing written.
	r = e.do("POST", "/scim/v2/acme/Groups", e.admA, map[string]any{"displayName": "Refused",
		"members": []any{map[string]any{"value": u1}, map[string]any{"value": "ghost"}}})
	if r.Status != 400 {
		t.Fatalf("refused create: %d %s", r.Status, r.Raw)
	}
	if l := e.do("GET", "/scim/v2/acme/Groups?filter="+qs(`displayName eq "Refused"`), e.admA, nil); l.total() != 0 {
		t.Fatalf("group left behind: %s", l.Raw)
	}
	if ug := e.do("GET", "/scim/v2/acme/Users/"+u1, e.admA, nil); len(ug.list("groups")) != 1 {
		t.Fatalf("user's groups after the refused create: %s", ug.Raw)
	}
}

// A PATCH or PUT changing more than service.MaxMembersPerChange memberships is refused with 413 (RFC 7644 §3.12).
func TestDeepSCIMGroupChangeTooLarge(t *testing.T) {
	e := newEnv(t)
	id := e.group("Big")
	members := make([]any, service.MaxMembersPerChange+1)
	for i := range members {
		members[i] = map[string]any{"value": fmt.Sprintf("user-%d", i)}
	}
	r := e.do("PATCH", "/scim/v2/acme/Groups/"+id, e.admA, patchBody(op("add", "members", members)))
	if r.Status != 413 {
		t.Fatalf("too large PATCH: %d %s", r.Status, r.Raw)
	}
	r = e.do("PUT", "/scim/v2/acme/Groups/"+id, e.admA, map[string]any{"displayName": "Big", "members": members})
	if r.Status != 413 {
		t.Fatalf("too large PUT: %d %s", r.Status, r.Raw)
	}
	if g := e.do("GET", "/scim/v2/acme/Groups/"+id, e.admA, nil); len(g.list("members")) != 0 {
		t.Fatalf("members after refused changes: %s", g.Raw)
	}
}
