package kvstore

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A store at format 3 holds records written before their kinds gained index fields (as that build encoded them,
// without the fields): opening it with this build rebuilds them, so an index lookup finds every record. An access
// entry's end (the sweep), a tenant taking self-registered applications, a client taking API tokens, a guest's link by
// its source user.
func TestFormat4IndexesFieldsAddedSinceFormat3(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenBadger(ctx, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	put := func(e model.Entity, without ...string) {
		t.Helper()
		r, err := store.Encode(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range without { // as the older build encoded it
			delete(r.Fields, f)
		}
		if err := s.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	end := time.Now().Add(time.Hour).UTC()
	put(&model.TenantAccess{Meta: model.Meta{ID: model.AccessID("t1", "u1")}, OrgID: "o", TenantID: "t1", SubjectType: model.SubjectUser,
		SubjectID: "u1", AllClients: true, Expires: end}, "expiring", "ends")
	set := model.DefaultTenantSettings()
	set.SelfRegistration = true
	put(&model.Tenant{Meta: model.Meta{ID: "t1"}, OrgID: "o", Name: "mcp", Settings: set, Resources: []string{"https://mcp.example/mcp"}}, "self_registration")
	put(&model.Client{Meta: model.Meta{ID: "c1"}, OrgID: "o", Name: "Tools", AcceptsAPITokens: true}, "accepts_api_tokens")
	put(&model.Identity{Meta: model.Meta{ID: "l1"}, UserID: "g1", OrgID: "b", ProviderID: "p1", Subject: "u1",
		Authority: model.ProviderOrganization + "|https://idp.example/o/a||1"}, "source_user")
	find := func(kind model.Kind, scope, field string, value any) int {
		t.Helper()
		res, err := s.List(ctx, kind, store.ListQuery{Scope: scope, Filters: []store.Filter{{Field: field, Value: value}}})
		if err != nil {
			t.Fatal(err)
		}
		return len(res.Records)
	}
	if find(model.KindClient, "o", "accepts_api_tokens", true) != 0 {
		t.Fatal("the seeded client is indexed already: the test seeds nothing old")
	}
	if err := s.markFormat(ctx, 3); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if s, err = OpenBadger(ctx, dir, BadgerOptions{}); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if b, _ := s.eng.Get(ctx, metaFormat); string(b) != strconv.Itoa(currentFormat()) {
		t.Fatalf("format after opening: %s", b)
	}
	for _, c := range []struct {
		kind         model.Kind
		scope, field string
		value        any
	}{
		{model.KindAccess, "o", "expiring", true},
		{model.KindTenant, "o", "self_registration", true},
		{model.KindClient, "o", "accepts_api_tokens", true},
		{model.KindIdentity, "", "source_user", "u1"},
	} {
		if n := find(c.kind, c.scope, c.field, c.value); n != 1 {
			t.Errorf("%s by %s after the migration: %d records", c.kind, c.field, n)
		}
	}
	if due, err := s.ListDue(ctx, model.KindAccess, end.Add(time.Minute), 10); err != nil || len(due) != 1 {
		t.Errorf("the access entry is not due for the sweep: %v %d", err, len(due))
	}
}

// A store at format 4 holds tenants written before members_only was indexed: opening it with this build indexes them,
// so the access request form finds every members-only tenant.
func TestFormat5IndexesMembersOnlyTenants(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenBadger(ctx, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	set := model.DefaultTenantSettings()
	set.MembersOnly = true
	r, err := store.Encode(&model.Tenant{Meta: model.Meta{ID: "t1"}, OrgID: "o", Name: "customer-b", Settings: set})
	if err != nil {
		t.Fatal(err)
	}
	delete(r.Fields, "members_only") // as format 4's build encoded it
	if err := s.Put(ctx, r); err != nil {
		t.Fatal(err)
	}
	find := func() int {
		t.Helper()
		res, err := s.List(ctx, model.KindTenant, store.ListQuery{Scope: "o", Filters: []store.Filter{{Field: "members_only", Value: true}}})
		if err != nil {
			t.Fatal(err)
		}
		return len(res.Records)
	}
	if find() != 0 {
		t.Fatal("the seeded tenant is indexed already: the test seeds nothing old")
	}
	if err := s.markFormat(ctx, 4); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err = OpenBadger(ctx, dir, BadgerOptions{}); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n := find(); n != 1 {
		t.Errorf("members-only tenants after the migration: %d", n)
	}
}
