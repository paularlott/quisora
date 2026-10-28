package model

import (
	"testing"
	"time"
)

// Every kind has a partition key by the rule documented on Index.Partition; a test per kind so a new kind or a changed
// rule cannot slip by.
func TestPartitionKeyOfEveryKind(t *testing.T) {
	const org = "org-1"
	meta := Meta{ID: "rec-1"}
	cases := map[Kind]Entity{
		KindOrg:       &Org{Meta: meta, Name: "acme"},
		KindUser:      &User{Meta: meta, OrgID: org, Username: "u"},
		KindGroup:     &Group{Meta: meta, OrgID: org, DisplayName: "g"},
		KindMember:    &Member{Meta: meta, OrgID: org, GroupID: "g", UserID: "u"},
		KindTenant:    &Tenant{Meta: meta, OrgID: org, Name: "t"},
		KindAccess:    &TenantAccess{Meta: meta, OrgID: org},
		KindClient:    &Client{Meta: meta, OrgID: org},
		KindProvider:  &Provider{Meta: meta, OrgID: org, Name: "p"},
		KindPasskey:   &Passkey{Meta: meta, OrgID: org, UserID: "u", CredentialID: []byte{1, 2, 3}},
		KindIdentity:  &Identity{Meta: meta, OrgID: org, UserID: "u", ProviderID: "p", Subject: "s"},
		KindSession:   &Session{Meta: meta, OrgID: org, UserID: "u"},
		KindGrant:     &Grant{Meta: meta, OrgID: org, UserID: "u"},
		KindAPIToken:  &APIToken{Meta: meta, OrgID: org, UserID: "u"},
		KindKey:       &SigningKey{Meta: meta},
		KindAudit:     &Audit{Meta: meta, OrgID: org},
		KindLink:      &LinkToken{Meta: meta, OrgID: org, UserID: "u", TokenHash: "h"},
		KindSignIn:    &SignIn{Meta: meta, OrgID: org},
		KindLock:      &Lock{Meta: meta},
		KindReplay:    &Replay{Meta: meta},
		KindEphemeral: &Ephemeral{Meta: meta},
		KindQueue:     &QueueItem{Meta: meta, Queue: "mail", Node: "node-1", Key: org},
	}
	want := map[Kind]string{
		KindOrg: "", KindKey: "", // global (partition 0)
		KindEphemeral: "", KindQueue: "", // node-local: never partitioned
		KindLock: "rec-1", KindReplay: "rec-1", // the record's own ID
	}
	for _, k := range Kinds() {
		e, ok := cases[k]
		if !ok {
			t.Errorf("kind %q has no case: decide its partition key and add it", k)
			continue
		}
		if e.Kind() != k {
			t.Errorf("%q: case holds a %q", k, e.Kind())
			continue
		}
		w, ok := want[k]
		if !ok {
			w = org // organization data
		}
		if got := e.Index().Partition; got != w {
			t.Errorf("%s: partition key %q, want %q", k, got, w)
		}
	}
}

// An entity with no organization (a self-registered client, a server-level audit event) is global.
func TestPartitionKeyEmptyOrgIsGlobal(t *testing.T) {
	for _, e := range []Entity{&Client{Meta: Meta{ID: "c"}, SelfRegistered: true}, &Audit{Meta: Meta{ID: "a"}}} {
		if got := e.Index().Partition; got != "" {
			t.Errorf("%s with no organization: partition key %q, want global", e.Kind(), got)
		}
	}
}

// Removed memberships (kept for their sequence fence) stay in their organization's partition.
func TestPartitionKeyRemovedMember(t *testing.T) {
	m := &Member{Meta: Meta{ID: "m"}, OrgID: "org-1", GroupID: "g", UserID: "u", Removed: time.Now()}
	if m.Active() {
		t.Fatal("setup: member still active")
	}
	if got := m.Index().Partition; got != "org-1" {
		t.Fatalf("removed member: partition key %q", got)
	}
}

// Every unique value of a record is scoped to the record's organization (so it lives in the record's partition): no
// unique value crosses partitions, so no write needs another organization's.
func TestUniqueValuesStayInPartition(t *testing.T) {
	const org = "034nmRmWuppROD1l9kiBPr"
	ents := []Entity{
		&User{Meta: Meta{ID: "u"}, OrgID: org, Username: "Al", Email: "a@x.org", ExternalID: "e1",
			LinkedEmails: []LinkedEmail{{Address: "b@x.org"}}},
		&Group{Meta: Meta{ID: "g"}, OrgID: org, DisplayName: "G", ExternalID: "e2"},
		&Tenant{Meta: Meta{ID: "t"}, OrgID: org, Name: "T", Resources: []string{"https://api.example.com/"}},
		&Provider{Meta: Meta{ID: "p"}, OrgID: org, Name: "P"},
		&Passkey{Meta: Meta{ID: "k"}, OrgID: org, UserID: "u", CredentialID: []byte{9, 9, 9}},
		&Identity{Meta: Meta{ID: "i"}, OrgID: org, UserID: "u", ProviderID: "p-1", Subject: "sub"},
		&LinkToken{Meta: Meta{ID: "l"}, OrgID: org, UserID: "u", TokenHash: "hash"},
		&Org{Meta: Meta{ID: org}, Name: "acme"},
	}
	for _, e := range ents {
		ix := e.Index()
		for _, u := range ix.Unique {
			scoped := len(u) >= len(org) && u[:len(org)] == org
			switch {
			case ix.Partition == "": // a global record: its values are global by being in partition 0
			case scoped:
			case e.Kind() == KindIdentity && len(u) > 4 && u[:4] == "p-1/": // scoped by the provider, which belongs to one organization
			case e.Kind() == KindPasskey && u == PasskeyCredentialKey("u", []byte{9, 9, 9}): // scoped by the user, who belongs to one organization
			case e.Kind() == KindLink && len(u) > 2 && u[:2] == "t/": // a random hash
			default:
				t.Errorf("%s unique value %q is not scoped to the organization", e.Kind(), u)
			}
			// What UniquePartition says of a value is the partition of the record holding it: a cluster node answers
			// the value missing from that partition's copy alone.
			key, ok := UniquePartition(e.Kind(), u)
			named := e.Kind() == KindOrg || e.Kind() == KindUser || e.Kind() == KindGroup || e.Kind() == KindTenant ||
				e.Kind() == KindProvider
			if ok != named || ok && key != ix.Partition {
				t.Errorf("%s unique value %q: UniquePartition %q %v, want %q %v", e.Kind(), u, key, ok, ix.Partition, named)
			}
		}
	}
	// A value whose first segment is not an organization's id names no partition.
	for _, v := range []string{"org1/u/al", "u-al", ""} {
		if key, ok := UniquePartition(KindUser, v); ok {
			t.Errorf("UniquePartition(user, %q) = %q, want none", v, key)
		}
	}
}
