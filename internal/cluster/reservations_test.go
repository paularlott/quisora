package cluster

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func (c *tcluster) reservationHolder(tn *tnode, kind model.Kind, key string) (string, bool) {
	r, err := tn.st().Get(bg, model.KindReservation, reservationID(kind, key))
	if err != nil {
		return "", false
	}
	var rv model.Reservation
	if store.Decode(r, &rv) != nil {
		return "", false
	}
	return rv.HolderID, true
}

// shortGrace makes reservations count as old after a moment, for the rest of the test.
func shortGrace(t *testing.T, d time.Duration) {
	saved := reservationGrace
	reservationGrace = d
	t.Cleanup(func() { reservationGrace = saved })
}

// holderRecord stores a tenant holding (or, with no resources, not holding) a global value in n's store as it is held on
// a node that has applied it, and returns its id.
func holderRecord(t *testing.T, n *Node, org string, resources ...string) string {
	t.Helper()
	return holderAs(t, n, model.NewID(), org, resources...)
}

// holderAs stores (a new version of) the tenant id as holderRecord does.
func holderAs(t *testing.T, n *Node, id, org string, resources ...string) string {
	t.Helper()
	tn := newTenant(org, "holder-"+id, resources...)
	tn.ID = id
	rec, err := store.Encode(tn)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.st.inner.Put(bg, rec); err != nil {
		t.Fatal(err)
	}
	return tn.ID
}

// A resource indicator, and a passkey's credential id, is unique across organizations although the records that claim
// it live in different partitions: a reservation, decided by one owner, holds it; the record itself is written without
// it.
func TestGlobalUniqueValuesAreReserved(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		c := started(t, b)
		// two organizations in different partitions
		orgA, orgB := "org-a", "org-b"
		for i := 0; partitionNum(orgA) == partitionNum(orgB); i++ {
			orgB = fmt.Sprintf("org-b%d", i)
		}
		res := "https://api.example.com/mcp"
		a := newTenant(orgA, "one", res)
		if err := tenants(c.nodes[0]).Create(bg, a); err != nil {
			t.Fatal(err)
		}
		// the same resource, written differently: its canonical form is what is unique
		b2 := newTenant(orgB, "two", "https://API.example.com/mcp/")
		if err := tenants(c.nodes[1]).Create(bg, b2); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("a resource held by a tenant of another organization: %v", err)
		}
		if _, err := tenants(c.nodes[1]).Get(bg, b2.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("the refused tenant was stored")
		}
		key := model.TenantResourceKey(res)
		waitFor(t, 10*time.Second, "the holder found by the value on every node", func() bool {
			for _, tn := range c.nodes {
				h, err := tn.st().GetByUnique(bg, model.KindTenant, key)
				if err != nil || h.ID != a.ID {
					return false
				}
				// the stored tenant does not list the global value: it is reserved, not indexed
				for _, u := range h.Unique {
					if model.GlobalUnique(model.KindTenant, u) {
						return false
					}
				}
			}
			return true
		})
		if _, err := c.nodes[2].st().GetByUnique(bg, model.KindTenant, model.TenantResourceKey("https://other.example.com")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a value nobody holds: %v", err)
		}

		// A tenant that holds its value can be updated, and can take another one.
		a2, _ := tenants(c.nodes[2]).Get(bg, a.ID)
		a2.Description = "changed"
		a2.Resources = []string{res, "https://second.example.com"}
		if err := tenants(c.nodes[2]).Update(bg, a2); err != nil {
			t.Fatalf("an update that keeps its value and adds one: %v", err)
		}
		c2 := newTenant(orgB, "three", "https://second.example.com")
		if err := tenants(c.nodes[1]).Create(bg, c2); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("the value it took: %v", err)
		}
		// Dropping a value frees it, afterwards; the other tenants' values are not touched.
		c.waitVersion(t, model.KindTenant, a.ID, a2.Version)
		a3, _ := tenants(c.nodes[0]).Get(bg, a.ID)
		a3.Resources = []string{"https://second.example.com"}
		if err := tenants(c.nodes[0]).Update(bg, a3); err != nil {
			t.Fatal(err)
		}
		if err := tenants(c.nodes[1]).Create(bg, newTenant(orgB, "four", res)); err != nil {
			t.Fatalf("the value the other tenant dropped: %v", err)
		}
		// Deleting the holder frees its values.
		if err := tenants(c.nodes[1]).Delete(bg, a.ID); err != nil {
			t.Fatal(err)
		}
		if err := tenants(c.nodes[2]).Create(bg, newTenant(orgA, "five", "https://second.example.com")); err != nil {
			t.Fatalf("the value of a deleted tenant: %v", err)
		}
		for _, tn := range c.nodes { // nothing is left reserved for the deleted tenant
			waitFor(t, 10*time.Second, "its reservation released", func() bool {
				h, ok := c.reservationHolder(tn, model.KindTenant, model.TenantResourceKey("https://second.example.com"))
				return ok && h != a.ID
			})
		}

		// Passkeys' credential ids, likewise (a discoverable sign-in looks one up with no organization).
		cred := []byte("credential-id-1")
		p1 := &model.Passkey{OrgID: orgA, UserID: "u1", CredentialID: cred, Name: "key"}
		if err := passkeys(c.nodes[0]).Create(bg, p1); err != nil {
			t.Fatal(err)
		}
		p2 := &model.Passkey{OrgID: orgB, UserID: "u2", CredentialID: cred, Name: "copy"}
		if err := passkeys(c.nodes[1]).Create(bg, p2); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("the same credential id in another organization: %v", err)
		}
		waitFor(t, 10*time.Second, "the lookup by credential id on every node", func() bool {
			for _, tn := range c.nodes {
				h, err := tn.st().GetByUnique(bg, model.KindPasskey, model.PasskeyCredentialKey(cred))
				if err != nil || h.ID != p1.ID {
					return false
				}
			}
			return true
		})
		if err := passkeys(c.nodes[2]).Delete(bg, p1.ID); err != nil {
			t.Fatal(err)
		}
		if err := passkeys(c.nodes[1]).Create(bg, p2); err != nil {
			t.Fatalf("the credential id of a deleted passkey: %v", err)
		}
	})
}

// Reservations on one healthy cluster (SQLite). The sweeps' counts take in every reservation of the cluster: the
// scenarios that sweep come first, and every one before them leaves its reservations held.
func TestReservationsOnOneCluster(t *testing.T) {
	runOn(t, started(t, sqliteBackend()),
		scenario{"stale reservation is taken over", testStaleReservationIsTakenOver},
		scenario{"sweep releases what is gone", testSweepReleasesWhatIsGone},
		scenario{"long value is held", testLongValueIsHeld},
		scenario{"concurrent claims of a global value", testConcurrentClaimsOfAGlobalValue})
}

// Claims of one global value at once, from every node: exactly one record holds it.
func testConcurrentClaimsOfAGlobalValue(t *testing.T, c *tcluster) {
	for round := range 4 {
		res := fmt.Sprintf("https://race-%d.example.com", round)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var winners []string
		for i := range 9 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tn := newTenant(fmt.Sprintf("org-race-%d", i), fmt.Sprintf("t-%d", round), res)
				switch err := tenants(c.nodes[i%3]).Create(bg, tn); {
				case err == nil:
					mu.Lock()
					winners = append(winners, tn.ID)
					mu.Unlock()
				case errors.Is(err, store.ErrConflict):
				default:
					t.Errorf("round %d claim %d: %v", round, i, err)
				}
			}()
		}
		wg.Wait()
		if len(winners) != 1 {
			t.Fatalf("round %d: %d tenants hold one resource", round, len(winners))
		}
		waitFor(t, 10*time.Second, "the holder on node 0", func() bool {
			h, err := c.nodes[0].st().GetByUnique(bg, model.KindTenant, model.TenantResourceKey(res))
			return err == nil && h.ID == winners[0]
		})
	}
}

// A claim whose record was never written (the claimant died between the two writes) holds the value for good as far as
// the claims go, since nothing shows the holder is gone; the housekeeping leader's sweep reads the holder through its
// owner and releases the reservation after the grace. One that comes sooner finds it young and leaves it.
func testStaleReservationIsTakenOver(t *testing.T, c *tcluster) {
	shortGrace(t, 1500*time.Millisecond)
	res := "https://crashed.example.com"
	key := model.TenantResourceKey(res)
	resv := reservationID(model.KindTenant, key)
	ghost := model.NewID()
	// the claim of a tenant that is never written
	if _, err := c.nodes[0].st().claim(bg, &store.Record{Kind: model.KindTenant, ID: ghost}, key); err != nil {
		t.Fatal(err)
	}
	real := newTenant("org-b", "real", res)
	if err := tenants(c.nodes[1]).Create(bg, real); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a claim within the grace of another: %v", err)
	}
	waitFor(t, 10*time.Second, "the reservation on every node", func() bool {
		for _, tn := range c.nodes {
			if _, ok := c.reservationHolder(tn, model.KindTenant, key); !ok {
				return false
			}
		}
		return true
	})
	time.Sleep(reservationGrace + 200*time.Millisecond)
	if err := tenants(c.nodes[1]).Create(bg, real); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("an old reservation whose holder nobody has is taken over by a claim: %v", err)
	}
	// the sweep (here by node 2: the leader's work, whichever node runs it) reads the holder through its owner
	var sw ReservationSweep
	released, err := c.nodes[2].n.SweepReservations(bg, &sw, 100)
	if err != nil || released != 1 {
		t.Fatalf("sweep: released %d, %v", released, err)
	}
	waitFor(t, 10*time.Second, "the reservation released everywhere", func() bool {
		for _, tn := range c.nodes {
			if r, err := tn.n.st.inner.Lookup(bg, model.KindReservation, resv); err != nil || !r.Deleted {
				return false
			}
		}
		return true
	})
	if err := tenants(c.nodes[1]).Create(bg, real); err != nil {
		t.Fatalf("a claim of a value whose reservation was swept: %v", err)
	}
	waitFor(t, 10*time.Second, "the new holder on every node", func() bool {
		for _, tn := range c.nodes {
			if h, err := tn.st().GetByUnique(bg, model.KindTenant, key); err != nil || h.ID != real.ID {
				return false
			}
		}
		return true
	})
}

// The sweep releases a reservation whose holder exists but no longer lists the value (the release was lost), keeps those
// whose holder holds the value, leaves young ones alone, and does not release what changed since it looked.
func testSweepReleasesWhatIsGone(t *testing.T, c *tcluster) {
	shortGrace(t, 1200*time.Millisecond)
	keep := newTenant("org-a", "keeps", "https://keeps.example.com")
	if err := tenants(c.nodes[0]).Create(bg, keep); err != nil {
		t.Fatal(err)
	}
	// a record that stopped holding its value, written behind the cluster layer's back: the release never happens
	lose := newTenant("org-a", "loses", "https://loses.example.com")
	if err := tenants(c.nodes[0]).Create(bg, lose); err != nil {
		t.Fatal(err)
	}
	lose.Resources = nil
	expect := lose.Version // (Encode stamps a new one)
	rec, _ := store.Encode(lose)
	rec.Unique = nil
	b, err := encodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	// written as a change of its partition, without the cluster store's release of the value it no longer holds
	res, err := c.nodes[0].st().submit(bg, recPartition(rec), &change{Op: opWrite, Mode: modeMatch, Expect: uint64(expect), Rec: b})
	if err != nil {
		t.Fatal(err)
	}
	var rep writeReply
	if err := decodeMsg(res.Reply, &rep); err != nil {
		t.Fatal(err)
	}
	lostKey := model.TenantResourceKey("https://loses.example.com")
	waitFor(t, 10*time.Second, "the change of the holder on every node, the reservation still there", func() bool {
		for _, tn := range c.nodes {
			h, err := tn.n.st.inner.Lookup(bg, model.KindTenant, lose.ID)
			if err != nil || uint64(h.Version) != rep.Version {
				return false
			}
			if _, ok := c.reservationHolder(tn, model.KindTenant, lostKey); !ok {
				return false
			}
		}
		return true
	})
	// young: nothing is released
	var sw ReservationSweep
	if n, err := c.nodes[0].n.SweepReservations(bg, &sw, 100); err != nil || n != 0 {
		t.Fatalf("a sweep within the grace: released %d, %v", n, err)
	}
	time.Sleep(reservationGrace + 200*time.Millisecond)
	// in batches: the sweep resumes where it stopped and starts again at the end
	released := 0
	for range 3 {
		n, err := c.nodes[1].n.SweepReservations(bg, &sw, 1)
		if err != nil {
			t.Fatal(err)
		}
		released += n
	}
	if released != 1 {
		t.Fatalf("released %d, want 1 (the one whose holder dropped its value)", released)
	}
	if _, err := tenants(c.nodes[2]).Get(bg, keep.ID); err != nil {
		t.Fatal(err)
	}
	if err := tenants(c.nodes[2]).Create(bg, newTenant("org-c", "dup", "https://keeps.example.com")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("the value of a holder that holds it was released: %v", err)
	}
	if err := tenants(c.nodes[2]).Create(bg, newTenant("org-c", "takes", "https://loses.example.com")); err != nil {
		t.Fatalf("the value the sweep released: %v", err)
	}
	// a release that names a version the reservation no longer has is refused
	other := newTenant("org-d", "other", "https://other.example.com")
	if err := tenants(c.nodes[0]).Create(bg, other); err != nil {
		t.Fatal(err)
	}
	okey := model.TenantResourceKey("https://other.example.com")
	p := partitionNum(reservationID(model.KindTenant, okey))
	_, err = c.nodes[0].st().submit(bg, p, &change{Op: opRelease, Kind: string(model.KindTenant), ID: other.ID,
		Resv: reservationID(model.KindTenant, okey), Expect: 12345})
	if refusalCode(err) != whyStale {
		t.Fatalf("a release of a version the reservation does not have: %v", err)
	}
}

// Reservation ids fit the SQL id column however long the value is, and are the same for the same value
// (testLongValueIsHeld).
func TestReservationIDs(t *testing.T) {
	short := reservationID(model.KindTenant, "res/https://a.example.com")
	if short != "tenant/res/https://a.example.com" {
		t.Fatalf("%q", short)
	}
	long := "res/https://example.com/" + strings.Repeat("x", 400)
	a, b := reservationID(model.KindTenant, long), reservationID(model.KindTenant, long)
	if a != b || len(a) > 191 || a == reservationID(model.KindTenant, long+"y") || a == reservationID(model.KindPasskey, long) {
		t.Fatalf("%q %q", a, b)
	}
}

// A tenant resource longer than the SQL id column is still held (TestReservationIDs).
func testLongValueIsHeld(t *testing.T, c *tcluster) {
	res := "https://example.com/" + strings.Repeat("y", 300)
	if err := tenants(c.nodes[0]).Create(bg, newTenant("org-a", "long", res)); err != nil {
		t.Fatal(err)
	}
	if err := tenants(c.nodes[1]).Create(bg, newTenant("org-b", "long2", res)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("%v", err)
	}
}

// A claim takes a reservation over, once it is old, only when the holder is known not to hold the value: the holder, as
// the reservation's owner has it, is a tombstone or a live record that does not list the value, written after the
// reservation. A holder the owner does not have, or has only as it was before the reservation, proves nothing (its copy
// of that partition may lag behind the update that added the value), a holder that holds it keeps it, and a young
// reservation is left alone whatever its holder looks like.
func TestClaimTakesOverOnlyOnPositiveEvidence(t *testing.T) {
	shortGrace(t, 50*time.Millisecond)
	n, _ := gnode(t)
	claim := func(res, holder string) error {
		key := model.TenantResourceKey(res)
		p := partitionNum(reservationID(model.KindTenant, key))
		b, _ := encodeMsg(&change{Op: opClaim, Kind: string(model.KindTenant), ID: holder, Key: key})
		_, _, err := n.pst.Prepare(p, b)
		return err
	}
	reserve := func(res, holder string) {
		t.Helper()
		key := model.TenantResourceKey(res)
		commitChange(t, n, partitionNum(reservationID(model.KindTenant, key)),
			&change{Op: opClaim, Kind: string(model.KindTenant), ID: holder, Key: key})
	}
	old := func() { time.Sleep(reservationGrace + 30*time.Millisecond) }

	// young: refused whatever the holder is
	absent := model.NewID()
	reserve("https://young.example.com", absent)
	if err := claim("https://young.example.com", "other"); refusalCode(err) != whyConflict {
		t.Fatalf("a young reservation of a holder that is not there: %v", err)
	}
	old()
	// absent holder: nothing proves it gone
	if err := claim("https://young.example.com", "other"); refusalCode(err) != whyConflict {
		t.Fatalf("an old reservation whose holder this node does not have: %v", err)
	}
	// a holder that holds it
	holds := holderRecord(t, n, "org-a", "https://holds.example.com")
	reserve("https://holds.example.com", holds)
	old()
	if err := claim("https://holds.example.com", "other"); refusalCode(err) != whyConflict {
		t.Fatalf("an old reservation of a record that holds the value: %v", err)
	}
	// a live holder that does not list it, as it was before the reservation: this node may not have the update that
	// added the value yet (left to the sweep)
	early := holderRecord(t, n, "org-a")
	reserve("https://early.example.com", early)
	old()
	if err := claim("https://early.example.com", "other"); refusalCode(err) != whyConflict {
		t.Fatalf("an old reservation whose holder this node has only from before it: %v", err)
	}
	// a live holder that no longer lists it, changed after the reservation
	lost := holderRecord(t, n, "org-a", "https://lost.example.com")
	reserve("https://lost.example.com", lost)
	holderAs(t, n, lost, "org-a")
	old()
	if err := claim("https://lost.example.com", "other"); err != nil {
		t.Fatalf("an old reservation of a record that no longer holds the value: %v", err)
	}
	// a tombstone from before the reservation proves nothing either
	before := holderRecord(t, n, "org-a")
	tb0 := store.Tombstone(model.KindTenant, before)
	tb0.Version, tb0.Partition = store.Clock.Now(), "org-a"
	if err := n.st.inner.Put(bg, tb0); err != nil {
		t.Fatal(err)
	}
	reserve("https://before.example.com", before)
	old()
	if err := claim("https://before.example.com", "other"); refusalCode(err) != whyConflict {
		t.Fatalf("an old reservation whose holder's tombstone predates it: %v", err)
	}
	// a tombstone of the holder
	gone := holderRecord(t, n, "org-a", "https://gone.example.com")
	reserve("https://gone.example.com", gone)
	tb := store.Tombstone(model.KindTenant, gone)
	tb.Version, tb.Partition = store.Clock.Now(), "org-a"
	if err := n.st.inner.Put(bg, tb); err != nil {
		t.Fatal(err)
	}
	old()
	if err := claim("https://gone.example.com", "other"); err != nil {
		t.Fatalf("an old reservation of a deleted record: %v", err)
	}
	// the holder itself claiming again is told it holds it already
	if err := claim("https://holds.example.com", holds); refusalCode(err) != whyHeld {
		t.Fatalf("the holder claiming again: %v", err)
	}
}

// The kinds the cluster store looks at for global values are the kinds the model says have them.
func TestGlobalKindsMatchTheModel(t *testing.T) {
	for _, k := range model.Kinds() {
		want := model.GlobalUnique(k, model.TenantResourceKey("https://x.example.com")) || model.GlobalUnique(k, "anything")
		if globalKind(k) != want {
			t.Errorf("%s: globalKind %v, the model says %v", k, globalKind(k), want)
		}
	}
}

// An update of a record that keeps its global unique value (a passkey's sign-in count, a tenant's name) skips the claim
// of the value when this node's reservation names the record already: one write, not a claim and a write. A whole-record
// put, or a change of the value, claims as before.
func TestUpdateKeepingAGlobalValueSkipsTheClaim(t *testing.T) {
	c := started(t, badgerBackend())
	ten := newTenant("org-claims", "app", "https://claims.example.com")
	if err := tenants(c.nodes[0]).Create(bg, ten); err != nil {
		t.Fatal(err)
	}
	key := model.TenantResourceKey("https://claims.example.com")
	waitFor(t, 10*time.Second, "the tenant and its reservation on node 1", func() bool {
		x, err := tenants(c.nodes[1]).Get(bg, ten.ID)
		h, ok := c.reservationHolder(c.nodes[1], model.KindTenant, key)
		return err == nil && x.Version == ten.Version && ok && h == ten.ID
	})
	n1 := c.nodes[1].n
	writes, refused := n1.stats.writes.Load(), n1.stats.refused.Load()
	cur, _ := tenants(c.nodes[1]).Get(bg, ten.ID)
	cur.Name = "renamed"
	if err := tenants(c.nodes[1]).Update(bg, cur); err != nil {
		t.Fatal(err)
	}
	if w, r := n1.stats.writes.Load()-writes, n1.stats.refused.Load()-refused; w != 1 || r != 0 {
		t.Fatalf("an update keeping the value: %d writes, %d refused (want the record's write alone)", w, r)
	}
	if h, ok := c.reservationHolder(c.nodes[1], model.KindTenant, key); !ok || h != ten.ID {
		t.Fatalf("the reservation after the update: %q %v", h, ok)
	}

	// a whole-record put claims (the owner answers that the record holds it already)
	writes, refused = n1.stats.writes.Load(), n1.stats.refused.Load()
	rec, err := store.Encode(cur)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.nodes[1].st().Put(bg, rec); err != nil {
		t.Fatal(err)
	}
	if w, r := n1.stats.writes.Load()-writes, n1.stats.refused.Load()-refused; w != 1 || r != 1 {
		t.Fatalf("a put: %d writes, %d refused (want the claim answered 'held', and the write)", w, r)
	}

	// a new value is claimed, the old one released; and another record cannot take the new one
	cur, _ = tenants(c.nodes[1]).Get(bg, ten.ID)
	cur.Resources = []string{"https://moved.example.com"}
	if err := tenants(c.nodes[1]).Update(bg, cur); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the old value released", func() bool {
		_, ok := c.reservationHolder(c.nodes[1], model.KindTenant, key)
		return !ok
	})
	if err := tenants(c.nodes[2]).Create(bg, newTenant("org-other", "app", "https://moved.example.com")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second tenant with the moved value: %v", err)
	}
}
