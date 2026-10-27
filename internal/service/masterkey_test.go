package service_test

import (
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

// Each node reports the master key it holds; the nodes agree when every live report is of this node's key, a node that
// does not see its own report trusts no empty view, and a report that is not renewed stops counting.
func TestMasterKeyAgreement(t *testing.T) {
	e := newEnv(t)
	if ok, others, err := e.svc.MasterKeyAgreed(e.ctx, ""); err != nil || !ok || len(others) != 0 {
		t.Errorf("no reports: %v %v %v", ok, others, err)
	}
	if ok, others, err := e.svc.MasterKeyAgreed(e.ctx, "node-a"); err != nil || ok || others["node-a"] == "" {
		t.Errorf("no report of this node in view: %v %v %v", ok, others, err)
	}
	if err := e.svc.ReportMasterKey(e.ctx, "node-a"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ReportMasterKey(e.ctx, "node-a"); err != nil { // renewed in place
		t.Fatal(err)
	}
	if ok, _, _ := e.svc.MasterKeyAgreed(e.ctx, "node-a"); !ok {
		t.Error("a node on this key disagrees")
	}
	// another node, on another key
	other := service.New(e.svc.Cfg, e.svc.Store, mustSealer(t))
	if err := other.ReportMasterKey(e.ctx, "node-b"); err != nil {
		t.Fatal(err)
	}
	ok, others, err := e.svc.MasterKeyAgreed(e.ctx, "")
	if err != nil || ok || others["node-b"] == "" || others["node-b"] == others["node-a"] {
		t.Fatalf("disagreement: %v %v %v", ok, others, err)
	}
	expireMasterKeyReport(t, e, "node-b")
	if ok, _, _ := e.svc.MasterKeyAgreed(e.ctx, ""); !ok {
		t.Error("an expired report still counts")
	}
	if err := other.ReportMasterKey(e.ctx, "node-b"); err != nil { // (on its own key)
		t.Fatal(err)
	}
	if err := e.svc.ReportMasterKey(e.ctx, "node-c"); err != nil {
		t.Fatal(err)
	}
	if ok, others, _ = e.svc.MasterKeyAgreed(e.ctx, "node-a"); ok || len(others) != 1 || others["node-b"] == "" {
		t.Fatalf("after the reports: %v %v", ok, others)
	}
	if st, err := e.svc.RotationStatus(e.ctx); err != nil || st.NodesAgree || st.State != "waiting_for_nodes" {
		t.Fatalf("status with a node on another key: %+v %v", st, err)
	}
}

// expireMasterKeyReport ages the report of a node (kept as a lock with a lifetime) past its end.
func expireMasterKeyReport(t *testing.T, e *env, node string) {
	t.Helper()
	l, err := e.svc.Locks.Get(e.ctx, "master-key/"+node)
	if err != nil {
		t.Fatal(err)
	}
	l.Until = time.Now().Add(-time.Minute)
	if err := e.svc.Locks.Update(e.ctx, l); err != nil {
		t.Fatal(err)
	}
}

// The state of a master key rotation: none, waiting for nodes on another key, re-sealing, secrets that cannot be
// opened, queued items still sealed with a previous key, and complete.
func TestRotationStatus(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		e := newEnv(t)
		st, err := e.svc.RotationStatus(e.ctx)
		if err != nil || st.State != "none" || st.Removable || !st.NodesAgree {
			t.Fatalf("no previous keys: %+v %v", st, err)
		}
	})

	t.Run("waiting_for_nodes", func(t *testing.T) {
		// Another node reports a different active key: the rotation waits for it, and nothing is declared removable.
		e := newEnv(t)
		if err := e.svc.ReportMasterKey(e.ctx, "node-a"); err != nil {
			t.Fatal(err)
		}
		if err := service.New(e.svc.Cfg, e.svc.Store, mustSealer(t)).ReportMasterKey(e.ctx, "node-b"); err != nil {
			t.Fatal(err)
		}
		st, err := e.svc.RotationStatus(e.ctx)
		if err != nil || st.State != "waiting_for_nodes" || st.NodesAgree || st.Removable || !strings.Contains(st.Detail, "node-b") {
			t.Fatalf("waiting: %+v %v", st, err)
		}
	})

	t.Run("resealing_then_unopenable", func(t *testing.T) {
		e := newEnv(t)
		oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
		old, _ := secure.NewSealer(oldKey)
		e.svc.Sealer.Replace(old)
		u := e.user(e.primary.ID, "alan", model.RoleUser)
		u.TOTPSecret = old.SealFor(service.TOTPBinding(u.ID), []byte("totp"))
		if err := e.svc.Users.Update(e.ctx, u); err != nil {
			t.Fatal(err)
		}
		ring, _ := secure.NewKeyring(newKey, oldKey)
		e.svc.Sealer.Replace(ring)
		if err := e.svc.ReportMasterKey(e.ctx, "n1"); err != nil {
			t.Fatal(err)
		}
		st, err := e.svc.RotationStatus(e.ctx)
		if err != nil || st.State != "resealing" || st.Stale == 0 || st.Removable {
			t.Fatalf("resealing: %+v %v", st, err)
		}
		// an unopenable secret outranks the rest
		u, _ = e.svc.Users.Get(e.ctx, u.ID)
		u.TOTPSecret = mustSealer(t).SealFor(service.TOTPBinding(u.ID), []byte("x"))
		_ = e.svc.Users.Update(e.ctx, u)
		if st, _ = e.svc.RotationStatus(e.ctx); st.State != "unopenable" || st.Unopenable != 1 {
			t.Fatalf("unopenable: %+v", st)
		}
	})

	t.Run("queued_items", func(t *testing.T) {
		// A node whose queues on disk still hold items sealed with a previous key (a re-seal that failed) keeps the
		// rotation unfinished: the previous keys are not reported removable.
		e := newEnv(t)
		oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
		ring, err := secure.NewKeyring(newKey, oldKey)
		if err != nil {
			t.Fatal(err)
		}
		e.svc.Sealer.Replace(ring)
		stale, lost := 2, 0
		e.svc.QueuesStale = func() (int, int) { return stale, lost }
		if err := e.svc.ReportMasterKey(e.ctx, "node-a"); err != nil {
			t.Fatal(err)
		}
		st, err := e.svc.RotationStatus(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.Removable || st.State != "resealing" || st.QueueStale != 2 {
			t.Fatalf("with stale queued items: %+v", st)
		}
		stale = 0
		if err := e.svc.ReportMasterKey(e.ctx, "node-a"); err != nil {
			t.Fatal(err)
		}
		if st, err = e.svc.RotationStatus(e.ctx); err != nil || !st.Removable {
			t.Fatalf("once re-sealed: %+v %v", st, err)
		}
		// Items sealed with a key that is not configured need none of the configured keys: the rotation completes,
		// with a warning to put their key back before they are given up.
		lost = 3
		if err := e.svc.ReportMasterKey(e.ctx, "node-a"); err != nil {
			t.Fatal(err)
		}
		if st, err = e.svc.RotationStatus(e.ctx); err != nil || !st.Removable || st.State != "complete" || st.QueueLost != 3 ||
			!strings.Contains(st.Detail, "3 queued messages on node-a") {
			t.Fatalf("with lost queued items: %+v %v", st, err)
		}
	})
}

// A grant's refresh token key is random and bound to the grant: it opens for that grant only; a grant without one
// has none.
func TestGrantKeys(t *testing.T) {
	e := newEnv(t)
	none := &model.Grant{Meta: model.Meta{ID: "g0"}}
	if k, err := e.svc.GrantRefreshKey(none); k != nil || err != nil {
		t.Errorf("grant without a key: %v %v", k, err)
	}
	n1, n2 := &model.Grant{Meta: model.Meta{ID: "n1"}}, &model.Grant{Meta: model.Meta{ID: "n2"}}
	e.svc.NewGrantKey(n1)
	e.svc.NewGrantKey(n2)
	k1, err1 := e.svc.GrantRefreshKey(n1)
	k2, _ := e.svc.GrantRefreshKey(n2)
	if err1 != nil || len(k1) != 32 || string(k1) == string(k2) {
		t.Errorf("new keys: %v", err1)
	}
	n1.ID = "n2" // moved onto another grant: it no longer opens
	if _, err := e.svc.GrantRefreshKey(n1); err == nil {
		t.Error("a grant key opened under another grant's id")
	}
}
