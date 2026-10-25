package service_test

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/secure"
)

// A node whose queues on disk still hold items sealed with a previous key (a re-seal that failed) keeps the rotation
// unfinished: the previous keys are not reported removable.
func TestRotationWaitsForStaleQueues(t *testing.T) {
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
	// Items sealed with a key that is not configured need none of the configured keys: the rotation completes, with
	// a warning to put their key back before they are given up.
	lost = 3
	if err := e.svc.ReportMasterKey(e.ctx, "node-a"); err != nil {
		t.Fatal(err)
	}
	if st, err = e.svc.RotationStatus(e.ctx); err != nil || !st.Removable || st.State != "complete" || st.QueueLost != 3 ||
		!strings.Contains(st.Detail, "3 queued messages on node-a") {
		t.Fatalf("with lost queued items: %+v %v", st, err)
	}
}
