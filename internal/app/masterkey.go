package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// resealQueues re-seals this node's queues on disk (mail, back-channel logouts) with the active master key and
// returns how many of their items still need a previous key, and how many one that is not configured
// (queue.Queue.Reseal; service.Service.QueuesStale reports both with this node's keys).
func (a *App) resealQueues() (stale, lost int) {
	if a.mailer != nil {
		stale, lost = a.mailer.Reseal()
	}
	if q := a.logoutQueue.Load(); q != nil {
		s, l := q.Reseal()
		stale, lost = stale+s, lost+l
	}
	return stale, lost
}

// ReloadMasterKeys switches the running server to the master keys master and previous (server.master_key and
// server.previous_master_keys, as a configuration reload reads them again on SIGHUP), without a restart: the keyring
// every part of the server uses is replaced in place. It refuses keys that do not include the key in use now (a
// mistyped or wrong key would seal new secrets with a key the other nodes cannot open, or open nothing), and, on a
// shared database, keys the database's key check does not accept, as start-up does.
func (a *App) ReloadMasterKeys(ctx context.Context, master string, previous []string) error {
	c := *a.Cfg
	c.Server.MasterKey, c.Server.PreviousMasterKeys = master, previous
	key, err := masterKey(&c)
	if err != nil {
		return err
	}
	next, err := newSealer(&c, key)
	if err != nil {
		return err
	}
	cur := a.Svc.Sealer
	if slices.Equal(next.KeyIDs(), cur.KeyIDs()) {
		a.Log.Info("master keys reloaded: no change", "key", cur.ActiveKeyID(), "previous", cur.KeyIDs()[1:])
		return nil
	}
	if !slices.Contains(next.KeyIDs(), cur.ActiveKeyID()) {
		return fmt.Errorf("the new keys do not include the key in use (%s); during a rotation it stays in "+
			"server.previous_master_keys until the rotation is complete", cur.ActiveKeyID())
	}
	// Dropping a key while anything stored is still sealed with it (or bound to it) would leave that unopenable.
	if gone := dropped(cur.KeyIDs(), next.KeyIDs()); len(gone) > 0 {
		st, err := a.Svc.RotationStatus(ctx)
		if err != nil {
			return fmt.Errorf("checking what still needs %v: %w", gone, err)
		}
		if st.Stale > 0 {
			return fmt.Errorf("%d secrets still need %v (state %s): keep it in server.previous_master_keys until "+
				"GET /api/master-key says complete", st.Stale, gone, st.State)
		}
	}
	if err := checkSharedKey(ctx, a.Store, next, a.Log, !c.Replicate() && c.SharedStorage()); err != nil {
		return err
	}
	// The queues are on this node's disk, where the leader's re-seal does not reach: they are re-sealed here, with the
	// active key before a key is dropped (an item that could not be moved off a key being dropped refuses the
	// reload: it would be lost) and with the new one before this node reports it (one left behind keeps the rotation
	// reported unfinished: service.Service.QueuesStale).
	if n, _ := a.resealQueues(); n > 0 && len(dropped(cur.KeyIDs(), next.KeyIDs())) > 0 {
		return fmt.Errorf("%d queued messages (mail, back-channel logouts) could not be re-sealed with the active "+
			"master key and still need a key being removed: keep it in server.previous_master_keys (the log says why)", n)
	}
	cur.Replace(next)
	a.resealQueues()
	a.Log.Info("master keys reloaded", "key", cur.ActiveKeyID(), "previous", cur.KeyIDs()[1:])
	if err := a.reportKey(ctx); err != nil && !errors.Is(err, context.Canceled) {
		a.Log.Warn("master key: reporting this node's key (retried)", "error", err)
	}
	return nil
}

// dropped returns the key ids of cur that next leaves out.
func dropped(cur, next []string) []string {
	return slices.DeleteFunc(slices.Clone(cur), func(id string) bool { return slices.Contains(next, id) })
}
