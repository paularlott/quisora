package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// resealQueues re-seals this node's queues on disk (mail, back-channel logouts) with the active master key.
func (a *App) resealQueues() {
	if a.mailer != nil {
		a.mailer.Reseal()
	}
	if a.logoutQueue != nil {
		a.logoutQueue.Reseal()
	}
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
	if dropped := slices.DeleteFunc(cur.KeyIDs(), func(id string) bool { return slices.Contains(next.KeyIDs(), id) }); len(dropped) > 0 {
		st, err := a.Svc.RotationStatus(ctx)
		if err != nil {
			return fmt.Errorf("checking what still needs %v: %w", dropped, err)
		}
		if st.Stale > 0 || st.LegacyGrants > 0 {
			return fmt.Errorf("%d secrets and %d refresh grants still need %v (state %s): keep it in "+
				"server.previous_master_keys until GET /api/master-key says complete", st.Stale, st.LegacyGrants,
				dropped, st.State)
		}
	}
	if err := checkSharedKey(ctx, a.Store, next, a.Log, !c.Replicate() && c.SharedStorage()); err != nil {
		return err
	}
	// The queues are on this node's disk, where the leader's re-seal does not reach: they are re-sealed here, with the
	// active key before a key is dropped and with the new one before this node reports it.
	a.resealQueues()
	cur.Replace(next)
	a.resealQueues()
	a.Log.Info("master keys reloaded", "key", cur.ActiveKeyID(), "previous", cur.KeyIDs()[1:])
	if err := a.Svc.ReportMasterKey(ctx, a.Node.ID()); err != nil && !errors.Is(err, context.Canceled) {
		a.Log.Warn("master key: reporting this node's key (retried)", "error", err)
	}
	return nil
}
