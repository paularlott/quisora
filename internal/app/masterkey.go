package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// ReloadMasterKeys switches the running server to the master keys master and previous (server.master_key and
// server.previous_master_keys, as config.LoadMasterKeys reads them again on SIGHUP), without a restart: the keyring
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
	if !c.Replicate() && c.SharedStorage() {
		if err := checkSharedKey(ctx, a.Store, next, a.Log); err != nil {
			return err
		}
	}
	cur.Replace(next)
	a.Log.Info("master keys reloaded", "key", cur.ActiveKeyID(), "previous", cur.KeyIDs()[1:])
	if err := a.Svc.ReportMasterKey(ctx, a.Node.ID()); err != nil && !errors.Is(err, context.Canceled) {
		a.Log.Warn("master key: reporting this node's key (retried)", "error", err)
	}
	return nil
}
