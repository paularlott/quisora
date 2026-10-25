// Package durable writes files that must survive a crash or a power loss whole or not at all.
package durable

import (
	"os"
	"path/filepath"
)

// WriteFile replaces path with b durably: b is written to tmp (in path's directory) and synced, tmp is renamed over
// path, and the directory is synced. After a crash path holds its old contents or b, never part of b; a tmp a crash
// left behind is replaced by the next write.
func WriteFile(tmp, path string, b []byte) error {
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	// Load-bearing: the rename is durable only once the directory is synced.
	return SyncDir(filepath.Dir(path))
}

// SyncDir syncs directory dir, making the names created, renamed or removed in it durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
