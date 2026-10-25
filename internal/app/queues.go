package app

import (
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/queue"
)

// PurgeLostQueueItems is "quisora queue purge-lost": it removes from this node's mail and back-channel logout queues
// the items sealed with a master key that is not configured (queue.PurgeLost), and returns how many of each.
func PurgeLostQueueItems(c *config.Config) (mail, logout int, err error) {
	key, err := masterKey(c)
	if err != nil {
		return 0, 0, err
	}
	sealer, err := newSealer(c, key)
	if err != nil {
		return 0, 0, err
	}
	if mail, err = queue.PurgeLost(c.DataPath(config.DirMailQueue), sealer); err != nil {
		return mail, 0, err
	}
	logout, err = queue.PurgeLost(c.DataPath(config.DirLogoutQueue), sealer)
	return mail, logout, err
}
