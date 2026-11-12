package app

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/paularlott/quisora/internal/config"
)

// ApplyLimits switches the running node to the limits l and the denied networks deny (server.deny_networks) of a
// configuration reload (SIGHUP, or the cluster-wide reload), without a restart. Each limit is read where it is used,
// at each use (config.LiveLimits), so the next request applies the new one; nothing counted so far is reset (sign-in
// attempts, failed passwords, requests in flight), so tightening a limit mid-attack hands nobody a fresh budget. The
// two limits that size the node at start-up, limits.password_workers and limits.ephemeral_mb, keep their value until
// a restart. Both l and deny are checked already (config.CheckedLimits, config.DeniedNetworks). It returns what
// changed, for the reload's report and log.
func (a *App) ApplyLimits(l config.Limits, deny []netip.Prefix) []string {
	cur := a.Cfg.LiveLimits()
	var restart []string
	if l.PasswordWorkers != cur.PasswordWorkers {
		restart = append(restart, "limits.password_workers")
		l.PasswordWorkers = cur.PasswordWorkers
	}
	if l.EphemeralMB != cur.EphemeralMB {
		restart = append(restart, "limits.ephemeral_mb")
		l.EphemeralMB = cur.EphemeralMB
	}
	changes := config.LimitChanges(cur, l)
	a.Cfg.SetLiveLimits(l)
	if before := a.Server.DenyNetworks(); !slices.Equal(before, deny) {
		a.Server.SetDenyNetworks(deny)
		changes = append(changes, fmt.Sprintf("server.deny_networks %v", deny))
	}
	if len(restart) > 0 {
		a.Log.Warn("changed limits apply only after a restart", "limits", restart)
		for _, n := range restart {
			changes = append(changes, n+" changed: applies after a restart")
		}
	}
	return changes
}
