package app

import (
	"context"
	"strconv"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/queue"
	"github.com/paularlott/quisora/internal/service"
)

// lostItemAge is how old an item of this node's queues (mail, back-channel logouts) that no configured master key
// opens is when the daily sweep gives it up: older than any link a queued email carries (an invitation,
// service.InviteTTL) and than either queue's retries, so it would be worthless even if its key came back. A younger
// one stays, to go out if its key is put back in server.previous_master_keys. Such items hold nothing back meanwhile:
// they need none of the configured keys (queue.Queue.Reseal).
const lostItemAge = service.InviteTTL + 24*time.Hour

// purgeLostDaily runs the sweep of lost items (purgeLostQueueItems) on this node's queues, once a day from shortly
// after the start, until ctx ends.
func (a *App) purgeLostDaily(ctx context.Context) {
	t := time.NewTimer(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, _, err := a.purgeLostQueueItems(ctx, time.Now().Add(-lostItemAge)); err != nil {
			a.Log.Warn("queues: giving up items sealed with a lost master key", "error", err)
		}
		t.Reset(24 * time.Hour)
	}
}

// purgeLostQueueItems removes from this node's queues the items no configured master key opens that were queued
// before before, as its delivery workers go on (queue.Queue.PurgeLost). When it removed any (or failed) it records it
// in the audit log (queue.purge_lost: the items, invitations and reset links among them, are gone for good) and
// reports this node's master keys again, with the warning about them gone.
func (a *App) purgeLostQueueItems(ctx context.Context, before time.Time) (mail, logout int, err error) {
	sealer := a.Svc.Sealer
	if a.mailer != nil {
		mail, err = a.mailer.PurgeLost(before)
	} else { // no SMTP server: no worker on the directory, which may still hold mail from before
		mail, err = queue.PurgeLost(a.Cfg.DataPath(config.DirMailQueue), sealer, before)
	}
	if err == nil {
		if q := a.logoutQueue.Load(); q != nil {
			logout, err = q.PurgeLost(before)
		} else {
			logout, err = queue.PurgeLost(a.Cfg.DataPath(config.DirLogoutQueue), sealer, before)
		}
	}
	if mail+logout == 0 && err == nil {
		return 0, 0, nil
	}
	detail := map[string]string{"emails": strconv.Itoa(mail), "logouts": strconv.Itoa(logout), "node": a.Node.ID(),
		"queued_before": before.UTC().Format(time.RFC3339)}
	if err != nil {
		detail["error"] = err.Error()
	}
	org := ""
	if p, perr := a.Svc.PrimaryOrg(ctx); perr == nil {
		org = p.ID
	}
	a.Svc.Audit(ctx, service.System, org, "queue.purge_lost", "queues", detail)
	if rerr := a.reportKey(context.WithoutCancel(ctx)); rerr != nil {
		a.Log.Warn("master key: reporting this node's key (retried)", "error", rerr)
	}
	return mail, logout, err
}
