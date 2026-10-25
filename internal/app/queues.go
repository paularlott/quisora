package app

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/queue"
	"github.com/paularlott/quisora/internal/service"
)

// ErrServerRunning means a server answers on this node's server.listen: its queue workers own the queue files.
var ErrServerRunning = errors.New("a server answers on this node's server.listen: stop it, then run this command again")

// PurgeLostQueueItems is "quisora queue purge-lost": it removes from this node's mail and back-channel logout queues
// the items sealed with a master key that is not configured (queue.PurgeLost), returns how many of each, and records
// it in the audit log (queue.purge_lost: the items, invitations and reset links among them, are gone for good). It
// refuses while the node runs: its workers would be delivering the same files.
func PurgeLostQueueItems(ctx context.Context, c *config.Config, log logger.Logger) (mail, logout int, err error) {
	if listening(c.Server.Listen) {
		return 0, 0, ErrServerRunning
	}
	st, sealer, err := openForCommand(ctx, c) // a BadgerDB store the node holds is refused here too
	if err != nil {
		return 0, 0, err
	}
	defer st.Close()
	svc := service.New(c, st, sealer)
	svc.Origin = service.CommandOrigin("queue purge-lost")
	defer cliAudit(c, svc, log)()
	if mail, err = queue.PurgeLost(c.DataPath(config.DirMailQueue), sealer); err == nil {
		logout, err = queue.PurgeLost(c.DataPath(config.DirLogoutQueue), sealer)
	}
	detail := map[string]string{"emails": strconv.Itoa(mail), "logouts": strconv.Itoa(logout)}
	if err != nil {
		detail["error"] = err.Error()
	}
	org := ""
	if p, perr := svc.PrimaryOrg(ctx); perr == nil {
		org = p.ID
	}
	svc.Audit(ctx, service.System, org, "queue.purge_lost", "queues", detail)
	return mail, logout, err
}

// listening reports whether something answers on listen (host:port; an empty or wildcard host is this machine).
func listening(listen string) bool {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
