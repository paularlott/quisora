package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// ErrStoreLocked means another process (the running server) holds the node-local store.
var ErrStoreLocked = errors.New("the data store is in use by another process: " +
	"stop the server and run this command again (a badger store cannot be opened twice)")

// InviteUser issues a fresh invitation for the user as the system and returns its URL and expiry. Earlier unused
// invitations of that user stop working. The user may be new (no password yet) or existing (password removed, or
// locked out of everything else).
func InviteUser(ctx context.Context, svc *service.Service, orgName, email string, breakGlass, superAdmin bool) (string, time.Time, error) {
	if superAdmin && !breakGlass {
		return "", time.Time{}, errors.New("--super-admin is a recovery: it needs --break-glass")
	}
	org, err := svc.OrgByName(ctx, strings.ToLower(strings.TrimSpace(orgName)))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("organization %q: %w", orgName, err)
	}
	u, err := svc.FindUserByEmail(ctx, org.ID, email)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("user %q in organization %q: %w", email, org.Name, err)
	}
	if breakGlass {
		return svc.CreateBreakGlassInvite(ctx, u.ID, superAdmin)
	}
	return svc.CreateInvite(ctx, service.System, u.ID)
}

// IssueInvite opens the configured store (as serve does), issues the invitation and closes the store again.
func IssueInvite(ctx context.Context, c *config.Config, log logger.Logger, orgName, email string, breakGlass, superAdmin bool) (string, time.Time, error) {
	key, err := masterKey(c)
	if err != nil {
		return "", time.Time{}, err
	}
	sealer, err := newSealer(c, key)
	if err != nil {
		return "", time.Time{}, err
	}
	st, err := OpenStore(ctx, c)
	if err != nil {
		if c.Storage.Backend == "badgerdb" && strings.Contains(strings.ToLower(err.Error()), "lock") {
			return "", time.Time{}, ErrStoreLocked
		}
		return "", time.Time{}, fmt.Errorf("storage: %w", err)
	}
	defer st.Close()
	store.SetOrigin("cli")
	svc := service.New(c, st, sealer)
	svc.Origin = service.CommandOrigin("invite")
	defer cliAudit(c, svc, log)()
	return InviteUser(ctx, svc, orgName, email, breakGlass, superAdmin)
}

// Bootstrap ("quisora bootstrap") opens the configured store, creates the primary organization, its default tenant
// and its first super admin when they do not exist, and closes the store. It returns the admin's invitation link,
// or "" when everything existed already (a second run does nothing). Serving never does this. In a gossip cluster
// run it on one node, with an empty database: it creates the cluster's data set (cluster.StartNewCluster), which the
// other nodes adopt and copy; a node that already holds a data set is refused.
func Bootstrap(ctx context.Context, c *config.Config, log logger.Logger) (user, link string, err error) {
	st, sealer, err := openForCommand(ctx, c)
	if err != nil {
		return "", "", err
	}
	defer st.Close()
	svc := service.New(c, st, sealer)
	svc.Origin = service.CommandOrigin("bootstrap")
	defer cliAudit(c, svc, log)()
	if c.Cluster.Bind != "" {
		// A node that already holds a data set is refused before anything is written (StartNewCluster would, after).
		if err := cluster.CheckNewCluster(c.Server.DataDir, st); err != nil {
			return "", "", err
		}
		// Only an empty database becomes a new cluster's first node: one that holds data belongs to a cluster
		// already (or holds part of a copy), and declaring it synced now would make whatever it holds the
		// cluster's. A second run on the first node finds everything there and changes nothing.
		empty, err := storeEmpty(ctx, st)
		if err != nil {
			return "", "", err
		}
		if !empty {
			if _, err := svc.PrimaryOrg(ctx); err == nil {
				return "", "", nil // already set up
			}
			return "", "", errors.New("this node's database already holds data but no primary organization (a copy " +
				"from a cluster that did not finish?): the first node of a new cluster starts with an empty database. " +
				"A node joining a cluster needs no bootstrap: start it with an empty database and it copies everything")
		}
	}
	u, link, err := svc.Bootstrap(ctx, c.Server.BootstrapAdmin)
	if err != nil || u == nil {
		return "", "", err
	}
	if c.Cluster.Bind != "" {
		// The first node of a new gossip cluster: its records become the first writes of their partitions and its data
		// is the cluster's (a gossip node whose records no partition write made refuses to start).
		if err := cluster.StartNewCluster(ctx, c.Server.DataDir, st); err != nil {
			return "", "", err
		}
	}
	return u.Email, link, nil
}

// storeEmpty reports whether st holds no records (node-local short-lived state and the node's own audit events aside: a
// gossip node records those whether it holds a data set or not).
func storeEmpty(ctx context.Context, st store.Store) (bool, error) {
	for _, k := range model.Kinds() {
		if k == model.KindEphemeral || k == model.KindAudit {
			continue
		}
		n, err := st.Count(ctx, k, "")
		if err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	return true, nil
}

// SetPrimary ("quisora set-primary") opens the configured store, makes orgName the primary organization with the user
// email as its super admin (service.SetPrimaryOrg), and closes the store. It returns the previous primary's name and
// the usernames of its super admins, now administrators.
func SetPrimary(ctx context.Context, c *config.Config, log logger.Logger, orgName, email string) (string, []string, error) {
	key, err := masterKey(c)
	if err != nil {
		return "", nil, err
	}
	sealer, err := newSealer(c, key)
	if err != nil {
		return "", nil, err
	}
	st, err := OpenStore(ctx, c)
	if err != nil {
		if c.Storage.Backend == "badgerdb" && strings.Contains(strings.ToLower(err.Error()), "lock") {
			return "", nil, ErrStoreLocked
		}
		return "", nil, fmt.Errorf("storage: %w", err)
	}
	defer st.Close()
	store.SetOrigin("cli")
	svc := service.New(c, st, sealer)
	svc.Origin = service.CommandOrigin("set-primary")
	defer cliAudit(c, svc, log)()
	return SetPrimaryOrg(ctx, svc, orgName, email)
}

// SetPrimaryOrg makes the organization named orgName primary with the user email as its super admin, and returns the
// previous primary's name ("" when this finished an interrupted change that no longer says which it was) and the
// emails of its super admins, now administrators.
func SetPrimaryOrg(ctx context.Context, svc *service.Service, orgName, email string) (string, []string, error) {
	org, err := svc.OrgByName(ctx, orgName)
	if err != nil {
		return "", nil, fmt.Errorf("no organization %q", orgName)
	}
	u, err := svc.FindUserByEmail(ctx, org.ID, email)
	if err != nil {
		return "", nil, fmt.Errorf("no user %q in organization %q", email, org.Name)
	}
	old, demoted, err := svc.SetPrimaryOrg(ctx, org.ID, u.ID)
	if err != nil {
		return "", nil, err
	}
	names := make([]string, len(demoted))
	for i, d := range demoted {
		names[i] = d.Email
	}
	if old == nil { // an interrupted change finished: nothing says which organization was primary
		return "", names, nil
	}
	return old.Name, names, nil
}
