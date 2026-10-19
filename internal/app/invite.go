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
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// ErrStoreLocked means another process (the running server) holds the node-local store.
var ErrStoreLocked = errors.New("the data store is in use by another process: " +
	"stop the server and run this command again (a badger store cannot be opened twice)")

// InviteUser issues a fresh invitation for the user as the system and returns its URL and expiry. Earlier unused
// invitations of that user stop working. The user may be new (no password yet) or existing (password removed, or
// locked out of everything else).
func InviteUser(ctx context.Context, svc *service.Service, orgName, email string) (string, time.Time, error) {
	org, err := svc.OrgByName(ctx, strings.ToLower(strings.TrimSpace(orgName)))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("organization %q: %w", orgName, err)
	}
	u, err := svc.FindUserByEmail(ctx, org.ID, email)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("user %q in organization %q: %w", email, org.Name, err)
	}
	return svc.CreateInvite(ctx, service.System, u.ID)
}

// IssueInvite opens the configured store (as serve does), issues the invitation and closes the store again.
func IssueInvite(ctx context.Context, c *config.Config, log logger.Logger, orgName, email string) (string, time.Time, error) {
	key, err := masterKey(c)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("master key: %w", err)
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
	return InviteUser(ctx, svc, orgName, email)
}

// Bootstrap ("quisora bootstrap") opens the configured store, creates the primary organization, its default tenant
// and its first super admin when they do not exist, and closes the store. It returns the admin's invitation link,
// or "" when everything existed already (a second run does nothing). Serving never does this. In a gossip cluster
// run it for the first node, before the others start; a run anywhere else changes nothing that exists.
func Bootstrap(ctx context.Context, c *config.Config, log logger.Logger) (user, link string, err error) {
	st, sealer, err := openForCommandCreatingKey(ctx, c)
	if err != nil {
		return "", "", err
	}
	defer st.Close()
	svc := service.New(c, st, sealer)
	svc.Origin = service.CommandOrigin("bootstrap")
	defer cliAudit(c, svc, log)()
	if c.Cluster.Bind != "" {
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
		// The first node of a new gossip cluster: its data is the cluster's, as of now (a gossip node whose data
		// has no sync time refuses to start).
		if err := cluster.MarkSynced(c.Server.DataDir, st.FeedID()); err != nil {
			return "", "", err
		}
	}
	return u.Email, link, nil
}

// storeEmpty reports whether st holds no records (node-local short-lived state aside).
func storeEmpty(ctx context.Context, st store.Store) (bool, error) {
	for _, k := range model.Kinds() {
		if k == model.KindEphemeral {
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

// openForCommandCreatingKey is openForCommand for the first command a new server runs: it creates the master key in
// the data directory when none is configured (as the first start used to).
func openForCommandCreatingKey(ctx context.Context, c *config.Config) (store.Store, *secure.Sealer, error) {
	if _, err := masterKey(c); err != nil {
		return nil, nil, fmt.Errorf("master key: %w", err)
	}
	return openForCommand(ctx, c)
}

// SetPrimary ("quisora set-primary") opens the configured store, makes orgName the primary organization with the user
// email as its super admin (service.SetPrimaryOrg), and closes the store. It returns the previous primary's name and
// the usernames of its super admins, now administrators.
func SetPrimary(ctx context.Context, c *config.Config, log logger.Logger, orgName, email string) (string, []string, error) {
	key, err := masterKey(c)
	if err != nil {
		return "", nil, fmt.Errorf("master key: %w", err)
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
	return old.Name, names, nil
}
