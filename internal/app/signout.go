package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// SignOut is "quisora sign-out" written into the store itself: the emergency sign-out of one organization (orgName) or
// ("") the whole server, from the command line with the master key, for when the console cannot be used. It then
// sweeps what it ended. A gossip node's store is refused: what is written there outside the partition protocol would
// never reach the other nodes (SignOutVia asks a running node instead).
func SignOut(ctx context.Context, c *config.Config, log logger.Logger, orgName, reason string, apiTokens bool) (*model.SignOutEvent, service.SignOutSweep, error) {
	var none service.SignOutSweep
	if c.Replicate() {
		return nil, none, errors.New("a gossip cluster's data is changed through a running node: the sign-out is asked " +
			"of one (quisora sign-out does so, at server.public_url or --server)")
	}
	key, err := masterKey(c)
	if err != nil {
		return nil, none, err
	}
	sealer, err := newSealer(c, key)
	if err != nil {
		return nil, none, err
	}
	st, err := OpenStore(ctx, c)
	if err != nil {
		if c.Storage.Backend == "badgerdb" && strings.Contains(strings.ToLower(err.Error()), "lock") {
			return nil, none, ErrStoreLocked
		}
		return nil, none, fmt.Errorf("storage: %w", err)
	}
	defer st.Close()
	store.SetOrigin("cli")
	svc := service.New(c, st, sealer)
	svc.Origin = service.CommandOrigin("sign-out")
	defer cliAudit(c, svc, log)()
	// The system acts, named as the audit log names a command's runner.
	a := *service.System
	a.Name = "cli:" + svc.Origin["os_user"] + "@" + svc.Origin["host"]
	ev, orgID, err := pullSignOut(ctx, svc, &a, orgName, service.SignOutOptions{Reason: reason, APITokens: apiTokens})
	if err != nil {
		return nil, none, err
	}
	n, err := svc.SweepSignOut(ctx, &a, orgID, apiTokens)
	return ev, n, err
}
