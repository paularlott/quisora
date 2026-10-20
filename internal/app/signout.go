package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// SignOut is "quisora sign-out": the emergency sign-out of one organization (orgName) or ("") the whole server, from
// the command line with the master key, for when the console cannot be used. It then sweeps what it ended.
func SignOut(ctx context.Context, c *config.Config, log logger.Logger, orgName, reason string, apiTokens bool) (*model.SignOutEvent, service.SignOutSweep, error) {
	var none service.SignOutSweep
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
	opt := service.SignOutOptions{Reason: reason, APITokens: apiTokens}
	var ev *model.SignOutEvent
	orgID := ""
	if orgName == "" {
		ev, err = svc.SignOutServer(ctx, &a, opt)
	} else {
		org, gerr := svc.OrgByName(ctx, orgName)
		if gerr != nil {
			return nil, none, fmt.Errorf("no organization %q", orgName)
		}
		orgID = org.ID
		ev, err = svc.SignOutOrg(ctx, &a, org.ID, opt)
	}
	if err != nil {
		return nil, none, err
	}
	n, err := svc.SweepSignOut(ctx, &a, orgID, apiTokens)
	return ev, n, err
}
