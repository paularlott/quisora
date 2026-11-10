package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// "quisora sign-out" against a running server, as "quisora invite" does (command.go): a gossip
// cluster's data is changed through its nodes (a write made to a stopped node's database belongs to no partition write
// and never reaches another node), and a node-local store belongs to the server that runs on it.
const commandSignOutPath = "/api-internal/command/sign-out"

// commandSignOut is the signed request: one organization (Org) or every one (All).
type commandSignOut struct {
	Org       string `json:"org,omitempty"`
	All       bool   `json:"all,omitempty"`
	Reason    string `json:"reason"`
	APITokens bool   `json:"api_tokens,omitempty"`
	commandSig
}

func (cs *commandSignOut) message() []string {
	return []string{"quisora command: sign-out v1", cs.Org, strconv.FormatBool(cs.All), cs.Reason,
		strconv.FormatBool(cs.APITokens), strconv.FormatInt(cs.At, 10), cs.Nonce}
}

func (m commandModule) signOut(w http.ResponseWriter, r *http.Request) {
	var in commandSignOut
	if !m.accept(w, r, &in) {
		return
	}
	if (in.Org == "") != in.All {
		commandRefuse(w, http.StatusBadRequest, "name one organization, or every organization")
		return
	}
	svc := m.a.Svc
	ctx := service.WithCommand(r.Context(), "sign-out", commandAuth)
	ev, orgID, err := pullSignOut(ctx, svc, service.System, in.Org, service.SignOutOptions{Reason: in.Reason, APITokens: in.APITokens})
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, service.ErrNotFound) {
			status = http.StatusNotFound
		}
		commandRefuse(w, status, err.Error())
		return
	}
	// Everything stamped before has stopped working already; deleting it and telling applications can take a while.
	svc.Background(ctx, service.BackgroundSweep, func(ctx context.Context) {
		if _, err := svc.SweepSignOut(ctx, service.System, orgID, in.APITokens); err != nil {
			m.a.Log.WithError(err).Warn("emergency sign-out: not every ended record could be removed (they no longer work)")
		}
	})
	web.WriteJSON(w, http.StatusOK, ev)
}

// pullSignOut pulls the emergency sign-out of the organization named orgName, or ("") of every organization, as a,
// and returns the event and the organization to sweep ("": every one).
func pullSignOut(ctx context.Context, svc *service.Service, a *service.Actor, orgName string,
	opt service.SignOutOptions) (*model.SignOutEvent, string, error) {
	if orgName == "" {
		ev, err := svc.SignOutServer(ctx, a, opt)
		return ev, "", err
	}
	org, err := svc.OrgByName(ctx, orgName)
	if err != nil {
		return nil, "", fmt.Errorf("%w: no organization %q", service.ErrNotFound, orgName)
	}
	ev, err := svc.SignOutOrg(ctx, a, org.ID, opt)
	return ev, org.ID, err
}

// RemoteSignOut asks the server at server (default: server.public_url) to pull the emergency sign-out of orgName (""
// for every organization). The server removes what it ended in the background.
func RemoteSignOut(ctx context.Context, c *config.Config, server, caFile string, insecure bool, orgName, reason string,
	apiTokens bool) (*model.SignOutEvent, error) {
	if server == "" {
		server = c.Server.PublicURL
	}
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the server must be an https URL, such as https://id.example.com")
	}
	client, err := commandClient(c, caFile, insecure)
	if err != nil {
		return nil, err
	}
	var out model.SignOutEvent
	req := &commandSignOut{Org: orgName, All: orgName == "", Reason: reason, APITokens: apiTokens, commandSig: newCommandSig()}
	if err := postCommand(ctx, c, client, u, commandSignOutPath, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SignOutVia is "quisora sign-out": through the running server when the store is the node's own (BadgerDB or SQLite,
// or any database of a gossip cluster) and a server answers at server (or server.public_url), which removes what it
// ended in the background (remote is then true and the sweep's counts are zero); else into the store directly (a
// shared database, which every node reads, or the store of a stopped node that does not replicate). A gossip
// cluster's data is changed only through a running node.
func SignOutVia(ctx context.Context, c *config.Config, log logger.Logger, server, caFile string, insecure bool, orgName,
	reason string, apiTokens bool) (ev *model.SignOutEvent, swept service.SignOutSweep, remote bool, err error) {
	if server != "" || !c.SharedStorage() || c.Replicate() {
		ev, err = RemoteSignOut(ctx, c, server, caFile, insecure, orgName, reason, apiTokens)
		if err == nil {
			return ev, swept, true, nil
		}
		if server != "" || !errors.Is(err, errServerDown) {
			return nil, swept, false, err
		}
		if c.Replicate() {
			return nil, swept, false, fmt.Errorf("%w: a gossip cluster's data is changed through a running node (start "+
				"the nodes, or a majority of them, and run the command again)", err)
		}
	}
	ev, swept, err = SignOut(ctx, c, log, orgName, reason, apiTokens)
	return ev, swept, false, err
}
