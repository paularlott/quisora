package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// "quisora set-primary" against a running server: a gossip cluster's data is changed through its nodes (a write made
// to a stopped node's database would belong to no partition write and never reach another node), so the command asks
// a running node, as "quisora invite" does (command.go).
const commandSetPrimaryPath = "/api-internal/command/set-primary"

type commandSetPrimary struct {
	Org   string `json:"org"`
	Email string `json:"email"`
	commandSig
}

func (cs *commandSetPrimary) message() []string {
	return []string{"quisora command: set-primary v1", cs.Org, cs.Email, fmt.Sprint(cs.At), cs.Nonce}
}

type commandSetPrimaryReply struct {
	Previous string   `json:"previous"`
	Demoted  []string `json:"demoted,omitempty"`
}

func (m commandModule) setPrimary(w http.ResponseWriter, r *http.Request) {
	var in commandSetPrimary
	if !m.accept(w, r, &in) {
		return
	}
	prev, demoted, err := SetPrimaryOrg(service.WithCommand(r.Context(), "set-primary", commandAuth), m.a.Svc, in.Org, in.Email)
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, service.ErrNotFound) {
			status = http.StatusNotFound
		}
		commandRefuse(w, status, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusOK, commandSetPrimaryReply{Previous: prev, Demoted: demoted})
}

// RemoteSetPrimary asks the server at server (default: server.public_url) to make orgName primary.
func RemoteSetPrimary(ctx context.Context, c *config.Config, server, caFile string, insecure bool, orgName,
	email string) (string, []string, error) {
	if server == "" {
		server = c.Server.PublicURL
	}
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", nil, fmt.Errorf("the server must be an https URL, such as https://id.example.com")
	}
	client, err := commandClient(c, caFile, insecure)
	if err != nil {
		return "", nil, err
	}
	var out commandSetPrimaryReply
	req := &commandSetPrimary{Org: orgName, Email: email, commandSig: newCommandSig()}
	if err := postCommand(ctx, c, client, u, commandSetPrimaryPath, req, &out); err != nil {
		return "", nil, err
	}
	return out.Previous, out.Demoted, nil
}

// SetPrimaryVia is "quisora set-primary": through the running server in a gossip cluster (and when --server names
// one), else into the store itself (a shared database, which every node reads, or a stopped node's own store).
func SetPrimaryVia(ctx context.Context, c *config.Config, log logger.Logger, server, caFile string, insecure bool, orgName,
	email string) (string, []string, error) {
	if server != "" || c.Replicate() {
		prev, demoted, err := RemoteSetPrimary(ctx, c, server, caFile, insecure, orgName, email)
		if err == nil || server != "" || !errors.Is(err, errServerDown) || !c.Replicate() {
			return prev, demoted, err
		}
		return "", nil, fmt.Errorf("%w: a gossip cluster's data is changed through a running node (start the nodes, or a "+
			"majority of them, and run the command again)", err)
	}
	return SetPrimary(ctx, c, log, orgName, email)
}
