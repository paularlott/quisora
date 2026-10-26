package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// "quisora invite" against a running server. A node-local store (BadgerDB, SQLite) belongs to the node that runs on
// it, so the command asks that server to issue the invitation instead of writing to the store itself (command.go).
const commandInvitePath = "/api-internal/command/invite"

// commandInvite is the signed request.
type commandInvite struct {
	Org        string `json:"org"`
	Email      string `json:"email"`
	BreakGlass bool   `json:"break_glass,omitempty"`
	SuperAdmin bool   `json:"super_admin,omitempty"`
	commandSig
}

func (ci *commandInvite) message() []string {
	return []string{"quisora command: invite v2", ci.Org, ci.Email, strconv.FormatBool(ci.BreakGlass), strconv.FormatBool(ci.SuperAdmin),
		strconv.FormatInt(ci.At, 10), ci.Nonce}
}

type commandInviteReply struct {
	Link    string    `json:"link"`
	Expires time.Time `json:"expires"`
}

func (m commandModule) invite(w http.ResponseWriter, r *http.Request) {
	var in commandInvite
	if !m.accept(w, r, &in) {
		return
	}
	link, expires, err := InviteUser(service.WithCommand(r.Context(), "invite", commandAuth), m.a.Svc, in.Org, in.Email, in.BreakGlass, in.SuperAdmin)
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, service.ErrNotFound) {
			status = http.StatusNotFound
		}
		commandRefuse(w, status, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusOK, commandInviteReply{Link: link, Expires: expires})
}

// RemoteInvite asks the server at server (default: server.public_url) to issue the invitation, signing the request
// with the configured master key (commandClient says which certificates it trusts).
func RemoteInvite(ctx context.Context, c *config.Config, server, caFile string, insecure bool, orgName, email string,
	breakGlass, superAdmin bool) (string, time.Time, error) {
	if server == "" {
		server = c.Server.PublicURL
	}
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", time.Time{}, fmt.Errorf("the server must be an https URL, such as https://id.example.com")
	}
	client, err := commandClient(c, caFile, insecure)
	if err != nil {
		return "", time.Time{}, err
	}
	var out commandInviteReply
	req := &commandInvite{Org: orgName, Email: email, BreakGlass: breakGlass, SuperAdmin: superAdmin, commandSig: newCommandSig()}
	if err := postCommand(ctx, c, client, u, commandInvitePath, req, &out); err != nil {
		return "", time.Time{}, err
	}
	if out.Link == "" {
		return "", time.Time{}, fmt.Errorf("server %s: unexpected answer", u.Host)
	}
	return out.Link, out.Expires, nil
}

// Invite is "quisora invite": through the running server when the store is the node's own (BadgerDB or SQLite, or
// any database of a gossip cluster) and a server answers at server (or server.public_url); else into the store
// directly (a shared database, which every node reads, or the store of a stopped node). A gossip cluster's data is
// changed only through a running node: a write that bypassed the partition protocol would reach no other node.
func Invite(ctx context.Context, c *config.Config, log logger.Logger, server, caFile string, insecure bool, orgName,
	email string, breakGlass, superAdmin bool) (link string, expires time.Time, how string, err error) {
	if server != "" || !c.SharedStorage() || c.Replicate() {
		link, expires, err = RemoteInvite(ctx, c, server, caFile, insecure, orgName, email, breakGlass, superAdmin)
		if err == nil {
			return link, expires, "the running server", nil
		}
		if server != "" || !errors.Is(err, errServerDown) {
			return "", time.Time{}, "", err
		}
		if c.Replicate() {
			return "", time.Time{}, "", fmt.Errorf("%w: a gossip cluster's data is changed through a running node (start the "+
				"nodes, or a majority of them, and run the command again)", err)
		}
	}
	link, expires, err = IssueInvite(ctx, c, log, orgName, email, breakGlass, superAdmin)
	return link, expires, "the store", err
}
