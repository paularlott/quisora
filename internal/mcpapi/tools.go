package mcpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/paularlott/mcp"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/web"
)

// The tools: reads, and the changes an administrator makes day to day. Each is one management API request of the
// organization (call), so its permission checks, validation and audit events are the API's. Left out on purpose:
// roles, deleting anything, locking out, removing a password or an authenticator (those need a recent
// re-authentication in the console anyway), applications, tenants, providers and the organization's settings.
func (m *Module) registerTools() {
	userID := mcp.String("user_id", "The user's id (from search_users)", mcp.Required())
	groupID := mcp.String("group_id", "The group's id (from list_groups)", mcp.Required())
	offset := mcp.Integer("offset", "How many results to skip, for the next page")
	limit := mcp.Integer("limit", "How many results to return: 25 unless given, at most 100")
	read := func(name, title, desc string, params ...mcp.Parameter) *mcp.ToolBuilder {
		return mcp.NewTool(name, desc, params...).Title(title).ReadOnly().OpenWorld(false)
	}

	// --- reads ---

	m.mcp.RegisterTool(read("search_users", "Search users",
		"Find the organization's enabled users (disabled ones too with include_disabled). query matches the start "+
			"of a username, email address, full name or family name (or, when nothing matches by name, a whole tag "+
			"such as dept:finance). Each user's active says whether they are enabled, and can_manage whether you "+
			"may change them.",
		mcp.String("query", "What to search for; empty lists everyone"),
		mcp.String("role", "Only users with this role: user, manager, admin or super_admin"),
		mcp.Boolean("include_disabled", "true: disabled users too; otherwise enabled users only"),
		offset, limit,
	), func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
		q := page(req)
		set(q, "q", req.StringOr("query", ""))
		set(q, "role", req.StringOr("role", ""))
		// Enabled users unless asked otherwise: a client that fills in the flag with false (or leaves it out) gets
		// the users it most likely means, never an empty list of disabled ones.
		if all, err := req.Bool("include_disabled"); err != nil || !all {
			q.Set("active", "1")
		}
		return m.call(ctx, http.MethodGet, "/users", q, nil, nil), nil
	})

	m.mcp.RegisterTool(read("get_user", "Get user",
		"A user's details: profile, status, groups, sign-in methods, and what you may change about them.", userID,
	), func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
		return m.call(ctx, http.MethodGet, "/users/"+arg(req, "user_id"), nil, nil, nil), nil
	})

	m.mcp.RegisterTool(read("list_user_sessions", "List user's sessions",
		"A user's signed-in browser sessions: when each started and was last seen, from where, and how they signed in.",
		userID,
	), func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
		return m.call(ctx, http.MethodGet, "/users/"+arg(req, "user_id")+"/sessions", nil, nil, nil), nil
	})

	m.mcp.RegisterTool(read("list_groups", "List groups",
		"The organization's groups, with how many members each has. query matches the start of a group's name.",
		mcp.String("query", "What to search for; empty lists every group"),
		offset, limit,
	), func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
		q := page(req)
		set(q, "q", req.StringOr("query", ""))
		return m.call(ctx, http.MethodGet, "/groups", q, nil, nil), nil
	})

	m.mcp.RegisterTool(read("list_group_members", "List group members",
		"The members of a group: each one's id, username, name, email address and role.", groupID, offset, limit,
	), func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
		return m.call(ctx, http.MethodGet, "/groups/"+arg(req, "group_id")+"/members", page(req), nil, nil), nil
	})

	m.mcp.RegisterTool(read("query_audit_log", "Query audit log",
		"The organization's audit log, newest first: who did what to whom, when, from where, and whether it succeeded.",
		mcp.String("query", "Matches the start of the actor's or the target's name"),
		mcp.String("action", "Only this action, such as user.update"),
		mcp.String("action_group", "Only actions starting with this, such as user. or group."),
		mcp.String("outcome", "Only this outcome: success or failure"),
		mcp.String("from", "Only events at or after this time (RFC 3339, such as 2026-10-21T09:00:00Z)"),
		mcp.String("to", "Only events before this time (RFC 3339)"),
		offset, limit,
	), func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
		q := page(req)
		for param, name := range map[string]string{"query": "q", "action": "action", "action_group": "action_group",
			"outcome": "outcome", "from": "from", "to": "to"} {
			set(q, name, req.StringOr(param, ""))
		}
		return m.call(ctx, http.MethodGet, "/audit", q, nil, nil), nil
	})

	// --- changes ---

	m.mcp.RegisterTool(mcp.NewTool("create_user",
		"Create a user with the default role (user): their given name, and an email address or a username, or "+
			"both. With send_invitation, the new user is emailed a link to set up how they sign in.",
		mcp.String("given_name", "Their given (first) name", mcp.Required()),
		mcp.String("email", "Their email address"),
		mcp.String("username", "Their username"),
		mcp.String("family_name", "Their family (last) name"),
		mcp.Boolean("send_invitation", "Email them an invitation to set up their sign-in (needs an email address)"),
	).Title("Create user").Destructive(false).OpenWorld(false),
		func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
			body := map[string]any{}
			for _, k := range []string{"given_name", "email", "username", "family_name"} {
				if v := req.StringOr(k, ""); v != "" {
					body[k] = v
				}
			}
			if req.BoolOr("send_invitation", false) {
				body["invite"] = map[string]bool{"email": true}
			}
			return m.call(ctx, http.MethodPost, "/users", nil, body, func(v map[string]any) {
				if inv, ok := v["invite"].(map[string]any); ok {
					withoutLink(inv)
				}
			}), nil
		})

	m.mcp.RegisterTool(mcp.NewTool("disable_user",
		"Disable a user: they can no longer sign in, and their sessions and applications' access end at once. "+
			"Disabling an administrator needs a recent re-authentication in the admin console and is refused here.",
		userID,
		mcp.String("reason", "Why, for the record (shown on their profile)"),
	).Title("Disable user").Destructive(true).Idempotent().OpenWorld(false),
		func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
			body := map[string]any{"active": false}
			if v := req.StringOr("reason", ""); v != "" {
				body["status_reason"] = v
			}
			return m.call(ctx, http.MethodPatch, "/users/"+arg(req, "user_id"), nil, body, nil), nil
		})

	m.mcp.RegisterTool(mcp.NewTool("enable_user", "Enable a disabled user, so they can sign in again.", userID).
		Title("Enable user").Destructive(false).Idempotent().OpenWorld(false),
		func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
			return m.call(ctx, http.MethodPatch, "/users/"+arg(req, "user_id"), nil, map[string]any{"active": true}, nil), nil
		})

	m.mcp.RegisterTool(mcp.NewTool("add_group_member", "Add a user to a group.", groupID, userID).
		Title("Add group member").Destructive(false).Idempotent().OpenWorld(false),
		func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
			return m.call(ctx, http.MethodPut, "/groups/"+arg(req, "group_id")+"/members/"+arg(req, "user_id"), nil, nil, nil), nil
		})

	m.mcp.RegisterTool(mcp.NewTool("remove_group_member", "Remove a user from a group.", groupID, userID).
		Title("Remove group member").Destructive(true).Idempotent().OpenWorld(false),
		func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
			return m.call(ctx, http.MethodDelete, "/groups/"+arg(req, "group_id")+"/members/"+arg(req, "user_id"), nil, nil, nil), nil
		})

	m.mcp.RegisterTool(mcp.NewTool("send_invitation",
		"Email a user a new invitation link: for a new user to set up how they sign in, or to reset the sign-in of "+
			"someone who lost it. When they accept it, it replaces their password and other ways of signing in, and "+
			"any earlier invitation stops working. One for another manager or administrator needs a recent "+
			"re-authentication in the admin console and is refused here.",
		userID,
	).Title("Send invitation").Destructive(true).OpenWorld(true),
		func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
			return m.call(ctx, http.MethodPost, "/users/"+arg(req, "user_id")+"/invite", nil, map[string]bool{"email": true}, withoutLink), nil
		})

	m.mcp.RegisterTool(mcp.NewTool("sign_out_user",
		"Sign a user out everywhere: every browser session ends, and applications are told to sign them out.",
		userID,
	).Title("Sign out user").Destructive(true).Idempotent().OpenWorld(false),
		func(ctx context.Context, req *mcp.ToolRequest) (*mcp.ToolResponse, error) {
			return m.call(ctx, http.MethodDelete, "/users/"+arg(req, "user_id")+"/sessions", nil, nil, nil), nil
		})
}

// withoutLink removes the link from an invitation result: it signs its holder in as the user, and an AI client's
// transcript is no place for it. The user has it by email.
func withoutLink(inv map[string]any) {
	if link, ok := inv["url"].(string); ok {
		delete(inv, "url")
		if link != "" { // none when the invitation could not be issued
			inv["link"] = "not shown to AI clients; open the user in the admin console to share one"
		}
	}
}

// arg is a path segment from an id argument: "-" (found nowhere) for anything that is not an id, so an argument
// never reaches another route.
func arg(req *mcp.ToolRequest, name string) string {
	if v := req.StringOr(name, ""); model.IsID(v) {
		return v
	}
	return "-"
}

// page is the query of a list: offset and limit when given.
func page(req *mcp.ToolRequest) url.Values {
	q := url.Values{}
	for _, k := range []string{"offset", "limit"} {
		if n, err := req.Int(k); err == nil && n > 0 {
			q.Set(k, strconv.Itoa(n))
		}
	}
	return q
}

func set(q url.Values, k, v string) {
	if v = strings.TrimSpace(v); v != "" {
		q.Set(k, v)
	}
}

// call makes management API request method path (under the organization's /api/orgs/<id>) with query q and JSON body
// for the actor of ctx, through the API's own handler, and turns its answer into the tool's result: the JSON it
// answered (edited by edit, when given), or a tool error with the API's message.
func (m *Module) call(ctx context.Context, method, path string, q url.Values, body any, edit func(map[string]any)) *mcp.ToolResponse {
	a := actorOf(ctx)
	if a == nil {
		return mcp.NewToolResponseError("Not signed in.")
	}
	target := "/api/orgs/" + url.PathEscape(a.OrgID) + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	var rd io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return mcp.NewToolResponseError("The request could not be encoded.")
		}
		rd = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return mcp.NewToolResponseError("The request could not be made.")
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := &recorder{header: http.Header{}, status: http.StatusOK}
	m.srv.ServeAs(w, r, a, m.API.ServeHTTP)

	if w.status < 200 || w.status > 299 {
		var e web.ErrorBody
		msg := http.StatusText(w.status)
		if json.Unmarshal(w.body.Bytes(), &e) == nil && e.Error != "" {
			msg = e.Error
			if e.Field != "" && e.Field != "reauth" { // the argument (or the API's field) it is about
				msg = e.Field + ": " + msg
			}
		}
		return mcp.NewToolResponseError("Refused (" + strconv.Itoa(w.status) + "): " + msg)
	}
	if w.body.Len() == 0 {
		return mcp.NewToolResponseText(`{"ok":true}`)
	}
	if edit != nil {
		var v map[string]any
		if err := json.Unmarshal(w.body.Bytes(), &v); err == nil {
			edit(v)
			return mcp.NewToolResponseJSON(v)
		}
	}
	return mcp.NewToolResponseText(strings.TrimSpace(w.body.String()))
}

// recorder keeps the response of an in-process management API request.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func (w *recorder) Header() http.Header { return w.header }

func (w *recorder) WriteHeader(status int) {
	if !w.wrote {
		w.status, w.wrote = status, true
	}
}

func (w *recorder) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.body.Write(b)
}
