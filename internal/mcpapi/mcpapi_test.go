package mcpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/mcp"
	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/mcpapi"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

func ptr[T any](v T) *T { return &v }

// env is a server with the OAuth provider, the management API and the MCP server, as the app wires them.
type env struct {
	*webtest.Env
	t        *testing.T
	resource string
	actor    *service.Actor // the bootstrap super admin
}

func setup(t *testing.T) *env {
	t.Helper()
	e := webtest.New(t, webtest.Options{Modules: func(s *web.Server) []web.Module {
		op := oidc.New(s)
		adm := admin.New()
		api := http.NewServeMux()
		for _, rt := range adm.Routes() {
			api.HandleFunc(rt.Method+" "+rt.Path, rt.Handler)
		}
		verify := func(r *http.Request, tok, resource string) (*service.Actor, bool, error) { // as the app wires it
			cl, u, err := op.VerifyResourceToken(r, "Bearer", tok, resource)
			if err != nil {
				return nil, false, err
			}
			return service.ActorForApp(u, cl.ClientID, web.ClientIP(r)), model.MFA(cl.AMR), nil
		}
		return []web.Module{op, adm, &mcpapi.Module{Verify: verify, API: api}}
	}})
	return &env{Env: e, t: t, resource: e.Cfg.OrgMCP(e.Primary.ID), actor: service.ActorForUser(e.Admin, "")}
}

func (e *env) user(name string, role model.Role) *model.User {
	e.t.Helper()
	u, err := e.Svc.CreateUser(context.Background(), service.System, e.Primary.ID, service.UserInput{Username: ptr(name),
		Email: ptr(name + "@example.com"), GivenName: ptr(name), Role: &role, Verified: ptr(true)})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// mcpServer switches the organization's MCP server on or off (OrgSettings.MCPServer).
func (e *env) mcpServer(on bool) {
	e.t.Helper()
	org, err := e.Svc.Org(context.Background(), e.Primary.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	st := org.Settings
	st.MCPServer = on
	if _, err := e.Svc.UpdateOrg(context.Background(), service.System, org.ID, service.OrgInput{Settings: &st}); err != nil {
		e.t.Fatal(err)
	}
}

// turnOn switches the organization's MCP server on, and makes a tenant own its address and accept self-registered
// apps (AI clients).
func (e *env) turnOn() *model.Tenant {
	e.t.Helper()
	e.mcpServer(true)
	set := model.DefaultTenantSettings()
	set.SelfRegistration, set.RequireMFA = true, false // the MCP server requires one itself, whatever the tenant does
	tn, err := e.Svc.CreateTenant(context.Background(), e.actor, e.Primary.ID,
		service.TenantInput{Name: ptr("ai"), Settings: &set, Resources: &[]string{e.resource}})
	if err != nil {
		e.t.Fatal(err)
	}
	return tn
}

type pool struct{ c *http.Client }

func (p pool) GetHTTPClient() *http.Client { return p.c }

// client is an MCP client that runs MCP authorization (discovery, dynamic registration, the code flow with PKCE and
// the resource) as an AI client would, with u signed in to Quisora with a second factor approving it on the consent
// page.
func (e *env) client(u *model.User) (*mcp.Client, *mcp.AuthorizationCodeAuth) {
	e.t.Helper()
	return e.clientAMR(u, []string{"pwd", "otp", "mfa"})
}

// clientAMR is client with u signed in with the methods amr.
func (e *env) clientAMR(u *model.User, amr []string) (*mcp.Client, *mcp.AuthorizationCodeAuth) {
	e.t.Helper()
	browser, csrf := e.SessionAMR(u, amr)
	authorizer := func(ctx context.Context, authURL string) (string, error) {
		resp, err := browser.Get(authURL)
		if err != nil {
			return "", err
		}
		resp.Body.Close()
		consent, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || consent.Path != web.OrgPath(e.Primary.ID, "/oauth/consent") {
			return resp.Header.Get("Location"), nil // refused: back to the client with the error
		}
		page, err := browser.Get(e.URL + consent.String())
		if err != nil {
			return "", err
		}
		html, _ := io.ReadAll(page.Body)
		page.Body.Close()
		if !strings.Contains(string(html), "Manage your organization as you") {
			e.t.Errorf("the consent page does not say the client will manage the organization:\n%.1500s", html)
		}
		b, _ := json.Marshal(map[string]any{"flow": consent.Query().Get("flow"), "approve": true})
		req, _ := http.NewRequest(http.MethodPost, e.URL+web.OrgPath(e.Primary.ID, "/api-internal/oauth/consent"), bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		resp, err = browser.Do(req)
		if err != nil {
			return "", err
		}
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		next := out["redirect"]
		if !strings.HasPrefix(next, "http") {
			next = e.URL + next
		}
		resp, err = browser.Get(next)
		if err != nil {
			return "", err
		}
		resp.Body.Close()
		return resp.Header.Get("Location"), nil
	}
	hc := e.HTTP.Client()
	auth, err := mcp.NewAuthorizationCodeAuth(mcp.AuthorizationCodeConfig{RedirectURI: "http://127.0.0.1:44001/callback",
		Authorizer: authorizer, ClientName: "Claude", HTTPClient: hc})
	if err != nil {
		e.t.Fatal(err)
	}
	return mcp.NewClientWithPool(e.resource, auth, "", pool{hc}), auth
}

// call calls tool name and returns its text and whether it was an error.
func call(t *testing.T, c *mcp.Client, name string, args map[string]any) (string, bool) {
	t.Helper()
	r, err := c.CallTool(context.Background(), name, args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var text strings.Builder
	for _, ct := range r.Content {
		text.WriteString(ct.Text)
	}
	return text.String(), r.IsError
}

// callOK calls tool name, which must succeed, and decodes its JSON answer.
func callOK(t *testing.T, c *mcp.Client, name string, args map[string]any) map[string]any {
	t.Helper()
	text, isErr := call(t, c, name, args)
	if isErr {
		t.Fatalf("%s %v: %s", name, args, text)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatalf("%s: not JSON: %s", name, text)
	}
	return v
}

func ids(list map[string]any) []string {
	var out []string
	items, _ := list["items"].([]any)
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m["id"].(string))
		}
	}
	return out
}

// An AI client finds Quisora from the MCP server's metadata, registers, has a manager sign in and approve it, and
// then manages users and groups through the tools, as that manager: the API's rules apply and the audit log names the
// application.
func TestManageThroughMCP(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	mia := e.user("mia", model.RoleManager)
	bob := e.user("bob", model.RoleUser)
	ada := e.user("ada", model.RoleAdmin)
	g, err := e.Svc.CreateGroup(ctx, e.actor, e.Primary.ID, service.GroupInput{DisplayName: ptr("Engineering")})
	if err != nil {
		t.Fatal(err)
	}

	// Until a tenant owns the address no client can be authorized for it.
	c, _ := e.client(mia)
	if err := c.Initialize(ctx); err == nil {
		t.Fatal("authorized for an address no tenant owns")
	}

	tn := e.turnOn()
	c, auth := e.client(mia)
	if err := c.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	// A JSON-RPC batch (protocol 2025-03-26) runs, up to mcpapi.MaxBatch requests: past that, one HTTP request
	// would be any number of API requests and their results held at once.
	if st, body := send(t, e, auth.Session().AccessToken, "2025-03-26", batch(mcpapi.MaxBatch)); st != http.StatusOK ||
		strings.Count(body, `"tools"`) != mcpapi.MaxBatch {
		t.Fatalf("a batch of %d: %d %.300s", mcpapi.MaxBatch, st, body)
	}
	if st, body := send(t, e, auth.Session().AccessToken, "2025-03-26", batch(mcpapi.MaxBatch+1)); st != http.StatusBadRequest ||
		!strings.Contains(body, "at most 10 requests in a batch") || strings.Contains(body, `"tools"`) {
		t.Fatalf("a batch of %d: %d %.300s", mcpapi.MaxBatch+1, st, body)
	}
	// No event stream (the tools send no notifications), and a body over the server's limit is too large.
	if st, _ := request(t, e, http.MethodGet, auth.Session().AccessToken, "", ""); st != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", st)
	}
	if st, _ := send(t, e, auth.Session().AccessToken, "", "["+strings.Repeat(" ", 2<<20)+"]"); st != http.StatusRequestEntityTooLarge {
		t.Errorf("a 2 MB body: %d", st)
	}

	// The hints as the server sends them on the wire, which is what an AI client reads.
	tools := listTools(t, e, auth.Session().AccessToken)
	hints := map[string]*mcp.ToolAnnotations{}
	for _, tl := range tools {
		hints[tl.Name] = tl.Annotations
	}
	want := map[string][2]bool{ // read-only, destructive
		"search_users": {true, false}, "get_user": {true, false}, "list_user_sessions": {true, false},
		"list_groups": {true, false}, "list_group_members": {true, false}, "query_audit_log": {true, false},
		"create_user": {false, false}, "enable_user": {false, false}, "add_group_member": {false, false},
		"disable_user": {false, true}, "remove_group_member": {false, true}, "send_invitation": {false, true},
		"sign_out_user": {false, true},
	}
	if len(tools) != len(want) {
		t.Errorf("%d tools, want %d", len(tools), len(want))
	}
	for name, w := range want {
		h := hints[name]
		switch {
		case h == nil:
			t.Errorf("%s: missing, or no hints", name)
		case w[0] && (h.ReadOnlyHint == nil || !*h.ReadOnlyHint):
			t.Errorf("%s: not read-only", name)
		case !w[0] && (h.DestructiveHint == nil || *h.DestructiveHint != w[1]):
			t.Errorf("%s: destructiveHint %v, want %v", name, h.DestructiveHint, w[1])
		}
	}
	app := auth.Session().ClientID
	if !strings.HasPrefix(app, model.DynamicClientPrefix) {
		t.Fatalf("client %q did not register itself", app)
	}

	// reads
	if got := ids(callOK(t, c, "search_users", map[string]any{"query": "bob"})); !slices.Equal(got, []string{bob.ID}) {
		t.Errorf("search_users bob: %v", got)
	}
	if u := callOK(t, c, "get_user", map[string]any{"user_id": bob.ID}); u["username"] != "bob" || u["can_manage"] != true {
		t.Errorf("get_user: %v", u)
	}
	if got := ids(callOK(t, c, "list_groups", map[string]any{"query": "Eng"})); !slices.Equal(got, []string{g.ID}) {
		t.Errorf("list_groups: %v", got)
	}
	callOK(t, c, "list_user_sessions", map[string]any{"user_id": bob.ID})

	// changes
	callOK(t, c, "add_group_member", map[string]any{"group_id": g.ID, "user_id": bob.ID})
	if got := ids(callOK(t, c, "list_group_members", map[string]any{"group_id": g.ID})); !slices.Equal(got, []string{bob.ID}) {
		t.Errorf("members after add: %v", got)
	}
	callOK(t, c, "remove_group_member", map[string]any{"group_id": g.ID, "user_id": bob.ID})
	if got := ids(callOK(t, c, "list_group_members", map[string]any{"group_id": g.ID})); len(got) != 0 {
		t.Errorf("members after remove: %v", got)
	}
	if u := callOK(t, c, "disable_user", map[string]any{"user_id": bob.ID, "reason": "left"}); u["active"] != false {
		t.Errorf("disable_user: %v", u)
	}
	// enabled users only, unless asked for disabled ones too: a client filling the flag in with false gets the same
	for _, args := range []map[string]any{{"query": "bob"}, {"query": "bob", "include_disabled": false}} {
		if got := ids(callOK(t, c, "search_users", args)); len(got) != 0 {
			t.Errorf("search_users %v found disabled bob: %v", args, got)
		}
	}
	if got := ids(callOK(t, c, "search_users", map[string]any{"query": "bob", "include_disabled": true})); !slices.Equal(got, []string{bob.ID}) {
		t.Errorf("search_users with include_disabled: %v", got)
	}
	if u := callOK(t, c, "enable_user", map[string]any{"user_id": bob.ID}); u["active"] != true {
		t.Errorf("enable_user: %v", u)
	}
	callOK(t, c, "sign_out_user", map[string]any{"user_id": bob.ID})
	created := callOK(t, c, "create_user", map[string]any{"email": "new@example.com", "given_name": "New", "send_invitation": true})
	inv, _ := created["invite"].(map[string]any)
	if created["role"] != "user" || inv == nil || inv["url"] != nil || inv["link"] == nil {
		t.Errorf("create_user: %v", created)
	}
	if sent := callOK(t, c, "send_invitation", map[string]any{"user_id": bob.ID}); sent["url"] != nil || sent["link"] == nil {
		t.Errorf("send_invitation: %v", sent)
	}

	// An argument is an id, never a way to another route.
	for _, bad := range []string{"../../keys", "", bob.ID + "/sessions"} {
		if text, isErr := call(t, c, "get_user", map[string]any{"user_id": bad}); !isErr {
			t.Errorf("get_user %q: %s", bad, text)
		}
	}

	// The API's rules: a manager cannot change an administrator.
	if text, isErr := call(t, c, "disable_user", map[string]any{"user_id": ada.ID}); !isErr {
		t.Errorf("a manager disabled an administrator: %s", text)
	}
	if cur, _ := e.Svc.Users.Get(ctx, ada.ID); !cur.Active {
		t.Error("the administrator was disabled")
	}

	// The audit log names the manager and the application. Only administrators read it, as in the console.
	if text, isErr := call(t, c, "query_audit_log", nil); !isErr {
		t.Errorf("a manager read the audit log: %.200s", text)
	}
	admins, _ := e.client(ada)
	audit := callOK(t, admins, "query_audit_log", map[string]any{"action_group": "user.", "query": "mia"})
	items, _ := audit["items"].([]any)
	found := false
	for _, it := range items {
		ev := it.(map[string]any)
		detail, _ := ev["detail"].(map[string]any)
		if ev["actor"] == "mia" && detail["app"] == app {
			found = true
		}
	}
	if !found {
		t.Errorf("no audit event by mia through %s: %v", app, audit)
	}

	// Removing the address from the tenant turns the server off at once, for tokens already issued too.
	tok := auth.Session().AccessToken
	if st := post(t, e, tok); st != http.StatusOK {
		t.Fatalf("a good token: %d", st)
	}
	if _, err := e.Svc.UpdateTenant(ctx, e.actor, tn.ID, service.TenantInput{Resources: &[]string{}}); err != nil {
		t.Fatal(err)
	}
	if st := post(t, e, tok); st != http.StatusUnauthorized {
		t.Errorf("a token after the address was removed: %d", st)
	}
}

// listTools lists the tools as the server sends them.
func listTools(t *testing.T, e *env, tok string) []mcp.MCPTool {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.resource, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := e.HTTP.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Result struct{ Tools []mcp.MCPTool } `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != 200 {
		t.Fatalf("tools/list: %d %v", resp.StatusCode, err)
	}
	return out.Result.Tools
}

// post sends an MCP ping with token, and returns the status.
func post(t *testing.T, e *env, tok string) int {
	t.Helper()
	st, _ := send(t, e, tok, "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	return st
}

// send posts body to the MCP server with token, in protocol version (none when ""), and returns the status and body.
func send(t *testing.T, e *env, tok, version, body string) (int, string) {
	t.Helper()
	return request(t, e, http.MethodPost, tok, version, body)
}

// request is send with another method. A response that takes over 10 seconds fails the test (an event stream left
// open would otherwise hang it).
func request(t *testing.T, e *env, method, tok, version, body string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, method, e.resource, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := e.HTTP.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// batch is a JSON-RPC batch of n tools/list requests.
func batch(n int) string {
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, i+1)
	}
	return "[" + strings.Join(items, ",") + "]"
}

// query_audit_log reads the audit log as the console does, so on the same budget: an organization's administrators
// share web.AuditReadsPerMinute pages a minute, each of them web.AuditReadsPerMinuteActor of it, through the console,
// the API and AI clients together, and past it the tool is refused (429) rather than add to the load on the log
// every organization shares.
func TestAuditLogBudget(t *testing.T) {
	e := setup(t)
	e.turnOn()
	c, _ := e.client(e.user("ada", model.RoleAdmin))
	if err := c.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := range web.AuditReadsPerMinuteActor {
		if text, isErr := call(t, c, "query_audit_log", map[string]any{"limit": 1}); isErr {
			t.Fatalf("read %d: %s", i+1, text)
		}
	}
	if text, isErr := call(t, c, "query_audit_log", nil); !isErr || !strings.Contains(text, "429") {
		t.Fatalf("past the budget: %v %s", isErr, text)
	}
}

// A user who is not a manager or above may sign the client in (the tenant decides who signs in), but the server
// refuses them.
func TestOnlyManagersAndUp(t *testing.T) {
	e := setup(t)
	e.turnOn()
	c, _ := e.client(e.user("uma", model.RoleUser))
	if err := c.Initialize(context.Background()); err == nil {
		t.Fatal("a plain user reached the MCP server")
	}
}

// Like the admin console, the server needs a sign-in that used a second factor, whatever the tenant requires: a
// manager who signed in with a password alone is refused, and the refusal says why; a passkey alone is enough.
func TestNeedsSecondFactor(t *testing.T) {
	e := setup(t)
	e.turnOn()
	c, auth := e.clientAMR(e.user("mia", model.RoleManager), []string{"pwd"})
	if err := c.Initialize(context.Background()); err == nil {
		t.Fatal("a sign-in without a second factor reached the MCP server")
	}
	if st, body := send(t, e, auth.Session().AccessToken, "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); st != http.StatusForbidden ||
		!strings.Contains(body, "passkey or an authenticator code") {
		t.Errorf("a password-only sign-in: %d %s", st, body)
	}
	c, _ = e.clientAMR(e.user("pia", model.RoleManager), []string{"hwk", "user"})
	if err := c.Initialize(context.Background()); err != nil {
		t.Errorf("a passkey sign-in: %v", err)
	}
}

// Disabling a user stops the tokens their client holds at once.
func TestDisabledUserRefused(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	e.turnOn()
	mia := e.user("mia", model.RoleManager)
	c, auth := e.client(mia)
	if err := c.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if st := post(t, e, auth.Session().AccessToken); st != http.StatusOK {
		t.Fatalf("before: %d", st)
	}
	if _, err := e.Svc.UpdateUser(ctx, e.actor, mia.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if st := post(t, e, auth.Session().AccessToken); st != http.StatusUnauthorized {
		t.Errorf("after the user was disabled: %d", st)
	}
}

// The MCP server is off unless the organization switches it on: its address and metadata are not found, even with a
// tenant listing the address, and switching it off stops a client already signed in.
func TestOffUnlessSwitchedOn(t *testing.T) {
	e := setup(t)
	wk := e.URL + "/.well-known/oauth-protected-resource" + web.OrgPath(e.Primary.ID, mcpapi.Path)
	status := func(method, u string) int {
		t.Helper()
		req, _ := http.NewRequest(method, u, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		resp, err := e.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if st := status(http.MethodGet, wk); st != http.StatusNotFound {
		t.Errorf("metadata of a new organization: %d", st)
	}
	if st := status(http.MethodPost, e.resource); st != http.StatusNotFound {
		t.Errorf("the address of a new organization: %d", st)
	}

	e.turnOn()
	c, auth := e.client(e.user("mia", model.RoleManager))
	if err := c.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.mcpServer(false) // the tenant still lists the address
	if st := status(http.MethodGet, wk); st != http.StatusNotFound {
		t.Errorf("metadata once switched off: %d", st)
	}
	if st := post(t, e, auth.Session().AccessToken); st != http.StatusNotFound {
		t.Errorf("a signed-in client once switched off: %d", st)
	}
	e.mcpServer(true)
	if st := post(t, e, auth.Session().AccessToken); st != http.StatusOK {
		t.Errorf("switched on again: %d", st)
	}

	// server.disable_mcp (--disable-mcp) turns every organization's off, whatever its settings say, and the API
	// refuses to switch one on (one already on may stay so, for its other settings to be saved).
	e.Cfg.Server.DisableMCP = true
	if st := post(t, e, auth.Session().AccessToken); st != http.StatusNotFound {
		t.Errorf("with --disable-mcp: %d", st)
	}
	if st := status(http.MethodGet, wk); st != http.StatusNotFound {
		t.Errorf("metadata with --disable-mcp: %d", st)
	}
	ctx := context.Background()
	org, _ := e.Svc.Org(ctx, e.Primary.ID)
	st := org.Settings
	if _, err := e.Svc.UpdateOrg(ctx, service.System, org.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Errorf("saving an organization whose MCP server was on before --disable-mcp: %v", err)
	}
	st.MCPServer = false
	if _, err := e.Svc.UpdateOrg(ctx, service.System, org.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	st.MCPServer = true
	if _, err := e.Svc.UpdateOrg(ctx, service.System, org.ID, service.OrgInput{Settings: &st}); err == nil ||
		!strings.Contains(err.Error(), "disable_mcp") {
		t.Errorf("switched on with --disable-mcp: %v", err)
	}
}

// The protected resource metadata points at the organization; a request without a token is told where to find it; a
// personal API token is no token here; the organization's name redirects to its id, the one address.
func TestDiscoveryAndRefusals(t *testing.T) {
	e := setup(t)
	e.mcpServer(true)
	hc := e.Client()
	wk := e.URL + "/.well-known/oauth-protected-resource" + web.OrgPath(e.Primary.ID, mcpapi.Path)
	resp, err := hc.Get(wk)
	if err != nil {
		t.Fatal(err)
	}
	var md map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&md)
	resp.Body.Close()
	as, _ := md["authorization_servers"].([]any)
	if resp.StatusCode != 200 || md["resource"] != e.resource || len(as) != 1 || as[0] != e.Cfg.OrgIssuer(e.Primary.ID) {
		t.Fatalf("metadata %d %v", resp.StatusCode, md)
	}

	req, _ := http.NewRequest(http.MethodPost, e.resource, strings.NewReader(`{}`))
	resp, err = hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `resource_metadata="`+wk+`"`) {
		t.Errorf("no token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	_, tok, err := e.Svc.CreateAPIToken(context.Background(), e.actor, service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	if st := post(t, e, tok); st != http.StatusUnauthorized {
		t.Errorf("a personal API token: %d", st)
	}

	for _, u := range []string{e.URL + web.OrgPath(e.Primary.Name, mcpapi.Path),
		e.URL + "/.well-known/oauth-protected-resource" + web.OrgPath(e.Primary.Name, mcpapi.Path)} {
		resp, err := hc.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusPermanentRedirect || !strings.Contains(resp.Header.Get("Location"), "/o/"+e.Primary.ID+"/") {
			t.Errorf("%s: %d %s", u, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}
