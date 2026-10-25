// Package scim is the SCIM 2.0 server (RFC 7643, RFC 7644): Users and Groups per organization under
// /scim/v2/{org}/, plus an Organizations resource for super admins at /scim/v2/Organizations.
//
// Every change goes through the service layer, so SCIM callers get exactly the RBAC and business rules of the admin
// UI.
//
// A Group change (POST with members, PUT, PATCH, DELETE) is atomic (RFC 7644 §3.5.2): the service commits it with
// one compare-and-swap of the group's record and materializes the memberships from it (service.ChangeGroup; see
// docs/REPLICATION.md, "Groups and their members"), so a refused or failed change leaves the group exactly as it was
// and a committed one is seen whole by every reader. The group's ETag is its record's version: it moves with every
// change, members included, and If-Match is checked against it (a change racing another is 412). One PATCH or PUT may
// add and remove at most service.MaxMembersPerChange (1,000) members; a larger one is refused with 413 and should be
// split.
package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

const (
	contentType  = "application/scim+json; charset=utf-8"
	maxBody      = 1 << 20
	defaultCount = 100
	maxCount     = 1000
)

// TokenVerifier turns a token that is not a personal API token (for example an OAuth client_credentials access
// token), presented in request r with scheme "Bearer" or "DPoP", into the actor for the request. It must return an
// error for tokens it does not accept.
type TokenVerifier func(r *http.Request, scheme, tok string) (*service.Actor, error)

// Module serves SCIM.
type Module struct {
	// TokenVerifier verifies non-API-token bearers; when nil only personal API tokens with the scim scope work.
	TokenVerifier TokenVerifier

	srv   *web.Server
	locks [64]sync.Mutex
}

// lock serializes read-modify-write cycles on one resource within this process, so that an If-Match check and the
// write it guards cannot interleave with another request on this node. (Across nodes the service's optimistic
// concurrency still prevents lost updates, but a stale If-Match is then only caught on the node that served it.)
func (m *Module) lock(key string) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	mu := &m.locks[h.Sum32()%uint32(len(m.locks))]
	mu.Lock()
	return mu.Unlock
}

// Register adds the SCIM routes. A single subtree handler does the routing so that /scim/v2/Organizations and
// /scim/v2/{org}/Users never clash in the mux.
func (m *Module) Register(s *web.Server) {
	m.srv = s
	s.Mux.HandleFunc("/scim/v2/", m.serve)
}

// ---------------------------------------------------------------------------------------------------------------
// Errors

// Error is a SCIM error response (RFC 7644 §3.12).
type Error struct {
	Status int
	Type   string // scimType
	Detail string
}

func (e *Error) Error() string { return e.Detail }

// errNeedsSession refuses what the management API keeps for a recently re-authenticated admin console session
// (granting an administrator role, deleting an organization, changing the primary organization's sign-in settings):
// SCIM is always called with a token, which cannot make those changes.
func errNeedsSession(what string) *Error {
	return &Error{Status: 403, Detail: what + " needs a recent re-authentication in the admin console; a token cannot make this change"}
}

// maxScan bounds the records a filter that cannot be answered from an index may evaluate in memory (RFC 7644
// §3.4.2.2 "tooMany"): far above any organization's size at the target scale, low enough to cap one request.
const maxScan = 50_000

var errTooMany = &Error{Status: 400, Type: "tooMany",
	Detail: "The filter matches too many resources to evaluate; narrow it with userName, externalId or emails."}

func errf(status int, typ, format string, args ...any) *Error {
	return &Error{Status: status, Type: typ, Detail: fmt.Sprintf(format, args...)}
}

func badValue(format string, args ...any) *Error  { return errf(400, "invalidValue", format, args...) }
func badSyntax(format string, args ...any) *Error { return errf(400, "invalidSyntax", format, args...) }
func badPath(format string, args ...any) *Error   { return errf(400, "invalidPath", format, args...) }
func noTarget(format string, args ...any) *Error  { return errf(400, "noTarget", format, args...) }
func notFound(what string) *Error                 { return errf(404, "", "%s not found", what) }

// fromService maps service errors onto SCIM errors.
func (m *Module) fromService(err error) *Error {
	var se *Error
	var fe *service.FieldError
	switch {
	case errors.As(err, &se):
		return se
	case errors.As(err, &fe) && errors.Is(err, service.ErrConflict):
		return errf(409, "uniqueness", "%s %s", fe.Field, fe.Msg)
	case errors.As(err, &fe):
		return badValue("%s %s", fe.Field, fe.Msg)
	case errors.Is(err, service.ErrForbidden):
		return errf(403, "", "You do not have permission to do that")
	case errors.Is(err, service.ErrNotFound):
		return errf(404, "", "Resource not found")
	case errors.Is(err, service.ErrConflict):
		return errf(409, "uniqueness", "A resource with that value already exists")
	case errors.Is(err, service.ErrStale):
		return errf(409, "", "The resource was changed by someone else, retry the request")
	case errors.Is(err, service.ErrTooLarge):
		// RFC 7644 §3.12: 413, the request is larger than the server processes; the client splits it.
		return errf(413, "", "%s", capitalise(err.Error()))
	case errors.Is(err, service.ErrLastAdmin), errors.Is(err, service.ErrNotEmpty), errors.Is(err, service.ErrPrimaryOrg),
		errors.Is(err, service.ErrTenantInUse):
		return errf(409, "", "%s", capitalise(err.Error()))
	case errors.Is(err, service.ErrNotReplicated):
		// Saved here, not yet confirmed by the cluster: a retry of a create would find the resource (409), so the
		// client is told to read it back rather than to treat this as a failure of its own.
		return errf(503, "", "The change was saved on this server but not yet confirmed by the cluster; read the resource back before retrying")
	case errors.Is(err, service.ErrUnavailable):
		return errf(503, "", "This server cannot make changes right now (it cannot reach enough of its cluster); nothing was changed, retry shortly")
	case errors.Is(err, service.ErrInvalid):
		return badValue("%s", err.Error())
	}
	if m.srv != nil && m.srv.Log != nil {
		m.srv.Log.Error("scim", "error", err)
	}
	return errf(500, "", "Internal error")
}

func capitalise(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-32) + s[1:]
}

type errorBody struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

func writeError(w http.ResponseWriter, e *Error) {
	if e.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
	}
	if e.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	write(w, e.Status, errorBody{Schemas: []string{schemaError}, Status: strconv.Itoa(e.Status), ScimType: e.Type, Detail: e.Detail})
}

func write(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// ---------------------------------------------------------------------------------------------------------------
// Request context and routing

type request struct {
	m     *Module
	w     http.ResponseWriter
	r     *http.Request
	ctx   context.Context
	actor *service.Actor
	org   *model.Org
	base  string // https://host/scim/v2
	// unseen holds the users of the org the caller does not see in full (loaded once, by unseenUsers): SCIM leaves
	// them out of every member list and membership filter, as it leaves them out of the users.
	unseen map[string]bool
	loaded bool
}

func (rq *request) fail(err error) {
	if errors.Is(err, service.ErrForbidden) && rq.actor != nil {
		rq.m.refused(rq.r, rq.actor, "not permitted")
	}
	writeError(rq.w, rq.m.fromService(err))
}

// unseenUsers returns the ids of the org's users the caller does not see in full.
func (rq *request) unseenUsers() map[string]bool {
	if !rq.loaded {
		rq.unseen, _ = rq.m.srv.Svc.NotSeenInFull(rq.ctx, rq.actor, rq.org.ID)
		rq.loaded = true
	}
	return rq.unseen
}

// location is the absolute URL of a resource of this org.
func (rq *request) location(kind, id string) string {
	return rq.base + "/" + rq.org.Name + "/" + kind + "/" + id
}

func (m *Module) serve(w http.ResponseWriter, r *http.Request) {
	rq := &request{m: m, w: w, r: r, ctx: r.Context(),
		base: strings.TrimRight(m.srv.Cfg.Server.PublicURL, "/") + "/scim/v2"}
	rest := strings.Trim(strings.TrimPrefix(r.URL.EscapedPath(), "/scim/v2/"), "/")
	var segs []string
	if rest != "" {
		for _, s := range strings.Split(rest, "/") {
			u, err := unescape(s)
			if err != nil {
				writeError(w, badSyntax("invalid path"))
				return
			}
			segs = append(segs, u)
		}
	}
	if len(segs) == 0 {
		writeError(w, notFound("Resource"))
		return
	}

	// Discovery is public: it holds nothing but the shape of the API.
	if isDiscovery(segs[0]) {
		rq.discovery(segs, true)
		return
	}
	if len(segs) >= 2 && isDiscovery(segs[1]) && !isResourceName(segs[0]) {
		rq.discovery(segs[1:], false)
		return
	}

	actor, e := m.authenticate(r)
	if e != nil {
		writeError(w, e)
		return
	}
	rq.actor = actor

	// Users and Groups live under their organization only (/scim/v2/{org}/Users, as every location this API
	// returns says): one base URL per organization for a provisioning client, never a second spelling of it.
	if segs[0] == "Organizations" {
		rq.organizations(segs[1:])
		return
	}
	org, err := m.srv.Svc.OrgByName(rq.ctx, segs[0])
	if err != nil || (!actor.IsSuper() && actor.OrgID != org.ID) {
		// The same answer for "does not exist" and "not yours", so org names cannot be probed.
		writeError(w, notFound("Organization"))
		return
	}
	rq.org = org
	rq.resource(segs[1:])
}

func unescape(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b = append(b, s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("bad escape")
		}
		v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", err
		}
		b = append(b, byte(v))
		i += 2
	}
	return string(b), nil
}

func isDiscovery(s string) bool {
	return s == "ServiceProviderConfig" || s == "ResourceTypes" || s == "Schemas"
}

func isResourceName(s string) bool {
	return s == "Users" || s == "Groups" || s == "Organizations" || isDiscovery(s)
}

// resource routes Users and Groups of rq.org.
func (rq *request) resource(segs []string) {
	if len(segs) == 0 || len(segs) > 2 {
		writeError(rq.w, notFound("Resource"))
		return
	}
	id := ""
	if len(segs) == 2 {
		id = segs[1]
	}
	switch segs[0] {
	case "Users":
		rq.users(id)
	case "Groups":
		rq.groups(id)
	default:
		writeError(rq.w, notFound("Resource"))
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Authentication

// bearerToken returns the request's token and its scheme: Bearer, or DPoP for a DPoP-bound OAuth token (RFC 9449).
func bearerToken(r *http.Request) (tok, scheme string) {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:]), "Bearer"
	}
	if len(h) > 5 && strings.EqualFold(h[:5], "DPoP ") {
		return strings.TrimSpace(h[5:]), "DPoP"
	}
	return "", ""
}

// authenticate resolves the bearer token to an actor holding the scim scope. Failed authentications count against
// the address (web.BearerFailuresPerIPMin, shared with the management API); a refusal of an authenticated actor is
// audited.
func (m *Module) authenticate(r *http.Request) (*service.Actor, *Error) {
	tok, scheme := bearerToken(r)
	if tok == "" {
		return nil, errf(401, "", "A bearer token is required")
	}
	if m.srv.BearerLimited(r) {
		return nil, errf(429, "", "Too many failed authentications from this address; try again in a minute")
	}
	actor, e := m.resolve(r, tok, scheme)
	if e != nil {
		if e.Status == 401 {
			m.srv.BearerFailed(r)
		}
		return nil, e
	}
	if !actor.HasScope(service.ScopeSCIM) {
		m.refused(r, actor, "the token does not have the scim scope")
		return nil, errf(403, "", "The token does not have the scim scope")
	}
	return actor, nil
}

// refused audits a SCIM request refused for the authenticated actor a.
func (m *Module) refused(r *http.Request, a *service.Actor, reason string) {
	if m.srv.Svc != nil {
		m.srv.Svc.AuditRefused(r.Context(), a, r.Method, r.URL.Path, reason)
	}
}

// resolve turns the token into its actor: a personal API token, or an OAuth access token of a provisioning client.
func (m *Module) resolve(r *http.Request, tok, scheme string) (*service.Actor, *Error) {
	var actor *service.Actor
	if service.IsAPIToken(tok) && scheme == "Bearer" {
		t, u, err := m.srv.Svc.ValidateAPIToken(r.Context(), tok)
		if errors.Is(err, service.ErrUnavailable) { // the store failed, not the caller: not counted
			return nil, errf(503, "", "The token could not be checked right now; try again shortly")
		}
		if err != nil {
			return nil, errf(401, "", "The token is invalid or has expired")
		}
		actor = service.ActorForToken(t, u, web.ClientIP(r))
		if !actor.Role.Privileged() {
			m.refused(r, actor, "the token's owner no longer has a role that may use SCIM")
			return nil, errf(403, "", "The token's owner no longer has a role that may use SCIM")
		}
	} else if m.TokenVerifier != nil {
		a, err := m.TokenVerifier(r, scheme, tok)
		if errors.Is(err, service.ErrUnavailable) { // the store failed, not the caller: not counted, and not "invalid"
			return nil, errf(503, "", "The token could not be checked right now; try again shortly")
		}
		if err != nil || a == nil {
			return nil, errf(401, "", "The token is invalid or has expired")
		}
		cp := *a
		cp.IP = web.ClientIP(r)
		actor = &cp
	} else {
		return nil, errf(401, "", "The token is invalid or has expired")
	}
	return actor, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Request helpers

// readBody decodes a JSON object body.
func (rq *request) readBody() (map[string]any, *Error) {
	rq.r.Body = http.MaxBytesReader(rq.w, rq.r.Body, maxBody)
	b, err := io.ReadAll(rq.r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errf(413, "", "The request body is too large")
		}
		return nil, badSyntax("The request body could not be read")
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil || v == nil {
		return nil, badSyntax("The request body must be a JSON object")
	}
	return v, nil
}

type listParams struct {
	filter   node
	sortBy   *attrPath
	desc     bool
	start    int // 1-based
	count    int
	attrs    []string
	excluded []string
}

func (rq *request) listParams() (*listParams, *Error) {
	q := rq.r.URL.Query()
	p := &listParams{start: 1, count: defaultCount}
	if f := q.Get("filter"); f != "" {
		n, err := parseFilter(f)
		if err != nil {
			return nil, errf(400, "invalidFilter", "%s", err.Error())
		}
		p.filter = n
	}
	if s := q.Get("sortBy"); s != "" {
		path, err := parsePath(s)
		if err != nil {
			return nil, errf(400, "invalidPath", "sortBy: %s", err.Error())
		}
		p.sortBy = &path
	}
	switch strings.ToLower(q.Get("sortOrder")) {
	case "", "ascending":
	case "descending":
		p.desc = true
	default:
		return nil, badValue("sortOrder must be ascending or descending")
	}
	if s := q.Get("startIndex"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, badValue("startIndex must be a number")
		}
		p.start = max(n, 1)
	}
	if s := q.Get("count"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, badValue("count must be a number")
		}
		p.count = min(max(n, 0), maxCount)
	}
	p.attrs, p.excluded = attrLists(q.Get("attributes"), q.Get("excludedAttributes"))
	return p, nil
}

func attrLists(attrs, excluded string) ([]string, []string) {
	split := func(s string) []string {
		var out []string
		for _, a := range strings.Split(s, ",") {
			if a = strings.TrimSpace(a); a != "" {
				out = append(out, a)
			}
		}
		return out
	}
	return split(attrs), split(excluded)
}

// ifMatch checks the If-Match precondition against the current ETag.
func ifMatch(r *http.Request, current string) *Error {
	h := r.Header.Get("If-Match")
	if h == "" {
		return nil
	}
	for _, t := range strings.Split(h, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || weakEqual(t, current) {
			return nil
		}
	}
	return errf(412, "", "The resource has changed on the server since it was read")
}

func weakEqual(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

func etagOf(res map[string]any) string {
	if meta, ok := res["meta"].(map[string]any); ok {
		if v, ok := meta["version"].(string); ok {
			return v
		}
	}
	return ""
}

// respond writes one resource with its ETag and Location headers.
func (rq *request) respond(status int, res map[string]any, attrs, excluded []string, schemas *schemaSet) {
	h := rq.w.Header()
	if v := etagOf(res); v != "" {
		h.Set("ETag", v)
	}
	if meta, ok := res["meta"].(map[string]any); ok {
		if loc, ok := meta["location"].(string); ok {
			h.Set("Content-Location", loc)
			if status == http.StatusCreated {
				h.Set("Location", loc)
			}
		}
	}
	write(rq.w, status, project(res, attrs, excluded, schemas))
}

// getParams reads attributes / excludedAttributes for single-resource responses.
func (rq *request) getParams() (attrs, excluded []string) {
	q := rq.r.URL.Query()
	return attrLists(q.Get("attributes"), q.Get("excludedAttributes"))
}

// retry runs a read-modify-write, repeating it when the record changed underneath (unless the caller sent If-Match,
// which turns a lost race into 412).
func (rq *request) retry(key string, fn func() error) error {
	defer rq.m.lock(key)()
	var err error
	for range 5 {
		err = fn()
		if !errors.Is(err, service.ErrStale) {
			return err
		}
		if rq.r.Header.Get("If-Match") != "" {
			return errf(412, "", "The resource has changed on the server since it was read")
		}
	}
	return err
}

func (rq *request) allow(methods ...string) bool {
	for _, m := range methods {
		if rq.r.Method == m {
			return true
		}
	}
	rq.w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(rq.w, errf(405, "", "Method %s is not allowed here", rq.r.Method))
	return false
}
