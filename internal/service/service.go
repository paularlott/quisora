// Package service holds the business rules and role checks. Every handler (UI JSON API, SCIM, OAuth) goes through
// it for anything a permission applies to.
package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/user"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

var (
	ErrForbidden = errors.New("forbidden")
	ErrNotFound  = errors.New("not found")
	// ErrLimit: a server-wide cap is reached (self-registered applications); try again later.
	ErrLimit      = errors.New("limit reached")
	ErrInvalid    = errors.New("invalid")
	ErrConflict   = errors.New("already exists")
	ErrStale      = errors.New("changed by someone else, reload and try again")
	ErrNotEmpty   = errors.New("organization still has users")
	ErrPrimaryOrg = errors.New("the primary organization cannot be deleted")
	// ErrOutcomeUnknown: the change was sent, and the node that decides it was lost before it answered: it may or may not
	// have been made (the next owner settles it, once or never). It is an ErrUnavailable too (try again shortly), but
	// what is not idempotent is read back first.
	ErrOutcomeUnknown = errors.New("the outcome of the change is not known")
	// ErrUnavailable: this server cannot make the change now (it is catching up with its cluster or cannot reach a
	// majority of it). Nothing changed (unless it is also an ErrOutcomeUnknown); try again shortly or through another
	// server.
	ErrUnavailable = errors.New("this server cannot make changes now")
)

// Invalid returns an ErrInvalid with a field-specific message.
func Invalid(field, msg string) error { return &FieldError{Field: field, Msg: msg} }

// FieldError is a validation failure on one input field; errors.Is(err, ErrInvalid) is true.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string        { return e.Field + ": " + e.Msg }
func (e *FieldError) Is(target error) bool { return target == ErrInvalid }

// mapStore converts store errors to service errors.
func mapStore(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, store.ErrConflict):
		return ErrConflict
	case errors.Is(err, store.ErrStale):
		return ErrStale
	case errors.Is(err, store.ErrBadQuery):
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	case errors.Is(err, store.ErrUnconfirmed):
		return fmt.Errorf("%w: %w: %v", ErrOutcomeUnknown, ErrUnavailable, err)
	case errors.Is(err, store.ErrNotWritable):
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return err
}

// Actor is who is making a request.
type Actor struct {
	UserID string
	OrgID  string
	Role   model.Role
	Name   string // for the audit log
	// Unscoped marks an actor with no scope limits: an interactive (browser session) user or the system. Every
	// other actor (an API token, an OAuth client) holds exactly Scopes: an actor built without either holds none.
	Unscoped bool
	Scopes   []string // the scopes of a token-authenticated actor (ignored when Unscoped)
	ClientID string   // set when acting as an OAuth client (client_credentials)
	TokenID  string   // the personal API token the actor authenticated with: recorded with every audit event
	IP       string
}

// CommandOrigin describes the command this process runs (quisora invite, restore, …) for the audit log: the
// operating-system user, the host and the process id (Service.Origin).
func CommandOrigin(command string) map[string]string {
	o := map[string]string{"command": command, "pid": strconv.Itoa(os.Getpid())}
	if u, err := user.Current(); err == nil {
		o["os_user"] = u.Username
	}
	if h, err := os.Hostname(); err == nil {
		o["host"] = h
	}
	return o
}

type commandKey struct{}

type commandInfo struct{ name, how string }

// WithCommand marks ctx as serving an operator's command that a running node carries out ("quisora invite" and "quisora
// set-primary" through the server, authenticated by the master key alone; "quisora force-start", by access to the node's
// data directory): the audit events the system records in it are attributed to that command (actor "command:<name>",
// the address a request came from, and the command and how it was authenticated in the detail), so an auditor can tell
// the operator's command from what the system does by itself.
func WithCommand(ctx context.Context, name, how string) context.Context {
	return context.WithValue(ctx, commandKey{}, commandInfo{name, how})
}

// System is an actor for internal operations (bootstrap, housekeeping).
var System = &Actor{Role: model.RoleSuperAdmin, Name: "system", Unscoped: true}

// HasScope reports whether the actor holds scope: an unscoped actor (interactive or the system) holds every scope,
// a token-authenticated one only those it was given.
func (a *Actor) HasScope(scope string) bool {
	return a.Unscoped || slices.Contains(a.Scopes, scope)
}

// Scoped reports whether the actor is limited to its Scopes (authenticated by a token).
func (a *Actor) Scoped() bool { return !a.Unscoped }

// IsSuper reports whether the actor is a super admin (always a member of the primary org).
func (a *Actor) IsSuper() bool { return a != nil && a.Role == model.RoleSuperAdmin }

// Service is the business layer.
type Service struct {
	refusals refusalLimiter // throttles refusal audit events (auditlimit.go)
	Cfg      *config.Config
	Store    store.Store
	Hasher   *secure.Hasher
	Sealer   *secure.Sealer
	// Log receives every audit event (group "audit") as well as the store, and any failure to store one.
	Log logger.Logger
	// AuditReader serves the audit pages (nil: this node's store) and AuditWriter takes audit events instead of the
	// store (nil: the store). Set by the app: every node of a gossip cluster (reader), VictoriaLogs (both).
	AuditReader AuditReader
	AuditWriter AuditWriter
	// Origin is set in a command's process (CommandOrigin): every audit event it records names who ran it and where,
	// and the system actor is shown as cli:<os user>@<host>.
	Origin map[string]string

	Orgs       *store.Table[model.Org, *model.Org]
	Users      *store.Table[model.User, *model.User]
	Groups     *store.Table[model.Group, *model.Group]
	Members    *store.Table[model.Member, *model.Member]
	Tenants    *store.Table[model.Tenant, *model.Tenant]
	Access     *store.Table[model.TenantAccess, *model.TenantAccess]
	Clients    *store.Table[model.Client, *model.Client]
	Providers  *store.Table[model.Provider, *model.Provider]
	Passkeys   *store.Table[model.Passkey, *model.Passkey]
	Identities *store.Table[model.Identity, *model.Identity]
	Sessions   *store.Table[model.Session, *model.Session]
	Grants     *store.Table[model.Grant, *model.Grant]
	APITokens  *store.Table[model.APIToken, *model.APIToken]
	Keys       *store.Table[model.SigningKey, *model.SigningKey]
	Audits     *store.Table[model.Audit, *model.Audit]
	Links      *store.Table[model.LinkToken, *model.LinkToken]
	SignIns    *store.Table[model.SignIn, *model.SignIn]
	Locks      *store.Table[model.Lock, *model.Lock]
	Replays    *store.Table[model.Replay, *model.Replay]

	primary primaryChoice    // the primary organization PrimaryOrg chose, for primaryChoiceTTL
	members confirmedMembers // memberships a fresh read decided (membersAt)

	signOut       signOutCache   // emergency sign-out counters (signout.go)
	bg            sync.WaitGroup // Background work
	tokenTouching sync.Map       // ids of API tokens whose last use is being recorded (touchAPIToken)

	// Writable reports whether this node may change replicated data now (cluster.Node.Writable; nil: always). Writes
	// made in passing while serving reads (a session's or token's last use, a sign-in's last-login stamp) are skipped
	// when it is false: the store would refuse them, and a node that cannot know its data is current must not
	// replicate anything it changed on its own.
	Writable func() bool
	// GlobalReadable reports whether this node can vouch for its copy of the global data (signing keys,
	// organizations); nil: always. What is cached from it (the signing keys, the published key set) is not served
	// while it is false: a key the cluster revoked must not be published or used by a node that trails it.
	GlobalReadable func() bool
	// Readable reports whether this node can vouch for its copy of a partition's records (an organization's id; "" the
	// global one); nil: always. A cached session or client is not served while it is false (a revoked session or a
	// rotated secret must not be honoured by a node that stopped following the owner of its partition).
	Readable func(partitionKey string) bool

	// OnSessionsEnding is called just before sessions are ended (sessionIDs nil = every session and refresh grant
	// of the user), so relying parties can be sent back-channel logout tokens. Set by the app.
	OnSessionsEnding func(ctx context.Context, userID string, sessionIDs []string)
	// QueuesStale, when set, re-seals this node's queues on disk and returns how many of their items still need a
	// previous master key (reported with the node's keys, ReportMasterKey: they keep the rotation unfinished), and how
	// many need one that is not configured (reported as a warning: they hold nothing back).
	QueuesStale func() (stale, lost int)
	// LiveNodes, when set, lists the ids of the nodes of the cluster that are up now (this one included). A live node
	// with no current master key report is not known to seal with the active key (MasterKeyAgreed). Without it (one
	// node, or nodes sharing a database) only the reports say which nodes are live. Set by the app.
	LiveNodes func() []string

	// OnAppAccessEnding is called just before a user's grants to one client are removed (RevokeAppAccess), so that
	// client can be sent back-channel logout tokens and the grants stop working at once. Set by the app.
	OnAppAccessEnding func(ctx context.Context, userID, clientID string)
}

// CanWrite reports whether best-effort writes made while serving reads should be attempted (see Writable).
func (s *Service) CanWrite() bool { return s.Writable == nil || s.Writable() }

// sessionsEnding runs the OnSessionsEnding hook if set.
func (s *Service) sessionsEnding(ctx context.Context, userID string, sessionIDs []string) {
	if s.OnSessionsEnding != nil {
		s.OnSessionsEnding(ctx, userID, sessionIDs)
	}
}

// SessionsEnding is called by the session manager before it deletes individual sessions.
func (s *Service) SessionsEnding(ctx context.Context, userID string, sessionIDs ...string) {
	s.sessionsEnding(ctx, userID, sessionIDs)
}

// New builds the service over s.
func New(cfg *config.Config, s store.Store, sealer *secure.Sealer) *Service {
	return &Service{
		Cfg: cfg, Store: s, Hasher: secure.NewHasher(cfg.Limits.PasswordWorkers), Sealer: sealer, Log: logger.NewNullLogger(),
		Orgs:       store.NewTable[model.Org](s),
		Users:      store.NewTable[model.User](s),
		Groups:     store.NewTable[model.Group](s),
		Members:    store.NewTable[model.Member](s),
		Tenants:    store.NewTable[model.Tenant](s),
		Access:     store.NewTable[model.TenantAccess](s),
		Clients:    store.NewTable[model.Client](s),
		Providers:  store.NewTable[model.Provider](s),
		Passkeys:   store.NewTable[model.Passkey](s),
		Identities: store.NewTable[model.Identity](s),
		Sessions:   store.NewTable[model.Session](s),
		Grants:     store.NewTable[model.Grant](s),
		APITokens:  store.NewTable[model.APIToken](s),
		Keys:       store.NewTable[model.SigningKey](s),
		Audits:     store.NewTable[model.Audit](s),
		Links:      store.NewTable[model.LinkToken](s),
		SignIns:    store.NewTable[model.SignIn](s),
		Locks:      store.NewTable[model.Lock](s),
		Replays:    store.NewTable[model.Replay](s),
	}
}

// RequestInfo is the request an operation is made for, as the audit log records it. The web server puts one in
// every request's context (WithRequest); the session middleware and a sign-in fill in the session.
type RequestInfo struct {
	ID        string
	IP        string // the client address (web.ClientIP), for events whose actor carries none
	UserAgent string
	SessionID string
}

type requestKey struct{}

// WithRequest returns ctx carrying ri.
func WithRequest(ctx context.Context, ri *RequestInfo) context.Context {
	return context.WithValue(ctx, requestKey{}, ri)
}

// RequestFrom returns the request ctx was made for, or nil (a command, housekeeping).
func RequestFrom(ctx context.Context) *RequestInfo {
	ri, _ := ctx.Value(requestKey{}).(*RequestInfo)
	return ri
}

// AuditRefused records an API request (management API or SCIM) refused for the authenticated actor a: what it asked
// for and why it was refused. At most one per caller and reason per minute on each node (auditRefusal): a caller can
// repeat a refused request as fast as it likes.
func (s *Service) AuditRefused(ctx context.Context, a *Actor, method, path, reason string) {
	who := a.UserID + "|" + a.TokenID + "|" + a.ClientID
	s.auditRefusal("api|"+who+"|"+reason, func(detail map[string]string) {
		detail["reason"] = reason
		s.Audit(ctx, a, a.OrgID, "api.request.refused", method+" "+path, detail)
	})
}

// Audit records a security event. Failures are not fatal to the operation.
func (s *Service) Audit(ctx context.Context, a *Actor, orgID, action, target string, detail map[string]string) {
	e, log, kv := s.auditEvent(ctx, a, orgID, action, target, detail)
	if s.AuditWriter != nil { // VictoriaLogs: the database keeps none
		s.AuditWriter.WriteAudit(e)
		return
	}
	if err := s.Audits.Put(context.WithoutCancel(ctx), e); err != nil {
		log.WithError(err).Error("audit event not stored", kv...)
	}
}

// AuditStored records a security event as Audit does and reports whether it was stored: for an event whose record the
// caller keeps until it is in the audit log (an operator's forced start), which tries again later when it was not.
// With VictoriaLogs the event is handed to its writer, which never loses it silently (WriteAudit). The database's copy
// is this node's own (with gossip, every node keeps its own audit events).
func (s *Service) AuditStored(ctx context.Context, a *Actor, orgID, action, target string, detail map[string]string) error {
	e, log, kv := s.auditEvent(ctx, a, orgID, action, target, detail)
	if s.AuditWriter != nil {
		s.AuditWriter.WriteAudit(e)
		return nil
	}
	if err := s.Audits.Put(context.WithoutCancel(ctx), e); err != nil {
		log.WithError(err).Error("audit event not stored", kv...)
		return err
	}
	return nil
}

// auditEvent makes the audit event of a security event (with its id and time) and writes it to the structured log; it
// returns the event and the log line's fields.
func (s *Service) auditEvent(ctx context.Context, a *Actor, orgID, action, target string, detail map[string]string) (*model.Audit, logger.Logger, []any) {
	if a == nil {
		a = System
	}
	// Queryable audit fields are stored in VARCHAR(255) columns on MySQL/MariaDB.
	e := &model.Audit{OrgID: orgID, ActorID: a.UserID, Actor: clip(a.Name, 255), Action: clip(action, 255),
		Target: clip(target, 255), IP: a.IP, Outcome: model.AuditOutcome(action),
		Detail: detail, Expires: time.Now().Add(time.Duration(s.Cfg.Audit.RetentionDays) * 24 * time.Hour)}
	if o, _ := ctx.Value(outcomeKey{}).(string); o != "" { // a change whose outcome is not known (auditUnknown)
		e.Outcome = o
	}
	if a.ClientID != "" && e.Actor == "" {
		e.Actor = "client:" + a.ClientID
	}
	if a.TokenID != "" { // which of the owner's tokens did it (revoking that one is the answer to a misuse)
		d := make(map[string]string, len(detail)+1)
		maps.Copy(d, detail)
		d["token_id"] = a.TokenID
		e.Detail, detail = d, d
	}
	metrics.AuditEvents.Inc(e.Action, e.Outcome)
	if ri := RequestFrom(ctx); ri != nil {
		e.RequestID, e.UserAgent, e.SessionID = ri.ID, clip(ri.UserAgent, 512), ri.SessionID
		if e.IP == "" {
			e.IP = ri.IP
		}
	}
	if cmd, _ := ctx.Value(commandKey{}).(commandInfo); cmd.name != "" && a == System { // an operator's command, not the system's own work
		e.Actor = "command:" + cmd.name
		d := make(map[string]string, len(detail)+2)
		maps.Copy(d, detail)
		d["command"], d["authenticated"] = cmd.name, cmd.how
		e.Detail, detail = d, d
	}
	if len(s.Origin) > 0 { // a command: who ran it, where, as what
		if a == System {
			e.Actor = clip("cli:"+s.Origin["os_user"]+"@"+s.Origin["host"], 255)
		}
		d := make(map[string]string, len(detail)+len(s.Origin))
		maps.Copy(d, detail)
		maps.Copy(d, s.Origin)
		e.Detail, detail = d, d
	}
	// The structured log gets every event too: the trail survives a store failure, and a log pipeline sees it
	// without VictoriaLogs. A request that ends (the client went away) does not lose its audit record.
	kv := []any{"action", e.Action, "outcome", e.Outcome, "org", orgID, "actor", e.Actor, "actor_id", e.ActorID,
		"target", e.Target, "ip", e.IP}
	for k, v := range map[string]string{"request_id": e.RequestID, "user_agent": e.UserAgent, "session_id": e.SessionID} {
		if v != "" {
			kv = append(kv, k, v)
		}
	}
	for k, v := range detail {
		kv = append(kv, "detail."+k, v)
	}
	log := s.Log.WithGroup("audit")
	log.Info("audit", kv...)
	e.ID, e.Created = model.NewID(), time.Now().UTC() // (VictoriaLogs takes the event as it is)
	return e, log, kv
}

// clip shortens s to at most n bytes without splitting a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

type selfServiceKey struct{}

// SelfService marks ctx as the account page acting for its signed-in user after it verified the change (current
// password or a recent re-authentication). Only then may UpdateUser change the actor's own password or email.
func SelfService(ctx context.Context) context.Context {
	return context.WithValue(ctx, selfServiceKey{}, true)
}

func isSelfService(ctx context.Context) bool { v, _ := ctx.Value(selfServiceKey{}).(bool); return v }

// Bindings for sealed secrets (see secure.Sealer.SealFor).
func TOTPBinding(userID string) string        { return "user/" + userID + "/totp" }
func ProviderSecretBinding(id string) string  { return "provider/" + id + "/client_secret" }
func SigningKeyBinding(id string) string      { return "key/" + id + "/private" }
func IdentityRefreshBinding(id string) string { return "identity/" + id + "/refresh" }
func GrantKeyBinding(id string) string        { return "grant/" + id + "/refresh_key" }
