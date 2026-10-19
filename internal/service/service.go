// Package service holds the business rules and role checks. Every handler (UI JSON API, SCIM, OAuth) goes through
// it for anything a permission applies to.
package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

var (
	ErrForbidden  = errors.New("forbidden")
	ErrNotFound   = errors.New("not found")
	ErrInvalid    = errors.New("invalid")
	ErrConflict   = errors.New("already exists")
	ErrStale      = errors.New("changed by someone else, reload and try again")
	ErrLastAdmin  = errors.New("cannot remove the last administrator")
	ErrNotEmpty   = errors.New("organization still has users")
	ErrPrimaryOrg = errors.New("the primary organization cannot be deleted")
	// ErrNotReplicated: the change was made on this server but no other server confirmed it yet (store.Applied).
	ErrNotReplicated = store.ErrNotReplicated
	// ErrUnavailable: this server cannot make the change now (it is catching up with its cluster, out of date, or
	// cannot reach a majority of it; with cluster.strict_durability, a majority did not confirm it). Nothing changed,
	// or the change was undone; try again shortly or through another server.
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
	case errors.Is(err, store.ErrNotWritable), errors.Is(err, store.ErrUnconfirmed):
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
	IP       string
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
	Cfg    *config.Config
	Store  store.Store
	Hasher *secure.Hasher
	Sealer *secure.Sealer
	// Log receives every audit event (group "audit") as well as the store, and any failure to store one.
	Log logger.Logger
	// AuditReader serves the audit pages (nil: this node's store) and AuditWriter takes audit events instead of the
	// store (nil: the store). Set by the app: every node of a gossip cluster (reader), VictoriaLogs (both).
	AuditReader AuditReader
	AuditWriter AuditWriter

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

	primary *orgCache

	// Writable reports whether this node may change replicated data now (cluster.Node.Writable; nil: always). Writes
	// made in passing while serving reads (a session's or token's last use, a sign-in's last-login stamp) are skipped
	// when it is false: the store would refuse them, and a node that cannot know its data is current must not
	// replicate anything it changed on its own.
	Writable func() bool

	// OnSessionsEnding is called just before sessions are ended (sessionIDs nil = every session and refresh grant
	// of the user), so relying parties can be sent back-channel logout tokens. Set by the app.
	OnSessionsEnding func(ctx context.Context, userID string, sessionIDs []string)

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
		primary:    &orgCache{},
	}
}

// Audit records a security event. Failures are not fatal to the operation.
func (s *Service) Audit(ctx context.Context, a *Actor, orgID, action, target string, detail map[string]string) {
	if a == nil {
		a = System
	}
	// Queryable audit fields are stored in VARCHAR(255) columns on MySQL/MariaDB.
	e := &model.Audit{OrgID: orgID, ActorID: a.UserID, Actor: clip(a.Name, 255), Action: clip(action, 255),
		Target: clip(target, 255), IP: a.IP,
		Detail: detail, Expires: time.Now().Add(time.Duration(s.Cfg.Audit.RetentionDays) * 24 * time.Hour)}
	if a.ClientID != "" && e.Actor == "" {
		e.Actor = "client:" + a.ClientID
	}
	// The structured log gets every event too: the trail survives a store failure, and a log pipeline sees it
	// without VictoriaLogs. A request that ends (the client went away) does not lose its audit record.
	kv := []any{"action", e.Action, "org", orgID, "actor", e.Actor, "actor_id", e.ActorID, "target", e.Target, "ip", e.IP}
	for k, v := range detail {
		kv = append(kv, "detail."+k, v)
	}
	log := s.Log.WithGroup("audit")
	log.Info("audit", kv...)
	if s.AuditWriter != nil { // VictoriaLogs: the database keeps none
		e.ID, e.Created = model.NewID(), time.Now().UTC()
		s.AuditWriter.WriteAudit(e)
		return
	}
	if err := s.Audits.Put(context.WithoutCancel(ctx), e); err != nil && !store.Applied(err) {
		log.WithError(err).Error("audit event not stored", kv...)
	}
}

// Durable marks ctx so the write it carries is acknowledged by a peer before returning (security-critical writes in
// replicated clusters; see cluster package).
func Durable(ctx context.Context) context.Context { return store.WithDurable(ctx) }

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
