package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// API token scopes. A token never grants more than its owner's role allows.
const (
	ScopeSCIM  = "scim"  // SCIM 2.0 API (owner must be manager+; groups need admin)
	ScopeAdmin = "admin" // admin JSON API
	// ScopeBackup downloads backups of the whole store (GET /api/v1/backup): super admins only, and such a token
	// always expires within BackupTokenMaxDays — a backup holds every credential (sealed) of every organization.
	ScopeBackup = "backup"
	ScopeAPI    = "api" // for the user's own applications: validated by them through introspection
)

// APITokenScopes are the scopes a user may choose from.
var APITokenScopes = []string{ScopeAPI, ScopeSCIM, ScopeAdmin, ScopeBackup}

// BackupTokenMaxDays bounds the lifetime of a token with the backup scope.
const BackupTokenMaxDays = 30

const apiTokenPrefix = "qsr_"

// APITokenInput describes a new personal API token.
type APITokenInput struct {
	Name    string   `json:"name"`
	Scopes  []string `json:"scopes"`
	Expires int      `json:"expires_days"` // 0 = the server maximum, or never when there is none
	// Audience (api scope only) lists the clients of the owner's organization that may see the token through
	// introspection; empty: any of its confidential clients.
	Audience []string `json:"audience"`
}

// maxTokenDays bounds a typed-in lifetime when the server sets no maximum (10 years).
const maxTokenDays = 3650

// maxTokenAudience bounds a token's audience list.
const maxTokenAudience = 20

// ListAPITokens lists the actor's own tokens.
func (s *Service) ListAPITokens(ctx context.Context, a *Actor, q store.ListQuery) ([]*model.APIToken, int, error) {
	if a.UserID == "" {
		return nil, 0, ErrForbidden
	}
	q.Scope = a.UserID
	l, n, err := s.APITokens.List(ctx, q)
	return l, n, mapStore(err)
}

// ListUserAPITokens lists the tokens of a user: the actor's own, or those of a user the actor manages (an
// administrator reviewing or revoking them). The secrets are never shown again.
func (s *Service) ListUserAPITokens(ctx context.Context, a *Actor, userID string, q store.ListQuery) ([]*model.APIToken, int, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, 0, mapStore(err)
	}
	if a.UserID != userID && !s.canManageUser(a, u) {
		if s.canManageUsers(a, u.OrgID) {
			return nil, 0, ErrForbidden
		}
		return nil, 0, ErrNotFound
	}
	q.Scope = userID
	l, n, err := s.APITokens.List(ctx, q)
	return l, n, mapStore(err)
}

// CreateAPIToken creates a token for the actor and returns the plaintext once: qsr_<id>_<secret>.
func (s *Service) CreateAPIToken(ctx context.Context, a *Actor, in APITokenInput) (*model.APIToken, string, error) {
	if a.UserID == "" || a.Scoped() {
		return nil, "", ErrForbidden // tokens cannot mint tokens
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		return nil, "", Invalid("name", "required, at most 100 characters")
	}
	if len(in.Scopes) == 0 {
		return nil, "", Invalid("scopes", "choose at least one scope")
	}
	// An api token is shown to the user's own applications (introspection): it must never also carry a scope of
	// Quisora's own APIs, or every application that sees it could administer Quisora with it.
	if slices.Contains(in.Scopes, ScopeAPI) && len(slices.DeleteFunc(slices.Clone(in.Scopes), func(s string) bool { return s == ScopeAPI })) > 0 {
		return nil, "", Invalid("scopes", "the api scope cannot be combined with scim, admin or backup: make a separate token")
	}
	for _, sc := range in.Scopes {
		if !slices.Contains(APITokenScopes, sc) {
			return nil, "", Invalid("scopes", "unknown scope "+sc)
		}
		if (sc == ScopeSCIM || sc == ScopeAdmin) && a.Role.Rank() < model.RoleManager.Rank() {
			return nil, "", Invalid("scopes", "your role cannot use the "+sc+" scope")
		}
		if sc == ScopeBackup {
			if !a.IsSuper() {
				return nil, "", Invalid("scopes", "only super admins can use the backup scope")
			}
			if in.Expires < 1 || in.Expires > BackupTokenMaxDays {
				return nil, "", Invalid("expires_days", "a token with the backup scope expires within "+itoa(BackupTokenMaxDays)+" days")
			}
		}
	}
	days := in.Expires
	max := s.Cfg.Tokens.APITokenMaxDays
	if max <= 0 && (days < 0 || days > maxTokenDays) {
		// no server maximum: a lifetime that is typed in is still a sensible number; longer means never (empty)
		return nil, "", Invalid("expires_days", "must be between 1 and "+itoa(maxTokenDays)+", or empty for no expiry")
	}
	if days < 0 || (max > 0 && days > max) {
		return nil, "", Invalid("expires_days", "must be between 1 and "+itoa(max))
	}
	if days == 0 {
		days = max
	}
	aud, err := s.tokenAudience(ctx, a.OrgID, in)
	if err != nil {
		return nil, "", err
	}
	t := &model.APIToken{Meta: model.Meta{ID: model.NewID()}, UserID: a.UserID, OrgID: a.OrgID, Name: name,
		Scopes: slices.Clone(in.Scopes), Audience: aud}
	if days > 0 {
		t.Expires = time.Now().Add(time.Duration(days) * 24 * time.Hour)
	}
	secret := secure.RandomToken(32)
	plain := apiTokenPrefix + t.ID + "_" + secret
	t.SecretHash = secure.HashSecret(secret)
	if err := s.APITokens.Create(ctx, t); err != nil {
		return nil, "", mapStore(err)
	}
	s.Audit(ctx, a, a.OrgID, "apitoken.create", name, map[string]string{"scopes": strings.Join(in.Scopes, " ")})
	return t, plain, nil
}

// tokenAudience validates the audience of a new token: clients of the owner's organization, for an api token only.
func (s *Service) tokenAudience(ctx context.Context, orgID string, in APITokenInput) ([]string, error) {
	var out []string
	for _, id := range in.Audience {
		id = strings.TrimSpace(id)
		if id == "" || slices.Contains(out, id) {
			continue
		}
		c, err := s.Clients.Get(ctx, id)
		if err != nil || c.OrgID != orgID {
			return nil, Invalid("audience", "unknown application "+id)
		}
		out = append(out, id)
	}
	if len(out) > 0 && !slices.Contains(in.Scopes, ScopeAPI) {
		return nil, Invalid("audience", "only a token with the api scope has an audience")
	}
	if len(out) > maxTokenAudience {
		return nil, Invalid("audience", "at most "+itoa(maxTokenAudience)+" applications")
	}
	return out, nil
}

// DeleteAPIToken revokes one of the actor's tokens (or any token of a user the actor manages).
func (s *Service) DeleteAPIToken(ctx context.Context, a *Actor, id string) error {
	t, err := s.APITokens.Get(ctx, id)
	if err != nil {
		return mapStore(err)
	}
	if t.UserID != a.UserID {
		u, err := s.Users.Get(ctx, t.UserID)
		if err != nil || !s.canManageUser(a, u) {
			return ErrNotFound
		}
	}
	if err := s.APITokens.Delete(Durable(ctx), id); err != nil {
		return mapStore(err)
	}
	var detail map[string]string
	if t.UserID != a.UserID {
		detail = map[string]string{"owner": t.UserID}
	}
	s.Audit(ctx, a, t.OrgID, "apitoken.delete", t.Name, detail)
	return nil
}

// IsAPIToken reports whether a bearer value looks like a personal API token.
func IsAPIToken(v string) bool { return strings.HasPrefix(v, apiTokenPrefix) }

var ErrBadToken = errors.New("invalid token")

// ValidateAPIToken checks a presented token and returns it with its (active) owner.
func (s *Service) ValidateAPIToken(ctx context.Context, presented string) (*model.APIToken, *model.User, error) {
	rest, ok := strings.CutPrefix(presented, apiTokenPrefix)
	if !ok {
		return nil, nil, ErrBadToken
	}
	id, secret, ok := strings.Cut(rest, "_")
	if !ok {
		return nil, nil, ErrBadToken
	}
	t, err := s.APITokens.Get(ctx, id)
	if err != nil || !secure.EqualSecret(secret, t.SecretHash) {
		return nil, nil, ErrBadToken
	}
	u, err := s.Users.Get(ctx, t.UserID)
	if err != nil || !u.Enabled(time.Now()) {
		return nil, nil, ErrBadToken
	}
	if u.Role.Rank() < model.RoleManager.Rank() && (slices.Contains(t.Scopes, ScopeSCIM) || slices.Contains(t.Scopes, ScopeAdmin)) {
		return nil, nil, ErrBadToken // the owner was demoted since the token was made
	}
	s.touchAPIToken(ctx, t)
	return t, u, nil
}

// apiTokenTouch is how stale a token's LastUsed may get before a use records it again: one write per token per
// interval, not one per request.
const apiTokenTouch = 5 * time.Minute

// touchAPIToken records that t was used (best effort: a lost race or a failed write only delays it).
func (s *Service) touchAPIToken(ctx context.Context, t *model.APIToken) {
	now := time.Now().UTC()
	if now.Sub(t.LastUsed) < apiTokenTouch || !s.CanWrite() {
		return
	}
	cp := *t
	cp.LastUsed = now
	if err := s.APITokens.Update(context.WithoutCancel(ctx), &cp); err == nil {
		t.LastUsed, t.Version = cp.LastUsed, cp.Version
	}
}

// ActorForToken builds the actor for a request authenticated with an API token.
func ActorForToken(t *model.APIToken, u *model.User, ip string) *Actor {
	return &Actor{UserID: u.ID, OrgID: u.OrgID, Role: u.Role, Name: u.Username, Scopes: t.Scopes, IP: ip}
}

// ActorForUser builds the actor for an interactive session (no scope limits).
func ActorForUser(u *model.User, ip string) *Actor {
	return &Actor{UserID: u.ID, OrgID: u.OrgID, Role: u.Role, Name: u.Username, IP: ip, Unscoped: true}
}

// ActorForClient builds the actor for a SCIM provisioning client (client_credentials): an admin of its org that
// can manage users and groups but never grant roles above manager.
func ActorForClient(c *model.Client, ip string) *Actor {
	return &Actor{OrgID: c.OrgID, Role: model.RoleAdmin, Name: "client:" + c.Name, ClientID: c.ID,
		Scopes: []string{ScopeSCIM}, IP: ip}
}
