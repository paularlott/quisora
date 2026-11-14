package service

import (
	"cmp"
	"context"
	"errors"
	"fmt"
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
	// ScopeBackup downloads backups of the whole store (GET /api/backup): super admins only, and such a token
	// always expires within BackupTokenMaxDays — a backup holds every credential (sealed) of every organization.
	ScopeBackup = "backup"
	// ScopeAPI is for the organization's own applications, which validate the token through introspection. Who may hold
	// one is the organization's decision (OrgSettings.APITokens, APITokensAllowed), and which applications see it theirs
	// (Client.AcceptsAPITokens).
	ScopeAPI = "api"
	// ScopeImport lets an admin-scope token create users with a password hash brought from another system
	// (UserInput.PasswordHash): super admins only.
	ScopeImport = "import"
)

// APITokenScopes are the scopes a user may choose from.
var APITokenScopes = []string{ScopeAPI, ScopeSCIM, ScopeAdmin, ScopeBackup, ScopeImport}

// SuperOnlyScope reports whether only super admins may hold a token with scope sc.
func SuperOnlyScope(sc string) bool { return sc == ScopeBackup || sc == ScopeImport }

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
	// AppScopes (api scope only) narrows the token to some of its applications' own scopes; empty: full access.
	AppScopes []string `json:"app_scopes"`
	// SetUpBy goes with a token made from the account page for a sign-in through this provider while the account has
	// no second factor of its own: it is recorded on the account (model.User.SetUpBy) in the write that makes the
	// token. Never read from a request body.
	SetUpBy string `json:"-"`
	// Seen is the account as the caller decided on the token (the session's copy, whose role chose whether a second
	// factor was needed and whose factors chose SetUpBy); nil: the account as CreateAPIToken reads it. Never read from
	// a request body.
	Seen *model.User `json:"-"`
}

// APITokenUpdate changes a token's name, applications or scopes; nil leaves a field as it is. The secret, the
// Quisora scopes and the expiry never change here (a new secret: RegenerateAPIToken).
type APITokenUpdate struct {
	Name      *string   `json:"name"`
	Audience  *[]string `json:"audience"`
	AppScopes *[]string `json:"app_scopes"`
}

// StandardScopes are the OpenID Connect scopes Quisora defines; a client's other scopes are its own, for its APIs.
var StandardScopes = []string{"openid", "profile", "email", "phone", "groups", "org", "roles", "enterprise", "idp", "offline_access"}

// AppScopesOf returns a client's own scopes (those that are not standard).
func AppScopesOf(c *model.Client) []string {
	out := []string{}
	for _, sc := range c.Scopes {
		if !slices.Contains(StandardScopes, sc) {
			out = append(out, sc)
		}
	}
	return out
}

// TokenApp is an application a personal api token can be made for, with its own scopes.
type TokenApp struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
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
		return nil, 0, s.denied(a, u)
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
		if (sc == ScopeSCIM || sc == ScopeAdmin) && !a.Role.Privileged() {
			return nil, "", Invalid("scopes", "your role cannot use the "+sc+" scope")
		}
		if SuperOnlyScope(sc) && !a.IsSuper() {
			return nil, "", Invalid("scopes", "only super admins can use the "+sc+" scope")
		}
		if sc == ScopeBackup {
			if in.Expires < 1 || in.Expires > BackupTokenMaxDays {
				return nil, "", Invalid("expires_days", "a token with the backup scope expires within "+itoa(BackupTokenMaxDays)+" days")
			}
		}
	}
	days := in.Expires
	o, err := s.OrgPolicy(ctx, a.OrgID)
	if err != nil {
		return nil, "", err
	}
	max := s.APITokenMaxDays(o)
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
	owner, err := s.Users.Get(ctx, a.UserID)
	if err != nil {
		return nil, "", mapStore(err)
	}
	// The token is made only for the account the caller decided on, and the actor's role judged above: a promotion, a
	// reset or a new factor since then is a stale request (the caller tries again on the account as it is now).
	if seen := cmp.Or(in.Seen, owner); seen.Role != owner.Role || seen.CredEpoch != owner.CredEpoch ||
		seen.SecurityGen != owner.SecurityGen || a.Role != owner.Role {
		return nil, "", ErrStale
	}
	if slices.Contains(in.Scopes, ScopeAPI) {
		if ok, err := s.APITokensAllowed(ctx, owner); err != nil {
			return nil, "", err
		} else if !ok {
			return nil, "", Invalid("scopes", "your organization does not let you make tokens with the api scope")
		}
	}
	aud, err := s.tokenAudience(ctx, a.OrgID, in)
	if err != nil {
		return nil, "", err
	}
	appScopes, err := s.tokenAppScopes(ctx, a, in.Scopes, aud, in.AppScopes)
	if err != nil {
		return nil, "", err
	}
	sources, err := s.tokenSources(ctx, a)
	if err != nil {
		return nil, "", err
	}
	t := &model.APIToken{Meta: model.Meta{ID: model.NewID()}, UserID: a.UserID, OrgID: a.OrgID, Name: name,
		Scopes: slices.Clone(in.Scopes), Audience: aud, AppScopes: appScopes, Epoch: owner.CredEpoch, Sources: sources}
	if days > 0 {
		t.Expires = time.Now().Add(time.Duration(days) * 24 * time.Hour)
	}
	secret := secure.RandomToken(32)
	plain := apiTokenPrefix + t.ID + "_" + secret
	t.SecretHash = secure.HashSecret(secret)
	if t.Stamp, err = s.apiTokenStamp(ctx, a.OrgID); err != nil {
		return nil, "", mapStore(err)
	}
	// The token is written in one transaction with the account as read above, at that version: the role and the
	// credential epoch it was judged and made by are those of the account when it is stored, and a change committed
	// in between (a promotion, a reset) refuses it (ErrStale) rather than leave a token the change did not see. When
	// the token is the provider's (SetUpBy), that write of the account records it, so a promotion that leaves the
	// account without the provider ends the token with the rest of what the provider's sign-in set up (applyRole);
	// otherwise the account is asserted, not written.
	tok, err := store.Encode(t)
	if err != nil {
		return nil, "", err
	}
	ops := []store.Op{store.AssertOp(model.KindUser, owner.OrgID, owner.ID, owner.Version), {Rec: tok, Match: true}}
	if in.SetUpBy != "" && owner.SetUpBy == "" {
		expect := owner.Version
		owner.SetUpBy = in.SetUpBy
		rec, err := store.Encode(owner)
		if err != nil {
			return nil, "", err
		}
		ops[0] = store.Op{Rec: rec, Match: true, Expect: expect}
	}
	if err := s.audited(ctx, a, a.OrgID, "apitoken.create", name, map[string]string{"scopes": strings.Join(in.Scopes, " ")},
		func() error { return s.Users.S.Tx(ctx, ops) }); err != nil {
		return nil, "", mapStore(err)
	}
	return t, plain, nil
}

// RegenerateAPIToken gives one of the actor's own tokens a new secret and returns the new plaintext once. Everything
// else stays (name, scopes, audience, expiry: a new secret never extends a token's life), and the old secret stops
// working at once. Only the owner: a secret is never shown to anyone else, an administrator included.
func (s *Service) RegenerateAPIToken(ctx context.Context, a *Actor, id string) (*model.APIToken, string, error) {
	if a.UserID == "" || a.Scoped() {
		return nil, "", ErrForbidden // tokens cannot mint tokens
	}
	// A use of the token records its last use in the background (touchAPIToken) and may land between the read and the
	// write: the change is made again on the record as it is now.
	for attempt := 0; ; attempt++ {
		t, err := s.ownLiveToken(ctx, a, id)
		if err != nil {
			return nil, "", err
		}
		// The owner's role may have changed since the token was made: a new secret only for scopes they may still use.
		for _, sc := range t.Scopes {
			if (sc == ScopeSCIM || sc == ScopeAdmin) && !a.Role.Privileged() ||
				SuperOnlyScope(sc) && !a.IsSuper() {
				return nil, "", Invalid("scopes", "your role can no longer use the "+sc+" scope: revoke this token instead")
			}
		}
		secret := secure.RandomToken(32)
		t.SecretHash = secure.HashSecret(secret)
		t.LastUsed = time.Time{} // the new secret has not been used
		err = s.APITokens.Update(ctx, t)
		if errors.Is(err, store.ErrStale) && attempt < 3 {
			continue
		}
		s.auditOutcome(ctx, a, err, change{t.OrgID, "apitoken.regenerate", t.Name, nil, nil})
		if err != nil {
			return nil, "", mapStore(err)
		}
		return t, apiTokenPrefix + t.ID + "_" + secret, nil
	}
}

// ownLiveToken returns a's own token id for a change (a new secret, a new name or audience): not one that stopped
// working when a's sign-in was reset (its epoch is no longer held: ValidateAPIToken refuses it), whose new secret or
// settings would never work.
func (s *Service) ownLiveToken(ctx context.Context, a *Actor, id string) (*model.APIToken, error) {
	t, err := s.APITokens.Get(ctx, id)
	if err != nil || t.UserID != a.UserID {
		return nil, ErrNotFound
	}
	u, err := s.Users.Get(ctx, a.UserID)
	if err != nil {
		return nil, mapStore(err)
	}
	if !u.Holds(t.Epoch) {
		return nil, Invalid("token", "this token stopped working when your sign-in was reset: delete it and make a new one")
	}
	return t, nil
}

// APITokensAllowed reports whether u may hold a personal API token with the api scope under their organization's
// setting (OrgSettings.APITokens): everyone, the members of its chosen groups, or nobody. The scim, admin, backup and
// import scopes are not decided here: their owner's role alone is. An error is a read that failed (the organization,
// the user's groups): no verdict, never "not allowed". The organization is read as Org reads it, within its bound,
// so this is cheap enough to ask at every use of a token.
func (s *Service) APITokensAllowed(ctx context.Context, u *model.User) (bool, error) {
	org, err := s.Org(ctx, u.OrgID)
	if err != nil {
		return false, err
	}
	switch org.Settings.APITokens {
	case model.APITokensEveryone:
		return true, nil
	case model.APITokensGroups:
		groups, err := s.UserGroups(ctx, u)
		if err != nil {
			return false, err
		}
		return slices.ContainsFunc(groups, func(g *model.Group) bool { return slices.Contains(org.Settings.APITokenGroups, g.ID) }), nil
	}
	return false, nil
}

// TokenApps lists the applications the actor may make a personal api token for: the enabled confidential clients of
// their organization that accept api tokens and that they have access to (as a sign-in to each would decide), by
// name, each with its own scopes.
func (s *Service) TokenApps(ctx context.Context, a *Actor) ([]TokenApp, error) {
	if a.UserID == "" {
		return nil, ErrForbidden
	}
	u, err := s.Users.Get(ctx, a.UserID)
	if err != nil {
		return nil, mapStore(err)
	}
	groups, err := s.UserGroups(ctx, u)
	if err != nil {
		return nil, err
	}
	gids := make([]string, 0, len(groups))
	for _, g := range groups {
		gids = append(gids, g.ID)
	}
	cs, _, err := s.Clients.List(ctx, store.ListQuery{Scope: u.OrgID})
	if err != nil {
		return nil, mapStore(err)
	}
	out := []TokenApp{}
	for _, c := range cs {
		if !c.Enabled || c.Public() || !c.AcceptsAPITokens {
			continue
		}
		t, err := s.ClientTenant(ctx, c)
		if err != nil {
			continue
		}
		if acc, err := s.ClientAccess(ctx, t, c, u, gids); err != nil || !acc.Allowed {
			continue
		}
		out = append(out, TokenApp{ID: c.ID, Name: c.Name, Scopes: AppScopesOf(c)})
	}
	slices.SortFunc(out, func(x, y TokenApp) int { return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)) })
	return out, nil
}

// tokenAppScopes validates the scopes a token is narrowed to: an api token's only, with applications chosen, each
// scope declared by one of them. (A token for every application is not narrowed: there is no one set of scopes.)
func (s *Service) tokenAppScopes(ctx context.Context, a *Actor, scopes, audience, appScopes []string) ([]string, error) {
	out, err := checkScopes(appScopes)
	if err != nil {
		var fe *FieldError
		if errors.As(err, &fe) {
			fe.Field = "app_scopes"
		}
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if !slices.Contains(scopes, ScopeAPI) {
		return nil, Invalid("app_scopes", "only a token with the api scope has application scopes")
	}
	if len(audience) == 0 {
		return nil, Invalid("app_scopes", "choose the applications the token is for to limit it to their scopes")
	}
	apps, err := s.TokenApps(ctx, a)
	if err != nil {
		return nil, err
	}
	declared := map[string]bool{}
	for _, app := range apps {
		if !slices.Contains(audience, app.ID) {
			continue
		}
		for _, sc := range app.Scopes {
			declared[sc] = true
		}
	}
	for _, sc := range out {
		if !declared[sc] {
			return nil, Invalid("app_scopes", sc+" is not a scope of an application this token is for")
		}
	}
	return out, nil
}

// UpdateAPIToken changes one of the actor's own tokens: its name, the applications it is for and the scopes it is
// narrowed to, checked as when it was made. Making a token with the new settings would give the same; the secret
// and the expiry stay.
func (s *Service) UpdateAPIToken(ctx context.Context, a *Actor, id string, in APITokenUpdate) (*model.APIToken, error) {
	if a.UserID == "" || a.Scoped() {
		return nil, ErrForbidden
	}
	t, err := s.ownLiveToken(ctx, a, id)
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || len(name) > 100 {
			return nil, Invalid("name", "required, at most 100 characters")
		}
		t.Name = name
	}
	if in.Audience != nil {
		aud, err := s.tokenAudience(ctx, a.OrgID, APITokenInput{Scopes: t.Scopes, Audience: *in.Audience})
		if err != nil {
			return nil, err
		}
		t.Audience = aud
	}
	appScopes := t.AppScopes
	if in.AppScopes != nil {
		appScopes = *in.AppScopes
	}
	// checked again whenever the applications change too: a scope must stay one of theirs
	if t.AppScopes, err = s.tokenAppScopes(ctx, a, t.Scopes, t.Audience, appScopes); err != nil {
		return nil, err
	}
	if err := s.audited(ctx, a, t.OrgID, "apitoken.update", t.Name, nil, func() error { return s.APITokens.Update(ctx, t) }); err != nil {
		return nil, mapStore(err)
	}
	return t, nil
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
		if !c.AcceptsAPITokens {
			return nil, Invalid("audience", c.Name+" does not accept API tokens")
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
	var detail map[string]string
	if t.UserID != a.UserID {
		detail = map[string]string{"owner": t.UserID}
	}
	return mapStore(s.audited(ctx, a, t.OrgID, "apitoken.delete", t.Name, detail, func() error { return s.APITokens.Delete(ctx, id) }))
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
	id, secret, ok := strings.Cut(rest, "_") // an id is letters and digits only: the first '_' ends it
	if !ok {
		return nil, nil, ErrBadToken
	}
	t, err := s.APITokens.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrBadToken // no such token: nobody to record it for (the caller counts the failure)
	}
	if err != nil { // not the caller's failure: it must not count against their address
		return nil, nil, fmt.Errorf("%w: the token could not be checked: %v", ErrUnavailable, err)
	}
	// A refusal of a token that exists is audited in its organization: a wrong secret for a real token id, or a
	// token that still circulates after it was ended, is worth an administrator's attention. Once per token and
	// reason per minute on each node (auditRefusal): anyone who learns a token's id can repeat it at will.
	refuse := func(reason string) (*model.APIToken, *model.User, error) {
		s.auditRefusal(t.OrgID, "token|"+t.ID+"|"+reason, func(detail map[string]string) {
			detail["reason"] = reason
			// The token's owner is the event's user: the refusal of a super admin's token is a super admin's event, hidden from
			// the administrators below them like every other (it names the token and what is wrong with it).
			owner := s.AuditTargetUser(ctx, t.OrgID, t.UserID)
			s.auditChange(ctx, &Actor{Name: "unauthenticated", TokenID: t.ID}, change{t.OrgID, "apitoken.refused", t.Name, detail, owner})
		})
		return nil, nil, ErrBadToken
	}
	if !secure.EqualSecret(secret, t.SecretHash) {
		return refuse("wrong secret")
	}
	// The sign-out counters that cannot be read now decide nothing (503), rather than refusing a good token as
	// "ended" and auditing an emergency sign-out that did not happen.
	want, err := s.apiTokenStamp(ctx, t.OrgID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the sign-out counters could not be read: %v", ErrUnavailable, err)
	}
	if !t.Stamp.Current(want) {
		return refuse("ended by an emergency sign-out")
	}
	u, err := s.Users.Get(ctx, t.UserID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, fmt.Errorf("%w: the token's owner could not be read: %v", ErrUnavailable, err)
	}
	if err != nil {
		return refuse("the owner is disabled or gone")
	}
	if ok, err := s.UserUsable(ctx, u); err != nil {
		return nil, nil, fmt.Errorf("%w: the token's owner could not be read: %v", ErrUnavailable, err)
	} else if !ok { // disabled, or its organization deleted
		return refuse("the owner is disabled or gone")
	}
	if !u.Holds(t.Epoch) {
		return refuse("the owner's sign-in was reset since the token was made")
	}
	// A guest's token stands on the accounts it came from (model.APIToken.Sources), as the person's own tokens there do.
	if ok, err := s.sourcesHold(ctx, t.Sources, s.storeUser, true); err != nil {
		return nil, nil, fmt.Errorf("%w: the accounts the token's owner signs in from could not be read: %v", ErrUnavailable, err)
	} else if !ok {
		return refuse("the owner's account in the organization they sign in from is disabled, gone or reset")
	}
	if !u.Role.Privileged() && (slices.Contains(t.Scopes, ScopeSCIM) || slices.Contains(t.Scopes, ScopeAdmin)) ||
		u.Role != model.RoleSuperAdmin && slices.ContainsFunc(t.Scopes, SuperOnlyScope) {
		return refuse("the owner's role no longer allows the token's scopes") // demoted since the token was made
	}
	// An api token lives by the organization's setting as it is now, not as it was when the token was made: turned off,
	// or the owner out of the chosen groups, it stops here, and works again should the setting allow it again. A read
	// that fails decides nothing (503), as with the owner above.
	if slices.Contains(t.Scopes, ScopeAPI) {
		if ok, err := s.APITokensAllowed(ctx, u); err != nil {
			return nil, nil, fmt.Errorf("%w: the organization's API token setting could not be read: %v", ErrUnavailable, err)
		} else if !ok {
			return refuse("the organization does not let the owner use api tokens")
		}
	}
	s.touchAPIToken(ctx, t)
	return t, u, nil
}

// apiTokenTouch is how stale a token's LastUsed may get before a use records it again: one write per token per
// interval, not one per request.
const apiTokenTouch = 5 * time.Minute

// touchAPIToken records that t was used, in the background (best effort: a lost race or a failed write only delays
// it): the request does not wait for a write it does not need. One write at a time per token; a request that finds one running skips it, and the
// next that finds the stamp old tries again. t itself is not changed.
func (s *Service) touchAPIToken(ctx context.Context, t *model.APIToken) {
	now := time.Now().UTC()
	if now.Sub(t.LastUsed) < apiTokenTouch {
		return
	}
	cp := *t
	if _, busy := s.tokenTouching.LoadOrStore(cp.ID, struct{}{}); busy {
		return
	}
	s.Background(ctx, BackgroundShort, func(ctx context.Context) {
		defer s.tokenTouching.Delete(cp.ID)
		cp.LastUsed = now
		_ = s.APITokens.Update(ctx, &cp)
	})
}

// ActorForToken builds the actor for a request authenticated with an API token.
func ActorForToken(t *model.APIToken, u *model.User, ip string) *Actor {
	return &Actor{UserID: u.ID, OrgID: u.OrgID, Role: u.Role, Name: u.Username, Scopes: t.Scopes, TokenID: t.ID, IP: ip}
}

// ActorForApp builds the actor for user u acting through application clientID with a user's access token (Quisora's
// own MCP server): limited to what a personal API token may do (Scoped, holding no scopes), and named in the audit log
// with the application.
func ActorForApp(u *model.User, clientID, ip string) *Actor {
	return &Actor{UserID: u.ID, OrgID: u.OrgID, Role: u.Role, Name: u.Username, App: clientID, IP: ip}
}

// ActorForUser builds the actor for an interactive session (no scope limits).
func ActorForUser(u *model.User, ip string) *Actor {
	return &Actor{UserID: u.ID, OrgID: u.OrgID, Role: u.Role, Name: u.Username, IP: ip, Unscoped: true}
}
