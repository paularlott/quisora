package service

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// Link purposes and lifetimes.
const (
	LinkInvite = "invite" // set a password and/or create a passkey (new users, or a fresh start for an existing one)
	LinkReset  = "reset"  // self-service "forgot password"
	LinkVerify = "verify" // confirm an email address

	InviteTTL = 7 * 24 * time.Hour
	// BreakGlassTTL is how long a break-glass invitation lasts: it is for the person standing at the server now.
	BreakGlassTTL = 24 * time.Hour
	ResetTTL      = time.Hour
	VerifyTTL     = 24 * time.Hour
)

// ErrLink means the link is unknown, expired, already used or of another kind.
var ErrLink = errors.New("this link is invalid or has expired")

func linkID(token string) string {
	return base64.RawURLEncoding.EncodeToString(secure.HashSecret(token))
}

// IssueLink creates a single-use link token for u. Issuing an invitation or reset revokes the user's earlier
// unused links of the same purpose, so only the newest one works.
func (s *Service) IssueLink(ctx context.Context, u *model.User, purpose, email string, ttl time.Duration) (string, *model.LinkToken, error) {
	return s.issueLink(ctx, u, purpose, email, ttl, "")
}

// issueLink is IssueLink recording who issued it (an invitation's issuer: see mayResetSignIn).
func (s *Service) issueLink(ctx context.Context, u *model.User, purpose, email string, ttl time.Duration, by string, edit ...func(*model.LinkToken)) (string, *model.LinkToken, error) {
	if purpose == LinkInvite || purpose == LinkReset {
		old, _, err := s.Links.List(ctx, store.ListQuery{Scope: u.ID, Filters: []store.Filter{{Field: "purpose", Value: purpose}}})
		if err != nil {
			return "", nil, err
		}
		for _, l := range old {
			_ = s.Links.Delete(ctx, l.ID)
		}
	}
	token := secure.RandomToken(32)
	l := &model.LinkToken{Meta: model.Meta{ID: linkID(token)}, UserID: u.ID, OrgID: u.OrgID, Purpose: purpose,
		Email: email, Expires: time.Now().Add(ttl), UserCreated: u.Created, IssuedBy: by, Gen: u.SecurityGen}
	for _, e := range edit {
		e(l)
	}
	if err := s.Links.Create(Durable(ctx), l); err != nil {
		return "", nil, mapStore(err)
	}
	return token, l, nil
}

// PeekLink returns a live, unused link of one of the purposes without using it (to render the page behind it).
func (s *Service) PeekLink(ctx context.Context, token string, purposes ...string) (*model.LinkToken, *model.User, error) {
	if token == "" || len(token) > 128 {
		return nil, nil, ErrLink
	}
	l, err := s.Links.Get(ctx, linkID(token))
	if err != nil || l.Used || !slices.Contains(purposes, l.Purpose) || time.Now().After(l.Expires) {
		return nil, nil, ErrLink
	}
	u, err := s.Users.Get(ctx, l.UserID)
	// The account must be the one the link was issued for: in a cluster a second "quisora bootstrap" on a new node
	// issues a link for a first administrator with the same fixed id, and that link must not open the real one.
	if err != nil || !(u.Enabled(time.Now()) || l.BreakGlass) || !u.Created.Equal(l.UserCreated) {
		return nil, nil, ErrLink
	}
	// An invitation or reset link sets the account's credentials, so it is bound to the account's security
	// generation (model.User.SecurityGen) as it was when the link was issued: once a credential has changed since —
	// its owner changed the password a reset was asked for, set up a second factor, a passkey was added or removed,
	// the account was disabled — the link opens nothing, and whoever wants one asks again. A verification link only
	// proves an address, and checks that the address is still on the account; a change of role or address is judged
	// below and by the caller, not here.
	if (l.Purpose == LinkInvite || l.Purpose == LinkReset) && l.Gen != u.SecurityGen {
		return nil, nil, ErrLink
	}
	if l.Purpose == LinkInvite && l.IssuedBy != "" && !s.issuerMayInvite(ctx, l.IssuedBy, u) {
		_ = s.Links.Delete(ctx, l.ID) // it can never become valid again: the issuer would have to issue a new one
		return nil, nil, ErrLink
	}
	return l, u, nil
}

// issuerMayInvite asks CreateInvite's rules again when an invitation is used, of its issuer as they are now: the
// account may have been promoted since (an administrator's invitation for a plain user must not open a super admin),
// or the issuer demoted or disabled (a link they hold keeps no authority they lost).
func (s *Service) issuerMayInvite(ctx context.Context, issuerID string, u *model.User) bool {
	iu, err := s.Users.Get(ctx, issuerID)
	if err != nil || !iu.Enabled(time.Now()) || iu.ID == u.ID {
		return false
	}
	a := ActorForUser(iu, "")
	return s.canManageUser(a, u) && s.mayResetSignIn(ctx, a, u, "user") == nil
}

// RedeemLink uses the link: exactly one caller succeeds (compare-and-put on the record).
func (s *Service) RedeemLink(ctx context.Context, token string, purposes ...string) (*model.LinkToken, *model.User, error) {
	l, u, err := s.PeekLink(ctx, token, purposes...)
	if err != nil {
		return nil, nil, err
	}
	l.Used = true
	if err := s.Links.Update(Durable(ctx), l); err != nil {
		return nil, nil, ErrLink
	}
	if l.Purpose == LinkInvite || l.Purpose == LinkReset {
		s.revokeOtherSignInLinks(ctx, l)
	}
	if l.BreakGlass && !u.Enabled(time.Now()) {
		reason, noEnd := "break-glass invitation used", ""
		in := UserInput{Active: ptrBool(true), StatusReason: &reason}
		if u.ValidUntil != nil && !time.Now().Before(*u.ValidUntil) {
			in.ValidUntil = &noEnd // ended: the account must be usable again to be recovered
		}
		fresh, err := s.UpdateUser(Durable(ctx), System, u.ID, in)
		if err != nil {
			return nil, nil, err
		}
		u = fresh
	}
	return l, u, nil
}

// revokeOtherSignInLinks deletes the user's other unused invitation and reset links once one is used: the account
// now has the credentials that link set, so no older link may reset them. Issuing a link already revokes earlier
// ones, but two issued at once (or on two nodes before either replicated) can both survive that; without this,
// the second would still open the account after its owner set it up (see mayReplaceInvite).
func (s *Service) revokeOtherSignInLinks(ctx context.Context, used *model.LinkToken) {
	others, _, err := s.Links.List(ctx, store.ListQuery{Scope: used.UserID})
	if err != nil {
		return
	}
	for _, o := range others {
		if o.ID != used.ID && !o.Used && (o.Purpose == LinkInvite || o.Purpose == LinkReset) {
			_ = s.Links.Delete(ctx, o.ID)
		}
	}
}

// MarkLinkSent records that the link with this URL (or token) was emailed to email: using it then proves the
// address (an invitation an administrator copies and shares some other way proves nothing).
func (s *Service) MarkLinkSent(ctx context.Context, link, email string) error {
	token := link
	if u, err := url.Parse(link); err == nil && u.Query().Get("token") != "" {
		token = u.Query().Get("token")
	}
	l, err := s.Links.Get(ctx, linkID(token))
	if err != nil {
		return mapStore(err)
	}
	l.Email = email
	return mapStore(s.Links.Update(Durable(ctx), l))
}

// LinkURL is the absolute URL of a link page for token ("/invite", "/reset", "/verify-email").
func (s *Service) LinkURL(path, token string) string {
	return s.Cfg.Server.PublicURL + path + "?token=" + url.QueryEscape(token)
}

// CreateBreakGlassInvite issues the invitation of "quisora invite --break-glass", for getting back into a server
// nobody can sign in to: only the command issues it (whoever runs it holds the master key and so everything already).
// Unlike CreateInvite it works for a disabled account (a super admin locked out, or past their end date), whose
// invitation enables it again when used; it lasts BreakGlassTTL. Earlier invitations stop working, and accepting it
// replaces every credential of the account, as any invitation does.
func (s *Service) CreateBreakGlassInvite(ctx context.Context, userID string) (string, time.Time, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return "", time.Time{}, mapStore(err)
	}
	token, l, err := s.issueLink(ctx, u, LinkInvite, "", BreakGlassTTL, "", func(l *model.LinkToken) { l.BreakGlass = true })
	if err != nil {
		return "", time.Time{}, err
	}
	detail := map[string]string{"role": string(u.Role)}
	if !u.Enabled(time.Now()) {
		detail["account"] = "disabled: enabled again when the invitation is used"
	}
	s.Audit(ctx, System, u.OrgID, "user.invite.break_glass", u.Username, detail)
	return s.LinkURL("/invite", token), l.Expires, nil
}

// CreateInvite issues a new invitation for a user (new or existing): the link lets them set a password (if their
// organization allows passwords) or create a passkey. Earlier invitations stop working.
func (s *Service) CreateInvite(ctx context.Context, a *Actor, userID string) (string, time.Time, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return "", time.Time{}, mapStore(err)
	}
	if a != System && !s.canManageUser(a, u) {
		return "", time.Time{}, s.denied(a, u)
	}
	if a != System && a.UserID == u.ID {
		return "", time.Time{}, Invalid("user", "you cannot invite yourself")
	}
	if err := s.mayResetSignIn(ctx, a, u, "user"); err != nil {
		return "", time.Time{}, err
	}
	if err := s.mayReplaceInvite(ctx, a, u); err != nil {
		return "", time.Time{}, err
	}
	if !u.Enabled(time.Now()) {
		return "", time.Time{}, Invalid("active", "the account is disabled")
	}
	by := ""
	if a != System {
		by = a.UserID
	}
	token, l, err := s.issueLink(ctx, u, LinkInvite, "", InviteTTL, by)
	if err != nil {
		return "", time.Time{}, err
	}
	s.Audit(ctx, a, u.OrgID, "user.invite", u.Username, nil)
	return s.LinkURL("/invite", token), l.Expires, nil
}

// RemovePassword deletes a user's password: they can no longer sign in with email and password until they set a
// new one through an invitation. Their sessions and refresh tokens end.
func (s *Service) RemovePassword(ctx context.Context, a *Actor, userID string) error {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return mapStore(err)
	}
	if !s.canManageUser(a, u) {
		return s.denied(a, u)
	}
	if a.UserID == u.ID {
		return Invalid("password", "remove your own password from your account page")
	}
	if err := s.mayResetSignIn(ctx, a, u, "password"); err != nil {
		return err
	}
	if u.PasswordHash == "" {
		return nil
	}
	now := time.Now().UTC()
	u.PasswordHash, u.PasswordChangedAt = "", &now
	u.BumpSecurity()
	err = s.Users.Update(Durable(ctx), u)
	if !store.Applied(err) {
		return mapStore(err)
	}
	// Applied here even if a peer has not confirmed it yet: the sessions end and the audit records it regardless.
	var detail map[string]string
	if serr := s.endUserSessions(ctx, u.ID, nil); serr != nil {
		detail = map[string]string{"sessions": "not all ended: " + serr.Error()}
	}
	s.Audit(ctx, a, u.OrgID, "user.password.remove", u.Username, detail)
	return mapStore(err)
}
