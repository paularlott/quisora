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
	ResetTTL  = time.Hour
	VerifyTTL = 24 * time.Hour
)

// ErrLink means the link is unknown, expired, already used or of another kind.
var ErrLink = errors.New("this link is invalid or has expired")

func linkID(token string) string {
	return base64.RawURLEncoding.EncodeToString(secure.HashSecret(token))
}

// IssueLink creates a single-use link token for u. Issuing an invitation or reset revokes the user's earlier
// unused links of the same purpose, so only the newest one works.
func (s *Service) IssueLink(ctx context.Context, u *model.User, purpose, email string, ttl time.Duration) (string, *model.LinkToken, error) {
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
		Email: email, Expires: time.Now().Add(ttl), UserCreated: u.Created}
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
	if err != nil || !u.Enabled(time.Now()) || !u.Created.Equal(l.UserCreated) {
		return nil, nil, ErrLink
	}
	return l, u, nil
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
	return l, u, nil
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

// CreateInvite issues a new invitation for a user (new or existing): the link lets them set a password (if their
// organization allows passwords) or create a passkey. Earlier invitations stop working.
func (s *Service) CreateInvite(ctx context.Context, a *Actor, userID string) (string, time.Time, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return "", time.Time{}, mapStore(err)
	}
	if a != System && !s.canManageUser(a, u) {
		if s.canManageUsers(a, u.OrgID) {
			return "", time.Time{}, ErrForbidden
		}
		return "", time.Time{}, ErrNotFound
	}
	if a != System && a.UserID == u.ID {
		return "", time.Time{}, Invalid("user", "you cannot invite yourself")
	}
	if !u.Enabled(time.Now()) {
		return "", time.Time{}, Invalid("active", "the account is disabled")
	}
	token, l, err := s.IssueLink(ctx, u, LinkInvite, "", InviteTTL)
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
		if s.canManageUsers(a, u.OrgID) {
			return ErrForbidden
		}
		return ErrNotFound
	}
	if a.UserID == u.ID {
		return Invalid("password", "remove your own password from your account page")
	}
	if u.PasswordHash == "" {
		return nil
	}
	now := time.Now().UTC()
	u.PasswordHash, u.PasswordChangedAt = "", &now
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
