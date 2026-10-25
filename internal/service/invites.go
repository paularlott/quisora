package service

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"slices"
	"strings"
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

// IssueLink creates a single-use link token for u. An account has at most one invitation: issuing one replaces the
// record of the earlier one, whose token then finds nothing. Reset links each stand alone, as verification links
// do: anyone can ask for one for any address, so a request must not end the link an earlier mail carries; the first
// one used changes the password, which ends the others (they are bound to the security generation: PeekLink).
func (s *Service) IssueLink(ctx context.Context, u *model.User, purpose, email string, ttl time.Duration) (string, *model.LinkToken, error) {
	return s.issueLink(ctx, u, purpose, email, ttl, "", nil)
}

// issueLink is IssueLink recording who issued it (an invitation's issuer: see mayResetSignIn). replace, when set,
// judges the live link the new one would overwrite, on every try: a write that conflicts and retries meets the record
// that won, and is judged against it.
func (s *Service) issueLink(ctx context.Context, u *model.User, purpose, email string, ttl time.Duration, by string,
	replace func(cur *model.LinkToken) error, edit ...func(*model.LinkToken)) (string, *model.LinkToken, error) {
	// The link is bound to the account as it is now (its security generation), not to the caller's copy: a link
	// issued from a stale copy would open nothing.
	cur, err := s.Users.Get(ctx, u.ID)
	if err != nil {
		return "", nil, mapStore(err)
	}
	u = cur
	token := secure.RandomToken(32)
	l := &model.LinkToken{UserID: u.ID, OrgID: u.OrgID, Purpose: purpose, Email: email, Expires: time.Now().Add(ttl),
		UserCreated: u.Created, IssuedBy: by, Gen: u.SecurityGen, TokenHash: linkID(token)}
	if purpose == LinkInvite || purpose == LinkReset {
		l.For = u.Email
	}
	for _, e := range edit {
		e(l)
	}
	if purpose != LinkInvite {
		l.ID = l.TokenHash
		if err := s.Links.Create(Durable(ctx), l); err != nil {
			return "", nil, mapStore(err)
		}
		return token, l, nil
	}
	l.ID = purpose + ":" + u.ID
	for range 8 {
		cur, err := s.Links.Get(ctx, l.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			l.Version = 0
			err = s.Links.Create(Durable(ctx), l)
		case err == nil:
			if replace != nil {
				if rerr := replace(cur); rerr != nil {
					return "", nil, rerr
				}
			}
			l.Version, l.Created = cur.Version, time.Time{}
			err = s.Links.Update(Durable(ctx), l)
		}
		if store.Applied(err) {
			return token, l, nil
		}
		if !errors.Is(err, store.ErrStale) {
			return "", nil, mapStore(err)
		}
	}
	return "", nil, ErrStale
}

// PeekLink returns a live, unused link of one of the purposes without using it (to render the page behind it).
func (s *Service) PeekLink(ctx context.Context, token string, purposes ...string) (*model.LinkToken, *model.User, error) {
	if token == "" || len(token) > 128 {
		return nil, nil, ErrLink
	}
	l, err := s.Links.GetByUnique(ctx, model.LinkTokenKey(linkID(token)))
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
	// It is also bound to the address it was issued for: an invitation mailed to a mistyped address, which an
	// administrator then corrected, must not set the credentials of the account whose address it no longer is. A
	// break-glass invitation is handed to whoever runs the command, not to an address.
	if (l.Purpose == LinkInvite || l.Purpose == LinkReset) && !l.BreakGlass && !strings.EqualFold(l.For, u.Email) {
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

// RedeemLink uses a verification link: exactly one caller succeeds (compare-and-put on the record). Invitations and
// resets are used by UseSignInLink.
func (s *Service) RedeemLink(ctx context.Context, token string) (*model.LinkToken, *model.User, error) {
	l, u, err := s.PeekLink(ctx, token, LinkVerify)
	if err != nil {
		return nil, nil, err
	}
	l.Used = true
	if err := s.Links.Update(Durable(ctx), l); err != nil {
		return nil, nil, ErrLink
	}
	return l, u, nil
}

// NewCredEpoch returns a fresh credential epoch (model.User.CredEpoch): random, so two acceptances of one invitation
// racing never pick the same one, and only the one whose commit wins counts.
func NewCredEpoch() uint64 {
	for {
		if e := binary.BigEndian.Uint64(secure.RandomBytes(8)); e != 0 {
			return e
		}
	}
}

// UseSignInLink accepts an invitation or a password reset (purpose) with token: it is the commit of the whole change,
// one compare-and-swap of the user record that sets the new password (none: "", an invitation that sets up a passkey
// instead), gives the account a new session epoch (every session and refresh grant stops counting), for an invitation
// also the credential epoch epoch (NewCredEpoch: every earlier passkey, connected provider and API token stops
// counting, and the passkey the flow stored for epoch starts), removes the authenticator app and the recovery codes, proves the address the link was sent to,
// re-enables the account of a break-glass invitation, and moves the account's security generation on. That move is
// what uses the link up, and every other invitation or reset link of the account with it (they are bound to the
// generation: PeekLink). Until then nothing of the account has changed and the link works: a failure before it is
// tried again with the same link. Of two acceptances racing, one commits; the other changes nothing that counts.
func (s *Service) UseSignInLink(ctx context.Context, token, purpose, password string, epoch uint64) (*model.LinkToken, *model.User, error) {
	if purpose == LinkReset && password == "" {
		return nil, nil, Invalid("password", "required")
	}
	hash := ""
	for range 8 {
		l, u, err := s.PeekLink(ctx, token, purpose)
		if err != nil {
			return nil, nil, err
		}
		if password != "" && hash == "" { // hashed once: a retry after a concurrent change reuses it
			if err := s.CheckPassword(ctx, u, password); err != nil {
				return nil, nil, err
			}
			if hash, err = s.hashPassword(ctx, u, password); err != nil {
				return nil, nil, err
			}
		}
		now := time.Now().UTC()
		if hash != "" || u.PasswordHash != "" {
			u.PasswordChangedAt = &now
		}
		u.PasswordHash = hash
		was := *u
		u.SessionEpoch = NewCredEpoch() // the account's sessions and refresh grants end at this write
		if purpose == LinkInvite {
			u.TOTPSecret, u.MFAEnrolledAt, u.RecoveryCodes, u.RecoveryCreated = "", nil, nil, nil
			u.SetCredEpoch(epoch) // and every credential, but the passkey stored for epoch
		}
		if l.Email != "" && strings.EqualFold(l.Email, u.Email) {
			u.EmailVerified = true // the link went to this address: it is proven
		}
		if l.BreakGlass && !u.Enabled(now) {
			u.Active = true
			if u.ValidUntil != nil && !now.Before(*u.ValidUntil) {
				u.ValidUntil = nil // ended: the account must be usable again to be recovered
			}
			noteStatus(u, System, "break-glass invitation used")
		}
		u.BumpSecurity()
		err = s.Users.Update(Durable(ctx), u)
		if errors.Is(err, store.ErrStale) {
			continue // changed meanwhile: read again (the link may no longer be good)
		}
		if !store.Applied(err) {
			return nil, nil, mapStore(err)
		}
		// Tidying, of what this write replaced and nothing later: the old epochs' records.
		if purpose == LinkInvite {
			_ = s.clearCredentials(ctx, u.ID, was.CredEpoch, was.SessionEpoch)
		} else {
			_ = s.endSessionsOf(ctx, u.ID, was.SessionEpoch)
		}
		_ = s.Links.DeleteIf(ctx, l.ID, l.Version) // tidying only, and only this link: a newer one issued since stays
		return l, u, nil
	}
	return nil, nil, ErrStale
}

// MarkLinkSent records that the link with this URL (or token) was emailed to email: using it then proves the
// address (an invitation an administrator copies and shares some other way proves nothing).
func (s *Service) MarkLinkSent(ctx context.Context, link, email string) error {
	token := link
	if u, err := url.Parse(link); err == nil && u.Query().Get("token") != "" {
		token = u.Query().Get("token")
	}
	l, err := s.Links.GetByUnique(ctx, model.LinkTokenKey(linkID(token)))
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
	token, l, err := s.issueLink(ctx, u, LinkInvite, "", BreakGlassTTL, "", nil, func(l *model.LinkToken) { l.BreakGlass = true })
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
	if !u.Enabled(time.Now()) {
		return "", time.Time{}, Invalid("active", "the account is disabled")
	}
	by := ""
	if a != System {
		by = a.UserID
	}
	token, l, err := s.issueLink(ctx, u, LinkInvite, "", InviteTTL, by, mayReplaceInvite(a, u))
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
