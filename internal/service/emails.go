package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Linked email addresses. A user has one primary address (User.Email: password sign-in, password resets, tokens)
// and up to model.MaxLinkedEmails linked ones. All of them live in the org's single email namespace (one unique
// value per address in the store), so an address is never anyone's primary or linked address twice. A linked address
// lets an upstream provider that reports it as verified find the user (see package upstream); it signs in nothing
// by itself.

func linkedAddrs(u *model.User) []string {
	out := make([]string, len(u.LinkedEmails))
	for i, l := range u.LinkedEmails {
		out[i] = l.Address
	}
	return out
}

// addsVerifiedLinked reports whether setLinked(u, list) would add a verified address u does not have verified yet
// (an address that does not parse is left to setLinked to refuse).
func addsVerifiedLinked(u *model.User, list []string) bool {
	for _, raw := range list {
		a, err := normEmail(raw)
		if err != nil || strings.EqualFold(a, u.Email) {
			continue
		}
		if cur, ok := u.LinkedEmail(a); !ok || !cur.Verified {
			return true
		}
	}
	return false
}

// setLinked replaces u's verified linked addresses with the addresses in list. It is how administrators and
// provisioning clients (SCIM) set a user's addresses, so every address in list is verified (they vouch for it),
// keeping the details of one that was already linked. Verified addresses not in list are unlinked. The addresses the
// user added themselves and has not verified yet are not part of that set (SCIM never sees them): they stay linked
// and unverified, so a provisioning write that does not name them changes nothing about them; only a list that names
// one (the directory adding that very address) verifies it. The primary address and duplicates are skipped.
func setLinked(u *model.User, list []string) error {
	out := make([]model.LinkedEmail, 0, len(list)+len(u.LinkedEmails))
	for _, raw := range list {
		a, err := normEmail(raw)
		if err != nil {
			return err
		}
		if strings.EqualFold(a, u.Email) {
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || strings.EqualFold(o.Address, a)
		}
		if dup {
			continue
		}
		l := model.LinkedEmail{Address: a, Verified: true, Added: time.Now().UTC()}
		if cur, ok := u.LinkedEmail(a); ok {
			l.Added = cur.Added
		}
		out = append(out, l)
	}
	for _, cur := range u.LinkedEmails {
		if cur.Verified {
			continue
		}
		named := false
		for _, o := range out {
			named = named || strings.EqualFold(o.Address, cur.Address)
		}
		if !named {
			out = append(out, cur) // the user's own pending address: kept, still unverified
		}
	}
	if len(out) > model.MaxLinkedEmails {
		return Invalid("email", "at most "+itoa(model.MaxLinkedEmails)+" linked email addresses are allowed")
	}
	u.LinkedEmails = out
	return nil
}

// emailActor decides how a may change u's addresses. self is true when a acts on their own account: only self-service
// (the caller checked a recent re-authentication), where a user makes a verified address primary and managers and up
// also add and remove their own; otherwise a must be able to manage u.
func (s *Service) emailActor(ctx context.Context, a *Actor, u *model.User) (self bool, err error) {
	if a == nil {
		a = System
	}
	if a != System && a.UserID == u.ID {
		if !isSelfService(ctx) {
			return true, ErrForbidden
		}
		return true, nil
	}
	if a != System && !s.canManageUser(a, u) {
		return false, s.denied(a, u)
	}
	return false, nil
}

// modifyUser re-reads and updates a user until the write is not stale. A change f makes to what signs the account in
// (securityState: the primary address made primary or verified, say) moves the security generation on with it.
func (s *Service) modifyUser(ctx context.Context, id string, f func(u *model.User) error) (*model.User, error) {
	for range 4 {
		u, err := s.Users.Get(ctx, id)
		if err != nil {
			return nil, mapStore(err)
		}
		was := stateOf(u)
		if err := f(u); err != nil {
			return nil, err
		}
		noteSecurity(was, u)
		err = s.Users.Update(ctx, u)
		switch {
		case err == nil:
			return u, nil
		case errors.Is(err, store.ErrStale):
			continue
		}
		return nil, s.userConflict(ctx, err, u)
	}
	return nil, ErrStale
}

// modifyUserAudited is modifyUser for a change that is audited as action on u (the user as the caller read them): see
// audited. f may add to detail what only it knows.
func (s *Service) modifyUserAudited(ctx context.Context, a *Actor, u *model.User, action string, detail map[string]string,
	f func(u *model.User) error) (out *model.User, err error) {
	err = s.audited(ctx, a, u.OrgID, action, u.Username, detail, func() (err error) {
		out, err = s.modifyUser(ctx, u.ID, f)
		return err
	})
	return out, err
}

// AddLinkedEmail links address to the user (provisioning sets linked addresses through SCIM instead). An address on
// an account reserves it in the organization and is offered to sign-in providers, so who may claim one is a
// manager's call: managers and up add them for the users they manage, and for themselves (the admin user page,
// self-service and re-authenticated; always unverified). Users below manager never add their own. verified says
// whether an address added for someone else counts as verified at once; otherwise the caller mails its owner a link
// (IssueEmailLink).
func (s *Service) AddLinkedEmail(ctx context.Context, a *Actor, userID, address string, verified bool) (*model.User, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	self, err := s.emailActor(ctx, a, u)
	if err != nil {
		return nil, err
	}
	if self && !u.Role.Privileged() {
		return nil, ErrForbidden
	}
	verified = verified && !self
	if verified {
		// as MarkEmailVerified: a verified address links sign-ins from providers to the account
		if err := s.mayResetSignIn(ctx, a, u, "email"); err != nil {
			return nil, err
		}
	}
	addr, err := normEmail(address)
	if err != nil {
		return nil, err
	}
	u, err = s.modifyUserAudited(ctx, a, u, "user.email.add", map[string]string{"email": addr, "verified": boolStr(verified)}, func(u *model.User) error {
		if strings.EqualFold(u.Email, addr) {
			return &conflictErr{Invalid("email", "is already the primary email address")}
		}
		if _, ok := u.LinkedEmail(addr); ok {
			return &conflictErr{Invalid("email", "is already linked")}
		}
		if len(u.LinkedEmails) >= model.MaxLinkedEmails {
			return Invalid("email", "at most "+itoa(model.MaxLinkedEmails)+" linked email addresses are allowed")
		}
		u.LinkedEmails = append(u.LinkedEmails, model.LinkedEmail{Address: addr, Verified: verified, Added: time.Now().UTC()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// RemoveLinkedEmail unlinks address: managers and up, for the users they manage and themselves, like AddLinkedEmail.
// The primary address cannot be removed (make another one primary first).
func (s *Service) RemoveLinkedEmail(ctx context.Context, a *Actor, userID, address string) (*model.User, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	if self, err := s.emailActor(ctx, a, u); err != nil {
		return nil, err
	} else if self && !u.Role.Privileged() {
		return nil, ErrForbidden
	}
	address = strings.TrimSpace(address)
	if strings.EqualFold(u.Email, address) {
		return nil, Invalid("email", "is the primary address; make another address primary before removing it")
	}
	u, err = s.modifyUserAudited(ctx, a, u, "user.email.remove", map[string]string{"email": address}, func(u *model.User) error {
		for i, l := range u.LinkedEmails {
			if strings.EqualFold(l.Address, address) {
				u.LinkedEmails = append(u.LinkedEmails[:i:i], u.LinkedEmails[i+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// MakePrimary swaps a verified linked address with the primary address: the old primary becomes a linked address
// (keeping its verified state). Password sign-in and password resets use the new primary from now on. Users may do
// this themselves (from the account page): they have proven they receive mail at every verified address.
func (s *Service) MakePrimary(ctx context.Context, a *Actor, userID, address string) (*model.User, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	if _, err := s.emailActor(ctx, a, u); err != nil {
		return nil, err
	}
	if a != System && a.UserID != u.ID {
		// as changing the primary address in UpdateUser: password resets go there
		if err := s.mayResetSignIn(ctx, a, u, "email"); err != nil {
			return nil, err
		}
	}
	address = strings.TrimSpace(address)
	detail := map[string]string{}
	u, err = s.modifyUserAudited(ctx, a, u, "user.email.primary", detail, func(u *model.User) error {
		l, ok := u.LinkedEmail(address)
		if !ok {
			return ErrNotFound
		}
		if !l.Verified {
			return Invalid("email", "must be verified before it can be made primary")
		}
		detail["previous"] = u.Email
		out := make([]model.LinkedEmail, 0, len(u.LinkedEmails))
		for _, x := range u.LinkedEmails {
			if !strings.EqualFold(x.Address, address) {
				out = append(out, x)
			}
		}
		out = append(out, model.LinkedEmail{Address: u.Email, Verified: u.EmailVerified, Added: time.Now().UTC()})
		u.Email, u.EmailVerified, u.LinkedEmails = l.Address, true, out
		detail["email"] = u.Email
		return nil
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// IssueEmailLink issues a verification link (valid VerifyTTL) for one address of the user (the primary or a linked
// address); the caller mails it to that address. Links for the same address issued earlier stay valid until used.
func (s *Service) IssueEmailLink(ctx context.Context, u *model.User, address string) (string, error) {
	l, ok := u.LinkedEmail(address)
	switch {
	case ok && l.Verified:
		return "", &conflictErr{Invalid("email", "is already verified")}
	case !ok && !strings.EqualFold(u.Email, address):
		return "", ErrNotFound
	case !ok && u.EmailVerified:
		return "", &conflictErr{Invalid("email", "is already verified")}
	}
	tok, _, err := s.IssueLink(ctx, u, LinkVerify, address, VerifyTTL)
	return tok, err
}

// MarkEmailVerified marks one of u's unverified addresses (the primary or a linked one) verified without the mailed
// link: a manager's call, for someone whose address they know to be right. A verified address links sign-ins from
// providers to the account and reaches every application as email_verified, so it is never done for your own
// account, and for an established manager or administrator only by a super admin (as changing their address).
func (s *Service) MarkEmailVerified(ctx context.Context, a *Actor, userID, address string) (*model.User, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	if a != System && a.UserID == u.ID {
		return nil, Invalid("email", "your own email address is verified by the link mailed to it")
	}
	if _, err := s.emailActor(ctx, a, u); err != nil {
		return nil, err
	}
	if err := s.mayResetSignIn(ctx, a, u, "email"); err != nil {
		return nil, err
	}
	address = strings.TrimSpace(address)
	u, err = s.modifyUserAudited(ctx, a, u, "user.email.verify", map[string]string{"email": address, "method": "manual"}, func(u *model.User) error {
		if strings.EqualFold(u.Email, address) {
			if u.EmailVerified {
				return &conflictErr{Invalid("email", "is already verified")}
			}
			u.EmailVerified = true
			return nil
		}
		for i := range u.LinkedEmails {
			if strings.EqualFold(u.LinkedEmails[i].Address, address) {
				if u.LinkedEmails[i].Verified {
					return &conflictErr{Invalid("email", "is already verified")}
				}
				u.LinkedEmails[i].Verified = true
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// CanMarkEmailVerified reports whether a may mark u's addresses verified (MarkEmailVerified), for what to show.
func (s *Service) CanMarkEmailVerified(ctx context.Context, a *Actor, u *model.User) bool {
	return a != System && a.UserID != u.ID && s.CanResetSignIn(ctx, a, u)
}

// VerifyEmailAddress marks one address of the user verified, as proven by a redeemed LinkVerify link. A link whose
// address is no longer on the account (removed, or replaced by another primary) verifies nothing.
func (s *Service) VerifyEmailAddress(ctx context.Context, userID, address string) error {
	cur, err := s.Users.Get(ctx, userID)
	if err != nil {
		return mapStore(err)
	}
	changed := false
	_, err = s.modifyUser(ctx, userID, func(u *model.User) error {
		changed = false
		if strings.EqualFold(u.Email, address) {
			changed, u.EmailVerified = !u.EmailVerified, true
			return nil
		}
		for i := range u.LinkedEmails {
			if strings.EqualFold(u.LinkedEmails[i].Address, address) {
				changed, u.LinkedEmails[i].Verified = !u.LinkedEmails[i].Verified, true
				return nil
			}
		}
		return ErrNotFound
	})
	if err == nil && !changed {
		return nil // nothing to record
	}
	s.auditOutcome(ctx, System, err, change{cur.OrgID, "user.email.verify", cur.Username, map[string]string{"email": address}})
	return err
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// UsersByVerifiedEmail returns the distinct users of org that have one of addresses as a VERIFIED primary or linked
// address (unverified addresses on the account side never match).
func (s *Service) UsersByVerifiedEmail(ctx context.Context, orgID string, addresses []string) ([]*model.User, error) {
	var out []*model.User
	seen := map[string]bool{}
	for _, addr := range addresses {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		u, err := s.Users.GetByUnique(ctx, model.UserEmailKey(orgID, addr))
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		ok := strings.EqualFold(u.Email, addr) && u.EmailVerified
		if l, found := u.LinkedEmail(addr); found && l.Verified {
			ok = true
		}
		if ok && !seen[u.ID] {
			seen[u.ID] = true
			out = append(out, u)
		}
	}
	return out, nil
}
