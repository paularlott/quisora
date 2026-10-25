package service

import (
	"context"
	"errors"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// Stored passwords are argon2id hashes sealed with the master key (the pepper), bound to the user's id: a copy of the
// database without the master key holds nothing to guess passwords against offline, and a hash copied onto another
// account does not open. Sealing the finished hash (rather than mixing a secret into the password) lets a master key
// rotation re-seal every hash without the passwords (ResealSecrets).

// PasswordBinding binds a user's sealed password hash to the user.
func PasswordBinding(userID string) string { return "user/" + userID + "/password" }

// hashPassword returns the stored form of password for u (it waits for a hashing worker in its organization's line).
func (s *Service) hashPassword(ctx context.Context, u *model.User, password string) (string, error) {
	h, err := s.Hasher.Hash(ctx, u.OrgID, password)
	if err != nil {
		return "", err
	}
	return s.SealPasswordHash(u.ID, h), nil
}

// SealPasswordHash seals an argon2id hash for the user with userID (the load test seeds many users with one hash).
func (s *Service) SealPasswordHash(userID, hash string) string {
	return s.Sealer.SealFor(PasswordBinding(userID), []byte(hash))
}

// VerifyPassword reports whether password is u's, for a sign-in at organization orgID (the hashing workers' waiting
// line: secure.Hasher). Every call costs one hash, whether or not there is a user or a password (nil u: an unknown
// account), so timing reveals neither. After a match, a hash made with other settings than today's is replaced (best
// effort: the sign-in goes ahead regardless).
func (s *Service) VerifyPassword(ctx context.Context, orgID string, u *model.User, password string) (bool, error) {
	stored := ""
	if u != nil {
		stored = u.PasswordHash
	}
	encoded := ""
	if stored != "" {
		plain, err := s.Sealer.OpenFor(PasswordBinding(u.ID), stored)
		if err != nil {
			// Sealed with a master key that is no longer configured, or damaged: the password cannot be checked.
			s.Log.WithError(err).Error("a password hash cannot be opened (is a previous master key missing?)", "user", u.ID)
			encoded = ""
		} else {
			encoded = string(plain)
		}
	}
	ok, rehash, err := s.Hasher.Verify(ctx, orgID, password, encoded)
	if errors.Is(err, secure.ErrHashParams) {
		s.Log.Error("a stored password hash names settings out of range: refused", "user", u.ID)
		return false, nil
	}
	if err != nil || !ok {
		return false, err
	}
	if rehash && s.CanWrite() {
		s.rehashPassword(ctx, u, stored, password)
	}
	return true, nil
}

// rehashPassword replaces the user's stored hash with one made with today's settings, if it is still stored (a change
// made meanwhile is never overwritten).
func (s *Service) rehashPassword(ctx context.Context, u *model.User, stored, password string) {
	ctx = context.WithoutCancel(ctx)
	userID := u.ID
	next, err := s.hashPassword(ctx, u, password)
	if err != nil {
		return
	}
	for range 3 {
		u, err := s.Users.Get(ctx, userID)
		if err != nil || u.PasswordHash != stored {
			return
		}
		u.PasswordHash = next
		if err = s.Users.Update(ctx, u); !errors.Is(err, store.ErrStale) {
			if !store.Applied(err) {
				s.Log.WithError(err).Warn("could not upgrade a password hash", "user", userID)
			}
			return
		}
	}
}
