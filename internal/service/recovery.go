package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Recovery codes: a second factor for when the usual one is out of reach (a lost phone, a broken security key).
// RecoveryCodeCount codes are made at once and shown once; each works once, in place of the authenticator code or
// passkey a sign-in asks for after the password. A code is 16 characters of Crockford's base32 (80 bits), so it is
// stored as a plain SHA-256 hash (salted with the user's id, like the other bearer secrets): it cannot be guessed
// offline from a copy of the database, and a master key rotation leaves the codes working. Using one is recorded on
// the user's sign-in record with a compare-and-swap (as a TOTP step is), so it works once even on two nodes at once.
const RecoveryCodeCount = 10

// crockford is Crockford's base32 alphabet: no I, L, O or U (they read as 1, 1, 0 and V).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newRecoveryCode makes one code: XXXX-XXXX-XXXX-XXXX.
func newRecoveryCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(crockford[c&31])
	}
	return sb.String()
}

// normRecoveryCode turns what a person typed into the code: upper case, spaces and dashes removed, and the letters
// Crockford's base32 reads as digits (I and L as 1, O as 0). "" when it cannot be a code.
func normRecoveryCode(s string) string {
	s = strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.ToUpper(strings.TrimSpace(s)))
	s = strings.NewReplacer("I", "1", "L", "1", "O", "0").Replace(s)
	if len(s) != 16 {
		return ""
	}
	for _, c := range s {
		if !strings.ContainsRune(crockford, c) {
			return ""
		}
	}
	return s
}

func recoveryHash(userID, norm string) string {
	sum := sha256.Sum256([]byte("quisora recovery code\x00" + userID + "\x00" + norm))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// CreateRecoveryCodes makes a new set of recovery codes for u (the old ones stop working) and returns them: the
// only time they are seen. u must have a second factor (an authenticator app or a passkey): the codes stand in for
// it.
func (s *Service) CreateRecoveryCodes(ctx context.Context, a *Actor, u *model.User) ([]string, error) {
	n, err := s.UsablePasskeys(ctx, u, "")
	if err != nil {
		return nil, err
	}
	if !u.HasTOTP() && n == 0 {
		return nil, Invalid("recovery_codes", "set up an authenticator app or a passkey first: recovery codes stand in for them")
	}
	codes := make([]string, RecoveryCodeCount)
	hashes := make([]string, RecoveryCodeCount)
	for i := range codes {
		codes[i] = newRecoveryCode()
		hashes[i] = recoveryHash(u.ID, normRecoveryCode(codes[i]))
	}
	now := time.Now().UTC()
	err = s.audited(ctx, a, u.OrgID, "account.recovery_codes.create", u.Username, map[string]string{"codes": itoa(RecoveryCodeCount)}, func() error {
		for attempt := 0; ; attempt++ {
			u.RecoveryCodes, u.RecoveryCreated = hashes, &now
			u.BumpSecurity() // a new set of codes is a new credential: what was in flight under the old one ends
			err := s.Users.Update(ctx, u)
			if !errors.Is(err, store.ErrStale) || attempt == 4 {
				return err
			}
			if u, err = s.Users.Get(ctx, u.ID); err != nil {
				return err
			}
		}
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return codes, nil
}

// DropRecoveryCodes removes userID's recovery codes once the account has no second factor left for them to stand
// in for (its last authenticator app or passkey removed): a factor added later must not bring old codes back.
func (s *Service) DropRecoveryCodes(ctx context.Context, userID string) error {
	for attempt := 0; ; attempt++ {
		u, err := s.Users.Get(ctx, userID)
		if err != nil {
			return mapStore(err)
		}
		if len(u.RecoveryCodes) == 0 || u.HasTOTP() {
			return nil
		}
		if n, err := s.UsablePasskeys(ctx, u, ""); err != nil || n > 0 {
			return err
		}
		u.RecoveryCodes, u.RecoveryCreated = nil, nil
		u.BumpSecurity()
		err = s.Users.Update(ctx, u)
		if !errors.Is(err, store.ErrStale) || attempt == 4 {
			return mapStore(err)
		}
	}
}

// RecoveryCodesLeft is how many of u's recovery codes are unused, and when they were made (nil: none made).
func (s *Service) RecoveryCodesLeft(ctx context.Context, u *model.User) (int, *time.Time) {
	if len(u.RecoveryCodes) == 0 {
		return 0, nil
	}
	used := []string{}
	if si, err := s.SignIns.Get(ctx, u.ID); err == nil {
		used = si.RecoveryUsed
	}
	left := 0
	for _, h := range u.RecoveryCodes {
		if !slices.Contains(used, h) {
			left++
		}
	}
	return left, u.RecoveryCreated
}

// ConsumeRecoveryCode uses one of u's recovery codes: true when code is one of them, unused until now. It is then
// used up on every node (a compare-and-swap on the sign-in record). left is how many remain. When the use cannot be
// recorded the code is refused with an error (ErrUnavailable; ErrOutcomeUnknown when it may have been recorded: the
// code is used up then): not a wrong code, which is no error.
func (s *Service) ConsumeRecoveryCode(ctx context.Context, u *model.User, code string) (ok bool, left int, err error) {
	norm := normRecoveryCode(code)
	if norm == "" || len(u.RecoveryCodes) == 0 {
		return false, 0, nil
	}
	h := recoveryHash(u.ID, norm)
	if !slices.Contains(u.RecoveryCodes, h) {
		return false, 0, nil
	}
	err = s.updateSignIn(ctx, u, func(si *model.SignIn) bool {
		if slices.Contains(si.RecoveryUsed, h) {
			ok = false
			return false
		}
		// keep only the codes of the current set (a new set leaves the old hashes behind)
		si.RecoveryUsed = slices.DeleteFunc(si.RecoveryUsed, func(x string) bool { return !slices.Contains(u.RecoveryCodes, x) })
		si.RecoveryUsed = append(si.RecoveryUsed, h)
		ok, left = true, len(u.RecoveryCodes)-len(si.RecoveryUsed)
		return true
	})
	if err != nil {
		s.Log.WithError(err).Warn("could not record a recovery code: code refused", "user", u.ID)
		return false, 0, mapStore(err)
	}
	return ok, left, nil
}
