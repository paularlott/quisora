package service

import (
	"context"
	"encoding/base32"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// What a migration brings along when it creates a user (UserInput.PasswordHash, TOTPSecret and Identities) is
// credentials someone may know or an identity a provider asserts, so all of it is allowed to the same actors and
// only for a new user.

const (
	// minTOTPSecretChars is 80 bits in base32: the length Google Authenticator's key URIs have long used, and the
	// smallest secret RFC 4226 recommends against guessing. Quisora's own are 160 bits.
	minTOTPSecretChars = 16
	// maxTOTPSecretChars is 80 bytes, more than the 64-byte block HMAC-SHA1 uses a key at full strength up to.
	maxTOTPSecretChars = 128

	// maxImportedLinks bounds the provider links one user is created with (a person has a handful of providers).
	maxImportedLinks = 10
	// maxSubjectLen bounds a provider subject: OpenID Connect caps a sub claim at 255 ASCII characters.
	maxSubjectLen = 255
)

// IdentityInput links a new user to a sign-in provider of its organization.
type IdentityInput struct {
	// Provider is the provider's id or its name in the organization (names are matched without regard to case).
	Provider string `json:"provider"`
	// Subject is what the provider asserts for the person (the sub claim, a GitHub user id): kept exactly as given.
	Subject string `json:"subject"`
}

// requireImport refuses an actor that may not import what (a password hash, an authenticator secret, provider
// links): the system and super admins, and a token only with the import scope.
func requireImport(a *Actor, field, what string) error {
	if a != System && !(a.IsSuper() && a.HasScope(ScopeImport)) {
		return Invalid(field, "only super admins import "+what+" (an API token needs the import scope)")
	}
	return nil
}

// normalizeTOTPSecret returns secret as Quisora stores and checks one: base32 in capitals, without padding. It is
// read the way authenticator apps and other systems write it: in either case, with spaces between groups and with or
// without the = padding. It must be 80 to 640 bits. The value is never part of an error.
func normalizeTOTPSecret(secret string) (string, error) {
	s := strings.ToUpper(strings.TrimRight(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, secret), "="))
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err != nil {
		return "", Invalid("totp_secret", "must be base32 (letters A to Z and digits 2 to 7)")
	}
	if len(s) < minTOTPSecretChars || len(s) > maxTOTPSecretChars {
		return "", Invalid("totp_secret", "must be 16 to 128 base32 characters (80 to 640 bits)")
	}
	return s, nil
}

// importTOTP gives u, which is being created, the authenticator app with the secret from another system: sealed to
// the user's id (chosen before this, so the binding holds) and enrolled as a set-up one is (SetTOTP), in the same
// record as the new user. No code is recorded as used: the app has not been verified here, and its next code works.
func (s *Service) importTOTP(a *Actor, u *model.User, secret string) error {
	if err := requireImport(a, "totp_secret", "authenticator secrets"); err != nil {
		return err
	}
	norm, err := normalizeTOTPSecret(secret)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	u.TOTPSecret, u.MFAEnrolledAt = s.Sealer.SealFor(TOTPBinding(u.ID), []byte(norm)), &now
	return nil
}

// importLinks makes the identities that link u, which is being created in orgID, to the providers in in: an
// administrator's links ("admin"), for the provider's current authority. Every provider must be the organization's
// own, once each (a user has one identity per provider), and every subject of a plausible size. It returns the
// identities and the providers' names.
func (s *Service) importLinks(ctx context.Context, a *Actor, u *model.User, in []IdentityInput) ([]*model.Identity, []string, error) {
	if err := requireImport(a, "identities", "provider links"); err != nil {
		return nil, nil, err
	}
	if len(in) > maxImportedLinks {
		return nil, nil, Invalid("identities", "at most "+itoa(maxImportedLinks)+" provider links are allowed")
	}
	var links []*model.Identity
	var names []string
	for _, l := range in {
		p, err := s.importProvider(ctx, u.OrgID, l.Provider)
		if err != nil {
			return nil, nil, err
		}
		if l.Subject == "" || len(l.Subject) > maxSubjectLen || !utf8.ValidString(l.Subject) {
			return nil, nil, Invalid("identities", "the subject of "+p.Name+" must be 1 to "+itoa(maxSubjectLen)+" characters")
		}
		if slices.ContainsFunc(links, func(o *model.Identity) bool { return o.ProviderID == p.ID }) {
			return nil, nil, Invalid("identities", "give one subject for "+p.Name)
		}
		links = append(links, model.NewIdentity(u, p, l.Subject, "", "admin"))
		names = append(names, p.Name)
	}
	return links, names, nil
}

// importProvider finds the provider of organization orgID that ref names, by id or else by name. A provider of
// another organization is not found, exactly as one that does not exist.
func (s *Service) importProvider(ctx context.Context, orgID, ref string) (*model.Provider, error) {
	p, err := s.Providers.Get(ctx, ref)
	if errors.Is(err, store.ErrNotFound) || err == nil && p.OrgID != orgID {
		p, err = s.Providers.GetByUnique(ctx, model.ProviderNameKey(orgID, ref))
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, Invalid("identities", "no sign-in provider of this organization has the id or name "+strconv.Quote(ref))
	}
	return p, mapStore(err)
}

// linkConflict names the imported links as the field that clashed when a creation failed on a unique value one of
// them wants and another user holds (the same subject at the same provider); nil when it is not that.
func (s *Service) linkConflict(ctx context.Context, err error, u *model.User, links []*model.Identity) error {
	if !errors.Is(err, store.ErrConflict) {
		return nil
	}
	for _, l := range links {
		if o, e := s.Identities.GetByUnique(ctx, model.IdentityKey(l.ProviderID, l.Subject)); e == nil && o.UserID != u.ID {
			return &conflictErr{Invalid("identities", "a subject is already linked to another user at that provider")}
		}
	}
	return nil
}
