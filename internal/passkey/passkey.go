// Package passkey runs the WebAuthn registration and sign-in ceremonies on top of go-webauthn.
//
// The relying party ID is the host of server.public_url and the only accepted origin is public_url itself, so a
// deployment behind an IP address (which WebAuthn forbids as an RP ID) cannot use passkeys; New reports that.
// Challenges live in the ephemeral store (namespace "webauthn") and are single use: Finish takes the challenge
// before verifying anything, so a replayed or failed response can never be retried against the same challenge.
// The WebAuthn user handle is the user id's bytes.
package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Namespace is the ephemeral namespace holding ceremony state.
const Namespace = "webauthn"

// ChallengeTTL is how long a begun ceremony stays valid.
const ChallengeTTL = 5 * time.Minute

var (
	// ErrChallenge means the challenge id is unknown, expired, already used or for another purpose.
	ErrChallenge = errors.New("passkey: unknown or expired challenge")
	// ErrVerify means the authenticator's response did not verify (bad signature, origin, RP id, user presence, ...).
	ErrVerify = errors.New("passkey: verification failed")
	// ErrUnknownCredential means no registered passkey matches the response.
	ErrUnknownCredential = errors.New("passkey: unknown credential")
	// ErrCloneDetected means the sign counter did not increase: the credential may have been cloned.
	ErrCloneDetected = errors.New("passkey: sign counter regression, credential may be cloned")
	// ErrInactive means the credential's user is disabled or gone.
	ErrInactive = errors.New("passkey: user is not active")
	// ErrUnusable means the passkey cannot sign in: disabled, or registered without user verification.
	ErrUnusable = errors.New("passkey: this passkey cannot sign in")
)

// Service performs the ceremonies.
type Service struct {
	wa  *webauthn.WebAuthn
	svc *service.Service
	eph ephemeral.Store
}

// New builds the service for the configured public URL. It fails when the host is not a valid RP ID (an IP address).
func New(cfg *config.Config, svc *service.Service, eph ephemeral.Store) (*Service, error) {
	u, err := url.Parse(cfg.Server.PublicURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("passkey: bad public url %q", cfg.Server.PublicURL)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: cfg.UI.SiteName,
		RPOrigins:     []string{strings.TrimSuffix(cfg.Server.PublicURL, "/")},
		// Attestation is not requested: passkeys here are sign-in credentials, not device attestations.
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired,
			// Required, as at sign-in: a key that cannot verify its user (a security key without a PIN) could
			// register (and get a session from an invitation) but never sign in again.
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &Service{wa: wa, svc: svc, eph: eph}, nil
}

// RPID returns the relying party id in use.
func (s *Service) RPID() string { return s.wa.Config.RPID }

// ---------------------------------------------------------------------------------------------------------------
// User adapter

type waUser struct {
	u     *model.User
	creds []webauthn.Credential
}

func (w *waUser) WebAuthnID() []byte                         { return []byte(w.u.ID) }
func (w *waUser) WebAuthnName() string                       { return w.u.Username }
func (w *waUser) WebAuthnDisplayName() string                { return w.u.FullName() }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// authenticator data flag bits (WebAuthn §6.1).
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
)

func toCredential(p *model.Passkey) webauthn.Credential {
	flags := byte(flagUP)
	if p.UserVerified {
		flags |= flagUV
	}
	if p.BackupEligible {
		flags |= flagBE
	}
	if p.BackupState {
		flags |= flagBS
	}
	tr := make([]protocol.AuthenticatorTransport, len(p.Transports))
	for i, t := range p.Transports {
		tr[i] = protocol.AuthenticatorTransport(t)
	}
	return webauthn.Credential{
		ID: p.CredentialID, PublicKey: p.PublicKey, AttestationType: "none", AttestationFormat: p.AttestationFmt,
		Transport: tr, Flags: webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(flags)),
		Authenticator: webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount},
	}
}

func (s *Service) loadUser(ctx context.Context, u *model.User) (*waUser, []*model.Passkey, error) {
	// Only the passkeys that count (service.CurrentPasskeys: one made before the account's sign-in was reset, or stored
	// by an invitation acceptance that lost, is not offered and does not sign in).
	pks, err := s.svc.CurrentPasskeys(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	w := &waUser{u: u, creds: make([]webauthn.Credential, 0, len(pks))}
	for _, p := range pks {
		w.creds = append(w.creds, toCredential(p))
	}
	return w, pks, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Ceremony state

type ceremony struct {
	Kind    string               `json:"k"` // "reg" or "login"
	Session webauthn.SessionData `json:"s"`
	UserID  string               `json:"u,omitempty"`
	Extra   map[string]string    `json:"x,omitempty"`
	// Gen is the user's security generation (model.User.SecurityGen) when a ceremony for a known user began: the
	// finish refuses the ceremony once the account's has moved on (a credential set, changed or removed meanwhile),
	// so a response to a challenge issued against the account as it was does not register or sign in against the
	// account as it is. A discoverable sign-in names no user and has nothing to bind to until it is finished.
	Gen uint64 `json:"g,omitempty"`
}

func (s *Service) save(ctx context.Context, c *ceremony) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return s.eph.New(ctx, Namespace, b, ChallengeTTL)
}

// take consumes the challenge: it is gone after this call whatever happens next.
func (s *Service) take(ctx context.Context, id, kind string) (*ceremony, error) {
	b, err := s.eph.Take(ctx, Namespace, id)
	if err != nil {
		return nil, ErrChallenge
	}
	var c ceremony
	if err := json.Unmarshal(b, &c); err != nil || c.Kind != kind {
		return nil, ErrChallenge
	}
	return &c, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Registration

// BeginRegistration starts enrolling a passkey for u. Existing credentials are excluded so one authenticator is not
// registered twice. extra is returned unchanged by FinishRegistration.
func (s *Service) BeginRegistration(ctx context.Context, u *model.User, extra map[string]string) (string, *protocol.CredentialCreation, error) {
	w, _, err := s.loadUser(ctx, u)
	if err != nil {
		return "", nil, err
	}
	creation, sd, err := s.wa.BeginRegistration(w,
		webauthn.WithExclusions(webauthn.Credentials(w.creds).CredentialDescriptors()),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		return "", nil, err
	}
	id, err := s.save(ctx, &ceremony{Kind: "reg", Session: *sd, UserID: u.ID, Extra: extra, Gen: u.SecurityGen})
	return id, creation, err
}

// FinishRegistration verifies the authenticator's attestation response (the JSON produced by
// PublicKeyCredential.toJSON()) and stores the new passkey under name.
func (s *Service) FinishRegistration(ctx context.Context, u *model.User, id string, credential []byte, name string) (*model.Passkey, map[string]string, error) {
	return s.FinishRegistrationAs(ctx, "", u, id, credential, name)
}

// PurposeKey is the ceremony Extra key naming what a ceremony is for (login, second-factor, reauth, enrol,
// register). The *As finishers reject a ceremony begun for another purpose.
const PurposeKey = "purpose"

// FinishRegistrationAs is FinishRegistration for a ceremony begun with Extra[PurposeKey] == purpose; any other
// purpose is ErrChallenge and nothing is stored. An empty purpose accepts any. It is VerifyRegistrationAs followed
// by StoreRegistration: u must be the user as just read by the caller (see StoreRegistration).
func (s *Service) FinishRegistrationAs(ctx context.Context, purpose string, u *model.User, id string, credential []byte, name string) (*model.Passkey, map[string]string, error) {
	reg, err := s.VerifyRegistrationAs(ctx, purpose, u, id, credential, name)
	if err != nil {
		return nil, nil, err
	}
	pk, err := s.StoreRegistration(ctx, u, reg)
	if err != nil {
		return nil, nil, err
	}
	return pk, reg.Extra, nil
}

// Registration is a verified passkey registration not yet stored (VerifyRegistrationAs): StoreRegistration writes
// it. Between the two the caller commits whatever the registration was the proof for (uses up a sign-in ticket, or
// redeems an invitation link), so that a response that does not verify costs it nothing, and nothing is stored
// before the caller's own commit succeeds.
type Registration struct {
	Passkey *model.Passkey
	Extra   map[string]string
}

// VerifyRegistrationAs takes the challenge and verifies the authenticator's attestation response for u (the ceremony
// must have been begun for u, for purpose, and at u's current security generation: a ceremony begun before the
// account changed is ErrChallenge). Nothing is stored.
func (s *Service) VerifyRegistrationAs(ctx context.Context, purpose string, u *model.User, id string, credential []byte, name string) (*Registration, error) {
	c, err := s.take(ctx, id, "reg")
	if err != nil {
		return nil, err
	}
	if purpose != "" && c.Extra[PurposeKey] != purpose {
		return nil, ErrChallenge
	}
	if c.UserID != u.ID || c.Gen != u.SecurityGen {
		return nil, ErrChallenge
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(credential)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerify, err)
	}
	w, _, err := s.loadUser(ctx, u)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.CreateCredential(w, c.Session, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerify, err)
	}
	if !cred.Flags.UserVerified { // belt and braces: sign-in requires user verification, so must registration
		return nil, fmt.Errorf("%w: the authenticator did not verify the user (set up a PIN or biometrics on it)", ErrVerify)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if len([]rune(name)) > 100 {
		name = string([]rune(name)[:100])
	}
	tr := make([]string, len(cred.Transport))
	for i, t := range cred.Transport {
		tr[i] = string(t)
	}
	pk := &model.Passkey{
		UserID: u.ID, OrgID: u.OrgID, Name: name, CredentialID: cred.ID, PublicKey: cred.PublicKey,
		AttestationFmt: cred.AttestationFormat, AAGUID: cred.Authenticator.AAGUID, SignCount: cred.Authenticator.SignCount,
		Transports: tr, BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
		UserVerified: cred.Flags.UserVerified,
	}
	return &Registration{Passkey: pk, Extra: c.Extra}, nil
}

// StoreRegistration stores a verified registration as a passkey of u, which must be the user as just read by the
// caller (not a cached copy). A passkey is a way into the account, so the write moves the account's security
// generation on first, with a compare-and-swap on u's version — store.ErrStale when the account changed since the
// caller read it (another completion set a factor, the owner changed the password), and nothing is stored — and
// only then writes the credential. Two completions racing to give an account its first factor therefore end with
// exactly one. A failure between the two writes leaves a moved-on generation and no passkey, which only makes people
// start again, never a passkey the generation does not account for.
func (s *Service) StoreRegistration(ctx context.Context, u *model.User, reg *Registration) (*model.Passkey, error) {
	if reg.Passkey.UserID != u.ID {
		return nil, ErrChallenge
	}
	u.BumpSecurity()
	if err := s.svc.Users.Update(service.Durable(ctx), u); !store.Applied(err) {
		u.SecurityGen--
		return nil, err
	}
	return s.createPasskey(ctx, reg, u.CredEpoch)
}

// StoreForInvite stores the passkey of an invitation being accepted, in the credential epoch the invitation's commit
// (service.UseSignInLink) will give the account: it counts for nothing until that commit, and only if it is the
// commit that wins (a concurrent acceptance commits its own epoch, and this passkey never counts). The account is not
// changed here: until the commit the link still works, so a failure in between is tried again with it.
func (s *Service) StoreForInvite(ctx context.Context, u *model.User, reg *Registration, epoch uint64) (*model.Passkey, error) {
	if reg.Passkey.UserID != u.ID {
		return nil, ErrChallenge
	}
	return s.createPasskey(ctx, reg, epoch)
}

func (s *Service) createPasskey(ctx context.Context, reg *Registration, epoch uint64) (*model.Passkey, error) {
	pk := *reg.Passkey
	pk.Epoch = epoch
	if err := s.svc.Passkeys.Create(ctx, &pk); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, fmt.Errorf("%w: credential already registered", ErrVerify)
		}
		return nil, err
	}
	return &pk, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Sign-in

// BeginLogin starts a sign-in. With u == nil the ceremony is discoverable (no allowCredentials: the authenticator
// offers its resident credentials for this RP). With a known user, only that user's credentials are allowed.
// User verification is required either way: a passkey is a complete sign-in on its own.
func (s *Service) BeginLogin(ctx context.Context, u *model.User, extra map[string]string) (string, *protocol.CredentialAssertion, error) {
	var (
		assertion *protocol.CredentialAssertion
		sd        *webauthn.SessionData
		err       error
		uid       string
	)
	uv := webauthn.WithUserVerification(protocol.VerificationRequired)
	if u == nil {
		assertion, sd, err = s.wa.BeginDiscoverableLogin(uv)
	} else {
		w, pks, lerr := s.loadUser(ctx, u)
		if lerr != nil {
			return "", nil, lerr
		}
		w.creds = w.creds[:0] // offer only the passkeys that can sign in
		for _, p := range pks {
			if p.Usable() {
				w.creds = append(w.creds, toCredential(p))
			}
		}
		if len(w.creds) == 0 {
			return "", nil, ErrUnknownCredential
		}
		uid = u.ID
		assertion, sd, err = s.wa.BeginLogin(w, uv)
	}
	if err != nil {
		return "", nil, err
	}
	c := &ceremony{Kind: "login", Session: *sd, UserID: uid, Extra: extra}
	if u != nil {
		c.Gen = u.SecurityGen
	}
	id, err := s.save(ctx, c)
	return id, assertion, err
}

// LoginResult is a verified passkey sign-in.
type LoginResult struct {
	User    *model.User
	Passkey *model.Passkey
	Extra   map[string]string
	// UserVerified and BackupEligible come from the assertion's authenticator flags and drive the amr claim.
	UserVerified   bool
	BackupEligible bool
}

// AMR returns the authentication method references for the sign-in: "hwk" (hardware-bound key) or "swk"
// (synced/software key), plus "user" when the authenticator verified the user (PIN or biometrics).
func (r *LoginResult) AMR() []string {
	a := "hwk"
	if r.BackupEligible {
		a = "swk"
	}
	if r.UserVerified {
		return []string{a, "user"}
	}
	return []string{a}
}

// FinishLogin verifies an assertion (PublicKeyCredential.toJSON()) against the begun ceremony, checks the sign
// counter and updates the stored credential. A sign counter that did not increase yields ErrCloneDetected.
func (s *Service) FinishLogin(ctx context.Context, id string, credential []byte) (*LoginResult, error) {
	return s.FinishLoginAs(ctx, id, credential)
}

// FinishLoginAs is FinishLogin for a ceremony begun with Extra[PurposeKey] among purposes; any other purpose is
// ErrChallenge (the challenge is consumed). No purposes accepts any.
func (s *Service) FinishLoginAs(ctx context.Context, id string, credential []byte, purposes ...string) (*LoginResult, error) {
	c, err := s.take(ctx, id, "login")
	if err != nil {
		return nil, err
	}
	if len(purposes) > 0 && !slices.Contains(purposes, c.Extra[PurposeKey]) {
		return nil, ErrChallenge
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(credential)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerify, err)
	}
	var (
		user *model.User
		pks  []*model.Passkey
		cred *webauthn.Credential
	)
	if c.UserID != "" {
		user, err = s.svc.Users.Get(ctx, c.UserID)
		if err != nil {
			return nil, ErrUnknownCredential
		}
		if !user.Enabled(time.Now()) {
			return nil, ErrInactive
		}
		if user.SecurityGen != c.Gen { // the account changed since the challenge was issued against it
			return nil, ErrChallenge
		}
		var w *waUser
		if w, pks, err = s.loadUser(ctx, user); err != nil {
			return nil, err
		}
		cred, err = s.wa.ValidateLogin(w, c.Session, parsed)
	} else {
		var wu webauthn.User
		wu, cred, err = s.wa.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			pk, perr := s.svc.Passkeys.GetByUnique(ctx, model.PasskeyCredentialKey(rawID))
			if perr != nil {
				return nil, ErrUnknownCredential
			}
			u, uerr := s.svc.Users.Get(ctx, pk.UserID)
			if uerr != nil || string(userHandle) != u.ID {
				return nil, ErrUnknownCredential
			}
			if !u.Enabled(time.Now()) {
				return nil, ErrInactive
			}
			w, all, lerr := s.loadUser(ctx, u)
			if lerr != nil {
				return nil, lerr
			}
			user, pks = u, all
			return w, nil
		}, c.Session, parsed)
		_ = wu
	}
	if err != nil {
		switch {
		case errors.Is(err, ErrInactive):
			return nil, ErrInactive
		case errors.Is(err, ErrUnknownCredential):
			return nil, ErrUnknownCredential
		}
		var unk *protocol.ErrorUnknownCredential
		if errors.As(err, &unk) {
			return nil, ErrUnknownCredential
		}
		return nil, fmt.Errorf("%w: %v", ErrVerify, err)
	}
	var pk *model.Passkey
	for _, p := range pks {
		if string(p.CredentialID) == string(cred.ID) {
			pk = p
		}
	}
	if pk == nil {
		return nil, ErrUnknownCredential
	}
	if !pk.Usable() {
		return &LoginResult{User: user, Passkey: pk}, ErrUnusable
	}
	if cred.Authenticator.CloneWarning {
		// The counter went backwards: another copy of this key may exist. It stops signing in until the user
		// deletes it and adds their authenticator again (the account page says why), and every session it signed in
		// ends — the copy's holder may be one of them.
		s.disable(ctx, pk)
		if _, err := s.svc.EndPasskeySessions(context.WithoutCancel(ctx), pk.UserID, pk.ID, ""); err != nil {
			s.svc.Log.WithError(err).Error("passkey clone detected; not every session it signed in could be ended", "user", pk.UserID, "passkey", pk.ID)
		}
		return &LoginResult{User: user, Passkey: pk}, ErrCloneDetected
	}
	s.touch(ctx, pk, cred)
	flags := parsed.Response.AuthenticatorData.Flags
	return &LoginResult{User: user, Passkey: pk, Extra: c.Extra, UserVerified: flags.HasUserVerified(),
		BackupEligible: flags.HasBackupEligible()}, nil
}

// disable marks a passkey disabled (durably; retried on a concurrent update) and moves the account's security
// generation on: a passkey that no longer signs in is a factor removed, so whatever is in flight for the account ends.
func (s *Service) disable(ctx context.Context, pk *model.Passkey) {
	ctx = service.Durable(context.WithoutCancel(ctx))
	defer func() { _, _ = s.svc.AdvanceSecurity(ctx, pk.UserID) }()
	for range 3 {
		pk.Disabled = true
		if err := s.svc.Passkeys.Update(ctx, pk); !errors.Is(err, store.ErrStale) {
			return
		}
		fresh, err := s.svc.Passkeys.Get(ctx, pk.ID)
		if err != nil {
			return
		}
		*pk = *fresh
	}
}

// touch stores the new sign count and backup state; LastUsed is refreshed at most once a minute.
func (s *Service) touch(ctx context.Context, pk *model.Passkey, cred *webauthn.Credential) {
	now := time.Now().UTC()
	if pk.SignCount == cred.Authenticator.SignCount && pk.BackupState == cred.Flags.BackupState &&
		now.Sub(pk.LastUsed) < time.Minute || !s.svc.CanWrite() {
		return
	}
	for range 3 {
		pk.SignCount, pk.BackupState, pk.LastUsed = cred.Authenticator.SignCount, cred.Flags.BackupState, now
		err := s.svc.Passkeys.Update(ctx, pk)
		if !errors.Is(err, store.ErrStale) {
			return
		}
		fresh, gerr := s.svc.Passkeys.Get(ctx, pk.ID)
		if gerr != nil {
			return
		}
		// Never move the counter backwards when another login on this credential won the race.
		if fresh.SignCount > cred.Authenticator.SignCount {
			return
		}
		*pk = *fresh
	}
}
