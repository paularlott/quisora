package login

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// Invitation sign-up. An invitation link (service.LinkInvite) lets its user finish setting up an account without a
// session: set a password and/or create a passkey, whichever the organization allows. The passkey ceremony is
// authorised by the link token (purpose "invite"). The link works until the account change commits
// (service.UseSignInLink): a failure before that leaves it usable for another try; the commit uses it up.

const msgBadInvite = "This invitation is invalid, has already been used or has expired."

// inviteContext loads a live invitation: its user, org and the sign-in methods the org offers.
func (m *Module) inviteContext(w http.ResponseWriter, r *http.Request, token string) (*model.User, *model.Org, *service.SignInMethods, bool) {
	ctx := r.Context()
	_, u, err := m.s.Svc.PeekLink(ctx, token, service.LinkInvite)
	if err != nil {
		writeErr(w, http.StatusGone, msgBadInvite, "")
		return nil, nil, nil, false
	}
	org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusGone, msgBadInvite, "")
		return nil, nil, nil, false
	}
	eff, err := m.s.Svc.EffectiveSignIn(ctx, org, nil)
	if err != nil {
		m.internalError(w, r, "sign-in methods", err)
		return nil, nil, nil, false
	}
	return u, org, eff, true
}

type inviteBeginReq struct {
	Token string `json:"token"`
}

// inviteBegin handles POST /api-internal/invite/passkey/begin: {token} -> {challenge, options}.
func (m *Module) inviteBegin(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) || !m.passkeysOK(w) {
		return
	}
	var in inviteBeginReq
	if !decode(w, r, &in) {
		return
	}
	if !m.rateLimit(w, r, "invite", known{any: true}) {
		return
	}
	u, _, eff, ok := m.inviteContext(w, r, in.Token)
	if !ok {
		return
	}
	if !eff.Passkey {
		writeErr(w, http.StatusForbidden, msgNoPasskeyLogin, "")
		return
	}
	id, opts, err := m.Passkeys.BeginRegistration(r.Context(), u, map[string]string{passkey.PurposeKey: purposeInvite})
	if err != nil {
		m.internalError(w, r, "passkey registration", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, passkeyBeginResp{Challenge: id, Options: opts})
}

type inviteCompleteReq struct {
	Token      string          `json:"token"`
	Password   string          `json:"password"`
	Challenge  string          `json:"challenge"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

// inviteComplete handles POST /api-internal/invite/complete: {token, password?, challenge?, credential?, name?} using the
// link up. The password is set as the system (every older session ends), the passkey is stored, then the user is
// signed in: straight away for a passkey, through the usual next step (second factor, MFA enrolment) after a
// password.
func (m *Module) inviteComplete(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in inviteCompleteReq
	if !decode(w, r, &in) {
		return
	}
	if !m.rateLimit(w, r, "invite", known{any: true}) {
		return
	}
	ctx := r.Context()
	u, org, eff, ok := m.inviteContext(w, r, in.Token)
	if !ok {
		return
	}
	wantPassword := in.Password != ""
	wantPasskey := len(in.Credential) > 0 && string(in.Credential) != "null"
	switch {
	case !wantPassword && !wantPasskey:
		writeErr(w, http.StatusUnprocessableEntity, "Choose a password or create a passkey.", "password")
		return
	case wantPassword && !eff.Password:
		writeErr(w, http.StatusForbidden, "This organization does not use passwords. Create a passkey instead.", "password")
		return
	case wantPasskey && (!eff.Passkey || m.Passkeys == nil):
		writeErr(w, http.StatusForbidden, msgNoPasskeyLogin, "")
		return
	}
	// Validate everything that can be rejected before the link is used, so a typo does not burn it.
	if wantPassword {
		if err := m.s.Svc.CheckPassword(r.Context(), u, in.Password); err != nil {
			web.WriteError(w, err)
			return
		}
	}
	var reg *passkey.Registration
	if wantPasskey {
		var err error
		reg, err = m.Passkeys.VerifyRegistrationAs(ctx, purposeInvite, u, in.Challenge, in.Credential, strings.TrimSpace(in.Name))
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "The passkey could not be registered. Try again.", "")
			return
		}
	}
	// An invitation starts the account afresh. Everything up to the commit (UseSignInLink) can be done again: the
	// link keeps working until then, so a failure here is a "try again", not a burnt link. First whatever else could
	// sign in as this user goes (sessions, other passkeys, connected providers, API tokens), then the new passkey is
	// stored; the commit then sets the password (or none), removes the authenticator app and recovery codes, and moves
	// the account's security generation on, which uses the link up.
	if err := m.s.Svc.ClearCredentials(ctx, u.ID, ""); err != nil {
		m.internalError(w, r, "clear credentials", err)
		return
	}
	var pk *model.Passkey
	if reg != nil {
		var err error
		if pk, err = m.Passkeys.StoreForInvite(ctx, u, reg); err != nil {
			m.internalError(w, r, "store passkey", err)
			return
		}
	}
	password := ""
	if wantPassword {
		password = in.Password
	}
	_, u, err := m.s.Svc.UseSignInLink(ctx, in.Token, service.LinkInvite, password)
	if err != nil {
		if errors.Is(err, service.ErrLink) {
			writeErr(w, http.StatusGone, msgBadInvite, "")
		} else {
			web.WriteError(w, err)
		}
		return
	}
	m.clearLocks(ctx, u.ID)
	m.s.Sessions.Evict("", u.ID)
	detail := map[string]string{}
	if wantPassword {
		detail["password"] = "set"
	}
	if pk != nil {
		detail["passkey"] = pk.Name
	}
	m.audit(r, "invite.accept", org, u, u.Username, detail)

	if pk != nil {
		// The passkey proves possession and user verification on its own: a complete sign-in, MFA included.
		k := "hwk"
		if pk.BackupEligible {
			k = "swk"
		}
		amr := []string{k}
		if pk.UserVerified {
			amr = append(amr, "user")
		}
		dest, err := m.completeWith(w, r, u, org, web.SessionOptions{AMR: amr, Passkey: pk.ID}, "")
		if err != nil {
			m.internalError(w, r, "create session", err)
			return
		}
		web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
		return
	}
	m.afterPassword(w, r, u, org, eff, "", "")
}
