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

// msgInviteUnknown answers an acceptance the cluster did not confirm: it may have been made.
const msgInviteUnknown = "The server lost contact with its cluster before it answered, so your invitation may have been accepted. " +
	"Try signing in with the password or passkey you chose; if that does not work, ask an administrator for a new invitation."

const msgBadInvite = "This invitation is invalid, has already been used or has expired."

// inviteContext loads a live invitation of the organization the path names: its user, the org and the sign-in
// methods the org offers. An invitation of another organization is invalid here.
func (m *Module) inviteContext(w http.ResponseWriter, r *http.Request, token string) (*model.User, *model.Org, *service.SignInMethods, bool) {
	ctx := r.Context()
	org := web.Org(r)
	u, ok := m.peekLink(ctx, org, token, service.LinkInvite)
	if !ok {
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

// inviteBegin handles POST /o/{org}/api-internal/invite/passkey/begin: {token} -> {challenge, options}.
func (m *Module) inviteBegin(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) || !m.passkeysOK(w) {
		return
	}
	var in inviteBeginReq
	if !decode(w, r, &in) {
		return
	}
	if !m.rateLimit(w, r, web.Org(r).ID+"|invite", known{any: true}) {
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

// inviteComplete handles POST /o/{org}/api-internal/invite/complete: {token, password?, challenge?, credential?, name?} using the
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
	if !m.rateLimit(w, r, web.Org(r).ID+"|invite", known{any: true}) {
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
	// An invitation starts the account afresh, in one commit (UseSignInLink): a compare-and-swap of the user record
	// that sets the password (or none), removes the authenticator app and recovery codes, gives the account a new
	// credential epoch — every earlier passkey, connected provider, API token and session stops counting — and moves
	// the security generation on, which uses the link up. The new passkey is stored first, in the epoch the commit
	// will set: it counts only once that commit lands, so an acceptance that loses a race leaves nothing usable, and
	// a failure before the commit is simply tried again with the same link.
	epoch := service.NewCredEpoch()
	var pk *model.Passkey
	if reg != nil {
		var err error
		if pk, err = m.Passkeys.StoreForInvite(ctx, u, reg, epoch); err != nil {
			m.internalError(w, r, "store passkey", err)
			return
		}
	}
	password := ""
	if wantPassword {
		password = in.Password
	}
	invited := u
	_, u, err := m.s.Svc.UseSignInLink(ctx, in.Token, service.LinkInvite, password, epoch)
	if err != nil {
		if errors.Is(err, service.ErrLink) {
			if pk != nil { // another acceptance committed: this passkey's epoch never will, tidy it away
				_ = m.s.Svc.Passkeys.Delete(ctx, pk.ID)
			}
			writeErr(w, http.StatusGone, msgBadInvite, "")
		} else if errors.Is(err, service.ErrOutcomeUnknown) {
			// (the commit may be in effect: its passkey stays; the sweep tidies orphans.) The invitation is used up if it
			// is, and trying it again would only say it is invalid: say what to do instead.
			m.auditUnknown(r, "invite.accept", org, invited, nil, err)
			writeErr(w, http.StatusServiceUnavailable, msgInviteUnknown, "")
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
