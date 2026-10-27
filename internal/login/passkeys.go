package login

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

type passkeyBeginReq struct {
	Ticket string `json:"ticket"` // login ticket of a password step that needs a passkey as second factor
	Next   string `json:"next"`
	Tenant string `json:"tenant"`
}

type passkeyBeginResp struct {
	Challenge string `json:"challenge"`
	Options   any    `json:"options"`
}

// passkeyBegin handles POST /o/{org}/api-internal/login/passkey/begin: {ticket?, next?, tenant?} -> {challenge, options}.
//
// With a ticket (password already verified, org requires MFA) the ceremony names the user's credentials. Without
// one it is discoverable: no allowCredentials, so nothing about any account is revealed.
func (m *Module) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) || !m.passkeysOK(w) {
		return
	}
	var in passkeyBeginReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	org := web.Org(r)
	var (
		user  *model.User
		extra = map[string]string{}
	)
	if in.Ticket != "" {
		// a passkey in place of the authenticator code, too; the organization's bucket (as every other step of its
		// sign-ins), and its audit log when limited
		_, u, _, ok := m.step(w, r, in.Ticket, "passkey", "totp")
		if !ok {
			return
		}
		user = u
		extra["ticket"] = in.Ticket
		extra[passkey.PurposeKey] = purposeSecondFactor
	} else {
		if !m.rateLimit(w, r, org.ID, known{orgID: org.ID}) {
			return
		}
		eff, tenant, err := m.methods(ctx, org, in.Tenant, "") // a passkey is two factors already
		if err != nil {
			m.internalError(w, r, "sign-in methods", err)
			return
		}
		if !eff.Passkey {
			writeErr(w, http.StatusForbidden, msgNoPasskeyLogin, "")
			return
		}
		extra["org"] = org.ID
		extra["tenant"] = tenant
		extra["next"] = safeNext(org, in.Next)
		extra[passkey.PurposeKey] = purposeLogin
	}
	id, opts, err := m.Passkeys.BeginLogin(ctx, user, extra)
	if err != nil {
		if errors.Is(err, passkey.ErrUnknownCredential) {
			writeErr(w, http.StatusUnprocessableEntity, "No passkey is registered for this account.", "")
			return
		}
		m.internalError(w, r, "passkey begin", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, passkeyBeginResp{Challenge: id, Options: opts})
}

type passkeyFinishReq struct {
	Challenge  string          `json:"challenge"`
	Credential json.RawMessage `json:"credential"`
}

const msgNoPasskeyLogin = "Passkey sign-in is not enabled for this organization."

const msgBadPasskey = "That passkey could not be verified."

// passkeyFinish handles POST /o/{org}/api-internal/login/passkey/finish: {challenge, credential} -> {next}. The
// passkey must be an account of the organization the path names, whatever page began the ceremony.
func (m *Module) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) || !m.passkeysOK(w) {
		return
	}
	var in passkeyFinishReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	if !m.rateLimit(w, r, web.Org(r).ID+"|passkey", known{any: true}) {
		return
	}
	res, err := m.Passkeys.FinishLoginAs(ctx, in.Challenge, in.Credential, purposeLogin, purposeSecondFactor)
	if err != nil {
		reason := "passkey"
		switch {
		case errors.Is(err, passkey.ErrCloneDetected):
			reason = "passkey clone suspected"
			if res != nil {
				org, _ := m.s.Svc.Orgs.Get(ctx, res.User.OrgID)
				m.audit(r, "passkey.clone", org, res.User, res.User.Username,
					map[string]string{"passkey": res.Passkey.Name})
			}
		case errors.Is(err, passkey.ErrUnusable):
			reason = "passkey disabled or unverified"
		case errors.Is(err, passkey.ErrChallenge):
			writeErr(w, http.StatusUnauthorized, "That sign-in has expired. Try again.", "")
			return
		case errors.Is(err, service.ErrUnavailable), errors.Is(err, store.ErrUnavailable):
			unavailableResponse(w)
			return
		}
		var org *model.Org
		var u *model.User
		if res != nil {
			u = res.User
			org, _ = m.s.Svc.Orgs.Get(ctx, u.OrgID)
		}
		m.audit(r, "login.failure", org, u, "", map[string]string{"reason": reason})
		writeErr(w, http.StatusUnauthorized, msgBadPasskey, "")
		return
	}
	u := res.User
	org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	if err != nil || org.ID != web.Org(r).ID {
		m.audit(r, "login.failure", org, u, u.Username, map[string]string{"reason": "passkey for another organization"})
		writeErr(w, http.StatusUnauthorized, msgBadPasskey, "")
		return
	}
	amr := res.AMR()
	next := res.Extra["next"]
	provider := ""

	if tid := res.Extra["ticket"]; tid != "" {
		// Second factor after a verified password: the ticket must still bind to the account the passkey just
		// signed in (ticketCurrent; u was read by the ceremony a moment ago).
		t, ok := m.getTicket(ctx, tid, "passkey", "totp")
		if !ok || !m.ticketCurrent(ctx, t, u) || !m.useTicket(ctx, tid) {
			writeErr(w, http.StatusUnauthorized, msgExpired, "")
			return
		}
		amr = append(append(append([]string{}, t.AMR...), amr...), "mfa")
		next, provider = t.Next, t.Provider
	} else {
		if res.Extra["org"] != org.ID { // a ceremony begun at another organization's page
			m.audit(r, "login.failure", org, u, u.Username, map[string]string{"reason": "passkey for another organization"})
			writeErr(w, http.StatusUnauthorized, msgBadPasskey, "")
			return
		}
		eff, _, err := m.methods(ctx, org, res.Extra["tenant"], "")
		if err != nil {
			m.internalError(w, r, "sign-in methods", err)
			return
		}
		if !eff.Passkey {
			writeErr(w, http.StatusForbidden, msgNoPasskeyLogin, "")
			return
		}
	}
	dest, err := m.completeWith(w, r, u, org, web.SessionOptions{AMR: amr, Passkey: res.Passkey.ID, Provider: provider}, next)
	if err != nil {
		m.internalError(w, r, "create session", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
}
