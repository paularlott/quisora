package login

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// Caller verification (docs/CALLER-VERIFICATION.md): Verify a caller, the agent's page (find the customer, start a
// verification, read its code out, see the answer), and Verify a call, the customer's (enter the code, see who asks,
// confirm it is you or say it is not). Both are reached from the account menu: the first for the members of their
// organization's agent groups, the second for the people of an organization whose users can be verified.

func (m *Module) registerCallVerification(h func(string, func(http.ResponseWriter, *http.Request, acct))) {
	h("GET /api-internal/account/verify-caller", m.agentVerifications)
	h("GET /api-internal/account/verify-caller/orgs", m.verifyOrgs)
	h("GET /api-internal/account/verify-caller/users", m.verifyUsers)
	h("POST /api-internal/account/verify-caller", m.startVerification)
	h("GET /api-internal/account/verify-caller/{id}", m.agentVerification)
	h("POST /api-internal/account/verify-caller/{id}/cancel", m.cancelVerification)
	h("GET /api-internal/account/verify-call", m.customerVerifications)
	h("GET /api-internal/account/verify-call/waiting", m.waitingVerifications)
	h("POST /api-internal/account/verify-call/find", m.findVerification)
	h("POST /api-internal/account/verify-call/{id}/confirm", m.answerVerification(true))
	h("POST /api-internal/account/verify-call/{id}/deny", m.answerVerification(false))
}

// verifyCallerPage handles GET /o/{org}/account/verify-caller.
func (m *Module) verifyCallerPage(w http.ResponseWriter, r *http.Request) {
	m.s.Render.Render(w, http.StatusOK, "account-verify-caller", m.s.Page(w, r, "Verify a caller", "verify-caller", nil))
}

// verifyCallPage handles GET /o/{org}/account/verify-call.
func (m *Module) verifyCallPage(w http.ResponseWriter, r *http.Request) {
	m.s.Render.Render(w, http.StatusOK, "account-verify-call", m.s.Page(w, r, "Verify a call", "verify-call", nil))
}

// verifyError answers err of a caller verification call: a field error, a refusal, or a server error.
func (m *Module) verifyError(w http.ResponseWriter, err error) {
	var fe *service.FieldError
	switch {
	case errors.As(err, &fe):
		writeErr(w, http.StatusUnprocessableEntity, fe.Msg, fe.Field)
	case errors.Is(err, service.ErrForbidden):
		writeErr(w, http.StatusForbidden, "You cannot do this.", "")
	case errors.Is(err, service.ErrNotFound):
		writeErr(w, http.StatusNotFound, "There is no such verification.", "")
	case errors.Is(err, service.ErrStale):
		writeErr(w, http.StatusConflict, "Something changed meanwhile: try again.", "")
	default:
		web.WriteError(w, err)
	}
}

// ---- the agent ---------------------------------------------------------------------------------------------------

// agentVerifications answers GET /api-internal/account/verify-caller: the verifications the agent started today and
// yesterday, newest first.
func (m *Module) agentVerifications(w http.ResponseWriter, r *http.Request, a acct) {
	l, err := m.s.Svc.AgentVerifications(r.Context(), a.actor)
	if err != nil {
		m.verifyError(w, err)
		return
	}
	if l == nil {
		l = []*service.CallVerificationView{}
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": l})
}

// verifyOrgs answers GET /api-internal/account/verify-caller/orgs?q=.
func (m *Module) verifyOrgs(w http.ResponseWriter, r *http.Request, a acct) {
	l, err := m.s.Svc.VerifyOrgs(r.Context(), a.actor, r.URL.Query().Get("q"), 10)
	if err != nil {
		m.verifyError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": l})
}

// verifyUsers answers GET /api-internal/account/verify-caller/users?org=&q=.
func (m *Module) verifyUsers(w http.ResponseWriter, r *http.Request, a acct) {
	l, err := m.s.Svc.VerifyUsers(r.Context(), a.actor, r.URL.Query().Get("org"), r.URL.Query().Get("q"), 10)
	if err != nil {
		m.verifyError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": l})
}

// startVerification answers POST /api-internal/account/verify-caller {org, user_id, reason}: the verification and its
// code, this once.
func (m *Module) startVerification(w http.ResponseWriter, r *http.Request, a acct) {
	var in service.VerifyCallInput
	if !decode(w, r, &in) {
		return
	}
	if ok, err := m.s.VerifyStartAllowed(r.Context(), a.u.ID); err != nil {
		unavailableResponse(w)
		return
	} else if !ok {
		writeErr(w, http.StatusTooManyRequests, "You have started many verifications in the last hour: wait a while.", "")
		return
	}
	v, code, err := m.s.Svc.StartCallVerification(r.Context(), a.actor, in)
	if err != nil {
		m.verifyError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, map[string]any{"verification": v, "code": code})
}

// agentVerification answers GET /api-internal/account/verify-caller/{id}: how it stands (the agent's page asks while
// it waits).
func (m *Module) agentVerification(w http.ResponseWriter, r *http.Request, a acct) {
	v, err := m.s.Svc.AgentVerification(r.Context(), a.actor, r.PathValue("id"))
	if err != nil {
		m.verifyError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, v)
}

// cancelVerification answers POST /api-internal/account/verify-caller/{id}/cancel.
func (m *Module) cancelVerification(w http.ResponseWriter, r *http.Request, a acct) {
	v, err := m.s.Svc.CancelCallVerification(r.Context(), a.actor, r.PathValue("id"))
	if err != nil {
		m.verifyError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, v)
}

// ---- the customer ------------------------------------------------------------------------------------------------

// customerVerifications answers GET /api-internal/account/verify-call: a page of who asked to verify the person, and
// what came of it, newest first.
func (m *Module) customerVerifications(w http.ResponseWriter, r *http.Request, a acct) {
	l, n, err := m.s.Svc.CustomerVerifications(r.Context(), a.actor, pageOf(r))
	if err != nil {
		m.verifyError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": l, "total": n})
}

// waitingVerifications answers GET /api-internal/account/verify-call/waiting: who is verifying the person right now
// (their verifications waiting for a code), newest first.
func (m *Module) waitingVerifications(w http.ResponseWriter, r *http.Request, a acct) {
	l, err := m.s.Svc.WaitingCallVerifications(r.Context(), a.actor)
	if err != nil {
		m.verifyError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": l})
}

// findVerification answers POST /api-internal/account/verify-call/find {code}: the verification waiting for that code
// in the person's account, which they then confirm or deny. Wrong codes are counted (VerifyCodeTriesLeft).
func (m *Module) findVerification(w http.ResponseWriter, r *http.Request, a acct) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	if ok, err := m.s.VerifyCodeTriesLeft(ctx, a.u.ID); err != nil {
		unavailableResponse(w)
		return
	} else if !ok {
		writeErr(w, http.StatusTooManyRequests, "Too many wrong codes: wait ten minutes, then ask for a new code.", "code")
		return
	}
	v, err := m.s.Svc.FindCallVerification(ctx, a.actor, in.Code)
	if errors.Is(err, service.ErrNotFound) {
		m.s.VerifyCodeWrong(ctx, a.u.ID)
		writeErr(w, http.StatusUnprocessableEntity, "That code is not right, or it has run out. Check it with the person you are talking to.", "code")
		return
	}
	if err != nil {
		m.verifyError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, v)
}

// answerVerification answers POST /api-internal/account/verify-call/{id}/confirm and …/deny. Confirming needs the
// person to have confirmed it is them just now (needReauth): the agent is told whether that was with a passkey or
// second factor. Saying it is not them needs nothing more.
func (m *Module) answerVerification(confirm bool) func(http.ResponseWriter, *http.Request, acct) {
	return func(w http.ResponseWriter, r *http.Request, a acct) {
		if confirm && !m.needReauth(w, r, a) {
			return
		}
		v, err := m.s.Svc.AnswerCallVerification(r.Context(), a.actor, r.PathValue("id"), confirm, confirm && m.secondFactorNow(r.Context(), a))
		if err != nil {
			m.verifyError(w, err)
			return
		}
		web.WriteJSON(w, http.StatusOK, v)
	}
}

// secondFactorNow reports whether the person's recent confirmation that it is them (needReauth) used a passkey or a
// second factor: a re-authentication with one, or a sign-in with one within the re-authentication window.
func (m *Module) secondFactorNow(ctx context.Context, a acct) bool {
	if _, _, second, ok := m.readReauth(ctx, a.sess.ID); ok && second && m.reauthed(ctx, a) {
		return true
	}
	return time.Since(a.sess.AuthTime) < reauthTTL &&
		slices.ContainsFunc(a.sess.AMR, func(v string) bool { return v == "otp" || v == "hwk" || v == "swk" })
}
