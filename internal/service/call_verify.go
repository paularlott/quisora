package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Caller verification (docs/CALLER-VERIFICATION.md): a support agent confirms that the person on a call is the account
// holder they say they are. The agent, a member of an agent group of an organization that verifies callers
// (model.OrgSettings.VerifyCallers), picks the customer, a user of their own organization (or, for the primary
// organization's agents, of an organization that lets them: VerifiedByPrimary), and reads the verification's
// six-digit code to them. The customer enters it on their
// own account page, sees who is asking and why, and confirms it is them with a passkey or second factor (the caller's
// recent re-authentication): the agent's page then says so. Nothing is sent to the customer: they go to their own
// account themselves, so a caller cannot send them to a page of their choosing.

// VerifyOrg is an organization an agent may verify the users of.
type VerifyOrg struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Own         bool   `json:"own"` // the agent's own organization
}

// VerifyUser is a user an agent may verify: who they are, no more.
type VerifyUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// CallVerificationView is a verification as the pages show it: the customer and both organizations by name.
type CallVerificationView struct {
	*model.CallVerification
	CustomerName    string `json:"customer_name"`
	CustomerEmail   string `json:"customer_email,omitempty"`
	CustomerOrgName string `json:"customer_org_name"`
	// SignInURL is where the customer verifies: their organization's account page (/o/<org>/account/verify-call).
	VerifyPath string `json:"verify_path"`
	Live       bool   `json:"live"` // pending, and its code still works
}

// verifyAgent is the agent the actor acts as, with their organization: a person signed in as themselves (never a guest
// from another organization, a personal API token or a service account) who is a member of one of their
// organization's agent groups while it verifies callers.
func (s *Service) verifyAgent(ctx context.Context, a *Actor) (*model.User, *model.Org, error) {
	if a == nil || a.UserID == "" || a.ClientID != "" || a.TokenID != "" || len(a.Sources) > 0 {
		return nil, nil, ErrForbidden
	}
	u, err := s.Users.Get(ctx, a.UserID)
	if err != nil {
		return nil, nil, mapStore(err)
	}
	if !u.Active {
		return nil, nil, ErrForbidden
	}
	o, err := s.OrgPolicy(ctx, u.OrgID)
	if err != nil {
		return nil, nil, err
	}
	if !o.Settings.VerifyCallers {
		return nil, nil, ErrForbidden
	}
	groups, err := s.UserGroups(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	if !slices.ContainsFunc(groups, func(g *model.Group) bool { return o.Settings.VerifyAgentGroup(g.ID) }) {
		return nil, nil, ErrForbidden
	}
	return u, o, nil
}

// verifiableOrg is organization ref (an id or name) when agentOrg's agents may verify its users: it is agentOrg, or
// agentOrg is the primary organization and the organization lets its agents (VerifiedByPrimary).
func (s *Service) verifiableOrg(ctx context.Context, agentOrg *model.Org, ref string) (*model.Org, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || ref == agentOrg.ID || ref == agentOrg.Name {
		return agentOrg, nil
	}
	o, err := s.OrgByRef(ctx, ref)
	if errors.Is(err, ErrNotFound) || errors.Is(err, store.ErrNotFound) || err == nil && !(agentOrg.Primary && o.Settings.VerifiedByPrimary) {
		return nil, Invalid("org", "choose an organization whose users you may verify")
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

// VerifyOrgs lists the organizations the actor (an agent) may verify the users of whose name starts with q (all of them
// when q is empty), up to limit: their own first, then, for the primary organization's agents, those that let them
// (one indexed read).
func (s *Service) VerifyOrgs(ctx context.Context, a *Actor, q string, limit int) ([]VerifyOrg, error) {
	_, own, err := s.verifyAgent(ctx, a)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	q = strings.TrimSpace(q)
	out := []VerifyOrg{}
	lq := strings.ToLower(q)
	if q == "" || strings.HasPrefix(strings.ToLower(own.Name), lq) || strings.HasPrefix(strings.ToLower(own.DisplayName), lq) {
		out = append(out, VerifyOrg{ID: own.ID, Name: own.Name, DisplayName: own.DisplayName, Own: true})
	}
	if !own.Primary {
		return out, nil
	}
	l, _, err := s.Orgs.List(ctx, store.ListQuery{Search: q, Sort: "display_name", Limit: limit,
		Filters: []store.Filter{{Field: "verified_by_primary", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	for _, o := range l {
		if o.ID != own.ID && len(out) < limit {
			out = append(out, VerifyOrg{ID: o.ID, Name: o.Name, DisplayName: o.DisplayName})
		}
	}
	return out, nil
}

// VerifyUsers lists the active users of organization orgRef the actor (an agent) may verify whose name, family name,
// username or email starts with q, up to limit: their name and email only. Not the agent themselves, and not super
// administrators.
func (s *Service) VerifyUsers(ctx context.Context, a *Actor, orgRef, q string, limit int) ([]VerifyUser, error) {
	agent, own, err := s.verifyAgent(ctx, a)
	if err != nil {
		return nil, err
	}
	o, err := s.verifiableOrg(ctx, own, orgRef)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	q = strings.TrimSpace(q)
	if q == "" {
		return []VerifyUser{}, nil // a name or address to look for, not a list of the organization's people
	}
	l, _, err := s.Users.List(ctx, store.ListQuery{Scope: o.ID, Search: q, Sort: "name", Limit: limit + 1,
		Filters: []store.Filter{ActiveFilter(true)}})
	if err != nil {
		return nil, mapStore(err)
	}
	out := []VerifyUser{}
	for _, u := range l {
		if u.ID == agent.ID || u.Role == model.RoleSuperAdmin || len(out) >= limit {
			continue
		}
		out = append(out, VerifyUser{ID: u.ID, Name: u.FullName(), Email: u.Email})
	}
	return out, nil
}

// VerifyCallInput starts a verification: the customer's organization (id or name; empty: the agent's own), the
// customer's user id, and why (shown to the customer).
type VerifyCallInput struct {
	Org    string `json:"org"`
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
}

// StartCallVerification is the actor (an agent) starting a verification of a customer: it returns the verification and
// its six-digit code, which is shown to the agent this once (only a hash of it is kept). The code works for
// model.VerifyCodeFor, for that customer only.
func (s *Service) StartCallVerification(ctx context.Context, a *Actor, in VerifyCallInput) (*CallVerificationView, string, error) {
	agent, own, err := s.verifyAgent(ctx, a)
	if err != nil {
		return nil, "", err
	}
	o, err := s.verifiableOrg(ctx, own, in.Org)
	if err != nil {
		return nil, "", err
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) > 200 {
		return nil, "", Invalid("reason", "at most 200 characters")
	}
	u, err := s.Users.Get(ctx, strings.TrimSpace(in.UserID))
	if errors.Is(err, store.ErrNotFound) || err == nil && (u.OrgID != o.ID || !u.Active || u.Role == model.RoleSuperAdmin) {
		return nil, "", Invalid("user_id", "choose a person of "+o.DisplayName)
	}
	if err != nil {
		return nil, "", mapStore(err)
	}
	if u.ID == agent.ID {
		return nil, "", Invalid("user_id", "you cannot verify yourself")
	}
	now := time.Now().UTC()
	for range 5 { // a code another verification of the customer holds now: another
		code, err := sixDigits()
		if err != nil {
			return nil, "", err
		}
		v := &model.CallVerification{Meta: model.Meta{ID: model.NewID()}, OrgID: o.ID, UserID: u.ID, AgentOrgID: own.ID, AgentID: agent.ID,
			AgentName: agent.FullName(), AgentEmail: agent.Email, AgentOrgName: own.DisplayName, Reason: reason,
			CodeKey: model.VerifyCodeKey(u.ID, code), State: model.VerifyPending, Expires: now.Add(model.VerifyCodeFor)}
		err = s.Verifications.Create(ctx, v)
		detail := map[string]string{"verification": v.ID, "user": u.ID, "customer_org": o.Name, "agent": agent.ID}
		if reason != "" {
			detail["reason"] = reason
		}
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		s.auditOutcome(ctx, a, err, change{own.ID, "call_verify.start", u.Username, detail, nil},
			change{o.ID, "call_verify.start", u.Username, detail, nil})
		if err != nil {
			return nil, "", mapStore(err)
		}
		return s.verificationView(ctx, v), code, nil
	}
	return nil, "", ErrStale
}

// sixDigits is a random code of six digits.
func sixDigits() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// AgentVerification reads verification id for the agent who started it.
func (s *Service) AgentVerification(ctx context.Context, a *Actor, id string) (*CallVerificationView, error) {
	v, err := s.Verifications.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && (a == nil || a.UserID == "" || v.AgentID != a.UserID) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, mapStore(err)
	}
	return s.verificationView(ctx, v), nil
}

// AgentVerifications lists the verifications the actor (an agent) started today and yesterday (UTC), newest first:
// one exact indexed read for each day.
func (s *Service) AgentVerifications(ctx context.Context, a *Actor) ([]*CallVerificationView, error) {
	agent, _, err := s.verifyAgent(ctx, a)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []*CallVerificationView
	for _, day := range []time.Time{now, now.Add(-24 * time.Hour)} {
		l, _, err := s.Verifications.List(ctx, store.ListQuery{Limit: 200, Filters: []store.Filter{
			{Field: "agent_day", Value: model.VerifyAgentDay(agent.ID, day)}}})
		if err != nil {
			return nil, mapStore(err)
		}
		for _, v := range l {
			out = append(out, s.verificationView(ctx, v))
		}
	}
	slices.SortFunc(out, func(x, y *CallVerificationView) int { return y.Created.Compare(x.Created) })
	return out, nil
}

// CancelCallVerification is the agent who started verification id stopping it while it waits.
func (s *Service) CancelCallVerification(ctx context.Context, a *Actor, id string) (*CallVerificationView, error) {
	v, err := s.Verifications.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && (a == nil || v.AgentID != a.UserID) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, mapStore(err)
	}
	if v.State != model.VerifyPending {
		return nil, Invalid("state", "this verification was "+v.State+" already")
	}
	v.State, v.DecidedAt = model.VerifyCancelled, time.Now().UTC()
	err = s.audited(ctx, a, v.AgentOrgID, "call_verify.cancel", v.UserID, map[string]string{"verification": v.ID},
		func() error { return s.Verifications.Update(ctx, v) })
	if err != nil {
		return nil, mapStore(err)
	}
	return s.verificationView(ctx, v), nil
}

// customer is the account the actor verifies as: a person signed in as themselves (not a guest, a token or a service
// account).
func (s *Service) customer(ctx context.Context, a *Actor) (*model.User, error) {
	if a == nil || a.UserID == "" || a.ClientID != "" || a.TokenID != "" || len(a.Sources) > 0 {
		return nil, ErrForbidden
	}
	u, err := s.Users.Get(ctx, a.UserID)
	if err != nil {
		return nil, mapStore(err)
	}
	if !u.Active {
		return nil, ErrForbidden
	}
	return u, nil
}

// FindCallVerification is the actor (a customer) entering a code: the verification of theirs waiting for it, or
// ErrNotFound (a wrong code, another person's, or one that ran out). The caller counts wrong codes.
func (s *Service) FindCallVerification(ctx context.Context, a *Actor, code string) (*CallVerificationView, error) {
	u, err := s.customer(ctx, a)
	if err != nil {
		return nil, err
	}
	code = strings.Join(strings.Fields(code), "")
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return nil, Invalid("code", "enter the six digits you were given")
	}
	v, err := s.Verifications.GetByUnique(ctx, model.VerifyCodeUnique(u.OrgID, u.ID, code))
	if errors.Is(err, store.ErrNotFound) || err == nil && (v.UserID != u.ID || !v.Pending(time.Now())) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, mapStore(err)
	}
	return s.verificationView(ctx, v), nil
}

// AnswerCallVerification is the customer answering verification id, found by its code: confirming it is them
// (secondFactor: they confirmed it is them to Quisora with a passkey or second factor, else their password alone), or
// saying it is not.
func (s *Service) AnswerCallVerification(ctx context.Context, a *Actor, id string, confirm, secondFactor bool) (*CallVerificationView, error) {
	u, err := s.customer(ctx, a)
	if err != nil {
		return nil, err
	}
	v, err := s.Verifications.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && v.UserID != u.ID {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, mapStore(err)
	}
	if v.State != model.VerifyPending {
		return nil, Invalid("state", "this verification was "+v.State+" already")
	}
	if !v.Pending(time.Now()) {
		return nil, Invalid("state", "this code has run out: ask for a new one")
	}
	action := "call_verify.confirm"
	v.State, v.DecidedAt = model.VerifyConfirmed, time.Now().UTC()
	v.SecondFactor = confirm && secondFactor
	if !confirm {
		v.State, action = model.VerifyDenied, "call_verify.deny"
	}
	detail := map[string]string{"verification": v.ID, "agent": v.AgentID, "agent_name": v.AgentName}
	if confirm {
		detail["second_factor"] = fmt.Sprint(v.SecondFactor)
	}
	err = s.Verifications.Update(ctx, v)
	s.auditOutcome(ctx, a, err, change{v.OrgID, action, u.Username, detail, nil}, change{v.AgentOrgID, action, u.Username, detail, nil})
	if err != nil {
		return nil, mapStore(err)
	}
	return s.verificationView(ctx, v), nil
}

// WaitingCallVerifications lists the verifications waiting for the actor (a customer) to enter their code, newest
// first: who is verifying them right now (never the code). Their Verify a call page shows them above the code, so a
// caller who asks for a code without having started a verification shows up as such.
func (s *Service) WaitingCallVerifications(ctx context.Context, a *Actor) ([]*CallVerificationView, error) {
	u, err := s.customer(ctx, a)
	if err != nil {
		return nil, err
	}
	l, _, err := s.Verifications.List(ctx, store.ListQuery{Scope: u.OrgID, Limit: 50, Filters: []store.Filter{
		{Field: "user_id", Value: u.ID}, {Field: "state", Value: model.VerifyPending}}})
	if err != nil {
		return nil, mapStore(err)
	}
	now := time.Now()
	out := []*CallVerificationView{}
	for _, v := range l {
		if v.Pending(now) {
			out = append(out, s.verificationView(ctx, v))
		}
	}
	slices.SortFunc(out, func(x, y *CallVerificationView) int { return y.Created.Compare(x.Created) })
	return out, nil
}

// CustomerVerifications lists a page of the actor's verifications (who asked to verify them, and what came of it),
// newest first, and how many there are.
func (s *Service) CustomerVerifications(ctx context.Context, a *Actor, q store.ListQuery) ([]*CallVerificationView, int, error) {
	u, err := s.customer(ctx, a)
	if err != nil {
		return nil, 0, err
	}
	l, n, err := s.Verifications.List(ctx, store.ListQuery{Scope: u.OrgID, Sort: "created", Desc: true, Offset: q.Offset,
		Limit: pageLimit(q), Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
	if err != nil {
		return nil, 0, mapStore(err)
	}
	out := make([]*CallVerificationView, 0, len(l))
	for _, v := range l {
		out = append(out, s.verificationView(ctx, v))
	}
	return out, n, nil
}

// ExpireCallVerifications is the housekeeping of caller verifications: a pending one whose code ran out is marked
// expired, and a closed one is removed once model.VerifyKeptFor has passed. It returns how many it changed.
func (s *Service) ExpireCallVerifications(ctx context.Context) (int, error) {
	n := 0
	stuck := map[string]bool{}
	for {
		due, err := s.dueVerifications(ctx, 200)
		if err != nil {
			return n, err
		}
		progressed := false
		for _, v := range due {
			if stuck[v.ID] {
				continue
			}
			if v.State == model.VerifyPending {
				v.State, v.DecidedAt = model.VerifyExpired, v.Expires
				err = s.Verifications.Update(ctx, v)
			} else {
				err = s.Verifications.DeleteIf(ctx, v.ID, v.Version)
			}
			if err != nil && !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrNotFound) {
				stuck[v.ID] = true
				s.Log.WithError(err).Warn("a caller verification could not be closed; housekeeping tries again", "verification", v.ID)
				continue
			}
			n++
			progressed = true
		}
		if len(due) < 200 || !progressed {
			return n, nil
		}
	}
}

// dueVerifications lists up to limit verifications due now (model.Due): from the due index where the store keeps one.
func (s *Service) dueVerifications(ctx context.Context, limit int) ([]*model.CallVerification, error) {
	now := time.Now()
	if dl, ok := s.Verifications.S.(store.DueLister); ok {
		recs, err := dl.ListDue(ctx, model.KindCallVerification, now, limit)
		if err == nil {
			out := make([]*model.CallVerification, 0, len(recs))
			for _, rec := range recs {
				var v model.CallVerification
				if err := store.Decode(rec, &v); err == nil {
					out = append(out, &v)
				}
			}
			return out, nil
		}
		if !errors.Is(err, store.ErrNoDueIndex) {
			return nil, mapStore(err)
		}
	}
	l, _, err := s.Verifications.List(ctx, store.ListQuery{Sort: "due", Limit: limit, Filters: []store.Filter{{Field: "due", Op: store.OpLT, Value: now}}})
	return l, mapStore(err)
}

// verificationView names v's customer and organization.
func (s *Service) verificationView(ctx context.Context, v *model.CallVerification) *CallVerificationView {
	out := &CallVerificationView{CallVerification: v, CustomerName: "a deleted user", CustomerOrgName: v.OrgID,
		Live: v.Pending(time.Now())}
	if u, err := s.Users.Get(ctx, v.UserID); err == nil {
		out.CustomerName, out.CustomerEmail = u.FullName(), u.Email
	}
	if o, err := s.Org(ctx, v.OrgID); err == nil {
		out.CustomerOrgName = o.DisplayName
		out.VerifyPath = "/o/" + o.Name + "/account/verify-call"
	}
	if v.State == model.VerifyPending && !out.Live {
		out.State = model.VerifyExpired // not yet tidied by housekeeping
	}
	return out
}
