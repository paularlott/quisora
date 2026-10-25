package admin

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

type groupRef struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

// userView is a user as the management API shows it. The password hash never leaves the server; has_password says
// whether one is set.
type userView struct {
	*model.User
	HasPassword bool       `json:"has_password"`
	Passkeys    *int       `json:"passkeys,omitempty"` // count; only when one user is fetched
	Groups      []groupRef `json:"groups,omitempty"`
	// Manager names the user's manager (work.manager_id) when one user is fetched.
	Manager *userRef `json:"manager,omitempty"`
	Tags    []string `json:"tags"` // never null
	// Name is the read-only full name (given + family name).
	Name         string              `json:"name"`
	LinkedEmails []model.LinkedEmail `json:"linked_emails"` // never null
	// Directory marks a user above the caller, shown as a directory entry only: id, name, role and status
	// (service.Visibility); every other field is empty.
	Directory bool `json:"directory,omitempty"`
	// CanManage says the caller may change this user at all (never someone of a higher role: a manager manages plain
	// users, an administrator everyone but super admins); the console shows another user read-only without it. Present
	// on lists and on GET of one user.
	CanManage *bool `json:"can_manage,omitempty"`
	// CanResetSignIn says the caller may issue this user an invitation or remove their password (a manager's or
	// administrator's only a super admin may, once they have a way to sign in); present on GET of one user.
	CanResetSignIn *bool `json:"can_reset_sign_in,omitempty"`
	// CanVerifyEmail says the caller may mark the user's unverified addresses verified (never their own); present
	// on GET of one user.
	CanVerifyEmail *bool `json:"can_verify_email,omitempty"`
}

func viewOf(u *model.User) userView {
	le := u.LinkedEmails
	if le == nil {
		le = []model.LinkedEmail{}
	}
	return userView{User: u, HasPassword: u.PasswordHash != "", Tags: nonNilTags(u.Tags), Name: u.FullName(), LinkedEmails: le}
}

func nonNilTags(t []string) []string {
	if t == nil {
		return []string{}
	}
	return t
}

// userBody is the writable part of a user. Passwords are not part of it: users choose them through an invitation
// link (the strict decoder rejects a "password" field).
type userBody struct {
	Username      *string            `json:"username"`
	Email         *string            `json:"email"`
	GivenName     *string            `json:"given_name"`
	FamilyName    *string            `json:"family_name"`
	Role          *model.Role        `json:"role"`
	Active        *bool              `json:"active"`
	ExternalID    *string            `json:"external_id"`
	Locale        *string            `json:"locale"`
	ZoneInfo      *string            `json:"zoneinfo"`
	UserType      *string            `json:"user_type"`
	ValidUntil    *string            `json:"valid_until"`
	Work          *service.WorkInput `json:"work"`
	Verified      *bool              `json:"email_verified"`
	Phone         *string            `json:"phone_number"`
	PhoneVerified *bool              `json:"phone_number_verified"`
	Tags          *[]string          `json:"tags"`
	// StatusReason is recorded when this change disables the user or enables them again.
	StatusReason *string `json:"status_reason"`
}

// userRef names another user.
type userRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (b userBody) input() service.UserInput {
	return service.UserInput{Username: b.Username, Email: b.Email, GivenName: b.GivenName,
		FamilyName: b.FamilyName, Role: b.Role, Active: b.Active, ExternalID: b.ExternalID, Locale: b.Locale,
		ZoneInfo: b.ZoneInfo, UserType: b.UserType, ValidUntil: b.ValidUntil, Work: b.Work,
		Verified: b.Verified, Phone: b.Phone, PhoneVerified: b.PhoneVerified, Tags: b.Tags, StatusReason: b.StatusReason}
}

// userFor loads the {id} user, which must belong to org.
func (m *Module) userFor(w http.ResponseWriter, r *http.Request, org *model.Org, a *service.Actor) (*model.User, bool) {
	u, err := m.s.Svc.GetUser(r.Context(), a, r.PathValue("id"))
	if err != nil || u.OrgID != org.ID {
		web.WriteError(w, service.ErrNotFound)
		return nil, false
	}
	return u, true
}

func (m *Module) listUsers(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	q := listQuery(r)
	v := r.URL.Query()
	if role := v.Get("role"); role != "" {
		if !model.Role(role).Valid() {
			web.WriteError(w, service.Invalid("role", "unknown role"))
			return
		}
		q.Filters = append(q.Filters, store.Filter{Field: "role", Value: role})
	}
	switch v.Get("active") {
	case "1":
		q.Filters = append(q.Filters, service.ActiveFilter(true))
	case "0":
		q.Filters = append(q.Filters, service.ActiveFilter(false))
	}
	var (
		items []*model.User
		total int
		err   error
	)
	if tag := v.Get("tag"); tag != "" {
		items, total, err = m.s.Svc.ListUsersTagged(r.Context(), a, org.ID, q, tag)
	} else {
		items, total, err = m.s.Svc.ListUsers(r.Context(), a, org.ID, q)
	}
	if err != nil {
		web.WriteError(w, err)
		return
	}
	views := make([]userView, len(items))
	for i, u := range items {
		views[i] = viewOf(u)
		can := m.s.Svc.CanManageUser(a, u)
		views[i].CanManage = &can
		views[i].Directory = m.s.Svc.Visibility(a, u) == service.Directory
	}
	writeList(w, views, total)
}

func (m *Module) getUser(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	view := viewOf(u)
	if m.s.Svc.Visibility(a, u) == service.Directory {
		// someone above the caller: who they are, nothing else (u is already the directory entry)
		no := false
		view.Directory, view.CanManage, view.CanResetSignIn, view.CanVerifyEmail = true, &no, &no, &no
		web.WriteJSON(w, http.StatusOK, view)
		return
	}
	if pks, err := m.s.Svc.CurrentPasskeys(r.Context(), u); err == nil {
		n := len(pks)
		view.Passkeys = &n
	}
	if gs, err := m.s.Svc.UserGroups(r.Context(), u); err == nil {
		for _, g := range gs {
			view.Groups = append(view.Groups, groupRef{ID: g.ID, DisplayName: g.DisplayName})
		}
	}
	if id := u.Work.ManagerID; id != "" {
		if mu, err := m.s.Svc.Users.Get(r.Context(), id); err == nil && mu.OrgID == u.OrgID && m.s.Svc.Visibility(a, mu) != service.Hidden {
			view.Manager = &userRef{ID: mu.ID, Name: mu.FullName()}
		}
	}
	manage := m.s.Svc.CanManageUser(a, u)
	view.CanManage = &manage
	can := m.s.Svc.CanResetSignIn(r.Context(), a, u)
	view.CanResetSignIn = &can
	canVerify := m.s.Svc.CanMarkEmailVerified(r.Context(), a, u)
	view.CanVerifyEmail = &canVerify
	web.WriteJSON(w, http.StatusOK, view)
}

type createUserBody struct {
	userBody
	// PasswordHash imports a password hash from another system (bcrypt or argon2id): super admins, and an API token
	// only with the import scope. See service.UserInput.PasswordHash.
	PasswordHash *string `json:"password_hash"`
	// Invite asks for an invitation link in the response; Invite.Email also mails it.
	Invite *struct {
		Email bool `json:"email"`
	} `json:"invite"`
}

func (m *Module) createUser(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in createUserBody
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	input := in.input()
	input.PasswordHash = in.PasswordHash
	input.Username = emptyToNil(input.Username)
	if input.Email != nil && *input.Email == "" {
		input.Email = nil
	}
	if in.Invite != nil && in.Invite.Email && input.Email == nil {
		web.WriteError(w, service.Invalid("email", "an email address is needed to send an invitation"))
		return
	}
	if input.Role != nil && input.Role.Rank() >= model.RoleAdmin.Rank() && !m.stepUp(w, r) {
		return
	}
	u, err := m.s.Svc.CreateUser(r.Context(), a, org.ID, input)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	resp := struct {
		userView
		Invite *inviteResult `json:"invite,omitempty"`
	}{userView: viewOf(u)}
	if in.Invite != nil {
		res, err := m.issueInvite(r, org, a, u, in.Invite.Email)
		if err != nil {
			// the user exists; report what failed without losing the 201
			res = &inviteResult{EmailNote: "The user was created but the invitation could not be issued: " + err.Error() + "."}
		}
		resp.Invite = res
	}
	web.WriteJSON(w, http.StatusCreated, resp)
}

func (m *Module) updateUser(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	var in userBody
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	input := in.input()
	// Changes to yourself are left to the service, which refuses demoting or disabling yourself.
	curbs := u.ID != a.UserID && service.CurbsAdmin(u, input)
	if (input.Role != nil && *input.Role != u.Role && input.Role.Rank() >= model.RoleAdmin.Rank() || curbs) && !m.stepUp(w, r) {
		return
	}
	upd, err := m.s.Svc.UpdateUser(r.Context(), a, u.ID, input)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if !strings.EqualFold(upd.Email, u.Email) && !upd.EmailVerified && m.s.Site.Mail {
		// A new primary address starts unverified: its owner is mailed a link, as for an added address. The change
		// stands either way; a failed mail is logged and the profile's "Send verification email" tries again.
		if err := m.Mailer.SendVerifyAddress(r.Context(), org, upd, upd.Email); err != nil {
			m.s.Log.Warn("admin: mailing a verification link", "user", upd.ID, "error", err)
		}
	}
	web.WriteJSON(w, http.StatusOK, viewOf(upd))
}

func (m *Module) deleteUser(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	if u.Role.Rank() >= model.RoleAdmin.Rank() && u.ID != a.UserID && !m.stepUp(w, r) { // as demoting them
		return
	}
	if err := m.s.Svc.DeleteUser(r.Context(), a, u.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// removePassword deletes the user's password; they sign in again only through a new invitation.
func (m *Module) removePassword(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	if u.ID != a.UserID && !m.stepUp(w, r) {
		return
	}
	if err := m.s.Svc.RemovePassword(r.Context(), a, u.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// lockOutUser handles POST /users/{id}/lock-out: disables the user and removes every way they had to sign in (a
// compromised account, or a leaver), after a recent re-authentication. See service.LockOutUser.
func (m *Module) lockOutUser(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	if !m.stepUp(w, r) {
		return
	}
	upd, err := m.s.Svc.LockOutUser(r.Context(), a, u.ID, in.Reason)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, viewOf(upd))
}

type inviteResult struct {
	URL       string    `json:"url"`
	Expires   time.Time `json:"expires"`
	Emailed   bool      `json:"emailed"`
	EmailNote string    `json:"email_warning,omitempty"`
}

// issueInvite creates the invitation and, when email is set and the user has an address, sends it. A failed send is
// reported in the result (the link still works); a missing address or disabled mail is the caller's 422 when the
// email was the whole point of the request.
func (m *Module) issueInvite(r *http.Request, org *model.Org, a *service.Actor, u *model.User, email bool) (*inviteResult, error) {
	link, exp, err := m.s.Svc.CreateInvite(r.Context(), a, u.ID)
	if err != nil {
		return nil, err
	}
	res := &inviteResult{URL: link, Expires: exp}
	if email {
		if err := m.Mailer.SendInviteLink(r.Context(), org, u, link, exp); err != nil {
			if errors.Is(err, ErrMailerDisabled) {
				res.EmailNote = "Email is not configured on this server; share the link yourself."
			} else {
				res.EmailNote = "The invitation could not be emailed: " + err.Error() + "."
			}
		} else {
			res.Emailed = true
		}
	}
	return res, nil
}

// inviteUser issues a new invitation link ({"email": true} also mails it) and returns it.
func (m *Module) inviteUser(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	var in struct {
		Email bool `json:"email"`
	}
	if r.ContentLength != 0 && !web.DecodeJSON(w, r, &in) {
		return
	}
	if in.Email && u.Email == "" {
		web.WriteError(w, service.Invalid("email", "this user has no email address"))
		return
	}
	// An accepted invitation replaces every way its user signs in: for a manager or administrator it takes the same
	// re-authentication as removing their password (an API token cannot issue one).
	if u.Role.Privileged() && u.ID != a.UserID && !m.stepUp(w, r) {
		return
	}
	res, err := m.issueInvite(r, org, a, u, in.Email)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, res)
}

func (m *Module) revokeSessions(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	if err := m.s.Svc.RevokeSessions(r.Context(), a, u.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// apiTokenView is a personal API token as administrators see it (never its secret).
type apiTokenView struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Scopes   []string `json:"scopes"`
	Audience []string `json:"audience"`
	// AppScopes are the application scopes the token is narrowed to; empty: its owner's full access.
	AppScopes []string  `json:"app_scopes"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires,omitzero"`
	LastUsed  time.Time `json:"last_used,omitzero"`
}

// listUserTokens handles GET /users/{id}/tokens: the user's personal API tokens, newest first.
func (m *Module) listUserTokens(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	q := listQuery(r)
	q.Sort, q.Desc, q.Search = "created", true, ""
	list, total, err := m.s.Svc.ListUserAPITokens(r.Context(), a, u.ID, q)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	out := make([]apiTokenView, 0, len(list))
	for _, t := range list {
		aud := t.Audience
		if aud == nil {
			aud = []string{}
		}
		as := t.AppScopes
		if as == nil {
			as = []string{}
		}
		out = append(out, apiTokenView{ID: t.ID, Name: t.Name, Scopes: t.Scopes, Audience: aud, AppScopes: as, Created: t.Created,
			Expires: t.Expires, LastUsed: t.LastUsed})
	}
	writeList(w, out, total)
}

// revokeUserToken handles DELETE /users/{id}/tokens/{token}: revokes one of the user's API tokens at once.
func (m *Module) revokeUserToken(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	t, err := m.s.Svc.APITokens.Get(r.Context(), r.PathValue("token"))
	if err != nil || t.UserID != u.ID {
		web.WriteError(w, service.ErrNotFound)
		return
	}
	if err := m.s.Svc.DeleteAPIToken(r.Context(), a, t.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// addEmail handles POST /users/{id}/emails {"address"}: links an address. With email set up it starts unverified and
// its owner is mailed a link (a mistyped address then proves nothing and matches no sign-in); without email nobody
// could verify it, so it counts as verified at once.
func (m *Module) addEmail(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	var in struct {
		Address string `json:"address"`
	}
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	ctx, proceed := m.selfCtx(w, r, a, u, true)
	if !proceed {
		return
	}
	mailOn := m.s.Site.Mail
	upd, err := m.s.Svc.AddLinkedEmail(ctx, a, u.ID, in.Address, !mailOn)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if l, ok := upd.LinkedEmail(in.Address); ok && !l.Verified {
		// The address is linked either way; a failed mail is logged and "Resend link" tries again.
		if err := m.Mailer.SendVerifyAddress(r.Context(), org, upd, l.Address); err != nil {
			m.s.Log.Warn("admin: mailing a verification link", "user", upd.ID, "error", err)
		}
	}
	web.WriteJSON(w, http.StatusCreated, viewOf(upd))
}

// resendEmail handles POST /users/{id}/emails/{address}/verify: mails the user a new verification link for one of
// their unverified addresses (whoever manages them, or the user themselves).
func (m *Module) resendEmail(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	if a.UserID != u.ID && !m.s.Svc.CanManageUser(a, u) {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	if err := m.Mailer.SendVerifyAddress(r.Context(), org, u, r.PathValue("address")); err != nil {
		if errors.Is(err, ErrMailerDisabled) {
			web.WriteJSON(w, http.StatusServiceUnavailable, web.ErrorBody{Error: "Email is not set up on this server."})
			return
		}
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// markEmailVerified handles POST /users/{id}/emails/{address}/mark-verified: marks one of the user's unverified
// addresses verified without the mailed link (service.MarkEmailVerified).
func (m *Module) markEmailVerified(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	upd, err := m.s.Svc.MarkEmailVerified(r.Context(), a, u.ID, r.PathValue("address"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, viewOf(upd))
}

// removeEmail handles DELETE /users/{id}/emails/{address}.
func (m *Module) removeEmail(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	ctx, proceed := m.selfCtx(w, r, a, u, true)
	if !proceed {
		return
	}
	upd, err := m.s.Svc.RemoveLinkedEmail(ctx, a, u.ID, r.PathValue("address"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, viewOf(upd))
}

// primaryEmail handles POST /users/{id}/emails/{address}/primary.
func (m *Module) primaryEmail(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	ctx, proceed := m.selfCtx(w, r, a, u, true)
	if !proceed {
		return
	}
	upd, err := m.s.Svc.MakePrimary(ctx, a, u.ID, r.PathValue("address"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, viewOf(upd))
}

// connectionsUser resolves the user of a connections route: one the actor may manage, or the actor themselves. It
// writes the error response itself.
func (m *Module) connectionsUser(w http.ResponseWriter, r *http.Request) (*model.User, *service.Actor, bool) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return nil, nil, false
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return nil, nil, false
	}
	if a.UserID != u.ID && !m.s.Svc.CanManageUser(a, u) {
		web.WriteError(w, service.ErrForbidden)
		return nil, nil, false
	}
	return u, a, true
}

// stepUp lets a dangerous change go ahead only after a recent re-authentication of the acting browser session
// (signed in or confirmed within the last 5 minutes): deleting an organization, rotating the signing keys, changing
// the primary organization's sign-in settings, making someone an administrator or demoting, disabling or deleting
// one (service.CurbsAdmin), removing another user's password. An
// API token is refused: whoever holds one has not proven anything recently. It writes the response itself; the
// console answers a 403 with field "reauth" with its re-authentication dialog and retries.
func (m *Module) stepUp(w http.ResponseWriter, r *http.Request) bool {
	if web.Session(r) == nil {
		web.WriteJSON(w, http.StatusForbidden, web.ErrorBody{Field: "reauth",
			Error: "This change needs a recent re-authentication in the admin console; an API token cannot make it."})
		return false
	}
	if m.s.Reauthed == nil || !m.s.Reauthed(r) {
		web.WriteReauth(w)
		return false
	}
	return true
}

// selfCtx is the context for a change to u: when u is the actor, the self-service one, after a recent
// re-authentication where reauth asks for it (as the account page does; an API token never has one). It writes the
// error response itself.
func (m *Module) selfCtx(w http.ResponseWriter, r *http.Request, a *service.Actor, u *model.User, reauth bool) (context.Context, bool) {
	if a.UserID != u.ID {
		return r.Context(), true
	}
	if reauth && (m.s.Reauthed == nil || !m.s.Reauthed(r)) {
		web.WriteReauth(w)
		return nil, false
	}
	return service.SelfService(r.Context()), true
}

// listUserApps handles GET /users/{id}/apps: the applications the user granted access to.
func (m *Module) listUserApps(w http.ResponseWriter, r *http.Request) {
	u, _, found := m.connectionsUser(w, r)
	if !found {
		return
	}
	items, err := m.s.Svc.ConnectedApps(r.Context(), u.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// removeUserApp handles DELETE /users/{id}/apps/{client}: ends the user's access to one application (it is told to
// sign them out by back-channel logout, and its refresh tokens stop working).
func (m *Module) removeUserApp(w http.ResponseWriter, r *http.Request) {
	u, a, found := m.connectionsUser(w, r)
	if !found {
		return
	}
	ctx, proceed := m.selfCtx(w, r, a, u, false) // as on the account page, no re-authentication to remove an app
	if !proceed {
		return
	}
	n, err := m.s.Svc.RemoveUserApp(ctx, a, u.ID, r.PathValue("client"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if n == 0 {
		web.WriteError(w, service.ErrNotFound)
		return
	}
	ok(w)
}

// listUserProviders handles GET /users/{id}/providers: the sign-in providers linked to the user.
func (m *Module) listUserProviders(w http.ResponseWriter, r *http.Request) {
	u, _, found := m.connectionsUser(w, r)
	if !found {
		return
	}
	items, err := m.s.Svc.LinkedProviders(r.Context(), u.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// disconnectUserProvider handles DELETE /users/{id}/providers/{provider}: unlinks the user's account at one provider.
func (m *Module) disconnectUserProvider(w http.ResponseWriter, r *http.Request) {
	u, a, found := m.connectionsUser(w, r)
	if !found {
		return
	}
	ctx, proceed := m.selfCtx(w, r, a, u, true)
	if !proceed {
		return
	}
	n, err := m.s.Svc.DisconnectProvider(ctx, a, u.ID, r.PathValue("provider"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if n == 0 {
		web.WriteError(w, service.ErrNotFound)
		return
	}
	ok(w)
}

// passkeyItem is one of a user's passkeys as the management API shows it (never the credential or its public key).
type passkeyItem struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Created        time.Time `json:"created"`
	LastUsed       time.Time `json:"last_used"`
	Transports     []string  `json:"transports"`
	BackupEligible bool      `json:"backup_eligible"`
	BackupState    bool      `json:"backup_state"`
	// Problem says why it cannot sign in: "disabled" (signs of a cloned authenticator) or "unverified" (registered
	// without user verification, which every sign-in now requires). Empty when it works.
	Problem string `json:"problem,omitempty"`
}

// listUserPasskeys handles GET /users/{id}/passkeys: the user's passkeys, oldest first.
func (m *Module) listUserPasskeys(w http.ResponseWriter, r *http.Request) {
	u, a, found := m.connectionsUser(w, r)
	if !found {
		return
	}
	ctx := r.Context()
	if a.UserID == u.ID {
		ctx = service.SelfService(ctx)
	}
	list, err := m.s.Svc.UserPasskeys(ctx, a, u.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	items := make([]passkeyItem, 0, len(list))
	for _, p := range list {
		tr := p.Transports
		if tr == nil {
			tr = []string{}
		}
		problem := ""
		switch {
		case p.Disabled:
			problem = "disabled"
		case !p.UserVerified:
			problem = "unverified"
		}
		items = append(items, passkeyItem{ID: p.ID, Name: p.Name, Created: p.Created, LastUsed: p.LastUsed, Transports: tr,
			BackupEligible: p.BackupEligible, BackupState: p.BackupState, Problem: problem})
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// removeUserPasskey handles DELETE /users/{id}/passkeys/{passkey}: removes one passkey (a lost or replaced device) and
// ends the sessions that signed in with it.
func (m *Module) removeUserPasskey(w http.ResponseWriter, r *http.Request) {
	u, a, found := m.connectionsUser(w, r)
	if !found {
		return
	}
	ctx, proceed := m.selfCtx(w, r, a, u, true)
	if !proceed {
		return
	}
	if _, err := m.s.Svc.RemovePasskey(ctx, a, u.ID, r.PathValue("passkey"), ""); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// sessionItem is one signed-in session of a user, by its handle (web.SessionHandle; never its id).
type sessionItem struct {
	ID        string    `json:"id"`
	Current   bool      `json:"current"` // the session making this request
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"last_seen"`
	Expires   time.Time `json:"expires"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	AMR       []string  `json:"amr"`
}

// listUserSessions handles GET /users/{id}/sessions: the user's live sessions, the current one first, then the most
// recently used.
func (m *Module) listUserSessions(w http.ResponseWriter, r *http.Request) {
	u, _, found := m.connectionsUser(w, r)
	if !found {
		return
	}
	list, err := m.s.Svc.Sessions.All(r.Context(), u.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	cur := ""
	if s := web.Session(r); s != nil {
		cur = s.ID
	}
	now := time.Now()
	items := make([]sessionItem, 0, len(list))
	for _, s := range list {
		if !s.Valid(now) {
			continue
		}
		amr := s.AMR
		if amr == nil {
			amr = []string{}
		}
		items = append(items, sessionItem{ID: web.SessionHandle(s.ID), Current: s.ID == cur, Created: s.Created,
			LastSeen: s.LastSeen, Expires: s.Expires, IP: s.IP, UserAgent: s.UserAgent, AMR: amr})
	}
	slices.SortFunc(items, func(x, y sessionItem) int {
		if x.Current != y.Current {
			if x.Current {
				return -1
			}
			return 1
		}
		return y.LastSeen.Compare(x.LastSeen)
	})
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// revokeUserSession handles DELETE /users/{id}/sessions/{session}: signs the user out of one session (its
// applications are sent back-channel logouts). The session making the request is not ended here: sign out instead.
func (m *Module) revokeUserSession(w http.ResponseWriter, r *http.Request) {
	u, a, found := m.connectionsUser(w, r)
	if !found {
		return
	}
	ctx := r.Context()
	list, err := m.s.Svc.Sessions.All(ctx, u.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	handle := r.PathValue("session")
	for _, s := range list {
		if web.SessionHandle(s.ID) != handle {
			continue
		}
		if cur := web.Session(r); cur != nil && cur.ID == s.ID {
			web.WriteJSON(w, http.StatusConflict, web.ErrorBody{Error: "That is the session you are using. Sign out instead."})
			return
		}
		if err := m.s.Sessions.Delete(ctx, s.ID); err != nil {
			web.WriteError(w, err)
			return
		}
		m.s.Svc.Audit(ctx, a, u.OrgID, "user.session.revoke", u.Username, map[string]string{"ip": s.IP})
		ok(w)
		return
	}
	web.WriteError(w, service.ErrNotFound)
}
