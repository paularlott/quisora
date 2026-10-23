package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

func itoa(n int) string { return strconv.Itoa(n) }

// WorkInput changes a user's work details (the SCIM enterprise extension). Nil fields are left unchanged; "" clears.
type WorkInput struct {
	Title          *string `json:"title"`
	Department     *string `json:"department"`
	Organization   *string `json:"organization"`
	Division       *string `json:"division"`
	CostCenter     *string `json:"cost_center"`
	EmployeeNumber *string `json:"employee_number"`
	ManagerID      *string `json:"manager_id"`
}

// UserInput is the editable part of a user. Nil fields are left unchanged.
type UserInput struct {
	Username   *string     `json:"username"`
	Email      *string     `json:"email"`
	GivenName  *string     `json:"given_name"`
	FamilyName *string     `json:"family_name"`
	Role       *model.Role `json:"role"`
	Active     *bool       `json:"active"`
	ExternalID *string     `json:"external_id"`
	Locale     *string     `json:"locale"`   // BCP 47 language tag; en_US is accepted and stored as en-US; "" clears
	ZoneInfo   *string     `json:"zoneinfo"` // IANA time zone; "" clears
	UserType   *string     `json:"user_type"`
	// ValidUntil ends the account: RFC 3339 time or a date (YYYY-MM-DD, ends at the start of that day UTC); "" = no end.
	ValidUntil *string    `json:"valid_until"`
	Work       *WorkInput `json:"work"`
	Password   *string    `json:"password"`
	// PasswordHash imports a password hash from another system when a user is created (never on an update): bcrypt
	// (cost 4 to 14) or argon2id. The system, or super admins (an API token needs the import scope). The first sign-in
	// re-hashes it with today's argon2id (passwords.go).
	PasswordHash *string `json:"password_hash"`
	Verified     *bool   `json:"email_verified"`
	// Phone is a contact number: spaces, dots, dashes and brackets are dropped and the rest must be E.164 (+ and
	// the country code); "" clears. A new number is unverified unless PhoneVerified says otherwise.
	Phone         *string   `json:"phone_number"`
	PhoneVerified *bool     `json:"phone_number_verified"`
	Tags          *[]string `json:"tags"`
	// StatusReason is recorded with the account being disabled or enabled again by this change (ignored otherwise).
	StatusReason *string `json:"status_reason"`
	// LinkedEmails replaces the user's verified linked addresses (set by administrators and provisioning clients,
	// never by users themselves: see setLinked); the user's own unverified addresses are kept as they are. Nil leaves
	// them unchanged.
	LinkedEmails *[]string `json:"-"`
}

// applyTags validates and normalizes (deduplicated, sorted) the tags in in and stores them in dst; nil leaves dst
// unchanged.
func applyTags(dst *[]string, in *[]string) error {
	if in == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(*in))
	out := make([]string, 0, len(*in))
	for _, t := range *in {
		if !model.ValidTag(t) {
			return Invalid("tags", strconv.Quote(t)+" is not a valid tag: use letters, digits and . _ : / - "+
				"(1–64 characters, starting and ending with a letter or digit)")
		}
		if _, dup := seen[t]; !dup {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	if len(out) > model.MaxTags {
		return Invalid("tags", "at most "+itoa(model.MaxTags)+" tags are allowed")
	}
	*dst = model.NormTags(out)
	return nil
}

var usernameRe = regexp.MustCompile(`^[\p{L}\p{N}._@+-]{1,128}$`)

// MinPasswordLength is the shortest password accepted.
const MinPasswordLength = 10

// ValidatePassword checks a new password against the policy.
func ValidatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLength {
		return Invalid("password", "must be at least "+itoa(MinPasswordLength)+" characters")
	}
	if len(pw) > 1024 {
		return Invalid("password", "is too long")
	}
	return nil
}

func normEmail(e string) (string, error) {
	e = strings.TrimSpace(e)
	if e == "" {
		return "", Invalid("email", "is required")
	}
	if len(e) > 254 {
		return "", Invalid("email", "is too long")
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || !strings.Contains(e, "@") {
		return "", Invalid("email", "is not a valid email address")
	}
	return e, nil
}

// apply copies in onto u, validating each field. Role changes are checked by the caller.
func (s *Service) apply(ctx context.Context, u *model.User, in UserInput) error {
	if in.Username != nil {
		v := strings.TrimSpace(*in.Username)
		switch {
		case v == "":
			u.Username = "" // defaults to the email below
		case !usernameRe.MatchString(v):
			return Invalid("username", "use 1–128 letters, digits and . _ @ + -")
		default:
			u.Username = v
		}
	}
	if in.Email != nil {
		v, err := normEmail(*in.Email)
		if err != nil {
			return err
		}
		if !strings.EqualFold(v, u.Email) {
			u.EmailVerified = false
		}
		u.Email = v
	}
	if u.Email == "" {
		return Invalid("email", "is required")
	}
	if in.LinkedEmails != nil {
		if err := setLinked(u, *in.LinkedEmails); err != nil {
			return err
		}
	}
	// The primary address can never also be linked (a linked address that becomes the primary is promoted).
	u.LinkedEmails = slices.DeleteFunc(u.LinkedEmails, func(l model.LinkedEmail) bool { return strings.EqualFold(l.Address, u.Email) })
	if u.Username == "" {
		u.Username = u.Email // the username is optional; it defaults to the email address
	}
	if in.Verified != nil {
		u.EmailVerified = *in.Verified
	}
	trim := func(p *string, max int, field string, dst *string) error {
		if p == nil {
			return nil
		}
		v := strings.TrimSpace(*p)
		if utf8.RuneCountInString(v) > max {
			return Invalid(field, "is too long")
		}
		*dst = v
		return nil
	}
	for _, f := range []struct {
		p     *string
		max   int
		field string
		dst   *string
	}{
		{in.GivenName, 100, "given_name", &u.GivenName},
		{in.FamilyName, 100, "family_name", &u.FamilyName}, {in.ExternalID, 255, "external_id", &u.ExternalID},
		{in.UserType, 64, "user_type", &u.UserType},
	} {
		if err := trim(f.p, f.max, f.field, f.dst); err != nil {
			return err
		}
	}
	if in.Locale != nil {
		v, ok := model.NormalizeLocale(*in.Locale)
		if !ok {
			return Invalid("locale", "choose a language from the list, or a language tag such as en-GB")
		}
		u.Locale = v
	}
	if in.ZoneInfo != nil {
		v := strings.TrimSpace(*in.ZoneInfo)
		if !model.ValidTimeZone(v) {
			return Invalid("zoneinfo", "choose a time zone from the list, such as Europe/London")
		}
		u.ZoneInfo = v
	}
	if in.ValidUntil != nil {
		v := strings.TrimSpace(*in.ValidUntil)
		if v == "" {
			u.ValidUntil = nil
		} else {
			t, err := parseEndDate(v)
			if err != nil {
				return Invalid("valid_until", "use a date (YYYY-MM-DD) or an RFC 3339 time, or leave it empty for no end")
			}
			u.ValidUntil = &t
		}
	}
	if in.Work != nil {
		w := in.Work
		for _, f := range []struct {
			p     *string
			field string
			dst   *string
		}{
			{w.Title, "work.title", &u.Work.Title}, {w.Department, "work.department", &u.Work.Department},
			{w.Organization, "work.organization", &u.Work.Organization}, {w.Division, "work.division", &u.Work.Division},
			{w.CostCenter, "work.cost_center", &u.Work.CostCenter},
			{w.EmployeeNumber, "work.employee_number", &u.Work.EmployeeNumber},
		} {
			if err := trim(f.p, 255, f.field, f.dst); err != nil {
				return err
			}
		}
		if w.ManagerID != nil {
			if err := s.setManager(ctx, u, strings.TrimSpace(*w.ManagerID)); err != nil {
				return err
			}
		}
	}
	if in.Phone != nil {
		p, err := NormalizePhone(*in.Phone)
		if err != nil {
			return err
		}
		if p != u.PhoneNumber {
			u.PhoneNumber, u.PhoneVerified = p, false
		}
	}
	if in.PhoneVerified != nil {
		u.PhoneVerified = *in.PhoneVerified && u.PhoneNumber != ""
	}
	if in.Active != nil {
		u.Active = *in.Active
	}
	if err := applyTags(&u.Tags, in.Tags); err != nil {
		return err
	}
	if u.GivenName == "" {
		return Invalid("given_name", "is required")
	}
	if in.PasswordHash != nil {
		return Invalid("password_hash", "a password hash is imported only when the user is created")
	}
	if in.Password != nil {
		if err := s.CheckPassword(ctx, u, *in.Password); err != nil {
			return err
		}
		h, err := s.HashPassword(ctx, u.ID, *in.Password)
		if err != nil {
			return err
		}
		u.PasswordHash = h
		now := time.Now().UTC()
		u.PasswordChangedAt = &now
	}
	return nil
}

var phoneRE = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// NormalizePhone returns a phone number in E.164 form: separators (spaces, dots, dashes, brackets) are dropped and
// what is left must be + and 7 to 15 digits. "" stays "".
func NormalizePhone(s string) (string, error) {
	p := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '.', '-', '(', ')', '\u00a0':
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if p == "" {
		return "", nil
	}
	if !phoneRE.MatchString(p) {
		return "", Invalid("phone_number", "enter the number in international form, starting with + and the country code")
	}
	return p, nil
}

// noteStatus records an account being disabled or enabled again by a.
func noteStatus(u *model.User, a *Actor, reason string) {
	id := a.UserID
	if id == "" {
		id = a.ClientID
	}
	u.StatusChanged = &model.StatusChange{At: time.Now().UTC(), By: a.Name, ByID: id, Reason: reason}
}

// GetUser returns a user the actor may see: anyone in their own org with a manager+ role, any user for super
// admins, and themselves.
func (s *Service) GetUser(ctx context.Context, a *Actor, id string) (*model.User, error) {
	u, err := s.Users.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	if a != nil && a.UserID != id && !s.canManageUsers(a, u.OrgID) {
		return nil, ErrNotFound
	}
	switch s.Visibility(a, u) {
	case Hidden:
		return nil, ErrNotFound
	case Directory:
		return DirectoryEntry(u), nil
	}
	s.WithSignIn(ctx, u)
	return u, nil
}

// ListUsers lists users of an org, with their last sign-in. Sorting by "last_login" (kept on the users' sign-in
// records, not on the users) loads the organization's users and sorts them in memory, like ListUsersTagged.
func (s *Service) ListUsers(ctx context.Context, a *Actor, orgID string, q store.ListQuery) ([]*model.User, int, error) {
	if !s.canManageUsers(a, orgID) {
		return nil, 0, ErrForbidden
	}
	q.Scope = orgID
	q = visibleQuery(a, q)
	if q.Sort == "last_login" {
		return s.listByLastLogin(ctx, a, q)
	}
	leaks, err := s.searchLeaks(ctx, a, q)
	if err != nil {
		return nil, 0, err
	}
	if q.Sort != "" && !directorySortable[q.Sort] {
		// The store orders on the stored value, which a directory entry does not show: the row's place would.
		unseen, err := s.NotSeenInFull(ctx, a, q.Scope)
		if err != nil {
			return nil, 0, err
		}
		if len(unseen) > 0 {
			return s.listByPresented(ctx, a, q, leaks)
		}
	}
	l, n, err := s.Users.List(ctx, q)
	if err != nil {
		return nil, 0, mapStore(err)
	}
	if len(leaks) > 0 {
		// each is in the full result set: the total loses them all; this page, those it holds
		l = slices.DeleteFunc(l, func(u *model.User) bool { return leaks[u.ID] })
		n -= len(leaks)
	}
	s.WithSignIn(ctx, l...)
	return s.present(a, l), n, nil
}

// directorySortable are the sort fields a directory entry keeps: sorting on them orders every row on what it shows.
var directorySortable = map[string]bool{"name": true, "role": true, "active": true, "created": true}

// listByPresented is ListUsers sorted on a field directory entries blank (username, email, department...) for a
// caller who sees some users only as directory entries: the matches are loaded, presented and sorted in memory on the
// values as shown, as the store would sort them, so a directory entry sorts on "" and its place reveals nothing.
func (s *Service) listByPresented(ctx context.Context, a *Actor, q store.ListQuery, leaks map[string]bool) ([]*model.User, int, error) {
	if err := store.ValidateQuery(model.KindUser, q); err != nil {
		return nil, 0, mapStore(err)
	}
	offset, limit, field, desc := q.Offset, q.Limit, q.Sort, q.Desc
	q.Sort, q.Desc, q.Offset, q.Limit = "", false, 0, 0
	all, _, err := s.Users.List(ctx, q)
	if err != nil {
		return nil, 0, mapStore(err)
	}
	all = slices.DeleteFunc(all, func(u *model.User) bool { return leaks[u.ID] })
	s.WithSignIn(ctx, all...)
	all = s.present(a, all)
	key := make(map[string]any, len(all))
	for _, u := range all {
		key[u.ID] = u.Index().Fields[field]
	}
	slices.SortStableFunc(all, func(x, y *model.User) int {
		c := store.CompareValues(key[x.ID], key[y.ID])
		if desc {
			c = -c
		}
		if c == 0 {
			c = strings.Compare(x.ID, y.ID)
		}
		return c
	})
	total := len(all)
	all = all[min(max(offset, 0), total):]
	if limit > 0 && limit < len(all) {
		all = all[:limit]
	}
	return all, total, nil
}

// ListUsersTagged lists the users of an org carrying exactly the tag (the store cannot filter inside a list, so the
// org's matches are filtered in memory — organizations hold on the order of a thousand users — then paged).
func (s *Service) ListUsersTagged(ctx context.Context, a *Actor, orgID string, q store.ListQuery, tag string) ([]*model.User, int, error) {
	if !s.canManageUsers(a, orgID) {
		return nil, 0, ErrForbidden
	}
	offset, limit := q.Offset, q.Limit
	byLogin, desc := q.Sort == "last_login", q.Desc
	if byLogin {
		q.Sort, q.Desc = "", false
	}
	q.Scope, q.Offset, q.Limit = orgID, 0, 0
	q = visibleQuery(a, q)
	all, _, err := s.Users.List(ctx, q)
	if err != nil {
		return nil, 0, mapStore(err)
	}
	out := all[:0]
	for _, u := range all {
		// the tags of someone a sees only as a directory entry are not theirs to see: no match on them either
		if slices.Contains(u.Tags, tag) && s.Visibility(a, u) == Full {
			out = append(out, u)
		}
	}
	s.WithSignIn(ctx, out...)
	if byLogin {
		sortByLastLogin(out, desc)
	}
	total := len(out)
	out = out[min(offset, total):]
	if limit > 0 && limit < len(out) {
		out = out[:limit]
	}
	return out, total, nil
}

// CreateUser creates a user in orgID.
func (s *Service) CreateUser(ctx context.Context, a *Actor, orgID string, in UserInput) (*model.User, error) {
	if !s.canManageUsers(a, orgID) {
		return nil, ErrForbidden
	}
	org, err := s.Orgs.Get(ctx, orgID)
	if err != nil {
		return nil, mapStore(err)
	}
	role := model.RoleUser
	if in.Role != nil {
		role = *in.Role
	}
	if !role.Valid() {
		return nil, Invalid("role", "unknown role")
	}
	if !s.canAssignRole(ctx, a, org, role) {
		return nil, ErrForbidden
	}
	if in.Password != nil && a != System {
		return nil, Invalid("password", "passwords are set by the user through their invitation link")
	}
	u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: orgID, Role: role, Active: true}
	if in.Email == nil || strings.TrimSpace(*in.Email) == "" {
		return nil, Invalid("email", "is required")
	}
	imported := ""
	if in.PasswordHash != nil {
		// Setting a hash is setting a password someone may know: only the system and super admins, and a token only
		// with the import scope, for a new user (an existing account could otherwise be taken over).
		if a != System && !(a.IsSuper() && a.HasScope(ScopeImport)) {
			return nil, Invalid("password_hash", "only super admins import password hashes (an API token needs the import scope)")
		}
		if in.Password != nil {
			return nil, Invalid("password_hash", "give a password or a password hash, not both")
		}
		kind, err := secure.CheckImport(*in.PasswordHash)
		if err != nil {
			return nil, Invalid("password_hash", "must be a bcrypt hash (cost 4 to 14) or an argon2id hash")
		}
		imported = kind
		u.PasswordHash = s.SealPasswordHash(u.ID, *in.PasswordHash)
		in.PasswordHash = nil // apply refuses it (updates never take one)
	}
	if err := s.apply(ctx, u, in); err != nil {
		return nil, err
	}
	if err := s.Users.Create(ctx, u); err != nil {
		return nil, s.userConflict(ctx, err, u)
	}
	detail := map[string]string{"role": string(role)}
	if len(u.Tags) > 0 {
		detail["tags"] = strings.Join(u.Tags, " ")
	}
	if imported != "" {
		detail["password"] = "imported " + imported
	}
	s.Audit(ctx, a, orgID, "user.create", u.Username, detail)
	return u, nil
}

// userConflict turns a unique clash into a field error naming the clashing field.
func (s *Service) userConflict(ctx context.Context, err error, u *model.User) error {
	if !errors.Is(err, store.ErrConflict) {
		return mapStore(err)
	}
	if o, e := s.Users.GetByUnique(ctx, model.UserUsernameKey(u.OrgID, u.Username)); e == nil && o.ID != u.ID {
		return &conflictErr{Invalid("username", "is already in use")}
	}
	for _, addr := range append([]string{u.Email}, linkedAddrs(u)...) {
		if o, e := s.Users.GetByUnique(ctx, model.UserEmailKey(u.OrgID, addr)); e == nil && o.ID != u.ID {
			return &conflictErr{Invalid("email", addr+" is already in use")}
		}
	}
	return &conflictErr{Invalid("external_id", "is already in use")}
}

// conflictErr is a field error that also matches ErrConflict.
type conflictErr struct{ error }

func (e *conflictErr) Is(target error) bool {
	return target == ErrConflict || errors.Is(e.error, target)
}
func (e *conflictErr) Unwrap() error { return e.error }

// UpdateUser changes a user. Users may change their own profile fields but not role, active, external id or
// verified state.
func (s *Service) UpdateUser(ctx context.Context, a *Actor, id string, in UserInput) (*model.User, error) {
	before, err := s.Users.Get(ctx, id)
	if err != nil || before.Role != model.RoleSuperAdmin || (in.Role == nil && in.Active == nil && in.ValidUntil == nil) {
		return s.updateUser(ctx, a, id, in)
	}
	// A change that can remove a super admin holds the primary organization's admin lock (cluster-wide), and its
	// last-super-admin check counts from a quorum's copies: two such changes on two nodes can never both pass it.
	unlock, err := s.lockAdmins(ctx, before.OrgID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.updateUser(ctx, a, id, in)
}

// dropUnchanged clears the fields of in that equal u's, so a form saving the whole record changes only what differs
// (the rules about changing yourself then see only real changes).
func dropUnchanged(u *model.User, in *UserInput) {
	same := func(p *string, cur string) bool { return p == nil || strings.TrimSpace(*p) == cur }
	if in.Username != nil && strings.EqualFold(strings.TrimSpace(*in.Username), u.Username) {
		in.Username = nil
	}
	if in.Role != nil && *in.Role == u.Role {
		in.Role = nil
	}
	if in.Active != nil && *in.Active == u.Active {
		in.Active = nil
	}
	if in.ExternalID != nil && same(in.ExternalID, u.ExternalID) {
		in.ExternalID = nil
	}
	if in.Verified != nil && *in.Verified == u.EmailVerified {
		in.Verified = nil
	}
	if in.PhoneVerified != nil && *in.PhoneVerified == u.PhoneVerified {
		in.PhoneVerified = nil
	}
	if in.Tags != nil {
		a, b := slices.Clone(*in.Tags), slices.Clone(u.Tags)
		slices.Sort(a)
		slices.Sort(b)
		if slices.Equal(a, b) {
			in.Tags = nil
		}
	}
	if in.UserType != nil && strings.EqualFold(strings.TrimSpace(*in.UserType), u.UserType) {
		in.UserType = nil
	}
	if w := in.Work; w != nil && same(w.Title, u.Work.Title) && same(w.Department, u.Work.Department) &&
		same(w.Organization, u.Work.Organization) && same(w.Division, u.Work.Division) &&
		same(w.CostCenter, u.Work.CostCenter) && same(w.EmployeeNumber, u.Work.EmployeeNumber) &&
		same(w.ManagerID, u.Work.ManagerID) {
		in.Work = nil
	}
	if in.ValidUntil != nil {
		v := strings.TrimSpace(*in.ValidUntil)
		switch {
		case v == "" && u.ValidUntil == nil:
			in.ValidUntil = nil
		case v != "" && u.ValidUntil != nil:
			// the form shows the end as a date: the same day is the same end
			if t, err := parseEndDate(v); err == nil && t.UTC().Format(time.DateOnly) == u.ValidUntil.UTC().Format(time.DateOnly) {
				in.ValidUntil = nil
			}
		}
	}
}

func isAdminRank(u *model.User) bool {
	return u.Role == model.RoleAdmin || u.Role == model.RoleSuperAdmin
}

func (s *Service) updateUser(ctx context.Context, a *Actor, id string, in UserInput) (*model.User, error) {
	u, err := s.Users.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	self := a.UserID == id
	if self {
		dropUnchanged(u, &in) // a form saving yourself sends every field: only what differs is a change
	}
	if !s.canManageUser(a, u) {
		if !self {
			return nil, s.denied(a, u)
		}
		if in.Role != nil || in.Active != nil || in.ExternalID != nil || in.Verified != nil || in.Username != nil ||
			in.Tags != nil || in.LinkedEmails != nil || in.PhoneVerified != nil {
			return nil, ErrForbidden
		}
	}
	if !self && in.Password != nil && a != System {
		return nil, Invalid("password", "remove the password or send a new invitation; users choose their own passwords")
	}
	if self && in.LinkedEmails != nil {
		return nil, ErrForbidden // own linked addresses change through AddLinkedEmail / RemoveLinkedEmail
	}
	if self && !isSelfService(ctx) {
		// Own credentials change only through the account page, which verifies the current password or a recent
		// re-authentication; the management API (sessions or tokens) must not be a shortcut around that.
		if in.Password != nil {
			return nil, Invalid("password", "change your own password from your account page")
		}
	}
	if !self && in.Email != nil && !strings.EqualFold(strings.TrimSpace(*in.Email), u.Email) {
		// Password resets go to the primary address: whoever sets a manager's or administrator's could reset their
		// password, so for an established privileged account that is a sign-in reset (super admins only).
		if err := s.mayResetSignIn(ctx, a, u, "email"); err != nil {
			return nil, err
		}
	}
	if self && a != System && in.Email != nil && !strings.EqualFold(strings.TrimSpace(*in.Email), u.Email) {
		// The primary address is what password sign-in, resets and every application's email claim use: someone
		// else sets it (a manager or administrator, or SCIM), whatever the user's own role; the user can only make one
		// of their verified addresses primary.
		return nil, Invalid("email", "is changed by another manager or administrator, not by yourself")
	}
	if self && a != System && ((in.Verified != nil && *in.Verified && !u.EmailVerified) ||
		(in.PhoneVerified != nil && *in.PhoneVerified && !u.PhoneVerified)) {
		// Applications trust these claims: your own address or number is verified only by proving you receive it.
		return nil, Invalid("email_verified", "your own email address is verified by the link mailed to it, not by marking it")
	}
	if !self && in.Verified != nil && *in.Verified && !u.EmailVerified && (in.Email == nil || strings.EqualFold(strings.TrimSpace(*in.Email), u.Email)) {
		// A verified address links sign-ins from providers to the account, as changing it does (just above).
		if err := s.mayResetSignIn(ctx, a, u, "email_verified"); err != nil {
			return nil, err
		}
	}
	if self && ((in.Role != nil && *in.Role != u.Role) || (in.Active != nil && !*in.Active)) {
		return nil, Invalid("role", "you cannot change your own role or disable yourself")
	}
	if self && (in.ValidUntil != nil || in.UserType != nil || in.Work != nil) && a != System && !a.IsSuper() {
		// Applications may trust these (a department, a manager): someone above you sets them. Super admins have
		// nobody above them.
		return nil, Invalid("work", "your work details, user type and end date are set by an administrator")
	}
	if self && (in.Tags != nil || in.Username != nil || in.ExternalID != nil) && a != System && !a.IsSuper() {
		// The same for the tags and username every application receives and the id provisioning matches on. Users
		// and managers were refused above (they cannot manage themselves); this catches an administrator, who can.
		return nil, ErrForbidden
	}
	critical := in.Password != nil || (in.Active != nil && *in.Active != u.Active) || in.ValidUntil != nil
	before := u.Role
	was := snapshot(u)
	if in.Role != nil && *in.Role != u.Role {
		org, err := s.Orgs.Get(ctx, u.OrgID)
		if err != nil {
			return nil, mapStore(err)
		}
		if !in.Role.Valid() {
			return nil, Invalid("role", "unknown role")
		}
		if !s.canAssignRole(ctx, a, org, *in.Role) {
			return nil, ErrForbidden
		}
		if privileged(u) && in.Role.Rank() < u.Role.Rank() && a != System && !a.IsSuper() {
			return nil, Invalid("role", "only a super admin can lower the role of a manager or administrator")
		}
		// Only a lower role can take administration away: a promotion never needs the guard.
		if in.Role.Rank() < u.Role.Rank() {
			if err := s.guardLastAdmin(ctx, u); err != nil {
				return nil, err
			}
		}
		u.Role = *in.Role
		critical = true
	}
	if in.Active != nil && !*in.Active && u.Active {
		if err := s.guardLastAdmin(ctx, u); err != nil {
			return nil, err
		}
	}
	if in.ValidUntil != nil {
		if err := s.guardEndDate(ctx, u, *in.ValidUntil); err != nil {
			return nil, err
		}
	}
	statusChange := in.Active != nil && *in.Active != u.Active
	reason := ""
	if in.StatusReason != nil {
		reason = strings.TrimSpace(*in.StatusReason)
		if len(reason) > model.MaxStatusReason {
			return nil, Invalid("status_reason", "at most "+strconv.Itoa(model.MaxStatusReason)+" characters")
		}
	}
	if err := s.apply(ctx, u, in); err != nil {
		return nil, err
	}
	if statusChange {
		noteStatus(u, a, reason)
	}
	if critical {
		ctx = Durable(ctx)
	}
	err = s.Users.Update(ctx, u)
	if !store.Applied(err) {
		return nil, s.userConflict(ctx, err, u)
	}
	// From here the change is in effect (perhaps not yet confirmed by a peer): what follows from it happens anyway.
	var sessErr error
	if in.Active != nil && !*in.Active || in.Password != nil || in.ValidUntil != nil && !u.Enabled(time.Now()) {
		// Disabling, an end date that has passed, or a password reset ends existing sessions and refresh grants
		// (except the actor's own). A failure is logged and noted in the audit entry; the change itself stands.
		sessErr = s.endUserSessions(ctx, u.ID, a)
	}
	if before.Rank() < model.RoleManager.Rank() && u.Role.Rank() >= model.RoleManager.Rank() {
		s.dropEmailLinks(ctx, a, u)
	}
	action := "user.update"
	if in.Password != nil {
		action = "user.password"
	}
	detail := map[string]string{}
	if in.Tags != nil {
		detail["tags"] = strings.Join(u.Tags, " ")
	}
	if statusChange {
		detail["active"] = strconv.FormatBool(u.Active)
		if reason != "" {
			detail["reason"] = reason
		}
	}
	if sessErr != nil {
		detail["sessions"] = "not all ended: " + sessErr.Error()
	}
	detail = addChanges(detail, was, u)
	s.Audit(ctx, a, u.OrgID, action, u.Username, detail)
	if err != nil {
		return nil, mapStore(err)
	}
	return u, nil
}

// guardLastAdmin refuses to demote, disable, delete or end-date a super admin when fewer than MinSuperAdmins usable
// super admins would remain (one, or two in a gossip cluster). A usable super admin is active and not past their end
// date. One without an end date may only stop being one while enough others without an end date remain: otherwise end
// dates set on each other would leave none once the last one passes. Organizations need no administrator: super admins
// administer every one of them. The caller holds the primary organization's admin lock (lockAdmins).
func (s *Service) guardLastAdmin(ctx context.Context, u *model.User) error {
	now := time.Now()
	if u.Role != model.RoleSuperAdmin || !u.Enabled(now) {
		return nil // not a usable super admin: removing them takes nothing away
	}
	need := max(s.MinSuperAdmins, 1)
	supers, err := s.usableAdmins(ctx, u.OrgID, model.RoleSuperAdmin)
	if err != nil {
		return err
	}
	others, lasting := 0, 0
	for _, o := range supers {
		if o.ID == u.ID {
			continue
		}
		others++
		if o.ValidUntil == nil {
			lasting++
		}
	}
	if others < need || (u.ValidUntil == nil && lasting < need) {
		return lastSuperAdminErr{need}
	}
	return nil
}

// lastSuperAdminErr is ErrLastAdmin saying how many super admins the server keeps.
type lastSuperAdminErr struct{ need int }

func (e lastSuperAdminErr) Error() string {
	if e.need > 1 {
		return "a gossip cluster keeps at least " + strconv.Itoa(e.need) + " super admins (a change one server made but the others have not confirmed must never leave none): make someone else a super admin first"
	}
	return "this is the last super admin: make someone else a super admin first"
}

func (e lastSuperAdminErr) Is(target error) bool { return target == ErrLastAdmin }

// guardEndDate applies guardLastAdmin to a change of u's end date to v (the UserInput value: "" clears it). Clearing
// an end date, or moving it later, never removes a super admin.
func (s *Service) guardEndDate(ctx context.Context, u *model.User, v string) error {
	if u.Role != model.RoleSuperAdmin {
		return nil
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	end, err := parseEndDate(v)
	if err != nil {
		return nil // apply reports the invalid value
	}
	if u.ValidUntil != nil && !end.Before(*u.ValidUntil) {
		return nil
	}
	return s.guardLastAdmin(ctx, u)
}

// parseEndDate reads an end date: an RFC 3339 time or a date (YYYY-MM-DD, the start of that day UTC).
func parseEndDate(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		if t, err = time.Parse(time.DateOnly, v); err != nil {
			return time.Time{}, err
		}
	}
	return t.UTC(), nil
}

// DeleteUser deletes a user and everything that belongs to them.
func (s *Service) DeleteUser(ctx context.Context, a *Actor, id string) error {
	u, err := s.Users.Get(ctx, id)
	if err != nil {
		return mapStore(err)
	}
	if u.Role == model.RoleSuperAdmin {
		unlock, err := s.lockAdmins(ctx, u.OrgID)
		if err != nil {
			return err
		}
		defer unlock()
	}
	if a.UserID == id {
		return Invalid("user", "you cannot delete yourself")
	}
	if !s.canManageUser(a, u) {
		return s.denied(a, u) // not found for users a may not see (other organizations, super admins)
	}
	if err := s.guardLastAdmin(ctx, u); err != nil {
		return err
	}
	// The user goes first, and only as the copy every check above was made on: a copy that is not the newest (one
	// read on a node that has not seen the user's promotion to administrator yet, so neither the admin lock nor the
	// last-admin check applied) is refused, instead of deleting an administrator unchecked. What belonged to them
	// follows.
	if err := s.Users.DeleteIf(Durable(ctx), u.ID, u.Version); !store.Applied(err) {
		// Refused (a newer copy), or not confirmed by a majority: the user may still exist, so nothing of theirs is
		// removed; a retry decides.
		return mapStore(err)
	}
	// The user is gone: what belonged to them goes too. That is best effort (a session or token of a deleted user
	// works nowhere, as every use looks the user up), so a failure here is logged and does not undo or hide the
	// deletion, which is audited either way.
	if err := s.deleteUserData(Durable(ctx), u); err != nil {
		s.Log.Error("user deleted; some of their records were not removed", "user", u.ID, "error", err)
	}
	s.Audit(ctx, a, u.OrgID, "user.delete", u.Username, nil)
	return nil
}

func (s *Service) deleteUserData(ctx context.Context, u *model.User) error {
	s.sessionsEnding(ctx, u.ID, nil)
	for _, k := range []model.Kind{model.KindSession, model.KindGrant, model.KindPasskey, model.KindIdentity,
		model.KindAPIToken} {
		res, err := s.Store.List(ctx, k, store.ListQuery{Scope: u.ID})
		if err != nil {
			return err
		}
		for _, r := range res.Records {
			if err := s.Store.Put(ctx, store.Tombstone(k, r.ID)); err != nil && !errors.Is(err, store.ErrStale) {
				return err
			}
		}
	}
	ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
	if err != nil {
		return err
	}
	for _, m := range ms {
		_ = s.Members.Delete(ctx, m.ID)
	}
	if err := s.SignIns.Delete(ctx, u.ID); err != nil && !store.Applied(err) && !errors.Is(err, store.ErrStale) {
		return mapStore(err)
	}
	s.deleteAccessWhere(ctx, u.OrgID, "subject_id", u.ID)
	s.clearManagerOf(ctx, u)
	return mapStore(s.Users.Delete(ctx, u.ID))
}

// ResetCredentials leaves a user with no way in but what an accepted invitation is about to set: every session and
// refresh grant ends (relying parties are told), and every passkey but keepPasskey, connected provider, API token,
// the authenticator app and the password go. Re-inviting a compromised account therefore evicts whoever had it.
func (s *Service) ResetCredentials(ctx context.Context, userID, keepPasskey string) error {
	ctx = Durable(ctx)
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return mapStore(err)
	}
	sessErr := s.endUserSessions(ctx, userID, nil)
	// Every credential is removed even when one removal fails (a failure must not leave the rest in place); the
	// errors are reported together at the end. A write that is applied but not yet confirmed by a peer is no failure.
	var errs []error
	fail := func(err error) {
		if !store.Applied(err) {
			errs = append(errs, err)
		}
	}
	fail(sessErr)
	for _, k := range []model.Kind{model.KindPasskey, model.KindIdentity, model.KindAPIToken} {
		res, err := s.Store.List(ctx, k, store.ListQuery{Scope: userID})
		if err != nil {
			fail(err)
			continue
		}
		for _, r := range res.Records {
			if k == model.KindPasskey && r.ID == keepPasskey {
				continue
			}
			if err := s.Store.Put(ctx, store.Tombstone(k, r.ID)); !errors.Is(err, store.ErrStale) {
				fail(err)
			}
		}
	}
	// The user record is cleared last, re-read and retried when a concurrent change (a profile edit, a sign-in's
	// last-login stamp) got there first: that change must not keep the old password or authenticator app.
	for attempt := 0; ; attempt++ {
		if u.PasswordHash != "" {
			now := time.Now().UTC()
			u.PasswordChangedAt = &now
		}
		u.PasswordHash, u.TOTPSecret, u.MFAEnrolledAt = "", "", nil
		err := s.Users.Update(ctx, u)
		if !errors.Is(err, store.ErrStale) || attempt == 9 {
			fail(err)
			break
		}
		if u, err = s.Users.Get(ctx, userID); err != nil {
			fail(err)
			break
		}
	}
	return mapStore(errors.Join(errs...))
}

// endUserSessions tombstones a user's sessions and refresh grants, except those of the acting session's user when
// they act on themselves (a password change keeps the current session, handled by the caller). Every one is tried
// even when one fails; the failures are returned together (a deletion applied here but not yet confirmed by a peer
// is no failure). A failure is logged here too: the callers' change stands, and the sessions of a disabled user stop
// working anyway (every use checks the user).
func (s *Service) endUserSessions(ctx context.Context, userID string, a *Actor) error {
	if a != nil && a.UserID == userID {
		return nil
	}
	s.sessionsEnding(ctx, userID, nil)
	var errs []error
	for _, k := range []model.Kind{model.KindSession, model.KindGrant} {
		res, err := s.Store.List(ctx, k, store.ListQuery{Scope: userID})
		if err != nil {
			errs = append(errs, fmt.Errorf("list %s: %w", k, err))
			continue
		}
		for _, r := range res.Records {
			if err := s.Store.Put(Durable(ctx), store.Tombstone(k, r.ID)); !store.Applied(err) && !errors.Is(err, store.ErrStale) {
				errs = append(errs, fmt.Errorf("end %s %s: %w", k, r.ID, err))
			}
		}
	}
	err := errors.Join(errs...)
	if err != nil {
		s.Log.WithError(err).Error("not every session and refresh grant of the user could be ended", "user", userID)
	}
	return err
}

// RevokeAppAccess removes everything a user granted one application (the account page's "remove access"): its
// refresh grants and remembered consent, once the OnAppAccessEnding hook has told the application to sign the user
// out (back-channel logout). It returns how many grants it removed; 0 means the user had granted that application
// nothing.
func (s *Service) RevokeAppAccess(ctx context.Context, userID, clientID string) (int, error) {
	grants, err := s.Grants.All(ctx, userID)
	if err != nil {
		return 0, err
	}
	var mine []*model.Grant
	for _, g := range grants {
		if g.ClientID == clientID {
			mine = append(mine, g)
		}
	}
	if len(mine) == 0 {
		return 0, nil
	}
	if s.OnAppAccessEnding != nil {
		s.OnAppAccessEnding(ctx, userID, clientID)
	}
	for _, g := range mine {
		if err := s.Grants.Delete(Durable(ctx), g.ID); err != nil {
			return 0, err
		}
	}
	return len(mine), nil
}

// RevokeSessions ends every session and refresh grant of a user (admin action or "sign out everywhere").
func (s *Service) RevokeSessions(ctx context.Context, a *Actor, userID string) error {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return mapStore(err)
	}
	if a.UserID != userID && !s.canManageUser(a, u) {
		return s.denied(a, u)
	}
	if err := s.endUserSessions(ctx, userID, nil); err != nil {
		s.Audit(ctx, a, u.OrgID, "user.sessions.revoke", u.Username, map[string]string{"result": "incomplete",
			"error": err.Error()})
		return mapStore(err)
	}
	s.Audit(ctx, a, u.OrgID, "user.sessions.revoke", u.Username, nil)
	return nil
}

// FindUserByEmail finds a user of org by PRIMARY email address, case-insensitively (public sign-in lookup; no
// actor). Neither the username nor a linked address is ever used to sign in with a password or to reset one.
func (s *Service) FindUserByEmail(ctx context.Context, orgID, email string) (*model.User, error) {
	email = strings.TrimSpace(email)
	u, err := s.Users.GetByUnique(ctx, model.UserEmailKey(orgID, email))
	if err != nil {
		return nil, mapStore(err)
	}
	if !strings.EqualFold(u.Email, email) {
		return nil, ErrNotFound
	}
	return u, nil
}

// UsablePasskeys counts the user's passkeys that can sign in (model.Passkey.Usable), leaving out except (a passkey
// about to be removed).
func (s *Service) UsablePasskeys(ctx context.Context, userID, except string) (int, error) {
	l, err := s.Passkeys.All(ctx, userID)
	n := 0
	for _, p := range l {
		if p.ID != except && p.Usable() {
			n++
		}
	}
	return n, err
}

// dropEmailLinks removes the provider links a newly promoted manager or administrator did not make themselves: links
// made automatically by email address (and links of unknown origin). Privileged accounts are never linked by email
// (upstream.ErrPrivileged), so a promotion must not keep one made before. Links the user connected while signed in,
// and the link of the provider that created the account, stay.
func (s *Service) dropEmailLinks(ctx context.Context, a *Actor, u *model.User) {
	ids, err := s.Identities.All(ctx, u.ID)
	if err != nil {
		return
	}
	for _, id := range ids {
		if id.Via != "email" && id.Via != "" {
			continue
		}
		if err := s.Identities.Delete(Durable(ctx), id.ID); store.Applied(err) {
			s.Audit(ctx, a, u.OrgID, "identity.unlink", u.Username, map[string]string{"provider": id.ProviderID,
				"reason": "promoted to " + string(u.Role)})
		}
	}
}

// setManager sets u's manager: another user of the same organization, and never one who reports to u (directly or
// further down), which would make a loop. "" clears it.
func (s *Service) setManager(ctx context.Context, u *model.User, id string) error {
	if id == "" {
		u.Work.ManagerID = ""
		return nil
	}
	if id == u.ID {
		return Invalid("work.manager_id", "a person cannot be their own manager")
	}
	m, err := s.Users.Get(ctx, id)
	if err != nil || m.OrgID != u.OrgID {
		return Invalid("work.manager_id", "choose a user of this organization")
	}
	for n, next := 0, m.Work.ManagerID; next != "" && n < 100; n++ {
		if next == u.ID {
			return Invalid("work.manager_id", "that person reports to this user")
		}
		up, err := s.Users.Get(ctx, next)
		if err != nil {
			break
		}
		next = up.Work.ManagerID
	}
	u.Work.ManagerID = id
	return nil
}

// clearManagerOf removes the user as the manager of everyone who reports to them (they are being deleted).
func (s *Service) clearManagerOf(ctx context.Context, u *model.User) {
	reports, _, err := s.Users.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "manager_id", Value: u.ID}}})
	if err != nil {
		return
	}
	for _, r := range reports {
		for range 3 {
			r.Work.ManagerID = ""
			if err := s.Users.Update(ctx, r); !errors.Is(err, store.ErrStale) {
				break
			}
			if r, err = s.Users.Get(ctx, r.ID); err != nil {
				break
			}
		}
	}
}

// ExpireUsers disables every active user whose end date (ValidUntil) has passed: their sessions and refresh grants
// end, with back-channel logout to the applications. (Sign-in and tokens already stop at the end date itself; this
// makes it visible and tells the applications.) Run by the housekeeping leader. Returns how many were disabled.
func (s *Service) ExpireUsers(ctx context.Context) (int, error) {
	endReached := "The end date was reached."
	now := time.Now()
	n := 0
	for {
		due, _, err := s.Users.List(ctx, store.ListQuery{Sort: "valid_until", Limit: 200, Filters: []store.Filter{
			{Field: "expiring", Value: true}, {Field: "active", Value: true}}})
		if err != nil {
			return n, mapStore(err)
		}
		done := 0
		for _, u := range due {
			if u.ValidUntil == nil || u.ValidUntil.After(now) {
				return n, nil // sorted by end date: the rest end later
			}
			if _, err := s.UpdateUser(ctx, System, u.ID, UserInput{Active: ptrBool(false), StatusReason: &endReached}); err != nil {
				continue // the last super admin(s) are never disabled; their end date still stops sign-in
			}
			s.Audit(ctx, System, u.OrgID, "user.expire", u.Username, map[string]string{"valid_until": u.ValidUntil.Format(time.RFC3339)})
			n++
			done++
		}
		if len(due) < 200 || done == 0 {
			return n, nil
		}
	}
}

func ptrBool(b bool) *bool { return &b }

// EndPasskeySessions ends every session that was signed in with the passkey (and the refresh grants made in them),
// telling the applications (back-channel logout). Used when a passkey turns out to be compromised: whoever holds the
// copy is signed out too. Returns how many sessions ended.
func (s *Service) EndPasskeySessions(ctx context.Context, userID, passkeyID string) int {
	ctx = Durable(ctx)
	sessions, err := s.Sessions.All(ctx, userID)
	if err != nil {
		return 0
	}
	var ids []string
	for _, ss := range sessions {
		if ss.Passkey == passkeyID {
			ids = append(ids, ss.ID)
		}
	}
	if len(ids) == 0 {
		return 0
	}
	s.sessionsEnding(ctx, userID, ids)
	if grants, err := s.Grants.All(ctx, userID); err == nil {
		for _, g := range grants {
			if slices.Contains(ids, g.SessionID) {
				_ = s.Grants.Delete(ctx, g.ID)
			}
		}
	}
	n := 0
	for _, id := range ids {
		if err := s.Sessions.Delete(ctx, id); store.Applied(err) {
			n++
		}
	}
	return n
}
