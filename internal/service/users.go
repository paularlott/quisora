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

	"github.com/paularlott/gossip/hlc"
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
	// IfVersion, when set, applies the update only to the user as read at that version (a read-modify-write, a SCIM
	// If-Match): a user changed since is ErrStale, and nothing is written.
	IfVersion hlc.Timestamp `json:"-"`
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

// validatePassword checks a new password's length: at least limits.password_min_length characters.
func (s *Service) validatePassword(pw string) error {
	n, min := utf8.RuneCountInString(pw), s.Cfg.Limits.PasswordMinLength
	if n < min {
		return Invalid("password", "must be at least "+itoa(min)+" characters")
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
		h, err := s.hashPassword(ctx, u, *in.Password)
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

// ListUsers lists users of an org, with their last sign-in (shown, not sortable: it is kept on the users' sign-in
// records, so sorting on it would read the whole organization).
func (s *Service) ListUsers(ctx context.Context, a *Actor, orgID string, q store.ListQuery) ([]*model.User, int, error) {
	if !s.canManageUsers(a, orgID) {
		return nil, 0, ErrForbidden
	}
	q.Scope = orgID
	q = visibleQuery(a, q)
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

// ListUsersTagged lists the users of an org carrying exactly the tag: ListUsers with a filter on the tag, which the
// key-value stores answer from the tag's index (the users carrying it), not by reading the organization.
func (s *Service) ListUsersTagged(ctx context.Context, a *Actor, orgID string, q store.ListQuery, tag string) ([]*model.User, int, error) {
	q.Filters = append(slices.Clone(q.Filters), store.Filter{Field: "tags", Value: tag})
	return s.ListUsers(ctx, a, orgID, q)
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
	detail := map[string]string{"role": string(role)}
	if len(u.Tags) > 0 {
		detail["tags"] = strings.Join(u.Tags, " ")
	}
	if imported != "" {
		detail["password"] = "imported " + imported
	}
	if err := s.Users.Create(ctx, u); err != nil {
		s.auditUnknown(ctx, err, a, orgID, "user.create", u.Username, detail)
		return nil, s.userConflict(ctx, err, u)
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
	if err != nil {
		return s.updateUser(ctx, a, id, in, nil)
	}
	// A new manager holds the organization's managers lock (cluster-wide), and its loop check reads the chain from a
	// the owners' copies (setManager): two changes on two nodes (A reports to B, B to A) can never both pass it. Taken
	// before the admin lock, always, so the two never wait on each other.
	if w := in.Work; w != nil && w.ManagerID != nil && strings.TrimSpace(*w.ManagerID) != "" &&
		strings.TrimSpace(*w.ManagerID) != before.Work.ManagerID {
		l, err := s.lock(ctx, "managers/"+before.OrgID, adminLockTTL, 10*time.Second,
			"another change of this organization's managers is in progress")
		if err != nil {
			return nil, err
		}
		defer l.release(ctx)
	}
	var al *lease
	if before.Role == model.RoleSuperAdmin && (in.Role != nil || in.Active != nil || in.ValidUntil != nil) {
		// A change that can remove a super admin holds the primary organization's admin lock (cluster-wide), and its
		// last-super-admin check counts from the owners' copies: two such changes on two nodes can never both pass it.
		// The write is fenced on the lease (lease.fence): one that lands after the lease lapsed is judged again.
		al, err = s.lockAdmins(ctx, before.OrgID)
		if err != nil {
			return nil, err
		}
		defer al.release(ctx)
	}
	return s.updateUser(ctx, a, id, in, al)
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

// CurbsAdmin reports whether in demotes or disables u, an administrator or super admin, or ends their account sooner. Like granting the role, that
// takes a recently re-authenticated console session in the management API (a stolen token or an unattended session
// must not lock the other administrators out). SCIM does not ask for it: a directory offboarding an administrator
// (disabling or deleting them) must work with its token, and the service's own guards (the last super admins) apply.
func CurbsAdmin(u *model.User, in UserInput) bool {
	if !isAdminRank(u) {
		return false
	}
	if in.Role != nil && in.Role.Rank() < u.Role.Rank() || in.Active != nil && !*in.Active && u.Active {
		return true
	}
	// An end date that comes sooner ends the account as surely as disabling it, only later. (The console shows the
	// end as a date: the same day is the same end; a value that does not parse is refused by the update itself.)
	if in.ValidUntil != nil && *in.ValidUntil != "" {
		t, err := parseEndDate(*in.ValidUntil)
		return err == nil && (u.ValidUntil == nil ||
			t.Format(time.DateOnly) < u.ValidUntil.UTC().Format(time.DateOnly))
	}
	return false
}

func isAdminRank(u *model.User) bool {
	return u.Role == model.RoleAdmin || u.Role == model.RoleSuperAdmin
}

// updateUser is UpdateUser under the locks it took: al is the admin lock, held while the change can remove a super
// admin (nil otherwise), which the write is fenced on.
func (s *Service) updateUser(ctx context.Context, a *Actor, id string, in UserInput, al *lease) (*model.User, error) {
	u, err := s.Users.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	if in.IfVersion != 0 && u.Version != in.IfVersion {
		return nil, ErrStale
	}
	self := a.UserID == id
	if self {
		dropUnchanged(u, &in) // a form saving yourself sends every field: only what differs is a change
	}
	if err := s.mayChange(ctx, a, u, in, self); err != nil {
		return nil, err
	}
	before := u.Role
	was := snapshot(u)
	secWas := stateOf(u) // the security generation moves on below if the change touches what signs the account in
	var prev *model.User // the copy the last-admin guard judged, for the fence after the write
	if al != nil {
		if prev, err = cloneUser(u); err != nil {
			return nil, err
		}
	}
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
		if u.Role.Privileged() && in.Role.Rank() < u.Role.Rank() && a != System && !a.IsSuper() {
			return nil, Invalid("role", "only a super admin can lower the role of a manager or administrator")
		}
	}
	if err := s.guardAdminChange(ctx, u, in); err != nil {
		return nil, err
	}
	if in.Role != nil {
		u.Role = *in.Role
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
	noteSecurity(secWas, u)
	err = s.Users.Update(ctx, u)
	// The commit boundary of a change the admin lock guarded (lease.fence): a write that landed after the lease lapsed
	// is judged again on the copy the guard judged, and undone if it would be refused now. So is one whose outcome is
	// unknown (it may have landed): the check reads the owners' copies, which settle it first.
	fence := func() error {
		return al.fence(ctx, func(ctx context.Context) error { return s.guardAdminChange(ctx, prev, in) },
			func(ctx context.Context) error { return s.restoreUser(ctx, prev, u) })
	}
	if err != nil {
		s.auditUnknown(ctx, err, a, u.OrgID, "user.update", u.Username, addChanges(nil, was, u))
		if al != nil && outcomeUnknown(err) {
			if ferr := fence(); ferr != nil {
				return nil, ferr
			}
		}
		return nil, s.userConflict(ctx, err, u)
	}
	if al != nil {
		if err := fence(); err != nil {
			return nil, err
		}
	}
	// From here the change is in effect (perhaps not yet confirmed by a peer): what follows from it happens anyway.
	var sessErr error
	if in.Active != nil && !*in.Active || in.Password != nil || in.ValidUntil != nil && !u.Enabled(time.Now()) {
		// Disabling, an end date that has passed, or a password reset ends existing sessions and refresh grants
		// (except the actor's own). A failure is logged and noted in the audit entry; the change itself stands.
		sessErr = s.endUserSessions(ctx, u.ID, a)
	}
	if !before.Privileged() && u.Role.Privileged() {
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

// mayChange is who may make which change of u (updateUser): a may manage u, or u is a's own account and the change is
// one a user may make to themselves; and what neither may make (someone else's password, a privileged account's
// sign-in address without a sign-in reset, your own role, verification or work details, ...). self: a is u.
func (s *Service) mayChange(ctx context.Context, a *Actor, u *model.User, in UserInput, self bool) error {
	if !s.canManageUser(a, u) {
		if !self {
			return s.denied(a, u)
		}
		if in.Role != nil || in.Active != nil || in.ExternalID != nil || in.Verified != nil || in.Username != nil ||
			in.Tags != nil || in.LinkedEmails != nil || in.PhoneVerified != nil {
			return ErrForbidden
		}
	}
	if !self && in.Password != nil && a != System {
		return Invalid("password", "remove the password or send a new invitation; users choose their own passwords")
	}
	if self && in.LinkedEmails != nil {
		return ErrForbidden // own linked addresses change through AddLinkedEmail / RemoveLinkedEmail
	}
	if self && !isSelfService(ctx) {
		// Own credentials change only through the account page, which verifies the current password or a recent
		// re-authentication; the management API (sessions or tokens) must not be a shortcut around that.
		if in.Password != nil {
			return Invalid("password", "change your own password from your account page")
		}
	}
	if !self && in.Email != nil && !strings.EqualFold(strings.TrimSpace(*in.Email), u.Email) {
		// Password resets go to the primary address: whoever sets a manager's or administrator's could reset their
		// password, so for an established privileged account that is a sign-in reset (super admins only).
		if err := s.mayResetSignIn(ctx, a, u, "email"); err != nil {
			return err
		}
	}
	if self && a != System && in.Email != nil && !strings.EqualFold(strings.TrimSpace(*in.Email), u.Email) {
		// The primary address is what password sign-in, resets and every application's email claim use: someone
		// else sets it (a manager or administrator, or SCIM), whatever the user's own role; the user can only make one
		// of their verified addresses primary.
		return Invalid("email", "is changed by another manager or administrator, not by yourself")
	}
	if self && a != System && ((in.Verified != nil && *in.Verified && !u.EmailVerified) ||
		(in.PhoneVerified != nil && *in.PhoneVerified && !u.PhoneVerified)) {
		// Applications trust these claims: your own address or number is verified only by proving you receive it.
		return Invalid("email_verified", "your own email address is verified by the link mailed to it, not by marking it")
	}
	if !self && in.LinkedEmails != nil && addsVerifiedLinked(u, *in.LinkedEmails) {
		// Linked addresses set here count as verified, and a verified address links sign-ins from providers to the
		// account: as AddLinkedEmail with verified, for an established privileged account that is a sign-in reset.
		if err := s.mayResetSignIn(ctx, a, u, "emails"); err != nil {
			return err
		}
	}
	if !self && in.Verified != nil && *in.Verified && !u.EmailVerified && (in.Email == nil || strings.EqualFold(strings.TrimSpace(*in.Email), u.Email)) {
		// A verified address links sign-ins from providers to the account, as changing it does (just above).
		if err := s.mayResetSignIn(ctx, a, u, "email_verified"); err != nil {
			return err
		}
	}
	if self && ((in.Role != nil && *in.Role != u.Role) || (in.Active != nil && !*in.Active)) {
		return Invalid("role", "you cannot change your own role or disable yourself")
	}
	if self && (in.ValidUntil != nil || in.UserType != nil || in.Work != nil) && a != System && !a.IsSuper() {
		// Applications may trust these (a department, a manager): someone above you sets them. Super admins have
		// nobody above them.
		return Invalid("work", "your work details, user type and end date are set by an administrator")
	}
	if self && (in.Tags != nil || in.Username != nil || in.ExternalID != nil) && a != System && !a.IsSuper() {
		// The same for the tags and username every application receives and the id provisioning matches on. Users
		// and managers were refused above (they cannot manage themselves); this catches an administrator, who can.
		return ErrForbidden
	}
	return nil
}

// guardAdminChange applies guardLastAdmin to the change in of u (as read, before the change): only a lower role,
// disabling, or a sooner end date can take administration away; a promotion never needs the guard.
func (s *Service) guardAdminChange(ctx context.Context, u *model.User, in UserInput) error {
	if in.Role != nil && in.Role.Rank() < u.Role.Rank() || in.Active != nil && !*in.Active && u.Active {
		if err := s.guardLastAdmin(ctx, u); err != nil {
			return err
		}
	}
	if in.ValidUntil != nil {
		return s.guardEndDate(ctx, u, *in.ValidUntil)
	}
	return nil
}

// cloneUser is a copy of u that later changes of u leave untouched.
func cloneUser(u *model.User) (*model.User, error) {
	r, err := store.EncodeAsIs(u)
	if err != nil {
		return nil, err
	}
	c := &model.User{}
	if err := store.Decode(r, c); err != nil {
		return nil, err
	}
	return c, nil
}

// restoreUser undoes a guarded change of a user (lease.fence): prev is the user as the guard judged them, u the copy
// the change wrote. The copy written is put back as prev; a copy changed since (a newer version) gets back only what
// the guard judged — role, active state, end date and the status note — unless it is a usable super admin again.
func (s *Service) restoreUser(ctx context.Context, prev, u *model.User) error {
	prev.Version = u.Version
	err := s.Users.Update(ctx, prev)
	for attempt := 0; err != nil; attempt++ {
		if !errors.Is(err, store.ErrStale) || attempt == 4 {
			return mapStore(err)
		}
		if u, err = s.Users.Get(ctx, u.ID); err != nil {
			return mapStore(err)
		}
		if u.Role == model.RoleSuperAdmin && u.Enabled(time.Now()) {
			return nil
		}
		u.Role, u.Active, u.ValidUntil, u.StatusChanged = prev.Role, prev.Active, prev.ValidUntil, prev.StatusChanged
		err = s.Users.Update(ctx, u)
	}
	return nil
}

// recreateUser undoes a guarded deletion of a user (lease.fence): u, as read before the deletion, is created again (a
// new generation of the record over its tombstone).
func (s *Service) recreateUser(ctx context.Context, u *model.User) error {
	err := s.Users.Create(ctx, u)
	if err != nil {
		if _, gerr := s.Users.Get(ctx, u.ID); gerr == nil {
			return nil // still there: a deletion whose outcome was unknown did not land
		}
	}
	return mapStore(err)
}

// guardLastAdmin refuses to demote, disable, delete or end-date a super admin when fewer than MinSuperAdmins usable
// super admins would remain (one unless the service is told otherwise). A usable super admin is active and not past
// their end date. One without an end date may only stop being one while enough others without an end date remain: otherwise end
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
		return "the server keeps at least " + strconv.Itoa(e.need) + " super admins: make someone else a super admin first"
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
	var al *lease
	if u.Role == model.RoleSuperAdmin {
		if al, err = s.lockAdmins(ctx, u.OrgID); err != nil {
			return err
		}
		defer al.release(ctx)
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
	// last-admin check applied) is refused, instead of deleting an administrator unchecked.
	// The commit boundary of a deletion the admin lock guarded (lease.fence): one that landed after the lease lapsed,
	// or whose outcome is unknown, is judged again, and the user created again if it would be refused now.
	fence := func() error {
		return al.fence(ctx, func(ctx context.Context) error { return s.guardLastAdmin(ctx, u) },
			func(ctx context.Context) error { return s.recreateUser(ctx, u) })
	}
	if err := s.Users.DeleteIf(ctx, u.ID, u.Version); err != nil {
		// Refused (a newer copy), or not confirmed by a majority: the user may still exist; a retry decides.
		s.auditUnknown(ctx, err, a, u.OrgID, "user.delete", u.Username, nil)
		if al != nil && outcomeUnknown(err) {
			if ferr := fence(); ferr != nil {
				return ferr
			}
		}
		return mapStore(err)
	}
	if al != nil {
		if err := fence(); err != nil {
			return err
		}
	}
	// The user is gone, and with it everything that was theirs: every session, grant, token, passkey or link stands on
	// its user, so none counts any more, and the orphan sweep removes their records (sweep.go). The applications are
	// told (back-channel logout), and the users they managed get no manager. Their memberships stand on them too:
	// every reader of a group's members leaves out those whose user is gone (memberIDs).
	s.sessionsEnding(ctx, u.ID, nil)
	s.clearManagerOf(ctx, u)
	s.Audit(ctx, a, u.OrgID, "user.delete", u.Username, nil)
	return nil
}

// ResetCredentials leaves a user with no way in but what an accepted invitation is about to set. One compare-and-swap
// of the user record is the change: it removes the password, the authenticator app and the recovery codes, gives the
// account new credential and session epochs (model.User.CredEpoch, SessionEpoch: every passkey, connected provider,
// API token, session and refresh grant stops counting at that write) and moves the security generation on (every
// sign-in step, set-up or link in flight ends). Removing the records of the epochs it replaced follows
// (clearCredentials), as tidying: relying parties are told of the ended sessions. Re-inviting a compromised account
// therefore evicts whoever had it, at once.
func (s *Service) ResetCredentials(ctx context.Context, userID string) error {
	for attempt := 0; ; attempt++ {
		u, err := s.Users.Get(ctx, userID)
		if err != nil {
			return mapStore(err)
		}
		was := *u
		if u.PasswordHash != "" {
			now := time.Now().UTC()
			u.PasswordChangedAt = &now
		}
		u.PasswordHash, u.TOTPSecret, u.MFAEnrolledAt = "", "", nil
		u.RecoveryCodes, u.RecoveryCreated = nil, nil
		u.SetCredEpoch(NewCredEpoch())
		u.SessionEpoch = NewCredEpoch()
		u.BumpSecurity()
		err = s.Users.Update(ctx, u)
		if err == nil {
			return s.clearCredentials(ctx, userID, was.CredEpoch, was.SessionEpoch)
		}
		// re-read and retried when a concurrent change (a profile edit, a sign-in's stamp) got there first
		if !errors.Is(err, store.ErrStale) || attempt == 9 {
			return mapStore(err)
		}
	}
}

// clearCredentials removes the records of the account's credentials made in credential epoch cred (passkeys,
// connected providers, API tokens) and of its sessions and refresh grants made in session epoch sess: the epochs a
// change of the user record just replaced (model.User.CredEpoch, SessionEpoch). They count for nothing already; this
// tidies them away, and only them: a record of a later epoch (a later change, or one being made) stays. Relying
// parties are told of the ended sessions. Doing it again is harmless. Every removal is tried even when one fails; the
// errors are returned together. A write that is applied but not yet confirmed by a peer is no failure.
func (s *Service) clearCredentials(ctx context.Context, userID string, cred, sess uint64) error {
	errs := []error{s.endSessionsOf(ctx, userID, sess)}
	fail := func(err error) {
		if err != nil && !errors.Is(err, store.ErrStale) {
			errs = append(errs, err)
		}
	}
	for _, k := range []model.Kind{model.KindPasskey, model.KindIdentity, model.KindAPIToken} {
		res, err := s.Store.List(ctx, k, store.ListQuery{Scope: userID})
		if err != nil {
			fail(err)
			continue
		}
		for _, r := range res.Records {
			if madeIn(r, cred) {
				fail(s.Store.Put(ctx, store.Tombstone(k, r.ID)))
			}
		}
	}
	return mapStore(errors.Join(errs...))
}

// endSessionsOf removes the user's sessions and refresh grants made in session epoch sess (one a change of the user
// record replaced), telling relying parties of the sessions first (back-channel logout).
func (s *Service) endSessionsOf(ctx context.Context, userID string, sess uint64) error {
	var errs []error
	for _, k := range []model.Kind{model.KindSession, model.KindGrant} {
		res, err := s.Store.List(ctx, k, store.ListQuery{Scope: userID})
		if err != nil {
			errs = append(errs, fmt.Errorf("list %s: %w", k, err))
			continue
		}
		var ended []string
		for _, r := range res.Records {
			if madeIn(r, sess) {
				ended = append(ended, r.ID)
			}
		}
		if k == model.KindSession && len(ended) > 0 {
			s.sessionsEnding(ctx, userID, ended)
		}
		for _, id := range ended {
			if err := s.Store.Put(ctx, store.Tombstone(k, id)); err != nil && !errors.Is(err, store.ErrStale) {
				errs = append(errs, fmt.Errorf("end %s %s: %w", k, id, err))
			}
		}
	}
	err := errors.Join(errs...)
	if err != nil {
		s.Log.WithError(err).Error("not every session and refresh grant of the user could be removed", "user", userID)
	}
	return err
}

// credentialOf decodes a credential, session or refresh grant record (false: another kind, or unreadable).
func credentialOf(r *store.Record) (model.Credential, bool) {
	e := model.NewEntity(r.Kind)
	if store.Decode(r, e) != nil {
		return nil, false
	}
	c, ok := e.(model.Credential)
	return c, ok
}

// madeIn reports whether r is a credential, session or refresh grant made in epoch.
func madeIn(r *store.Record, epoch uint64) bool {
	c, ok := credentialOf(r)
	if !ok {
		return false
	}
	e, _ := c.MadeIn()
	return e == epoch
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
			if err := s.Store.Put(ctx, store.Tombstone(k, r.ID)); err != nil && !errors.Is(err, store.ErrStale) {
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
// out (back-channel logout). It returns how many grants it removed; 0 with no error means the user had granted that
// application nothing. Every grant is tried even when one fails, and the failures are returned together with the
// count of those that did go, so the caller can say the removal is partly done (a grant left behind still refreshes).
func (s *Service) RevokeAppAccess(ctx context.Context, userID, clientID string) (int, error) {
	grants, err := s.Grants.All(ctx, userID)
	if err != nil {
		return 0, mapStore(err)
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
	n := 0
	var errs []error
	for _, g := range mine {
		if err := s.Grants.Delete(ctx, g.ID); err != nil && !errors.Is(err, store.ErrStale) {
			errs = append(errs, mapStore(err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
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

// UsablePasskeys counts u's passkeys that can sign in (Ways), leaving out except (a passkey about to be removed).
func (s *Service) UsablePasskeys(ctx context.Context, u *model.User, except string) (int, error) {
	w, err := s.UserWays(ctx, u)
	if err != nil {
		return 0, err
	}
	return len(w.without(way{passkey: except}).Passkeys), nil
}

// HeldPasskeys counts u's passkeys that still belong to the account (made in its credential epoch, not removed),
// usable or not: a disabled one is still evidence that the account had a second factor. One from an earlier epoch is
// inert, whether or not its record is gone yet, and does not count.
func (s *Service) HeldPasskeys(ctx context.Context, u *model.User) (int, error) {
	pks, err := s.Passkeys.All(ctx, u.ID)
	if err != nil {
		return 0, mapStore(err)
	}
	n := 0
	for _, p := range pks {
		if u.Counts(p) {
			n++
		}
	}
	return n, nil
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
		if err := s.Identities.Delete(ctx, id.ID); err == nil {
			s.Audit(ctx, a, u.OrgID, "identity.unlink", u.Username, map[string]string{"provider": id.ProviderID,
				"reason": "promoted to " + string(u.Role)})
		}
	}
}

// setManager sets u's manager: another user of the same organization, and never one who reports to u (directly or
// further down), which would make a loop. "" clears it. The chain is read from the owners' copies (FreshUser), under
// the managers lock UpdateUser holds, so a change confirmed on another node is seen.
func (s *Service) setManager(ctx context.Context, u *model.User, id string) error {
	if id == "" {
		u.Work.ManagerID = ""
		return nil
	}
	if id == u.ID {
		return Invalid("work.manager_id", "a person cannot be their own manager")
	}
	if id == u.Work.ManagerID {
		return nil // unchanged
	}
	m, err := s.FreshUserIn(ctx, u.OrgID, id)
	if errors.Is(err, ErrUnavailable) {
		return err
	}
	if err != nil || m.OrgID != u.OrgID {
		return Invalid("work.manager_id", "choose a user of this organization")
	}
	for n, next := 0, m.Work.ManagerID; next != ""; n++ {
		if next == u.ID || n == maxManagerChain {
			return Invalid("work.manager_id", "that person reports to this user")
		}
		up, err := s.FreshUserIn(ctx, u.OrgID, next)
		if errors.Is(err, ErrUnavailable) {
			return err
		}
		if err != nil {
			break // the chain ends at a user who is gone
		}
		next = up.Work.ManagerID
	}
	u.Work.ManagerID = id
	return nil
}

// maxManagerChain bounds how far setManager follows a chain of managers: one longer than this (or a loop written
// before the check existed) is refused rather than followed for ever.
const maxManagerChain = 100

// clearManagerOf removes the user as the manager of everyone who reports to them (they are being deleted).
func (s *Service) clearManagerOf(ctx context.Context, u *model.User) {
	reports, _, err := s.Users.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "manager_id", Value: u.ID}}})
	if err != nil {
		return
	}
	for _, r := range reports {
		for range 3 {
			if r.Work.ManagerID != u.ID {
				break // reassigned meanwhile (the re-read below): that change stands
			}
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
	// Users this pass could not end (the last super admin(s) are never disabled, though their end date still stops
	// sign-in; or a write that failed) stay at the front of the due list: they are skipped, and each read asks for
	// that many more, so they never hide the users behind them.
	stuck := map[string]bool{}
	for {
		limit := 200 + len(stuck)
		due, err := s.dueUsers(ctx, now, limit)
		if err != nil {
			return n, mapStore(err)
		}
		progress := false
		for _, u := range due {
			if u.ValidUntil == nil || u.ValidUntil.After(now) {
				return n, nil // sorted by end date: the rest end later
			}
			if stuck[u.ID] {
				continue
			}
			progress = true
			if _, err := s.UpdateUser(ctx, System, u.ID, UserInput{Active: ptrBool(false), StatusReason: &endReached}); err != nil {
				stuck[u.ID] = true
				continue
			}
			s.Audit(ctx, System, u.OrgID, "user.expire", u.Username, map[string]string{"valid_until": u.ValidUntil.Format(time.RFC3339)})
			n++
		}
		if len(due) < limit || !progress {
			return n, nil
		}
	}
}

// dueUsers returns up to limit active users with an end date, earliest end first: from the store's due index where it
// keeps one (the key-value stores, whose filtered queries would read every user), else by a query (SQL answers it
// from its indexes).
func (s *Service) dueUsers(ctx context.Context, now time.Time, limit int) ([]*model.User, error) {
	if dl, ok := s.Users.S.(store.DueLister); ok {
		recs, err := dl.ListDue(ctx, model.KindUser, now, limit)
		if !errors.Is(err, store.ErrNoDueIndex) {
			if err != nil {
				return nil, err
			}
			out := make([]*model.User, 0, len(recs))
			for _, r := range recs {
				var u model.User
				if err := store.Decode(r, &u); err != nil {
					return nil, err
				}
				out = append(out, &u)
			}
			return out, nil
		}
	}
	due, _, err := s.Users.List(ctx, store.ListQuery{Sort: "valid_until", Limit: limit, Filters: []store.Filter{
		{Field: "expiring", Value: true}, ActiveFilter(true)}})
	return due, err
}

func ptrBool(b bool) *bool { return &b }

// ActiveFilter is the user listing filter for active (or disabled) accounts. It filters on the indexed "inactive"
// field: the disabled accounts are few, so both are served from a small index set, where a filter on "active" would
// read the whole organization (model.Field: an indexed bool marks a small set).
func ActiveFilter(active bool) store.Filter { return store.Filter{Field: "inactive", Value: !active} }

// EndPasskeySessions ends every session that was signed in with the passkey (and the refresh grants made in them),
// telling the applications (back-channel logout). Used when a passkey turns out to be compromised: whoever holds the
// copy is signed out too. Returns how many sessions ended, and the failures together: a session or refresh grant
// that could not be deleted still works (for the copy's holder too), so the caller records that the sign-out did not
// finish rather than only how many did.
func (s *Service) EndPasskeySessions(ctx context.Context, userID, passkeyID, keepSession string) (int, error) {
	sessions, err := s.Sessions.All(ctx, userID)
	if err != nil {
		return 0, mapStore(err)
	}
	var ids []string
	for _, ss := range sessions {
		if ss.Passkey == passkeyID && ss.ID != keepSession {
			ids = append(ids, ss.ID)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	s.sessionsEnding(ctx, userID, ids)
	var errs []error
	grants, err := s.Grants.All(ctx, userID)
	if err != nil {
		errs = append(errs, fmt.Errorf("list refresh grants: %w", mapStore(err)))
	}
	for _, g := range grants {
		if slices.Contains(ids, g.SessionID) {
			if err := s.Grants.Delete(ctx, g.ID); err != nil && !errors.Is(err, store.ErrStale) {
				errs = append(errs, fmt.Errorf("end refresh grant %s: %w", g.ID, mapStore(err)))
			}
		}
	}
	n := 0
	for _, id := range ids {
		if err := s.Sessions.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrStale) {
			errs = append(errs, fmt.Errorf("end session %s: %w", id, mapStore(err)))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}
