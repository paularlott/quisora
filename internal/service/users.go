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
	// (cost 4 to 14), SHA-512 crypt or argon2id. The system, or super admins (an API token needs the import scope).
	// The first sign-in re-hashes it with today's argon2id (passwords.go).
	PasswordHash *string `json:"password_hash"`
	// TOTPSecret imports the authenticator app's base32 secret from another system when a user is created (never on
	// an update), under the same rule as PasswordHash: the user keeps the app they have (see normalizeTOTPSecret).
	TOTPSecret *string `json:"totp_secret"`
	// Identities links the new user to sign-in providers of the organization (never on an update), under the same
	// rule as PasswordHash: a provider's sign-in with that subject is then this user.
	Identities []IdentityInput `json:"identities"`
	Verified   *bool           `json:"email_verified"`
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
	if in.PasswordHash != nil || in.TOTPSecret != nil || in.Identities != nil {
		return Invalid("password_hash", "credentials and provider links are imported only when the user is created")
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

// listByPresented is ListUsers sorted on a field directory entries blank (username, email...) for a
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
	return s.CreateUserLinked(ctx, a, orgID, in, nil)
}

// CreateUserLinked is CreateUser for an account made with its link to a sign-in provider (auto-provisioning at a first
// sign-in): link makes the link of the new user, and both are written in one transaction, so there is never an
// account without its way in, nor a link without its account. nil makes none.
func (s *Service) CreateUserLinked(ctx context.Context, a *Actor, orgID string, in UserInput,
	link func(u *model.User) *model.Identity) (*model.User, error) {
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
		if err := requireImport(a, "password_hash", "password hashes"); err != nil {
			return nil, err
		}
		if in.Password != nil {
			return nil, Invalid("password_hash", "give a password or a password hash, not both")
		}
		kind, err := secure.CheckImport(*in.PasswordHash)
		if err != nil {
			return nil, Invalid("password_hash", "must be a bcrypt hash (cost 4 to 14), a SHA-512 crypt hash ($6$, at most 1,000,000 rounds) or an argon2id hash")
		}
		imported = kind
		u.PasswordHash = s.SealPasswordHash(u.ID, *in.PasswordHash)
		in.PasswordHash = nil // apply refuses it (updates never take one)
	}
	if in.TOTPSecret != nil {
		if err := s.importTOTP(a, u, *in.TOTPSecret); err != nil {
			return nil, err
		}
		in.TOTPSecret = nil // apply refuses it too
	}
	identities := in.Identities
	in.Identities = nil
	if err := s.apply(ctx, u, in); err != nil {
		return nil, err
	}
	var imports []*model.Identity
	var providers []string
	if identities != nil {
		// after apply, as every identity is of the account's credential epoch as it is written
		if imports, providers, err = s.importLinks(ctx, a, u, identities); err != nil {
			return nil, err
		}
	}
	detail := map[string]string{"role": string(role)}
	if len(u.Tags) > 0 {
		detail["tags"] = strings.Join(u.Tags, " ")
	}
	if imported != "" {
		detail["password"] = "imported " + imported
	}
	if len(providers) > 0 {
		detail["providers"] = strings.Join(providers, " ")
	}
	links := imports
	if link != nil {
		links = append(links, link(u))
	}
	events := []change{userChange(u, "user.create", detail)}
	if u.HasTOTP() {
		events = append(events, userChange(u, "mfa.import", map[string]string{"method": "totp"})) // never the secret
	}
	err = s.createUser(ctx, u, links)
	s.auditOutcome(ctx, a, err, events...)
	if err != nil {
		if lerr := s.linkConflict(ctx, err, u, imports); lerr != nil {
			return nil, lerr
		}
		return nil, s.userConflict(ctx, err, u)
	}
	return u, nil
}

// createUser writes the new user u (and its links) in one transaction that asserts its
// organization's deletion guard is as it was found, open (store.Op.Assert: the guard is read, not written, so creations
// never conflict with each other): a deletion that has taken the guard refuses it (errOrgDeleting), and one that takes
// the guard after it counts the user (see orgDeleting). A guard changed meanwhile is read and judged again.
func (s *Service) createUser(ctx context.Context, u *model.User, links []*model.Identity) error {
	for attempt := 0; ; attempt++ {
		g, err := s.openOrgGuard(ctx, u.OrgID)
		if err != nil {
			return err
		}
		ents := []model.Entity{u}
		for _, l := range links {
			ents = append(ents, l)
		}
		var ops []store.Op
		for _, e := range ents {
			rec, err := store.Encode(e)
			if err != nil {
				return err
			}
			ops = append(ops, store.Op{Rec: rec, Match: true})
		}
		ops = append(ops, store.AssertOp(model.KindLock, u.OrgID, u.OrgID, g.Version))
		err = s.Users.S.Tx(ctx, ops)
		if errors.Is(err, store.ErrStale) && attempt < 7 {
			continue
		}
		if err == nil {
			u.Version = ops[0].Rec.Version
		}
		return err
	}
}

// LinkExisting links a new way into user userID's existing account (a sign-in provider's identity matched by email
// address): link makes the identity, and it is created in the one write that moves the account's security generation
// on (what is in flight for the account ends), only while allow passes on the account as that write finds it. A change
// of the account committed meanwhile (a promotion, say) makes the write stale, and allow is asked again on the newer
// copy, so the account is never linked on a judgement of a copy it has moved past.
func (s *Service) LinkExisting(ctx context.Context, userID string, allow func(u *model.User) error,
	link func(u *model.User) *model.Identity) (*model.User, error) {
	return s.modifyUserWith(ctx, userID, func(u *model.User) ([]store.Op, error) {
		if err := allow(u); err != nil {
			return nil, err
		}
		u.BumpSecurity()
		rec, err := store.Encode(link(u))
		if err != nil {
			return nil, err
		}
		return []store.Op{{Rec: rec, Match: true}}, nil
	})
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
// (disabling or deleting them) must work with its token, and the service's own rules (nobody curbs their own account, only a super admin curbs a super admin) apply.
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

// UpdateUser changes a user. Users may change their own profile fields but not role, active, external id or
// verified state.
func (s *Service) UpdateUser(ctx context.Context, a *Actor, id string, in UserInput) (*model.User, error) {
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
	was := snapshot(u)
	secWas := stateOf(u) // the security generation moves on below if the change touches what signs the account in
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
	if a == System && u.Role == model.RoleSuperAdmin && CurbsAdmin(u, in) {
		return nil, errSparesSuperAdmins
	}
	var also []store.Op
	roleDone := func(context.Context, *Actor, error) {}
	promoted, sessWas := false, u.SessionEpoch // promoted: the account becomes privileged, which ends its sessions (applyRole)
	if in.Role != nil {
		var err error
		wasPrivileged := u.Role.Privileged()
		if also, roleDone, err = s.applyRole(ctx, u, *in.Role); err != nil {
			return nil, err
		}
		promoted = !wasPrivileged && u.Role.Privileged()
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
	addChanges(detail, was, u)
	// Disabling, an end date that has passed, or a password set by someone else ends the account's sessions and refresh
	// grants (not the actor's own, changing their own account) in this write: a new session epoch, so they stop counting
	// at the commit. Removing their records after it is tidying (and tells the applications: back-channel logout).
	endsSessions := (in.Active != nil && !*in.Active || in.Password != nil || in.ValidUntil != nil && !u.Enabled(time.Now())) &&
		a.UserID != u.ID
	if endsSessions {
		u.SessionEpoch = NewCredEpoch()
	}
	err = s.AuditedUser(ctx, a, u, action, detail, func() error {
		err := s.writeUser(ctx, u, also)
		roleDone(ctx, a, err)
		if err == nil && endsSessions {
			if sessErr := s.endUserSessions(ctx, u.ID, a); sessErr != nil {
				detail["sessions"] = "not all ended: " + sessErr.Error()
			}
		} else if err == nil && promoted {
			// the promotion moved the session epoch (applyRole): removing what it replaced is tidying
			if sessErr := s.endSessionsOf(ctx, u.ID, sessWas); sessErr != nil {
				detail["sessions"] = "not all ended: " + sessErr.Error()
			}
		}
		return err
	})
	if err != nil {
		return nil, s.userConflict(ctx, err, u)
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
	if self && in.ValidUntil != nil {
		return Invalid("valid_until", "your own end date is set by someone else") // nobody ends or extends their own access
	}
	if self && (in.UserType != nil || in.Work != nil) && a != System && !a.IsSuper() {
		// Applications may trust these (a department, a manager): someone above you sets them. Super admins have
		// nobody above them.
		return Invalid("work", "your work details and user type are set by an administrator")
	}
	if self && (in.Tags != nil || in.Username != nil || in.ExternalID != nil) && a != System && !a.IsSuper() {
		// The same for the tags and username every application receives and the id provisioning matches on. Users
		// and managers were refused above (they cannot manage themselves); this catches an administrator, who can.
		return ErrForbidden
	}
	return nil
}

// errSparesSuperAdmins is what the system (housekeeping, bootstrap, commands that act as System) gets when it would
// demote, disable, end-date or delete a super admin: only another super admin does that.
var errSparesSuperAdmins = Invalid("user", "automatic changes never demote, disable, end-date or delete a super admin")

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
	if a.UserID == id {
		return Invalid("user", "you cannot delete yourself")
	}
	if !s.canManageUser(a, u) {
		return s.denied(a, u) // not found for users a may not see (other organizations, super admins)
	}
	if a == System && u.Role == model.RoleSuperAdmin {
		return errSparesSuperAdmins
	}
	// The user goes first, and only as the copy every check above was made on: a copy that is not the newest (one
	// read on a node that has not seen the user's promotion to administrator yet, so the rank rules above did not
	// apply) is refused, instead of deleting an administrator unchecked.
	err = s.AuditedUser(ctx, a, u, "user.delete", nil, func() error { return s.Users.DeleteIf(ctx, u.ID, u.Version) })
	if err != nil {
		return mapStore(err)
	}
	// The user is gone, and with it everything that was theirs: every session, grant, token, passkey or link stands on
	// its user, so none counts any more, and the orphan sweep removes their records (sweep.go), as it clears the
	// manager of the users they managed (a deletion whose outcome was not known is followed by the sweep alone). The
	// applications are told (back-channel logout), and their reports get no manager. Their memberships stand on them
	// too: every reader of a group's members leaves out those whose user is gone (memberIDs).
	s.sessionsEnding(ctx, u.ID, nil)
	s.clearManagerOf(ctx, u)
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

// RevokeSessions ends every session and refresh grant of a user (admin action or "sign out everywhere"). They end at
// one write of the user: a new session epoch (model.User.SessionEpoch), so every session and grant made so far stops
// counting at the commit, one a sign-in has made since the listing below included. Removing their records is tidying
// after it (and tells the applications: back-channel logout). Whether a may do it is judged in that write, on the
// user as it is written.
func (s *Service) RevokeSessions(ctx context.Context, a *Actor, userID string) error {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return mapStore(err)
	}
	if a.UserID != userID && !s.canManageUser(a, u) {
		return s.denied(a, u)
	}
	was, _, err := s.moveSessionEpoch(ctx, userID, func(u *model.User) error {
		if a.UserID != userID && !s.canManageUser(a, u) {
			return s.denied(a, u)
		}
		return nil
	})
	if err == nil {
		err = s.endSessionsOf(ctx, userID, was)
	}
	if err != nil {
		s.AuditUser(ctx, a, u, "user.sessions.revoke", map[string]string{"result": "incomplete",
			"error": err.Error()})
		return mapStore(err)
	}
	s.AuditUser(ctx, a, u, "user.sessions.revoke", nil)
	return nil
}

// RevokeOtherSessions is RevokeSessions for the user's own "sign out my other sessions": every session and refresh
// grant but session keep (and its refresh grants) ends, and it reports how many sessions ended. The session epoch
// moves on, so a session created while it runs is ended too, and keep is re-stamped to the new epoch, with its grants,
// so it goes on working (as pullSignOut keeps the session of whoever pulls the lever). A session that was not found
// (it ended meanwhile) is simply not kept.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, keep string) (int, error) {
	was, now, err := s.moveSessionEpoch(ctx, userID, nil)
	if err != nil {
		return 0, err
	}
	var errs []error
	if keep != "" {
		errs = append(errs, s.carryOver(ctx, userID, keep, now))
	}
	n := 0
	if list, err := s.Sessions.All(ctx, userID); err != nil {
		errs = append(errs, mapStore(err))
	} else {
		for _, x := range list {
			if x.Epoch == was && x.ID != keep {
				n++
			}
		}
	}
	errs = append(errs, s.endSessionsOf(ctx, userID, was))
	return n, errors.Join(errs...)
}

// moveSessionEpoch gives the user a new session epoch: every session and refresh grant made before it stops counting
// at the write (SessionUsable, the grants' use). allow, when set, judges the user as the write finds it, on every try.
// It returns the epoch it replaced (endSessionsOf removes what was made in it) and the new one.
func (s *Service) moveSessionEpoch(ctx context.Context, userID string, allow func(u *model.User) error) (was, now uint64, err error) {
	_, err = s.modifyUser(ctx, userID, func(u *model.User) error {
		if allow != nil {
			if err := allow(u); err != nil {
				return err
			}
		}
		was, now = u.SessionEpoch, NewCredEpoch()
		u.SessionEpoch = now
		return nil
	})
	return was, now, err
}

// carryOver makes session keep, and the refresh grants it carries on, belong to session epoch now (the account's
// current one), so a revocation that moved the epoch does not end them. The session first: a grant an exchange
// makes from an older copy of it is then refused (CreateSessionGrant), so none is made in the epoch just ended.
func (s *Service) carryOver(ctx context.Context, userID, keep string, now uint64) error {
	for attempt := 0; ; attempt++ {
		sess, err := s.Sessions.Get(ctx, keep)
		if errors.Is(err, store.ErrNotFound) || err == nil && sess.UserID != userID {
			return nil
		}
		if err == nil {
			sess.Epoch = now
			err = s.Sessions.Update(ctx, sess)
		}
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrStale) || attempt == 4 {
			return fmt.Errorf("keep the current session: %w", mapStore(err))
		}
	}
	grants, err := s.Grants.All(ctx, userID)
	if err != nil {
		return fmt.Errorf("keep the current session's refresh grants: %w", mapStore(err))
	}
	var errs []error
	for _, g := range grants {
		if g.SessionID != keep {
			continue
		}
		for attempt := 0; ; attempt++ {
			g.Epoch = now
			err := s.Grants.Update(ctx, g)
			if err == nil || errors.Is(err, store.ErrNotFound) {
				break
			}
			if !errors.Is(err, store.ErrStale) || attempt == 4 {
				errs = append(errs, fmt.Errorf("keep refresh grant %s: %w", g.ID, mapStore(err)))
				break
			}
			if g, err = s.Grants.Get(ctx, g.ID); err != nil {
				break
			}
		}
	}
	return errors.Join(errs...)
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

// unchosenLinks returns u's links to sign-in providers that u did not make from their own account page: made by email
// address, by an account created at a provider's first sign-in, by an administrator, or of unknown origin. The side
// that controls the provider controls such a link, so applyRole deletes them when u becomes privileged. Only a link
// u connected while signed in ("connect") stays.
func (s *Service) unchosenLinks(ctx context.Context, u *model.User) ([]*model.Identity, error) {
	ids, err := s.Identities.All(ctx, u.ID)
	if err != nil {
		return nil, mapStore(err)
	}
	return slices.DeleteFunc(ids, func(id *model.Identity) bool { return id.Via == "connect" }), nil
}

// writeUser writes u, the copy read at its version (a compare-and-swap, as Users.Update), and the writes that go with
// the change (also: the records it ends) in one transaction: they take effect together or not at all.
func (s *Service) writeUser(ctx context.Context, u *model.User, also []store.Op) error {
	if len(also) == 0 {
		return s.Users.Update(ctx, u)
	}
	expect := u.Version
	rec, err := store.Encode(u)
	if err == nil {
		err = s.Users.S.Tx(ctx, append([]store.Op{{Rec: rec, Match: true, Expect: expect}}, also...))
	}
	if err != nil {
		u.Version = expect
		return err
	}
	u.Version = rec.Version
	return nil
}

// setManager sets u's manager: another user of the same organization, and never one who reports to u (directly or
// further down), which would make a loop. "" clears it. The chain is read as the store answers (current within its
// bound), and bounded (maxManagerChain). Two changes at once on two nodes can still make a loop (a reporting line is directory data only; the walk above is bounded, so a loop harms nothing).
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
	m, err := s.getUser(ctx, id)
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
		up, err := s.getUser(ctx, next)
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
	// Users this pass could not end (super admins are never disabled by the system, though their end date still stops
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
			if u.Role == model.RoleSuperAdmin {
				stuck[u.ID] = true
			}
			if stuck[u.ID] {
				continue
			}
			progress = true
			if err := s.AuditedUser(ctx, System, u, "user.expire", map[string]string{"valid_until": u.ValidUntil.Format(time.RFC3339)}, func() error {
				_, err := s.UpdateUser(ctx, System, u.ID, UserInput{Active: ptrBool(false), StatusReason: &endReached})
				return err
			}); err != nil {
				stuck[u.ID] = true
				continue
			}
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

// passkeySessionEnds returns the sessions passkeyID signed in for userID (but keepSession) and the deletions that end
// them with their refresh grants, for a transaction; the applications are told first (back-channel logout). Each
// session is deleted only at the version listed: a grant made meanwhile changed it (CreateSessionGrant), so the
// transaction is refused (ErrStale) and decided again on fresh listings (removeWay), as EndSession does.
func (s *Service) passkeySessionEnds(ctx context.Context, userID, passkeyID, keepSession string) ([]string, []store.Op, error) {
	sessions, err := s.Sessions.All(ctx, userID)
	if err != nil {
		return nil, nil, mapStore(err)
	}
	var ids []string
	var ops []store.Op
	for _, ss := range sessions {
		if ss.Passkey == passkeyID && ss.ID != keepSession {
			ids = append(ids, ss.ID)
			ops = append(ops, store.Op{Rec: store.Tombstone(model.KindSession, ss.ID), Match: true, Expect: ss.Version})
		}
	}
	if len(ids) == 0 {
		return nil, nil, nil
	}
	grants, err := s.Grants.All(ctx, userID)
	if err != nil {
		return nil, nil, mapStore(err)
	}
	for _, g := range grants {
		if slices.Contains(ids, g.SessionID) {
			ops = append(ops, store.Op{Rec: store.Tombstone(model.KindGrant, g.ID)})
		}
	}
	s.sessionsEnding(ctx, userID, ids)
	return ids, ops, nil
}

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
	var ending []*model.Session
	var ids []string
	for _, ss := range sessions {
		if ss.Passkey == passkeyID && ss.ID != keepSession {
			ending, ids = append(ending, ss), append(ids, ss.ID)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	s.sessionsEnding(ctx, userID, ids)
	return s.EndSessions(ctx, userID, ending)
}
