package scim

import (
	"errors"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func versionTag(v hlc.Timestamp) string { return `W/"` + strconv.FormatUint(uint64(v), 10) + `"` }

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// userResource renders u. groups is nil when memberships are not wanted. It fails when the manager's visibility cannot
// be read: the manager is then neither shown nor left out, as a write back of a user without one would clear it.
func (rq *request) userResource(u *model.User, groups []*model.Group, withGroups bool) (map[string]any, error) {
	res := map[string]any{
		"id":       u.ID,
		"userName": u.Username,
		"active":   u.Active,
	}
	schemas := []string{schemaUser}
	res["displayName"] = u.FullName()
	if u.ExternalID != "" {
		res["externalId"] = u.ExternalID
	}
	res["name"] = map[string]any{"givenName": u.GivenName, "familyName": u.FamilyName, "formatted": u.FullName()}
	if u.Locale != "" {
		res["locale"] = u.Locale
		res["preferredLanguage"] = u.Locale
	}
	for k, v := range map[string]string{"timezone": u.ZoneInfo, "userType": u.UserType, "title": u.Work.Title} {
		if v != "" {
			res[k] = v
		}
	}
	if u.PhoneNumber != "" {
		res["phoneNumbers"] = []any{map[string]any{"value": u.PhoneNumber, "type": "work", "primary": true}}
	}
	if u.Email != "" {
		emails := []any{map[string]any{"value": u.Email, "type": "work", "primary": true}}
		// Only verified linked addresses are the directory's business: an address the user added and has not
		// verified yet is never shown, so a PUT or PATCH that writes the whole list back cannot vouch for it.
		for _, l := range u.LinkedEmails {
			if l.Verified {
				emails = append(emails, map[string]any{"value": l.Address, "type": "other", "primary": false})
			}
		}
		res["emails"] = emails
	}
	if withGroups {
		res["groups"] = rq.groupsValue(groups)
	}
	ent, err := rq.enterpriseValue(u)
	if err != nil {
		return nil, err
	}
	if len(ent) > 0 {
		schemas = append(schemas, schemaEnterprise)
		res[schemaEnterprise] = ent
	}
	schemas = append(schemas, schemaIdpUser)
	ext := map[string]any{"role": string(u.Role), "tags": tagsValue(u.Tags)}
	if u.ValidUntil != nil {
		ext["validUntil"] = rfc3339(*u.ValidUntil)
	}
	res[schemaIdpUser] = ext
	res["schemas"] = schemas
	res["meta"] = map[string]any{
		"resourceType": "User",
		"created":      rfc3339(u.Created),
		"lastModified": rfc3339(u.Updated),
		"version":      versionTag(u.Version),
		"location":     rq.location("Users", u.ID),
	}
	return res, nil
}

// tagsValue renders tags as a JSON array (never null).
func tagsValue(tags []string) []any {
	out := make([]any, len(tags))
	for i, t := range tags {
		out[i] = t
	}
	return out
}

// parseTags reads the "tags" attribute of an extension object; the second result tells whether it was present.
// null clears the tags.
func parseTags(ext map[string]any) ([]string, bool, *Error) {
	raw, present := getCI(ext, "tags"), false
	if _, ok := keyOf(ext, "tags"); ok {
		present = true
	}
	if !present {
		return nil, false, nil
	}
	out := []string{}
	switch t := raw.(type) {
	case nil:
	case []any:
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, true, badValue("tags must be a list of strings")
			}
			out = append(out, s)
		}
	default:
		return nil, true, badValue("tags must be a list of strings")
	}
	return out, true, nil
}

// keepTags makes a patched resource carry its (possibly emptied) tags list in extension urn, so that PATCH remove of
// the attribute clears the tags, while a PUT that does not mention tags leaves them alone.
func keepTags(res map[string]any, urn string) {
	m, _ := res[urn].(map[string]any)
	if m == nil {
		m = map[string]any{}
		res[urn] = m
	}
	if _, ok := keyOf(m, "tags"); !ok {
		m["tags"] = []any{}
	}
}

// keepValidUntil makes a patched user carry validUntil in the extension (null when the PATCH removed it), so that
// removing the attribute clears the end date while a PUT that does not mention it leaves it alone.
func keepValidUntil(res map[string]any) {
	m, _ := res[schemaIdpUser].(map[string]any)
	if m == nil {
		m = map[string]any{}
		res[schemaIdpUser] = m
	}
	if _, ok := keyOf(m, "validUntil"); !ok {
		m["validUntil"] = nil
	}
}

// groupsValue renders the read-only groups attribute.
func (rq *request) groupsValue(groups []*model.Group) []any {
	gs := make([]any, 0, len(groups))
	for _, g := range groups {
		gs = append(gs, map[string]any{"value": g.ID, "display": g.DisplayName, "type": "direct",
			"$ref": rq.location("Groups", g.ID)})
	}
	return gs
}

// groupIndex maps user id -> groups of the org, for rendering users. Each user's groups are read from their own
// memberships (an index read, then the groups by id), so the cost follows the users listed, not the number of groups
// of the organization.
func (rq *request) groupIndex(users []*model.User) (map[string][]*model.Group, error) {
	idx := make(map[string][]*model.Group, len(users))
	for _, u := range users {
		gs, err := rq.m.srv.Svc.UserGroups(rq.ctx, u)
		if err != nil {
			return nil, err
		}
		idx[u.ID] = gs
	}
	return idx, nil
}

func str(m map[string]any, key string) (string, bool, *Error) {
	v := getCI(m, key)
	switch t := v.(type) {
	case nil:
		return "", false, nil
	case string:
		return t, true, nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true, nil
	}
	return "", false, badValue("%s must be a string", key)
}

func parseBool(v any, name string) (bool, *Error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, badValue("%s must be true or false", name)
}

// pickValue returns the value of the primary (else first) element of a multi-valued attribute.
func pickValue(v any, name string) (string, bool, *Error) {
	var first, primary string
	var hasFirst, hasPrimary bool
	for _, e := range asSlice(v) {
		em, ok := e.(map[string]any)
		if !ok {
			if s, isStr := e.(string); isStr && s != "" && !hasFirst {
				first, hasFirst = s, true
				continue
			}
			return "", false, badValue("%s must be a list of objects", name)
		}
		val, ok, err := str(em, "value")
		if err != nil {
			return "", false, err
		}
		if !ok || val == "" {
			continue
		}
		if !hasFirst {
			first, hasFirst = val, true
		}
		if p, has := em["primary"]; has && !hasPrimary {
			if b, err := parseBool(p, name+".primary"); err == nil && b {
				primary, hasPrimary = val, true
			}
		}
	}
	if hasPrimary {
		return primary, true, nil
	}
	return first, hasFirst, nil
}

// validEmail reports whether s is a plain email address.
func validEmail(s string) bool {
	s = strings.TrimSpace(s)
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && strings.Contains(s, "@")
}

// userInput maps a SCIM user (a request body or a patched copy of the current resource) to a service input. With an
// existing user, attributes missing from res are cleared (replace semantics); without one they are left unset.
func (rq *request) userInput(res map[string]any, existing *model.User) (service.UserInput, *Error) {
	var in service.UserInput
	replace := existing != nil
	optional := func(dst **string, v string, present bool) {
		switch {
		case present:
			*dst = &v
		case replace:
			empty := ""
			*dst = &empty
		}
	}
	v, ok, e := str(res, "userName")
	if e != nil {
		return in, e
	}
	if ok {
		un := v
		in.Username = &un
	} else if !replace {
		return in, badValue("userName is required")
	}
	if v, ok, e = str(res, "externalId"); e != nil {
		return in, e
	} else {
		optional(&in.ExternalID, v, ok)
	}
	// The display name is derived from the first and last name, so it is accepted and ignored — except as the first
	// name when name.givenName is absent.
	display, _, e := str(res, "displayName")
	if e != nil {
		return in, e
	}
	var given, family string
	var hasGiven, hasFamily bool
	if nm, isMap := getCI(res, "name").(map[string]any); isMap {
		if given, hasGiven, e = str(nm, "givenName"); e != nil {
			return in, e
		}
		if family, hasFamily, e = str(nm, "familyName"); e != nil {
			return in, e
		}
	} else if getCI(res, "name") != nil {
		return in, badValue("name must be an object")
	}
	if !hasGiven && strings.TrimSpace(display) != "" {
		given, hasGiven = strings.TrimSpace(display), true
	}
	if hasGiven && strings.TrimSpace(given) != "" {
		in.GivenName = &given // the first name is never cleared: absent on replace, it stays as it is
	}
	optional(&in.FamilyName, family, hasFamily)
	if a := getCI(res, "active"); a != nil {
		b, e := parseBool(a, "active")
		if e != nil {
			return in, e
		}
		in.Active = &b
	}
	email, _, e := pickValue(getCI(res, "emails"), "emails")
	if e != nil {
		return in, e
	}
	others, e := otherEmails(getCI(res, "emails"), email)
	if e != nil {
		return in, e
	}
	// The primary (else first) phone number is the user's contact number. One that is not a full international
	// number (E.164 once separators are dropped) is ignored rather than failing the user: provisioning clients pass
	// on whatever their directory holds. addresses are accepted and ignored.
	phone, hasPhone, e := pickValue(getCI(res, "phoneNumbers"), "phoneNumbers")
	if e != nil {
		return in, e
	}
	if p, err := service.NormalizePhone(phone); err == nil {
		optional(&in.Phone, p, hasPhone || getCI(res, "phoneNumbers") != nil)
	}
	if e := rq.profileInput(res, &in, existing, optional); e != nil {
		return in, e
	}
	// Passwords are never provisioned: the user chooses their own through an invitation link (or a passkey).
	if pw, ok, e := str(res, "password"); e != nil {
		return in, e
	} else if ok && pw != "" {
		return in, errf(400, "mutability", "passwords are set by the user through an invitation")
	}
	if ext, isMap := getCI(res, schemaIdpUser).(map[string]any); isMap {
		if r, ok, e := str(ext, "role"); e != nil {
			return in, e
		} else if ok {
			role := model.Role(strings.ToLower(strings.TrimSpace(r)))
			if !role.Valid() {
				return in, badValue("role must be user, manager, admin or super_admin")
			}
			in.Role = &role
		}
		if tags, ok, e := parseTags(ext); e != nil {
			return in, e
		} else if ok {
			in.Tags = &tags
		}
		// The end date changes only when the extension names it: a value sets it, null or "" clears it. A PUT that
		// leaves it out (a client that does not know the extension) keeps it; a PATCH that removes it clears it
		// (keepValidUntil).
		if _, present := keyOf(ext, "validUntil"); present {
			v, _, e := str(ext, "validUntil")
			if e != nil {
				return in, e
			}
			in.ValidUntil = &v
		}
	}
	// An email address is required (it is the sign-in name): the primary (else first) email, or userName when that
	// is itself an email address (Entra and Okta usually send the UPN / email there).
	if email = strings.TrimSpace(email); email == "" {
		if in.Username != nil && validEmail(*in.Username) {
			email = strings.TrimSpace(*in.Username)
		} else {
			return in, badValue("an email address is required")
		}
	}
	in.Email = &email
	if in.GivenName == nil && !replace {
		// A first name is required but provisioning clients do not always send one: default it to the part of the
		// email address before the @ rather than refusing the user.
		local, _, _ := strings.Cut(email, "@")
		in.GivenName = &local
	}
	// The remaining emails are the user's verified linked addresses (administrators provision them, so they are
	// verified); PUT and PATCH replace that set, leaving the user's own unverified addresses alone (they are never
	// rendered). Without an emails attribute on create there are none.
	if replace || len(others) > 0 {
		for i := range others {
			if others[i] == email {
				others = slices.Delete(others, i, i+1)
				break
			}
		}
		in.LinkedEmails = &others
	}
	return in, nil
}

// otherEmails lists the values of a multi-valued emails attribute other than primary (trimmed, not de-duplicated).
func otherEmails(v any, primary string) ([]string, *Error) {
	out := []string{}
	for _, e := range asSlice(v) {
		var val string
		switch t := e.(type) {
		case string:
			val = t
		case map[string]any:
			s, _, err := str(t, "value")
			if err != nil {
				return nil, err
			}
			val = s
		}
		if val = strings.TrimSpace(val); val != "" && val != strings.TrimSpace(primary) {
			out = append(out, val)
		}
	}
	return out, nil
}

// diffUser keeps only the fields of in that differ from u, so unchanged fields never reach the RBAC checks.
func diffUser(u *model.User, in service.UserInput) service.UserInput {
	var d service.UserInput
	ch := func(dst **string, p *string, cur string) {
		if p != nil && *p != cur {
			*dst = p
		}
	}
	ch(&d.Username, in.Username, u.Username)
	ch(&d.Email, in.Email, u.Email)
	ch(&d.GivenName, in.GivenName, u.GivenName)
	ch(&d.FamilyName, in.FamilyName, u.FamilyName)
	ch(&d.ExternalID, in.ExternalID, u.ExternalID)
	ch(&d.Locale, in.Locale, u.Locale)
	ch(&d.ZoneInfo, in.ZoneInfo, u.ZoneInfo)
	ch(&d.UserType, in.UserType, u.UserType)
	ch(&d.Phone, in.Phone, u.PhoneNumber)
	cur := ""
	if u.ValidUntil != nil {
		cur = rfc3339(*u.ValidUntil)
	}
	if in.ValidUntil != nil && !sameTime(*in.ValidUntil, cur) {
		d.ValidUntil = in.ValidUntil
	}
	if in.Work != nil {
		var w service.WorkInput
		changed := false
		wc := func(dst **string, p *string, cur string) {
			if p != nil && *p != cur {
				*dst, changed = p, true
			}
		}
		wc(&w.Title, in.Work.Title, u.Work.Title)
		wc(&w.Department, in.Work.Department, u.Work.Department)
		wc(&w.Organization, in.Work.Organization, u.Work.Organization)
		wc(&w.Division, in.Work.Division, u.Work.Division)
		wc(&w.CostCenter, in.Work.CostCenter, u.Work.CostCenter)
		wc(&w.EmployeeNumber, in.Work.EmployeeNumber, u.Work.EmployeeNumber)
		wc(&w.ManagerID, in.Work.ManagerID, u.Work.ManagerID)
		if changed {
			d.Work = &w
		}
	}
	if in.Role != nil && *in.Role != u.Role {
		d.Role = in.Role
	}
	if in.Active != nil && *in.Active != u.Active {
		d.Active = in.Active
	}
	if in.Tags != nil && !slices.Equal(model.NormTags(*in.Tags), model.NormTags(u.Tags)) {
		d.Tags = in.Tags
	}
	if in.LinkedEmails != nil && !sameLinked(u, *in.LinkedEmails, d.Email != nil) {
		d.LinkedEmails = in.LinkedEmails
	}
	return d
}

// sameLinked reports whether the wanted addresses are exactly the user's verified linked addresses (the primary
// changing counts as a change, as it may be promoted out of the list). The user's unverified addresses are not
// rendered to SCIM and take no part in the comparison.
func sameLinked(u *model.User, want []string, primaryChanging bool) bool {
	if primaryChanging {
		return false
	}
	verified := 0
	for _, l := range u.LinkedEmails {
		if l.Verified {
			verified++
		}
	}
	if len(want) != verified {
		return false
	}
	for _, w := range want {
		l, ok := u.LinkedEmail(w)
		if !ok || !l.Verified {
			return false
		}
	}
	return true
}

func emptyInput(in service.UserInput) bool {
	return in.Username == nil && in.Email == nil && in.LinkedEmails == nil && in.GivenName == nil && in.FamilyName == nil &&
		in.Role == nil && in.Active == nil && in.ExternalID == nil && in.Locale == nil && in.ZoneInfo == nil &&
		in.UserType == nil && in.ValidUntil == nil && in.Work == nil && in.Phone == nil &&
		in.Password == nil && in.Verified == nil && in.Tags == nil
}

// ---------------------------------------------------------------------------------------------------------------
// Handlers

func (rq *request) users(id string) {
	if !rq.m.srv.Svc.CanManageUsers(rq.actor, rq.org.ID) {
		writeError(rq.w, errf(403, "", "You do not have permission to manage users"))
		return
	}
	if id == "" {
		switch rq.r.Method {
		case http.MethodGet:
			rq.listUsers()
		case http.MethodPost:
			rq.createUser()
		default:
			rq.allow("GET", "POST")
		}
		return
	}
	switch rq.r.Method {
	case http.MethodGet:
		rq.getUser(id)
	case http.MethodPut:
		rq.replaceUser(id)
	case http.MethodPatch:
		rq.patchUser(id)
	case http.MethodDelete:
		rq.deleteUser(id)
	default:
		rq.allow("GET", "PUT", "PATCH", "DELETE")
	}
}

// loadUser fetches a user of the URL's org (other orgs' users are not found).
func (rq *request) loadUser(id string) (*model.User, error) {
	u, err := rq.m.srv.Svc.GetUser(rq.ctx, rq.actor, id)
	if err != nil {
		return nil, err
	}
	// SCIM shows only users seen in full: someone above the caller is not there at all
	if u.OrgID != rq.org.ID || rq.m.srv.Svc.Visibility(rq.actor, u) != service.Full {
		return nil, service.ErrNotFound
	}
	return u, nil
}

func (rq *request) getUser(id string) {
	u, err := rq.loadUser(id)
	if err != nil {
		rq.fail(err)
		return
	}
	if match := rq.r.Header.Get("If-None-Match"); match != "" && weakEqual(match, versionTag(u.Version)) {
		rq.w.Header().Set("ETag", versionTag(u.Version))
		rq.w.WriteHeader(http.StatusNotModified)
		return
	}
	attrs, excl := rq.getParams()
	gs, err := rq.m.srv.Svc.UserGroups(rq.ctx, u)
	if err != nil {
		rq.fail(err)
		return
	}
	res, err := rq.userResource(u, gs, true)
	if err != nil {
		rq.fail(err)
		return
	}
	rq.respond(http.StatusOK, res, attrs, excl, userSchemas)
}

func (rq *request) createUser() {
	body, e := rq.readBody()
	if e != nil {
		writeError(rq.w, e)
		return
	}
	in, e := rq.userInput(body, nil)
	if e != nil {
		writeError(rq.w, e)
		return
	}
	if in.Role != nil && in.Role.Rank() >= model.RoleAdmin.Rank() {
		writeError(rq.w, errNeedsSession("granting an administrator role"))
		return
	}
	u, err := rq.m.srv.Svc.CreateUser(rq.ctx, rq.actor, rq.org.ID, in)
	if err != nil {
		rq.fail(err)
		return
	}
	attrs, excl := rq.getParams()
	res, err := rq.userResource(u, nil, true)
	if err != nil {
		rq.fail(err)
		return
	}
	rq.respond(http.StatusCreated, res, attrs, excl, userSchemas)
}

// updateUser runs a read-modify-write on one user: mutate edits the current SCIM representation (or replaces it) and
// the result is written back as a minimal service update.
func (rq *request) updateUser(id string, mutate func(cur map[string]any) (map[string]any, *Error)) {
	var result *model.User
	err := rq.retry(id, func() error {
		u, err := rq.loadUser(id)
		if err != nil {
			return err
		}
		if e := ifMatch(rq.r, versionTag(u.Version)); e != nil {
			return e
		}
		cur, err := rq.userResource(u, nil, false)
		if err != nil {
			return err
		}
		next, e := mutate(cur)
		if e != nil {
			return e
		}
		in, e := rq.userInput(next, u)
		if e != nil {
			return e
		}
		in = diffUser(u, in)
		if emptyInput(in) {
			result = u
			return nil
		}
		if in.Role != nil && *in.Role != u.Role && in.Role.Rank() >= model.RoleAdmin.Rank() {
			return errNeedsSession("granting an administrator role")
		}
		// The change was worked out from this copy (and If-Match checked against it): it applies to this copy only.
		// A user changed since is stale: retried from fresh data, or 412 with If-Match.
		in.IfVersion = u.Version
		result, err = rq.m.srv.Svc.UpdateUser(rq.ctx, rq.actor, id, in)
		return err
	})
	if err != nil {
		rq.fail(err)
		return
	}
	attrs, excl := rq.getParams()
	gs, _ := rq.m.srv.Svc.UserGroups(rq.ctx, result)
	res, err := rq.userResource(result, gs, true)
	if err != nil {
		rq.fail(err)
		return
	}
	rq.respond(http.StatusOK, res, attrs, excl, userSchemas)
}

func (rq *request) replaceUser(id string) {
	body, e := rq.readBody()
	if e != nil {
		writeError(rq.w, e)
		return
	}
	rq.updateUser(id, func(map[string]any) (map[string]any, *Error) { return body, nil })
}

func (rq *request) patchUser(id string) {
	body, e := rq.readBody()
	if e != nil {
		writeError(rq.w, e)
		return
	}
	ops, e := parsePatch(body)
	if e != nil {
		writeError(rq.w, e)
		return
	}
	rl := &patchRules{sch: userSchemas, readOnly: map[string]bool{"id": true, "meta": true, "schemas": true, "groups": true}}
	rq.updateUser(id, func(cur map[string]any) (map[string]any, *Error) {
		for _, op := range ops {
			if e := rl.apply(cur, op); e != nil {
				return nil, e
			}
		}
		keepTags(cur, schemaIdpUser)
		keepValidUntil(cur)
		return cur, nil
	})
}

func (rq *request) deleteUser(id string) {
	err := rq.retry(id, func() error {
		u, err := rq.loadUser(id)
		if err != nil {
			return err
		}
		if e := ifMatch(rq.r, versionTag(u.Version)); e != nil {
			return e
		}
		return rq.m.srv.Svc.DeleteUser(rq.ctx, rq.actor, id)
	})
	if err != nil {
		rq.fail(err)
		return
	}
	rq.w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------------------------
// Listing

// userSortField maps a SCIM sort attribute to a store sort field when the store can order by it.
func userSortField(sortBy *attrPath) (field string, ok bool) {
	if sortBy == nil {
		return "", true // the store's default order is by id
	}
	p := *sortBy
	if p.Filter != nil || p.URN != "" {
		return "", false
	}
	switch strings.ToLower(p.Name + "." + p.Sub) {
	case "username.":
		return "username", true
	case "displayname.", "name.formatted":
		return "name", true
	case "emails.", "emails.value":
		return "email", true
	case "active.":
		return "active", true
	case "meta.created":
		return "created", true
	case "id.":
		return "", true // store default order is by id
	}
	return "", false
}

// narrow derives what the store can do for the top-level AND conjuncts of the filter: one user by id or by a unique
// value, or a narrower listing. The full filter is still evaluated in memory afterwards, so this only has to return
// a superset of the matches, unless exact: q is then the whole filter (every conjunct an equality on an indexed
// field), and the store can order and page the matches and tell their number.
func (rq *request) narrow(f node) (id, unique string, q store.ListQuery, exact bool) {
	if f == nil {
		return "", "", q, true
	}
	for _, c := range conjuncts(f) {
		cn, ok := c.(*cmpNode)
		if !ok {
			continue
		}
		p := cn.path
		name := strings.ToLower(p.Name)
		s, isStr := cn.val.(string)
		if p.Filter != nil {
			// emails[type eq "work"].value eq "x" (Entra's matching attribute): the address, whatever the type, is
			// one user at most (every address of a user is a unique value of the organization)
			if p.URN == "" && name == "emails" && strings.EqualFold(p.Sub, "value") && cn.op == "eq" && isStr && s != "" {
				unique = model.UserEmailKey(rq.org.ID, s)
			}
			continue
		}
		switch {
		case p.URN == "" && p.Sub == "" && name == "id" && cn.op == "eq" && isStr && s != "":
			id = s
		case p.URN == "" && p.Sub == "" && name == "username" && cn.op == "eq" && isStr:
			unique = model.UserUsernameKey(rq.org.ID, s)
		case p.URN == "" && p.Sub == "" && name == "externalid" && cn.op == "eq" && isStr && s != "":
			unique = model.UserExternalIDKey(rq.org.ID, s)
		case p.URN == "" && name == "emails" && (p.Sub == "" || strings.EqualFold(p.Sub, "value")) && cn.op == "eq" && isStr && s != "":
			unique = model.UserEmailKey(rq.org.ID, s)
		case p.URN == "" && p.Sub == "" && name == "active" && cn.op == "eq":
			if b, isBool := cn.val.(bool); isBool {
				q.Filters = append(q.Filters, service.ActiveFilter(b))
			}
		case strings.EqualFold(p.URN, schemaIdpUser) && strings.EqualFold(p.Name, "role") && cn.op == "eq" && isStr:
			if r := model.Role(strings.ToLower(s)); r.Valid() {
				q.Filters = append(q.Filters, store.Filter{Field: "role", Value: string(r)})
			}
		// The store's search is a prefix match on the username, address and names: it narrows "eq" and "sw" (the
		// filter itself decides).
		case isStr && s != "" && q.Search == "" && p.URN == "" && (cn.op == "eq" || cn.op == "sw") &&
			((p.Sub == "" && (name == "username" || name == "displayname")) || (name == "emails" && strings.EqualFold(p.Sub, "value"))):
			q.Search = s
		}
	}
	// Each exact conjunct is one filter of q, and nothing else of q is exact.
	return id, unique, q, id == "" && unique == "" && q.Search == "" && len(q.Filters) == len(conjuncts(f))
}

func (rq *request) listUsers() {
	p, e := rq.listParams()
	if e != nil {
		writeError(rq.w, e)
		return
	}
	svc := rq.m.srv.Svc
	needGroups := wantsAttr(p, "groups") || (p.filter != nil && referencesAttr(p.filter, "groups")) ||
		(p.sortBy != nil && strings.EqualFold(p.sortBy.Name, "groups"))
	render := func(users []*model.User) ([]map[string]any, error) {
		var idx map[string][]*model.Group
		if needGroups {
			var err error
			if idx, err = rq.groupIndex(users); err != nil {
				return nil, err
			}
		}
		out := make([]map[string]any, len(users))
		for i, u := range users {
			var err error
			if out[i], err = rq.userResource(u, idx[u.ID], needGroups); err != nil {
				return nil, err
			}
		}
		return out, nil
	}

	id, unique, q, exact := rq.narrow(p.filter)
	if exact {
		// The store orders and pages what the filter says (every user, or those with an indexed value), so only the
		// page is read and rendered, however many users there are. A sort it has no index for is the scan below.
		if field, ok := userSortField(p.sortBy); ok {
			users, total, err := svc.ListUsers(rq.ctx, rq.actor, rq.org.ID, service.FullViewQuery(rq.actor, pageQuery(q, p, field)))
			if err != nil {
				rq.fail(err)
				return
			}
			if p.count == 0 { // only the total was asked for
				users = nil
			}
			items, err := render(users)
			if err != nil {
				rq.fail(err)
				return
			}
			rq.listResponse(items, total, p, userSchemas)
			return
		}
	}
	var users []*model.User
	if id != "" || unique != "" {
		var u *model.User
		var err error
		if id != "" {
			u, err = svc.Users.Get(rq.ctx, id)
		} else {
			u, err = svc.Users.GetByUnique(rq.ctx, unique)
		}
		// Only "not found" is an empty list: any other failure is an error, or a client that is told the user is
		// missing creates it again.
		switch {
		case err == nil:
			if u.OrgID == rq.org.ID && svc.Visibility(rq.actor, u) == service.Full {
				users = []*model.User{u}
			}
		case !errors.Is(err, store.ErrNotFound):
			rq.fail(err)
			return
		}
	} else {
		// What the store cannot express is evaluated in memory over every user the narrowed listing finds, at most
		// maxScan of them (RFC 7644 §3.4.2.2: tooMany).
		var err error
		var n int
		q.Limit = maxScan + 1
		if users, n, err = svc.ListUsers(rq.ctx, rq.actor, rq.org.ID, service.FullViewQuery(rq.actor, q)); err != nil {
			rq.fail(err)
			return
		}
		if n > maxScan {
			writeError(rq.w, errTooMany)
			return
		}
	}
	// Memberships are only read for the rows that are returned, unless the filter or sort needs them for every row.
	filterNeedsGroups := (p.filter != nil && referencesAttr(p.filter, "groups")) ||
		(p.sortBy != nil && strings.EqualFold(p.sortBy.Name, "groups"))
	if filterNeedsGroups || !needGroups {
		items, err := render(users)
		if err != nil {
			rq.fail(err)
			return
		}
		page, total := selectItems(items, p, userSchemas)
		rq.listResponse(page, total, p, userSchemas)
		return
	}
	needGroups = false
	items, err := render(users)
	if err != nil {
		rq.fail(err)
		return
	}
	page, total := selectItems(items, p, userSchemas)
	byID := make(map[string]*model.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	pageUsers := make([]*model.User, 0, len(page))
	for _, it := range page {
		pageUsers = append(pageUsers, byID[it["id"].(string)])
	}
	idx, err := rq.groupIndex(pageUsers)
	if err != nil {
		rq.fail(err)
		return
	}
	for _, it := range page {
		it["groups"] = rq.groupsValue(idx[it["id"].(string)])
	}
	rq.listResponse(page, total, p, userSchemas)
}

// enterpriseValue renders the enterprise extension of u (nil when no work detail other than the title is set).
func (rq *request) enterpriseValue(u *model.User) (map[string]any, error) {
	w := u.Work
	out := map[string]any{}
	for k, v := range map[string]string{"employeeNumber": w.EmployeeNumber, "costCenter": w.CostCenter,
		"organization": w.Organization, "division": w.Division, "department": w.Department} {
		if v != "" {
			out[k] = v
		}
	}
	if w.ManagerID != "" {
		unseen, err := rq.unseenUsers()
		if err != nil {
			return nil, err
		}
		if !unseen[w.ManagerID] { // a manager the caller does not see is not shown
			m := map[string]any{"value": w.ManagerID, "$ref": rq.location("Users", w.ManagerID)}
			if mu, err := rq.m.srv.Svc.Users.Get(rq.r.Context(), w.ManagerID); err == nil && mu.OrgID == u.OrgID {
				m["displayName"] = mu.FullName()
			}
			out["manager"] = m
		}
	}
	return out, nil
}

// profileInput reads the language, time zone, user type, title and enterprise extension of a SCIM user into in.
func (rq *request) profileInput(res map[string]any, in *service.UserInput, existing *model.User,
	optional func(**string, string, bool)) *Error {
	for _, f := range []struct {
		name string
		dst  **string
	}{{"timezone", &in.ZoneInfo}, {"userType", &in.UserType}} {
		v, ok, e := str(res, f.name)
		if e != nil {
			return e
		}
		optional(f.dst, v, ok)
	}
	// locale, else the first preferredLanguage ("en-GB,en;q=0.9" → en-GB)
	loc, hasLoc, e := str(res, "locale")
	if e != nil {
		return e
	}
	if !hasLoc || strings.TrimSpace(loc) == "" {
		if pl, ok, e := str(res, "preferredLanguage"); e != nil {
			return e
		} else if ok {
			first, _, _ := strings.Cut(pl, ",")
			first, _, _ = strings.Cut(first, ";")
			loc, hasLoc = strings.TrimSpace(first), true
		}
	}
	optional(&in.Locale, loc, hasLoc)

	work := &service.WorkInput{}
	title, ok, e := str(res, "title")
	if e != nil {
		return e
	}
	optional(&work.Title, title, ok)
	ent, _ := getCI(res, schemaEnterprise).(map[string]any)
	if ent == nil && getCI(res, schemaEnterprise) != nil {
		return badValue("%s must be an object", schemaEnterprise)
	}
	for _, f := range []struct {
		name string
		dst  **string
	}{{"employeeNumber", &work.EmployeeNumber}, {"costCenter", &work.CostCenter}, {"organization", &work.Organization},
		{"division", &work.Division}, {"department", &work.Department}} {
		v, ok := "", false
		if ent != nil {
			if v, ok, e = str(ent, f.name); e != nil {
				return e
			}
		}
		optional(f.dst, v, ok)
	}
	// The manager is a reference to another user here. One this organization does not have (yet: provisioning
	// clients do not send users in order) is left unset rather than failing the whole user.
	mgr, hasMgr := "", false
	if ent != nil {
		switch m := getCI(ent, "manager").(type) {
		case map[string]any:
			if mgr, hasMgr, e = str(m, "value"); e != nil {
				return e
			}
		case string:
			mgr, hasMgr = m, true
		case nil:
		default:
			return badValue("manager must be an object with a value")
		}
	}
	mgr = strings.TrimSpace(mgr)
	if hasMgr && mgr != "" {
		unseen, err := rq.unseenUsers()
		if err != nil {
			return rq.m.fromService(err)
		}
		if mu, err := rq.m.srv.Svc.Users.Get(rq.r.Context(), mgr); err != nil || mu.OrgID != rq.org.ID ||
			(existing != nil && mu.ID == existing.ID) || unseen[mu.ID] {
			hasMgr, mgr = existing == nil, "" // unknown: unset on create, unchanged on update
			if existing != nil {
				mgr, hasMgr = existing.Work.ManagerID, true
			}
		}
	}
	optional(&work.ManagerID, mgr, hasMgr)
	if work != (&service.WorkInput{}) {
		in.Work = work
	}
	return nil
}

// sameTime reports whether two RFC 3339 times (or both empty) are the same moment.
func sameTime(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	ta, err1 := time.Parse(time.RFC3339, a)
	tb, err2 := time.Parse(time.RFC3339, b)
	return err1 == nil && err2 == nil && ta.Equal(tb)
}
