package scim

import (
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// memberRef is a member as it appears in a group resource.
type memberRef struct{ id, display string }

// groupResource renders g. members is nil when membership is not wanted.
func (rq *request) groupResource(g *model.Group, members []memberRef, withMembers bool) map[string]any {
	res := map[string]any{
		"schemas":     []string{schemaGroup},
		"id":          g.ID,
		"displayName": g.DisplayName,
	}
	if g.ExternalID != "" {
		res["externalId"] = g.ExternalID
	}
	res["schemas"] = []string{schemaGroup, schemaIdpGroup}
	res[schemaIdpGroup] = map[string]any{"tags": tagsValue(g.Tags)}
	if withMembers {
		ms := make([]any, len(members))
		for i, m := range members {
			e := map[string]any{"value": m.id, "type": "User", "$ref": rq.location("Users", m.id)}
			if m.display != "" {
				e["display"] = m.display
			}
			ms[i] = e
		}
		res["members"] = ms
	}
	res["meta"] = map[string]any{
		"resourceType": "Group",
		"created":      rfc3339(g.Created),
		"lastModified": rfc3339(g.Updated),
		"version":      versionTag(g.Version),
		"location":     rq.location("Groups", g.ID),
	}
	return res
}

// memberIndex returns the member user ids of every group of the org, in one pass.
func (rq *request) memberIndex() (map[string][]string, error) {
	ms, _, err := rq.m.srv.Svc.Members.List(rq.ctx, store.ListQuery{Scope: rq.org.ID})
	if err != nil {
		return nil, err
	}
	idx := map[string][]string{}
	unseen := rq.unseenUsers()
	for _, m := range ms {
		if !unseen[m.UserID] {
			idx[m.GroupID] = append(idx[m.GroupID], m.UserID)
		}
	}
	for _, ids := range idx {
		sort.Strings(ids)
	}
	return idx, nil
}

// refs turns user ids into members with display names (one lookup per user for small groups, one scan for large).
func (rq *request) refs(ids []string) []memberRef {
	unseen := rq.unseenUsers()
	ids = slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return unseen[id] })
	out := make([]memberRef, len(ids))
	for i, id := range ids {
		out[i].id = id
	}
	if len(ids) == 0 {
		return out
	}
	svc := rq.m.srv.Svc
	if len(ids) <= 200 {
		for i, id := range ids {
			if u, err := svc.Users.Get(rq.ctx, id); err == nil {
				out[i].display = u.FullName()
			}
		}
		return out
	}
	if users, err := svc.Users.All(rq.ctx, rq.org.ID); err == nil {
		names := make(map[string]string, len(users))
		for _, u := range users {
			names[u.ID] = u.FullName()
		}
		for i := range out {
			out[i].display = names[out[i].id]
		}
	}
	return out
}

// memberIDs reads the member ids out of a group resource; the second result tells whether members were given.
func memberIDs(res map[string]any) ([]string, bool, *Error) {
	raw := getCI(res, "members")
	if raw == nil {
		return nil, false, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, false, badValue("members must be a list")
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(arr))
	for _, e := range arr {
		em, ok := e.(map[string]any)
		if !ok {
			return nil, false, badValue("members must be a list of objects")
		}
		v, ok, err := str(em, "value")
		if err != nil {
			return nil, false, err
		}
		if !ok || v == "" {
			return nil, false, badValue("every member needs a value (the user id)")
		}
		if !seen[v] {
			seen[v] = true
			ids = append(ids, v)
		}
	}
	return ids, true, nil
}

func (rq *request) groupFields(res map[string]any, existing *model.Group) (service.GroupInput, *Error) {
	var in service.GroupInput
	name, ok, e := str(res, "displayName")
	if e != nil {
		return in, e
	}
	if !ok || strings.TrimSpace(name) == "" {
		return in, badValue("displayName is required")
	}
	in.DisplayName = &name
	ext, hasExt, e := str(res, "externalId")
	if e != nil {
		return in, e
	}
	if hasExt || existing != nil {
		in.ExternalID = &ext
	}
	if x, isMap := getCI(res, schemaIdpGroup).(map[string]any); isMap {
		if tags, ok, e := parseTags(x); e != nil {
			return in, e
		} else if ok {
			in.Tags = &tags
		}
	}
	return in, nil
}

func (rq *request) groups(id string) {
	if !rq.m.srv.Svc.CanManageUsers(rq.actor, rq.org.ID) {
		writeError(rq.w, errf(403, "", "You do not have permission to read groups"))
		return
	}
	if id == "" {
		switch rq.r.Method {
		case http.MethodGet:
			rq.listGroups()
		case http.MethodPost:
			rq.createGroup()
		default:
			rq.allow("GET", "POST")
		}
		return
	}
	switch rq.r.Method {
	case http.MethodGet:
		rq.getGroup(id)
	case http.MethodPut:
		rq.replaceGroup(id)
	case http.MethodPatch:
		rq.patchGroup(id)
	case http.MethodDelete:
		rq.deleteGroup(id)
	default:
		rq.allow("GET", "PUT", "PATCH", "DELETE")
	}
}

func (rq *request) loadGroup(id string) (*model.Group, error) {
	g, err := rq.m.srv.Svc.GetGroup(rq.ctx, rq.actor, id)
	if err != nil {
		return nil, err
	}
	if g.OrgID != rq.org.ID {
		return nil, service.ErrNotFound
	}
	return g, nil
}

// groupWithMembers renders a group with its current members.
func (rq *request) groupWithMembers(g *model.Group) (map[string]any, error) {
	ids, err := rq.m.srv.Svc.GroupMembers(rq.ctx, rq.actor, g.ID)
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	return rq.groupResource(g, rq.refs(ids), true), nil
}

func (rq *request) getGroup(id string) {
	g, err := rq.loadGroup(id)
	if err != nil {
		rq.fail(err)
		return
	}
	if match := rq.r.Header.Get("If-None-Match"); match != "" && weakEqual(match, versionTag(g.Version)) {
		rq.w.Header().Set("ETag", versionTag(g.Version))
		rq.w.WriteHeader(http.StatusNotModified)
		return
	}
	res, err := rq.groupWithMembers(g)
	if err != nil {
		rq.fail(err)
		return
	}
	attrs, excl := rq.getParams()
	rq.respond(http.StatusOK, res, attrs, excl, groupSchemas)
}

func (rq *request) createGroup() {
	body, e := rq.readBody()
	if e != nil {
		writeError(rq.w, e)
		return
	}
	in, e := rq.groupFields(body, nil)
	if e != nil {
		writeError(rq.w, e)
		return
	}
	ids, _, e := memberIDs(body)
	if e != nil {
		writeError(rq.w, e)
		return
	}
	svc := rq.m.srv.Svc
	g, err := svc.CreateGroup(rq.ctx, rq.actor, rq.org.ID, in)
	if err != nil {
		rq.fail(err)
		return
	}
	withMembers, err := svc.ChangeGroup(rq.ctx, rq.actor, g, service.GroupInput{}, ids, nil)
	if err != nil {
		_ = svc.DeleteGroup(rq.ctx, rq.actor, g.ID) // roll back: a failed create leaves nothing behind
		rq.fail(err)
		return
	}
	g = withMembers
	attrs, excl := rq.getParams()
	rq.respond(http.StatusCreated, rq.groupResource(g, rq.refs(ids), true), attrs, excl, groupSchemas)
}

// updateGroup is the read-modify-write for PUT and PATCH. keepMembers says that a missing members list means "no
// change" (PUT) rather than "empty" (PATCH, where the patched resource always carries the full list).
func (rq *request) updateGroup(id string, keepMembers bool, mutate func(cur map[string]any) (map[string]any, *Error)) {
	svc := rq.m.srv.Svc
	var result *model.Group
	err := rq.retry(id, func() error {
		g, err := rq.loadGroup(id)
		if err != nil {
			return err
		}
		if e := ifMatch(rq.r, versionTag(g.Version)); e != nil {
			return e
		}
		cur, err := rq.groupWithMembers(g)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for _, m := range asSlice(cur["members"]) {
			have[m.(map[string]any)["value"].(string)] = true
		}
		next, e := mutate(cur) // edits cur in place; have was taken before
		if e != nil {
			return e
		}
		in, e := rq.groupFields(next, g)
		if e != nil {
			return e
		}
		want, given, e := memberIDs(next)
		if e != nil {
			return e
		}
		if !given && keepMembers {
			want = nil
		} else {
			given = true
		}
		var add, remove []string
		if given {
			wantSet := map[string]bool{}
			for _, uid := range want {
				wantSet[uid] = true
				if !have[uid] {
					add = append(add, uid)
				}
			}
			for uid := range have {
				if !wantSet[uid] {
					remove = append(remove, uid)
				}
			}
		}
		result, err = svc.ChangeGroup(rq.ctx, rq.actor, g, in, add, remove)
		return err
	})
	if err != nil {
		rq.fail(err)
		return
	}
	res, err := rq.groupWithMembers(result)
	if err != nil {
		rq.fail(err)
		return
	}
	attrs, excl := rq.getParams()
	rq.respond(http.StatusOK, res, attrs, excl, groupSchemas)
}

func (rq *request) replaceGroup(id string) {
	body, e := rq.readBody()
	if e != nil {
		writeError(rq.w, e)
		return
	}
	rq.updateGroup(id, true, func(map[string]any) (map[string]any, *Error) { return body, nil })
}

func (rq *request) patchGroup(id string) {
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
	rl := &patchRules{sch: groupSchemas, readOnly: map[string]bool{"id": true, "meta": true, "schemas": true}}
	rq.updateGroup(id, false, func(cur map[string]any) (map[string]any, *Error) {
		for _, op := range ops {
			if e := rl.apply(cur, op); e != nil {
				return nil, e
			}
		}
		keepTags(cur, schemaIdpGroup)
		return cur, nil
	})
}

func (rq *request) deleteGroup(id string) {
	err := rq.retry(id, func() error {
		g, err := rq.loadGroup(id)
		if err != nil {
			return err
		}
		if e := ifMatch(rq.r, versionTag(g.Version)); e != nil {
			return e
		}
		return rq.m.srv.Svc.DeleteGroup(rq.ctx, rq.actor, id)
	})
	if err != nil {
		rq.fail(err)
		return
	}
	rq.w.WriteHeader(http.StatusNoContent)
}

func (rq *request) listGroups() {
	p, e := rq.listParams()
	if e != nil {
		writeError(rq.w, e)
		return
	}
	svc := rq.m.srv.Svc
	q := store.ListQuery{}
	var groups []*model.Group
	unique := ""
	if p.filter != nil {
		for _, c := range conjuncts(p.filter) {
			cn, ok := c.(*cmpNode)
			if !ok || cn.path.Filter != nil || cn.path.URN != "" || cn.path.Sub != "" {
				continue
			}
			s, isStr := cn.val.(string)
			if !isStr || s == "" {
				continue
			}
			switch strings.ToLower(cn.path.Name) {
			case "displayname":
				if cn.op == "eq" {
					unique = model.GroupNameKey(rq.org.ID, s)
				} else if cn.op == "co" || cn.op == "sw" || cn.op == "ew" {
					q.Search = s
				}
			case "externalid":
				if cn.op == "eq" {
					unique = model.GroupExternalIDKey(rq.org.ID, s)
				}
			}
		}
	}
	if unique != "" {
		if g, err := svc.Groups.GetByUnique(rq.ctx, unique); err == nil {
			groups = []*model.Group{g}
		}
	} else {
		var err error
		var n int
		q.Limit = maxScan + 1
		if groups, n, err = svc.ListGroups(rq.ctx, rq.actor, rq.org.ID, q); err != nil {
			rq.fail(err)
			return
		}
		if n > maxScan {
			writeError(rq.w, errTooMany)
			return
		}
	}
	needMembers := wantsAttr(p, "members")
	// Members are read for every group only when the filter or sort looks at them; otherwise just for the page.
	allMembers := (p.filter != nil && referencesAttr(p.filter, "members")) ||
		(p.sortBy != nil && strings.EqualFold(p.sortBy.Name, "members"))
	var idx map[string][]string
	if allMembers {
		var err error
		if idx, err = rq.memberIndex(); err != nil {
			rq.fail(err)
			return
		}
	}
	items := make([]map[string]any, len(groups))
	byID := make(map[string]*model.Group, len(groups))
	for i, g := range groups {
		byID[g.ID] = g
		var ms []memberRef
		for _, uid := range idx[g.ID] {
			ms = append(ms, memberRef{id: uid})
		}
		items[i] = rq.groupResource(g, ms, allMembers)
	}
	page, total := selectItems(items, p, groupSchemas)
	if needMembers && !allMembers {
		for _, it := range page {
			g := byID[it["id"].(string)]
			ms, _, err := svc.Members.List(rq.ctx, store.ListQuery{Scope: rq.org.ID,
				Filters: []store.Filter{{Field: "group_id", Value: g.ID}}})
			if err != nil {
				rq.fail(err)
				return
			}
			ids := make([]string, len(ms))
			for i, m := range ms {
				ids[i] = m.UserID
			}
			sort.Strings(ids)
			it["members"] = rq.groupResource(g, rq.refs(ids), true)["members"]
		}
	} else if allMembers && needMembers {
		for _, it := range page {
			ms := idx[it["id"].(string)]
			it["members"] = rq.groupResource(byID[it["id"].(string)], rq.refs(ms), true)["members"]
		}
	}
	rq.listResponse(page, total, p, groupSchemas)
}
