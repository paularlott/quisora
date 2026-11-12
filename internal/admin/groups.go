package admin

import (
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

func (m *Module) groupFor(w http.ResponseWriter, r *http.Request, org *model.Org, a *service.Actor) (*model.Group, bool) {
	g, err := m.s.Svc.GetGroup(r.Context(), a, r.PathValue("id"))
	if unanswered(w, err) {
		return nil, false
	}
	if err != nil || g.OrgID != org.ID {
		web.WriteError(w, service.ErrNotFound)
		return nil, false
	}
	return g, true
}

// groupView is a group as the management API shows it (tags are never null), with its number of members.
type groupView struct {
	*model.Group
	Tags    []string `json:"tags"`
	Members int      `json:"members"`
}

func (m *Module) groupViewOf(r *http.Request, g *model.Group) groupView {
	n, _ := m.s.Svc.GroupMemberCount(r.Context(), web.Actor(r), g)
	return groupView{Group: g, Tags: nonNilTags(g.Tags), Members: n}
}

func (m *Module) listGroups(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	q := listQuery(r)
	if tag := r.URL.Query().Get("tag"); tag != "" { // exactly this tag (search matches names, not tags)
		q.Filters = append(q.Filters, store.Filter{Field: "tags", Value: tag})
	}
	items, total, err := m.s.Svc.ListGroups(r.Context(), a, org.ID, q)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	views := make([]groupView, len(items))
	for i, g := range items {
		views[i] = m.groupViewOf(r, g)
	}
	writeList(w, views, total)
}

func (m *Module) getGroup(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	if g, found := m.groupFor(w, r, org, a); found {
		web.WriteJSON(w, http.StatusOK, m.groupViewOf(r, g))
	}
}

func (m *Module) createGroup(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.GroupInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	g, err := m.s.Svc.CreateGroup(r.Context(), a, org.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, m.groupViewOf(r, g))
}

func (m *Module) updateGroup(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	g, found := m.groupFor(w, r, org, a)
	if !found {
		return
	}
	var in service.GroupInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	upd, err := m.s.Svc.UpdateGroup(r.Context(), a, g.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.groupViewOf(r, upd))
}

func (m *Module) deleteGroup(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	g, found := m.groupFor(w, r, org, a)
	if !found {
		return
	}
	if err := m.s.Svc.DeleteGroup(r.Context(), a, g.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

type memberView struct {
	ID       string     `json:"id"`
	Username string     `json:"username"`
	Name     string     `json:"name"`
	Email    string     `json:"email"`
	Role     model.Role `json:"role"`
}

// listMembers pages through a group's members (?offset=&limit=); members are ordered as stored.
func (m *Module) listMembers(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	g, found := m.groupFor(w, r, org, a)
	if !found {
		return
	}
	ids, err := m.s.Svc.GroupMembers(r.Context(), a, g.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	q := listQuery(r)
	total := len(ids)
	lo := min(q.Offset, total)
	hi := min(lo+q.Limit, total)
	out := make([]memberView, 0, hi-lo)
	users, err := m.s.Svc.GetUsers(r.Context(), a, ids[lo:hi]) // the page's members in one read
	if err != nil {
		web.WriteError(w, err)
		return
	}
	for _, u := range users {
		out = append(out, memberView{ID: u.ID, Username: u.Username, Name: u.FullName(), Email: u.Email, Role: u.Role})
	}
	writeList(w, out, total)
}

func (m *Module) addMember(w http.ResponseWriter, r *http.Request) { m.setMember(w, r, true) }
func (m *Module) removeMember(w http.ResponseWriter, r *http.Request) {
	m.setMember(w, r, false)
}

func (m *Module) setMember(w http.ResponseWriter, r *http.Request, member bool) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	g, found := m.groupFor(w, r, org, a)
	if !found {
		return
	}
	if err := m.s.Svc.SetMembership(r.Context(), a, g.ID, r.PathValue("user"), member); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}
