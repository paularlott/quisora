package scim_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// SCIM shows only users the caller sees in full: a manager's token in the primary organization finds neither its
// administrators nor its super admins, by listing, count, an exact userName filter, an id, or a group's members.
func TestSCIMVisibility(t *testing.T) {
	e := newEnv(t)
	p := e.primary()
	mgr := e.mkUser(p, "pm", model.RoleManager)
	adm := e.mkUser(p, "pa", model.RoleAdmin)
	plain := e.mkUser(p, "pp", model.RoleUser)
	g, err := e.Svc.CreateGroup(e.ctx, service.System, p.ID, service.GroupInput{DisplayName: ptr("All")})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{e.Admin.ID, adm.ID, plain.ID} {
		if err := e.Svc.SetMembership(e.ctx, service.System, g.ID, id, true); err != nil {
			t.Fatal(err)
		}
	}
	tok := e.token(mgr, "scim")
	base := "/scim/v2/" + p.Name

	r := e.do("GET", base+"/Users?count=100", tok, nil)
	if r.Status != 200 {
		t.Fatalf("list: %d %s", r.Status, r.Raw)
	}
	for _, hidden := range []string{e.Admin.ID, adm.ID} {
		if strings.Contains(string(r.Raw), hidden) {
			t.Errorf("listed a user above the manager: %s", hidden)
		}
	}
	if !strings.Contains(string(r.Raw), plain.ID) || int(r.Body["totalResults"].(float64)) != len(r.list("Resources")) {
		t.Errorf("list: %s", r.Raw)
	}
	if c := e.do("GET", base+"/Users?count=0", tok, nil); int(c.Body["totalResults"].(float64)) != len(r.list("Resources")) {
		t.Errorf("count only: %v", c.Body["totalResults"])
	}
	for _, u := range []*model.User{e.Admin, adm} {
		f := e.do("GET", base+"/Users?filter="+url.QueryEscape(`userName eq "`+u.Username+`"`), tok, nil)
		if len(f.list("Resources")) != 0 {
			t.Errorf("exact filter finds %s", u.Username)
		}
		if g := e.do("GET", base+"/Users/"+u.ID, tok, nil); g.Status != 404 {
			t.Errorf("get %s: %d", u.Username, g.Status)
		}
	}
	gr := e.do("GET", base+"/Groups/"+g.ID, tok, nil)
	if gr.Status != 200 || len(gr.list("members")) != 1 || strings.Contains(string(gr.Raw), adm.ID) || strings.Contains(string(gr.Raw), e.Admin.ID) {
		t.Errorf("group members: %d %s", gr.Status, gr.Raw)
	}
	if f := e.do("GET", base+"/Groups?filter="+url.QueryEscape(`members.value eq "`+adm.ID+`"`), tok, nil); len(f.list("Resources")) != 0 {
		t.Errorf("a membership filter finds the administrator's group: %s", f.Raw)
	}
}
