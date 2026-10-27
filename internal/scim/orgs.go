package scim

import (
	"net/http"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// The Organizations resource is quisora's own SCIM extension for super admins: /scim/v2/Organizations.

func (rq *request) orgLocation(id string) string { return rq.base + "/Organizations/" + id }

func (rq *request) orgResource(o *model.Org) map[string]any {
	return map[string]any{
		"schemas":     []string{schemaOrg},
		"id":          o.ID,
		"name":        o.Name,
		"displayName": o.DisplayName,
		"primary":     o.Primary(),
		"settings": map[string]any{
			"passwordLogin": o.Settings.PasswordLogin,
			"passwordReset": o.Settings.PasswordReset,
			"passkeyLogin":  o.Settings.PasskeyLogin,
			"requireMfa":    o.Settings.RequireMFA,
			"sessionTtl":    o.Settings.SessionTTL,
			"sessionIdle":   o.Settings.SessionIdle,
		},
		"meta": map[string]any{
			"resourceType": "Organization",
			"created":      rfc3339(o.Created),
			"lastModified": rfc3339(o.Updated),
			"version":      versionTag(o.Version),
			"location":     rq.orgLocation(o.ID),
		},
	}
}

func intVal(v any, name string) (int, *Error) {
	f, ok := toFloat(v)
	if !ok || f != float64(int(f)) {
		return 0, badValue("%s must be a whole number", name)
	}
	return int(f), nil
}

// orgInput maps an Organization resource to a service input.
func (rq *request) orgInput(res map[string]any, existing *model.Org) (service.OrgInput, *Error) {
	var in service.OrgInput
	name, ok, e := str(res, "name")
	if e != nil {
		return in, e
	}
	if ok {
		in.Name = &name
	} else if existing == nil {
		return in, badValue("name is required")
	}
	if dn, ok, e := str(res, "displayName"); e != nil {
		return in, e
	} else if ok {
		in.DisplayName = &dn
	}
	if raw := getCI(res, "settings"); raw != nil {
		sm, ok := raw.(map[string]any)
		if !ok {
			return in, badValue("settings must be an object")
		}
		s := model.DefaultOrgSettings()
		if existing != nil {
			s = existing.Settings
		}
		for k, v := range sm {
			switch strings.ToLower(k) {
			case "passwordlogin", "passwordreset", "passkeylogin", "requiremfa":
				b, e := parseBool(v, "settings."+k)
				if e != nil {
					return in, e
				}
				switch strings.ToLower(k) {
				case "passwordlogin":
					s.PasswordLogin = b
				case "passwordreset":
					s.PasswordReset = b
				case "passkeylogin":
					s.PasskeyLogin = b
				default:
					s.RequireMFA = b
				}
			case "sessionttl", "sessionidle":
				n, e := intVal(v, "settings."+k)
				if e != nil {
					return in, e
				}
				if strings.EqualFold(k, "sessionttl") {
					s.SessionTTL = n
				} else {
					s.SessionIdle = n
				}
			}
		}
		in.Settings = &s
	}
	return in, nil
}

func (rq *request) organizations(segs []string) {
	if !rq.actor.IsSuper() {
		writeError(rq.w, errf(403, "", "Only super admins can manage organizations"))
		return
	}
	if len(segs) > 1 {
		writeError(rq.w, notFound("Resource"))
		return
	}
	id := ""
	if len(segs) == 1 {
		id = segs[0]
	}
	if id == "" {
		switch rq.r.Method {
		case http.MethodGet:
			rq.listOrgs()
		case http.MethodPost:
			rq.createOrg()
		default:
			rq.allow("GET", "POST")
		}
		return
	}
	switch rq.r.Method {
	case http.MethodGet:
		o, err := rq.m.srv.Svc.GetOrg(rq.ctx, rq.actor, id)
		if err != nil {
			rq.fail(err)
			return
		}
		attrs, excl := rq.getParams()
		rq.respond(http.StatusOK, rq.orgResource(o), attrs, excl, orgSchemas)
	case http.MethodPut:
		body, e := rq.readBody()
		if e != nil {
			writeError(rq.w, e)
			return
		}
		rq.updateOrg(id, func(map[string]any) (map[string]any, *Error) { return body, nil })
	case http.MethodPatch:
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
		rl := &patchRules{sch: orgSchemas, readOnly: map[string]bool{"id": true, "meta": true, "schemas": true, "primary": true}}
		rq.updateOrg(id, func(cur map[string]any) (map[string]any, *Error) {
			for _, op := range ops {
				if e := rl.apply(cur, op); e != nil {
					return nil, e
				}
			}
			return cur, nil
		})
	case http.MethodDelete:
		// Deleting an organization needs a super admin's re-authentication, which only a console session can give:
		// never over SCIM (organizations() admits super admins only).
		writeError(rq.w, errNeedsSession("deleting an organization"))
	default:
		rq.allow("GET", "PUT", "PATCH", "DELETE")
	}
}

func (rq *request) createOrg() {
	body, e := rq.readBody()
	if e != nil {
		writeError(rq.w, e)
		return
	}
	in, e := rq.orgInput(body, nil)
	if e != nil {
		writeError(rq.w, e)
		return
	}
	o, err := rq.m.srv.Svc.CreateOrg(rq.ctx, rq.actor, in)
	if err != nil {
		rq.fail(err)
		return
	}
	attrs, excl := rq.getParams()
	rq.respond(http.StatusCreated, rq.orgResource(o), attrs, excl, orgSchemas)
}

func (rq *request) updateOrg(id string, mutate func(cur map[string]any) (map[string]any, *Error)) {
	svc := rq.m.srv.Svc
	var result *model.Org
	err := rq.retry(id, func() error {
		o, err := svc.GetOrg(rq.ctx, rq.actor, id)
		if err != nil {
			return err
		}
		if e := ifMatch(rq.r, versionTag(o.Version)); e != nil {
			return e
		}
		next, e := mutate(rq.orgResource(o))
		if e != nil {
			return e
		}
		in, e := rq.orgInput(next, o)
		if e != nil {
			return e
		}
		if in.Name != nil && *in.Name == o.Name {
			in.Name = nil
		}
		if in.DisplayName != nil && *in.DisplayName == o.DisplayName {
			in.DisplayName = nil
		}
		if in.Settings != nil && *in.Settings == o.Settings {
			in.Settings = nil
		}
		if in.Settings != nil && o.Primary() && rq.actor.IsSuper() {
			return errNeedsSession("changing the primary organization's sign-in settings")
		}
		result = o
		if in.Name == nil && in.DisplayName == nil && in.Settings == nil {
			return nil
		}
		result, err = svc.UpdateOrg(rq.ctx, rq.actor, id, in)
		return err
	})
	if err != nil {
		rq.fail(err)
		return
	}
	attrs, excl := rq.getParams()
	rq.respond(http.StatusOK, rq.orgResource(result), attrs, excl, orgSchemas)
}

func (rq *request) listOrgs() {
	p, e := rq.listParams()
	if e != nil {
		writeError(rq.w, e)
		return
	}
	svc := rq.m.srv.Svc
	q := store.ListQuery{}
	if p.filter != nil {
		for _, c := range conjuncts(p.filter) {
			if cn, ok := c.(*cmpNode); ok && cn.path.Filter == nil && cn.path.URN == "" && cn.path.Sub == "" {
				if s, isStr := cn.val.(string); isStr && s != "" && q.Search == "" {
					switch strings.ToLower(cn.path.Name) {
					case "name", "displayname":
						if cn.op == "eq" || cn.op == "sw" { // a prefix match: it narrows these only
							q.Search = s
						}
					}
				}
			}
		}
	}
	orgs, _, err := svc.ListOrgs(rq.ctx, rq.actor, q)
	if err != nil {
		rq.fail(err)
		return
	}
	items := make([]map[string]any, len(orgs))
	for i, o := range orgs {
		items[i] = rq.orgResource(o)
	}
	page, total := selectItems(items, p, orgSchemas)
	rq.listResponse(page, total, p, orgSchemas)
}
