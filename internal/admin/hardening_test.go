package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// Administrators can list and revoke another user's personal API tokens; the role limits still apply.
func TestAdminListsAndRevokesUserTokens(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	alan := w.users["user"]
	tok, plain, err := w.env.Svc.CreateAPIToken(ctx, service.ActorForUser(alan, ""), service.APITokenInput{Name: "ci", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	ad := w.as("admin")
	r := ad.get(AU + "/" + alan.ID + "/tokens")
	want(t, r, 200)
	if r.total() != 1 || r.items()[0].(map[string]any)["id"] != tok.ID || strings.Contains(string(r.Raw), plain) ||
		r.items()[0].(map[string]any)["name"] != "ci" {
		t.Fatalf("token list: %s", r.Raw)
	}
	// another user's token id under this user is not found; another org's user is not found
	want(t, ad.delete(AU+"/"+w.users["manager"].ID+"/tokens/"+tok.ID), 404)
	want(t, ad.get(G+"/users/"+w.users["other"].ID+"/tokens"), 404)
	// a manager cannot manage an admin's tokens
	want(t, w.as("manager").get(AU+"/"+w.users["admin"].ID+"/tokens"), 403)

	want(t, ad.delete(AU+"/"+alan.ID+"/tokens/"+tok.ID), 200)
	if _, _, err := w.env.Svc.ValidateAPIToken(ctx, plain); err == nil {
		t.Fatal("revoked token still valid")
	}
	if r := ad.get(AU + "/" + alan.ID + "/tokens"); r.total() != 0 {
		t.Fatalf("after revoke: %s", r.Raw)
	}
	if len(auditActions(t, w, "apitoken.delete")) != 1 {
		t.Fatal("revocation not audited")
	}
}

// The Bearer scheme name is case-insensitive.
func TestBearerSchemeCaseInsensitive(t *testing.T) {
	w := newWorld(t)
	st := w.withBearer("super", service.ScopeAdmin)
	tok := st.bearer
	st.bearer = ""
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		want(t, st.do("GET", "/api/v1/orgs", nil, "Authorization", scheme+" "+tok), 200)
	}
}

// The OpenAPI document matches what the handlers do: the rotate response, the member schema, the backup scope and
// the 503 answers.
func TestOpenAPIDetails(t *testing.T) {
	w := newWorld(t)
	r := w.anon().get("/api/openapi.json")
	want(t, r, 200)
	var doc struct {
		Paths map[string]map[string]struct {
			Security   []map[string][]string      `json:"security"`
			Responses  map[string]json.RawMessage `json:"responses"`
			Parameters []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
		} `json:"paths"`
		Comps struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(r.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	if b := doc.Paths["/api/v1/backup"]["get"]; len(b.Security) != 2 || b.Security[1]["bearer"][0] != "backup" {
		t.Errorf("backup security: %+v", b.Security)
	}
	in := map[string]string{}
	for _, p := range doc.Paths["/api/v1/backup"]["get"].Parameters {
		in[p.Name] = p.In
	}
	if in["plain"] != "query" || in["X-Backup-Password"] != "header" {
		t.Errorf("backup parameters: %v", in)
	}
	if _, ok := doc.Paths["/api/v1/orgs/{org}/users"]["post"].Responses["503"]; !ok {
		t.Error("no 503 response")
	}
	if p := doc.Comps.Schemas["Member"].Properties; p["name"] == nil || p["display_name"] != nil {
		t.Errorf("Member schema: %v", p)
	}
	if !strings.Contains(string(r.Raw), `"#/components/schemas/KeyRotated"`) || doc.Comps.Schemas["KeyRotated"].Properties["rotated"] == nil {
		t.Error("rotate response schema")
	}
	rot := w.as("super").post("/api/v1/keys/rotate", nil)
	if rot.Status == 200 && rot.JSON["rotated"] != true {
		t.Errorf("rotate response: %s", rot.Raw)
	}
}
