package scim_test

import (
	"net/url"
	"strings"
	"testing"
)

// Language, time zone, user type, end date and the manager reference round-trip, and the new attributes filter.
func TestProfileAndEnterprise(t *testing.T) {
	e := newEnv(t)
	bossID := e.mk("boss", map[string]any{"name": map[string]any{"givenName": "Big", "familyName": "Boss"}})
	id := e.mk("pat", map[string]any{
		"userType": "contractor", "timezone": "Europe/Paris", "preferredLanguage": "fr-FR,fr;q=0.9,en;q=0.5",
		entURN:     map[string]any{"department": "QA", "costCenter": "CC-7", "manager": map[string]any{"value": bossID}},
		quisoraURN: map[string]any{"validUntil": "2099-03-01T00:00:00Z"},
	})
	g := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	if g.Status != 200 || g.str("userType") != "contractor" || g.str("timezone") != "Europe/Paris" || g.str("locale") != "fr-FR" ||
		g.str(entURN, "department") != "QA" || g.str(entURN, "manager", "value") != bossID ||
		g.str(entURN, "manager", "displayName") != "Big Boss" || !strings.HasSuffix(g.str(entURN, "manager", "$ref"), "/Users/"+bossID) ||
		g.str(quisoraURN, "validUntil") != "2099-03-01T00:00:00Z" {
		t.Fatalf("round trip: %s", g.Raw)
	}
	// a bad time zone is refused
	if r := e.patch(id, op("Replace", "timezone", "Mars/Base")); r.Status != 400 {
		t.Errorf("bad time zone: %d", r.Status)
	}
	// filters on the new attributes; a listing names the manager as a read of the user does (the managers of a page
	// are read together)
	for _, f := range []string{`userType eq "contractor"`, entURN + `:department eq "QA"`} {
		r := e.do("GET", "/scim/v2/acme/Users?filter="+url.QueryEscape(f), e.admA, nil)
		if r.Status != 200 || len(r.list("Resources")) != 1 || !strings.Contains(string(r.Raw), `"displayName":"Big Boss"`) {
			t.Errorf("filter %s: %d %s", f, r.Status, r.Raw)
		}
	}
	// The manager may be given as a bare id too; one of another organization is left unset rather than refused.
	r := e.createUser("acme", e.admA, map[string]any{"userName": "bare-boss", entURN: map[string]any{"manager": e.users["mgr-a"].ID}})
	if r.Status != 201 || r.str(entURN, "manager", "value") != e.users["mgr-a"].ID {
		t.Errorf("manager as a bare id: %d %s", r.Status, r.Raw)
	}
	r = e.createUser("acme", e.admA, map[string]any{"userName": "foreign-boss", entURN: map[string]any{"manager": e.users["adm-b"].ID}})
	if r.Status != 201 || strings.Contains(string(r.Raw), e.users["adm-b"].ID) {
		t.Errorf("manager of another organization: %d %s", r.Status, r.Raw)
	}
	// removing the manager and the end date
	r = e.patch(id, op("Remove", entURN+":manager", nil), op("Remove", quisoraURN+":validUntil", nil))
	if r.Status != 200 || strings.Contains(string(r.Raw), "manager") || strings.Contains(string(r.Raw), "validUntil") {
		t.Errorf("remove: %d %s", r.Status, r.Raw)
	}
}

// phoneNumbers: the primary (else first) number is kept in E.164 form; one that is not international is ignored
// rather than failing the user; a replace without phoneNumbers clears it.
func TestPhoneNumbers(t *testing.T) {
	e := newEnv(t)
	id := e.mk("pat", map[string]any{"phoneNumbers": []any{
		map[string]any{"value": "+1 415 555 0100", "type": "home"},
		map[string]any{"value": "+44 20 7946 0958", "type": "work", "primary": true}}})
	g := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	if !strings.Contains(string(g.Raw), `"phoneNumbers":[{"primary":true,"type":"work","value":"+442079460958"}]`) {
		t.Fatalf("stored: %s", g.Raw)
	}
	if r := e.patch(id, op("Replace", "phoneNumbers", []any{map[string]any{"value": "020 7946 0958"}})); r.Status != 200 ||
		!strings.Contains(string(r.Raw), "+442079460958") {
		t.Fatalf("local number: %d %s", r.Status, r.Raw)
	}
	if r := e.patch(id, op("Remove", "phoneNumbers", nil)); r.Status != 200 || strings.Contains(string(r.Raw), "phoneNumbers") {
		t.Fatalf("removed: %d %s", r.Status, r.Raw)
	}
	// A number added by sub-attribute or filtered path is kept the same way; addresses are accepted and ignored.
	ph := map[string]any{"value": "+441632960961", "type": "work"}
	for _, o := range []map[string]any{op("add", "phoneNumbers.value", "+441632960961"), op("add", `phoneNumbers[type eq "work"]`, ph)} {
		if r := e.patch(id, o); r.Status != 200 || !strings.Contains(string(r.Raw), "+441632960961") {
			t.Errorf("%v: %d %s", o, r.Status, r.Raw)
		}
	}
	if r := e.patch(id, op("add", "addresses", []any{ph})); r.Status != 200 || r.Body["addresses"] != nil {
		t.Errorf("addresses: %d %s", r.Status, r.Raw)
	}
}
