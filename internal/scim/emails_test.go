package scim_test

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func emailValues(r resp) (primary string, others []string) {
	for _, x := range r.list("emails") {
		m := x.(map[string]any)
		if m["primary"] == true {
			primary = m["value"].(string)
		} else {
			others = append(others, m["value"].(string))
		}
	}
	return
}

func TestSCIMEmailsMapToPrimaryAndLinked(t *testing.T) {
	e := newEnv(t)
	body := map[string]any{"userName": "paul", "name": map[string]any{"givenName": "Paul"},
		"emails": []any{
			map[string]any{"value": "paul@the7thdream.com", "type": "work"},
			map[string]any{"value": "paul.arlott@gmail.com", "type": "home", "primary": true},
			map[string]any{"value": "paul@other.example", "type": "other"},
		}}
	r := e.createUser("acme", e.admA, body)
	if r.Status != 201 {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	primary, others := emailValues(r)
	if primary != "paul.arlott@gmail.com" || len(others) != 2 {
		t.Fatalf("emails %s", r.Raw)
	}
	id := r.str("id")
	// linked addresses provisioned by SCIM are verified
	u, _ := e.Svc.Users.Get(e.ctx, id)
	if len(u.LinkedEmails) != 2 || !u.LinkedEmails[0].Verified || !u.LinkedEmails[1].Verified {
		t.Fatalf("stored %+v", u.LinkedEmails)
	}
	// without a primary flag the first value is the primary
	r = e.createUser("acme", e.admA, map[string]any{"userName": "first", "emails": []any{
		map[string]any{"value": "first@acme.test"}, map[string]any{"value": "first2@acme.test"}}})
	if p, o := emailValues(r); r.Status != 201 || p != "first@acme.test" || len(o) != 1 {
		t.Fatalf("first is primary: %s", r.Raw)
	}

	// PUT replaces the linked set
	put := e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, map[string]any{"userName": "paul", "name": map[string]any{"givenName": "Paul"},
		"emails": []any{map[string]any{"value": "paul.arlott@gmail.com", "primary": true}, map[string]any{"value": "new@acme.test"}}})
	if p, o := emailValues(put); put.Status != 200 || p != "paul.arlott@gmail.com" || len(o) != 1 || o[0] != "new@acme.test" {
		t.Fatalf("put: %d %s", put.Status, put.Raw)
	}
	// PUT without emails other than the primary clears them
	put = e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, map[string]any{"userName": "paul", "emails": mail("paul.arlott@gmail.com")})
	if _, o := emailValues(put); put.Status != 200 || len(o) != 0 {
		t.Fatalf("put clears: %s", put.Raw)
	}
	// PATCH add / remove a linked address
	r = e.patch(id, op("add", "emails", []any{map[string]any{"value": "added@acme.test", "type": "other"}}))
	if _, o := emailValues(r); r.Status != 200 || len(o) != 1 || o[0] != "added@acme.test" {
		t.Fatalf("patch add: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("remove", `emails[value eq "added@acme.test"]`, nil))
	if _, o := emailValues(r); r.Status != 200 || len(o) != 0 {
		t.Fatalf("patch remove: %d %s", r.Status, r.Raw)
	}
	// making a linked address primary through PATCH swaps them
	e.patch(id, op("add", "emails", []any{map[string]any{"value": "swap@acme.test"}}))
	r = e.patch(id, op("add", "emails", []any{map[string]any{"value": "swap@acme.test", "primary": true}}))
	if p, o := emailValues(r); r.Status != 200 || p != "swap@acme.test" || len(o) != 1 || o[0] != "paul.arlott@gmail.com" {
		t.Fatalf("primary swap: %d %s", r.Status, r.Raw)
	}
	// filtering finds a user by a linked address
	f := e.do("GET", `/scim/v2/acme/Users?filter=emails.value%20eq%20%22paul.arlott@gmail.com%22`, e.admA, nil)
	if f.total() != 1 {
		t.Fatalf("filter on a linked address: %s", f.Raw)
	}
}

func TestSCIMEmailClashesAre409(t *testing.T) {
	e := newEnv(t)
	e.createUser("acme", e.admA, map[string]any{"userName": "owner", "emails": []any{
		map[string]any{"value": "owner@acme.test", "primary": true}, map[string]any{"value": "shared@acme.test"}}})
	// linked address already someone's linked address
	r := e.createUser("acme", e.admA, map[string]any{"userName": "dup1", "emails": []any{
		map[string]any{"value": "dup1@acme.test", "primary": true}, map[string]any{"value": "shared@acme.test"}}})
	if r.Status != 409 || r.str("scimType") != "uniqueness" {
		t.Fatalf("linked clash: %d %s", r.Status, r.Raw)
	}
	// linked address already someone's primary
	r = e.createUser("acme", e.admA, map[string]any{"userName": "dup2", "emails": []any{
		map[string]any{"value": "dup2@acme.test", "primary": true}, map[string]any{"value": "owner@acme.test"}}})
	if r.Status != 409 || r.str("scimType") != "uniqueness" {
		t.Fatalf("primary clash: %d %s", r.Status, r.Raw)
	}
	// primary equal to someone's linked address
	r = e.createUser("acme", e.admA, map[string]any{"userName": "dup3", "emails": mail("shared@acme.test")})
	if r.Status != 409 {
		t.Fatalf("primary onto linked: %d %s", r.Status, r.Raw)
	}
	// PUT / PATCH of another user onto it
	id := e.mk("other", nil)
	put := e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, map[string]any{"userName": "other", "emails": []any{
		map[string]any{"value": "other@acme.test", "primary": true}, map[string]any{"value": "shared@acme.test"}}})
	if put.Status != 409 || put.str("scimType") != "uniqueness" {
		t.Fatalf("put clash: %d %s", put.Status, put.Raw)
	}
	r = e.patch(id, op("add", "emails", []any{map[string]any{"value": "shared@acme.test"}}))
	if r.Status != 409 {
		t.Fatalf("patch clash: %d %s", r.Status, r.Raw)
	}
	// too many
	many := []any{map[string]any{"value": "many@acme.test", "primary": true}}
	for i := 0; i < model.MaxLinkedEmails+1; i++ {
		many = append(many, map[string]any{"value": "m" + string(rune('a'+i)) + "@acme.test"})
	}
	if r = e.createUser("acme", e.admA, map[string]any{"userName": "many", "emails": many}); r.Status != 400 {
		t.Fatalf("too many: %d %s", r.Status, r.Raw)
	}
}

func TestSCIMNames(t *testing.T) {
	e := newEnv(t)
	// displayName alone is the first name; responses derive displayName from first + last
	r := e.createUser("acme", e.admA, map[string]any{"userName": "cher", "displayName": "Cher"})
	if r.Status != 201 || r.str("name", "givenName") != "Cher" || r.str("displayName") != "Cher" || r.str("name", "formatted") != "Cher" {
		t.Fatalf("displayName only: %s", r.Raw)
	}
	// displayName is ignored when name.givenName is present
	r = e.createUser("acme", e.admA, map[string]any{"userName": "pat", "displayName": "Ignored Name",
		"name": map[string]any{"givenName": "Pat", "familyName": "Lee"}})
	if r.str("displayName") != "Pat Lee" || r.str("name", "formatted") != "Pat Lee" {
		t.Fatalf("derived name: %s", r.Raw)
	}
	// neither: the first name defaults to the part of the address before the @
	r = e.createUser("acme", e.admA, map[string]any{"userName": "anon"})
	if r.Status != 201 || r.str("name", "givenName") != "anon" {
		t.Fatalf("default first name: %s", r.Raw)
	}
	// a PUT without a name keeps the first name (never cleared)
	put := e.do("PUT", "/scim/v2/acme/Users/"+r.str("id"), e.admA, map[string]any{"userName": "anon", "emails": mail("anon@acme.test")})
	if put.Status != 200 || put.str("name", "givenName") != "anon" {
		t.Fatalf("put without a name: %s", put.Raw)
	}
	// sorting by displayName works
	if z := e.do("GET", "/scim/v2/acme/Users?sortBy=displayName", e.admA, nil); z.Status != 200 {
		t.Fatalf("sortBy displayName: %d", z.Status)
	}
}

// An unverified address (added from the admin page, its link not yet followed) is never shown to SCIM, so a
// provisioning write (PATCH of anything else, or a PUT of what the client read) cannot vouch for it: it stays
// unverified and cannot be made primary.
func TestSCIMKeepsPendingAddressUnverified(t *testing.T) {
	e := newEnv(t)
	r := e.createUser("acme", e.admA, map[string]any{"userName": "selfie", "emails": []any{
		map[string]any{"value": "selfie@acme.test", "primary": true}, map[string]any{"value": "dir@acme.test"}}})
	if r.Status != 201 {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	u, err := e.Svc.AddLinkedEmail(e.ctx, service.System, id, "mine@elsewhere.test", false)
	if err != nil || u.LinkedEmails[len(u.LinkedEmails)-1].Verified {
		t.Fatalf("pending add: %v", err)
	}
	self := service.ActorForUser(u, "")
	// GET does not show it
	g := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	if _, o := emailValues(g); len(o) != 1 || o[0] != "dir@acme.test" {
		t.Fatalf("rendered linked addresses: %s", g.Raw)
	}
	// an unrelated PATCH, then a PUT of what was read back
	if p := e.patch(id, op("replace", "name.familyName", "Smith")); p.Status != 200 {
		t.Fatalf("patch: %d %s", p.Status, p.Raw)
	}
	g = e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	g.Body["name"] = map[string]any{"givenName": "Selfie", "familyName": "Jones"}
	if p := e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, g.Body); p.Status != 200 {
		t.Fatalf("put: %d %s", p.Status, p.Raw)
	}
	u, _ = e.Svc.Users.Get(e.ctx, id)
	l, ok := u.LinkedEmail("mine@elsewhere.test")
	if !ok || l.Verified {
		t.Fatalf("pending address after SCIM writes: %+v (linked=%v)", l, ok)
	}
	if d, ok := u.LinkedEmail("dir@acme.test"); !ok || !d.Verified {
		t.Fatalf("directory address: %+v", u.LinkedEmails)
	}
	if _, err := e.Svc.MakePrimary(service.SelfService(e.ctx), self, id, "mine@elsewhere.test"); err == nil {
		t.Fatal("an unverified address became primary")
	}
	// The directory naming the address itself does vouch for it.
	if p := e.patch(id, op("add", "emails", []any{map[string]any{"value": "mine@elsewhere.test"}})); p.Status != 200 {
		t.Fatalf("patch add: %d %s", p.Status, p.Raw)
	}
	u, _ = e.Svc.Users.Get(e.ctx, id)
	if l, ok := u.LinkedEmail("mine@elsewhere.test"); !ok || !l.Verified {
		t.Fatalf("directory-added address: %+v", u.LinkedEmails)
	}
}

// A PUT that leaves out the Quisora extension (a client that does not know it) keeps the end date; naming it with
// null clears it, and a PATCH that removes it clears it.
func TestSCIMPutKeepsValidUntil(t *testing.T) {
	e := newEnv(t)
	id := e.mk("temp", map[string]any{quisoraURN: map[string]any{"validUntil": "2099-03-01T00:00:00Z"}})
	put := e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, map[string]any{"userName": "temp", "emails": mail("temp@acme.test")})
	if put.Status != 200 || put.str(quisoraURN, "validUntil") != "2099-03-01T00:00:00Z" {
		t.Fatalf("put without the extension: %d %s", put.Status, put.Raw)
	}
	put = e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, map[string]any{"userName": "temp", "emails": mail("temp@acme.test"),
		quisoraURN: map[string]any{"role": "user"}})
	if put.Status != 200 || put.str(quisoraURN, "validUntil") != "2099-03-01T00:00:00Z" {
		t.Fatalf("put with the extension but no validUntil: %d %s", put.Status, put.Raw)
	}
	put = e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, map[string]any{"userName": "temp", "emails": mail("temp@acme.test"),
		quisoraURN: map[string]any{"validUntil": nil}})
	if put.Status != 200 || put.str(quisoraURN, "validUntil") != "" {
		t.Fatalf("put clearing validUntil: %d %s", put.Status, put.Raw)
	}
	if u, _ := e.Svc.Users.Get(e.ctx, id); u.ValidUntil != nil {
		t.Fatalf("stored end date %v", u.ValidUntil)
	}
}

// An address added through SCIM is verified, so it is a sign-in address: an administrator's provisioning token
// cannot add one to a manager or administrator who already signs in (here, with a password), which would let whoever
// controls the address take the account over through upstream sign-in. Only a super admin resets such a sign-in.
func TestPatchCannotLinkEmailToEstablishedAdmin(t *testing.T) {
	e := newEnv(t)
	target := e.mkUser(e.orgA, "privileged-target", model.RoleAdmin)
	password := "correct horse battery staple 9"
	if _, err := e.Svc.UpdateUser(e.ctx, service.System, target.ID, service.UserInput{Password: &password}); err != nil {
		t.Fatal(err)
	}
	address := "attacker@controlled.example"
	r := e.do("PATCH", "/scim/v2/acme/Users/"+target.ID, e.admA, patchBody(op("add", "emails", []any{map[string]any{"value": address, "type": "other"}})))
	if r.Status != 400 || r.str("scimType") != "invalidValue" || !strings.Contains(r.str("detail"), "only a super admin") {
		t.Errorf("adding an address to an established admin: %d %s", r.Status, r.Raw)
	}
	if matched, err := e.Svc.UsersByVerifiedEmail(e.ctx, e.orgA.ID, []string{address}); err != nil || len(matched) != 0 {
		t.Fatalf("the address signs in: %d matches, %v", len(matched), err)
	}
}
