package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

const (
	topicsType = "https://example.com/topics"
	otherType  = "urn:example:other"
)

// detailsOf returns the authorization_details of a token's claims or a JSON response, re-encoded compact.
func detailsOf(t *testing.T, m map[string]any) string {
	t.Helper()
	v, ok := m["authorization_details"]
	if !ok {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func rawDetails(s string) *json.RawMessage {
	r := json.RawMessage(s)
	return &r
}

// adSetup is a members-only tenant whose client uses the topics and other types, and a group access of the user's
// carrying details of those types, one of a type the client does not use, and one for a single API (locations).
func adSetup(t *testing.T) (*harness, *model.Client, string) {
	h := setup(t, nil)
	ctx := context.Background()
	tn := h.tenant("hub", membersOnly())
	cl, secret := h.tenantClient(tn, func(in *service.ClientInput) {
		in.AuthorizationDetailsTypes = &[]string{topicsType, otherType, " " + otherType + " "}
	})
	g, err := h.env.Svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("Readers")})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.SetMembership(ctx, h.admin, g.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateMembership(h.env.Primary.ID)
	h.grant(tn, model.SubjectGroup, g.ID, service.AccessInput{AuthorizationDetails: rawDetails(`[
		{"type": "` + topicsType + `", "actions": ["subscribe"], "topics": [{"match": "https://chat.example/users/{{sub}}"}]},
		{"type": "` + otherType + `", "identifier": "{{tenant}}"},
		{"type": "urn:example:unused"},
		{"type": "` + otherType + `", "locations": ["https://api.example/a"], "actions": ["write"]}]`)})
	// the user's own entry repeats one of the group's details: it is issued once
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{AuthorizationDetails: rawDetails(
		`[{"type": "` + otherType + `", "identifier": "{{tenant}}"}]`)})
	return h, cl, secret
}

func TestAuthorizationDetailsIssued(t *testing.T) {
	t.Parallel()
	h, cl, secret := adSetup(t)
	tenant := cl.TenantID
	topics := `{"actions":["subscribe"],"topics":[{"match":"https://chat.example/users/` + h.user.ID + `"}],"type":"` + topicsType + `"}`
	other := `{"identifier":"` + tenant + `","type":"` + otherType + `"}`
	located := `{"actions":["write"],"locations":["https://api.example/a"],"type":"` + otherType + `"}`

	// The access token carries the details of the client's types, placeholders filled in, without the one for an API
	// the token is not for; the token response states them (RFC 9396 §7), introspection reports them (§9.2). The
	// user's own entry comes first, then their groups'.
	r, _ := h.login(cl, secret, nil)
	want := "[" + other + "," + topics + "]"
	if got := detailsOf(t, claimsOf(t, r.str("access_token"))); got != want {
		t.Fatalf("access token: %s\nwant %s", got, want)
	}
	if got := detailsOf(t, r.m); got != want {
		t.Fatalf("token response: %s", got)
	}
	if got := detailsOf(t, claimsOf(t, r.str("id_token"))); got != "" {
		t.Fatalf("ID token: %s", got)
	}
	if got := detailsOf(t, h.introspect(cl, secret, r.str("access_token"))); got != want {
		t.Fatalf("introspection: %s", got)
	}
	rr := h.refreshWith(cl, secret, r.str("refresh_token"))
	if rr.status != 200 || detailsOf(t, claimsOf(t, rr.str("access_token"))) != want {
		t.Fatalf("refresh: %d %v", rr.status, rr.m)
	}

	// A token for the API named in locations carries that detail too.
	r, _ = h.login(cl, secret, url.Values{"resource": {"https://api.example/a"}})
	if got, want := detailsOf(t, claimsOf(t, r.str("access_token"))), "["+other+","+topics+","+located+"]"; got != want {
		t.Fatalf("with resource: %s\nwant %s", got, want)
	}

	// Asking for one type at authorization: the tokens carry only that type, a refresh keeps to it, and a token
	// request may not widen it.
	r, _ = h.login(cl, secret, url.Values{"authorization_details": {`[{"type":"` + otherType + `","actions":["read"]}]`}})
	if got := detailsOf(t, r.m); got != "["+other+"]" {
		t.Fatalf("narrowed: %s", got)
	}
	rr = h.refreshWith(cl, secret, r.str("refresh_token"))
	if rr.status != 200 || detailsOf(t, claimsOf(t, rr.str("access_token"))) != "["+other+"]" {
		t.Fatalf("narrowed refresh: %d %v", rr.status, rr.m)
	}
	rr = h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.str("refresh_token")},
		"authorization_details": {`[{"type":"` + topicsType + `"}]`}}, cl, secret)
	tokenErr(t, rr, 400, "invalid_authorization_details")

	// A refresh of a grant that named no type may narrow to one.
	r, _ = h.login(cl, secret, nil)
	rr = h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.str("refresh_token")},
		"authorization_details": {`[{"type":"` + topicsType + `"}]`}}, cl, secret)
	if rr.status != 200 || detailsOf(t, rr.m) != "["+topics+"]" || detailsOf(t, claimsOf(t, rr.str("access_token"))) != "["+topics+"]" {
		t.Fatalf("refresh narrowed: %d %v", rr.status, rr.m)
	}

	// The code exchange may narrow too.
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	rr = h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}, "authorization_details": {`[{"type":"` + topicsType + `"}]`}}, cl, secret)
	if rr.status != 200 || detailsOf(t, rr.m) != "["+topics+"]" {
		t.Fatalf("exchange narrowed: %d %v", rr.status, rr.m)
	}
}

func TestAuthorizationDetailsRefused(t *testing.T) {
	t.Parallel()
	h, cl, secret := adSetup(t)
	c, _ := h.session(h.user)
	_, ch := pkce()
	for _, ad := range []string{
		`[{"type":"urn:example:unused"}]`, // a type the client is not registered for (§5)
		`[{"type":"` + otherType + `","actions":"read"}]`,
		`{"type":"` + otherType + `"}`,
		`[]`,
	} {
		if code, _, e := h.tryCode(c, cl, ch, url.Values{"authorization_details": {ad}}); code != "" || e != "invalid_authorization_details" {
			t.Errorf("authorize %s: code %q error %q", ad, code, e)
		}
		r := h.token(url.Values{"grant_type": {"client_credentials"}, "authorization_details": {ad}}, cl, secret)
		tokenErr(t, r, 400, "invalid_authorization_details")
	}
	// pushed authorization requests check them as the authorization endpoint does
	r := h.clientPost(h.at(cl, "/oauth/par"), url.Values{"response_type": {"code"}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_challenge": {ch}, "code_challenge_method": {"S256"}, "scope": {"openid"},
		"authorization_details": {`[{"type":"urn:example:unused"}]`}}, cl, secret)
	tokenErr(t, r, 400, "invalid_authorization_details")
}

// An application not registered for any type gets no details, whatever access gives.
func TestAuthorizationDetailsNeedClientTypes(t *testing.T) {
	t.Parallel()
	h, cl, secret := adSetup(t)
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{AuthorizationDetailsTypes: &[]string{}}); err != nil {
		t.Fatal(err)
	}
	r, _ := h.login(cl, secret, nil)
	if got := detailsOf(t, claimsOf(t, r.str("access_token"))); got != "" {
		t.Fatalf("access token: %s", got)
	}
	if _, ok := r.m["authorization_details"]; ok {
		t.Fatalf("token response: %v", r.m)
	}
}

func TestAuthorizationDetailsClientCredentials(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.AuthorizationDetailsTypes = &[]string{topicsType, otherType}
		in.AuthorizationDetails = rawDetails(`[{"type":"` + topicsType + `","actions":["publish"],"topics":[{"match":"https://chat.example/{{org}}/*","match_type":"wildcard"}],"payload":{"by":"{{sub}}"}}]`)
	})
	want := `[{"actions":["publish"],"payload":{"by":"` + cl.ID + `"},"topics":[{"match":"https://chat.example/` + h.env.Primary.ID +
		`/*","match_type":"wildcard"}],"type":"` + topicsType + `"}]`
	r := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret)
	if r.status != 200 || detailsOf(t, claimsOf(t, r.str("access_token"))) != want || detailsOf(t, r.m) != want {
		t.Fatalf("client credentials: %d %v", r.status, r.m)
	}
	// asked for a type it has none of: none issued, and the response says so
	r = h.token(url.Values{"grant_type": {"client_credentials"}, "authorization_details": {`[{"type":"` + otherType + `"}]`}}, cl, secret)
	if r.status != 200 || detailsOf(t, r.m) != "[]" || detailsOf(t, claimsOf(t, r.str("access_token"))) != "" {
		t.Fatalf("other type: %d %v", r.status, r.m)
	}
}

func TestAuthorizationDetailsValidated(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	tn := h.tenant("v", membersOnly())
	for _, ad := range []string{`{"type":"a"}`, `[{"type":""}]`, `[{"type":"a","t":"{{user}}"}]`, `[{"type":"a","locations":"x"}]`} {
		_, err := h.env.Svc.AddAccess(ctx, h.admin, tn.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: h.user.ID,
			AuthorizationDetails: rawDetails(ad)})
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != "authorization_details" {
			t.Errorf("access %s: %v", ad, err)
		}
		_, _, err = h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("x"),
			RedirectURIs: &[]string{rpCallback}, AuthorizationDetails: rawDetails(ad)})
		if !errors.As(err, &fe) || fe.Field != "authorization_details" {
			t.Errorf("client %s: %v", ad, err)
		}
	}
	for _, types := range [][]string{{"has space"}, {strings.Repeat("t", 257)}, strings.Fields(strings.Repeat("t ", 1) + "a b c d e f g h i j k l m n o p")} {
		_, _, err := h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("x"),
			RedirectURIs: &[]string{rpCallback}, AuthorizationDetailsTypes: &types})
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != "authorization_details_types" {
			t.Errorf("types %v: %v", types, err)
		}
	}
	// stored compact; [] removes them
	e := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{AuthorizationDetails: rawDetails(` [ {"type" : "a"} ] `)})
	if string(e.AuthorizationDetails) != `[{"type":"a"}]` {
		t.Fatalf("stored %s", e.AuthorizationDetails)
	}
	e, err := h.env.Svc.UpdateAccess(ctx, h.admin, tn.ID, e.ID, service.AccessInput{AuthorizationDetails: rawDetails(`[]`)})
	if err != nil || e.AuthorizationDetails != nil {
		t.Fatalf("cleared: %v %s", err, e.AuthorizationDetails)
	}
}

// A device authorization request may ask for fewer types, which its tokens then keep to; a poll may not widen them,
// and a poll refused for that does not spend the approval.
func TestAuthorizationDetailsDevice(t *testing.T) {
	t.Parallel()
	h, cl, _ := adSetup(t)
	dev := h.deviceClient(func(in *service.ClientInput) {
		in.TenantID = &cl.TenantID
		in.AuthorizationDetailsTypes = &[]string{topicsType, otherType}
	})
	r := h.post(h.orgBase+"/oauth/device_authorization", url.Values{"client_id": {dev.ID}, "scope": {"openid"},
		"authorization_details": {`[{"type":"urn:example:unused"}]`}}, "", "")
	tokenErr(t, r, 400, "invalid_authorization_details")
	r = h.post(h.orgBase+"/oauth/device_authorization", url.Values{"client_id": {dev.ID}, "scope": {"openid"},
		"authorization_details": {`[{"type":"` + topicsType + `"}]`}}, "", "")
	if r.status != 200 {
		t.Fatalf("device authorization: %d %v", r.status, r.m)
	}
	b, csrf := h.session(h.user)
	if st, _ := h.consentDevice(b, csrf, r.str("user_code"), true); st != 200 {
		t.Fatalf("approve: %d", st)
	}
	wide := h.token(url.Values{"grant_type": {service.GrantDeviceCode}, "device_code": {r.str("device_code")},
		"authorization_details": {`[{"type":"` + otherType + `"}]`}}, dev, "")
	tokenErr(t, wide, 400, "invalid_authorization_details")
	tr := h.pollDevice(dev, r.str("device_code"))
	if tr.status != 200 || !strings.Contains(detailsOf(t, claimsOf(t, tr.str("access_token"))), topicsType) ||
		strings.Contains(detailsOf(t, tr.m), otherType) {
		t.Fatalf("device tokens: %d %v", tr.status, tr.m)
	}
}

// A token exchange issues the details of the calling client's access and types, not the subject token's.
func TestAuthorizationDetailsExchange(t *testing.T) {
	t.Parallel()
	h, cl, secret := adSetup(t)
	api, apiSecret := h.tenantClient(&model.Tenant{Meta: model.Meta{ID: cl.TenantID}}, func(in *service.ClientInput) {
		withExchange(in)
		in.IntrospectOrg = ptr(true)
		in.AuthorizationDetailsTypes = &[]string{topicsType}
	})
	r, _ := h.login(cl, secret, nil)
	x := h.exchange(api, apiSecret, r.str("access_token"), nil)
	got := detailsOf(t, claimsOf(t, x.str("access_token")))
	if x.status != 200 || !strings.Contains(got, topicsType) || strings.Contains(got, otherType) || detailsOf(t, x.m) != got {
		t.Fatalf("exchange: %d %v", x.status, x.m)
	}
	x = h.exchange(api, apiSecret, r.str("access_token"), url.Values{"authorization_details": {`[{"type":"` + otherType + `"}]`}})
	tokenErr(t, x, 400, "invalid_authorization_details")
}
