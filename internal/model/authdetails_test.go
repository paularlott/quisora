package model

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shamaton/msgpack/v3"
)

func TestParseAuthDetails(t *testing.T) {
	t.Parallel()
	good := []string{
		`[]`,
		`[{"type":"a"}]`,
		`[{"type":"https://example.com/topics","actions":["subscribe"],"topics":[{"match":"*"}]}]`,
		`[{"type":"a","locations":["https://api.example"],"identifier":"x","datatypes":[],"privileges":["p"]}]`,
	}
	for _, s := range good {
		if _, err := ParseAuthDetails([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := []string{
		``, `null`, `{}`, `"x"`, `[1]`, `[{}]`, `[{"type":""}]`, `[{"type":"has space"}]`, `[{"type":7}]`,
		`[{"type":"a","locations":"https://api.example"}]`, `[{"type":"a","actions":[1]}]`, `[{"type":"a","identifier":["x"]}]`,
		`[{"type":"a"}] []`, `[{"type":"` + strings.Repeat("t", 257) + `"}]`,
		`[` + strings.TrimSuffix(strings.Repeat(`{"type":"a"},`, MaxAuthDetails+1), ",") + `]`,
		`[{"type":"a","x":"` + strings.Repeat("x", MaxAuthDetailsBytes) + `"}]`,
	}
	for _, s := range bad {
		if _, err := ParseAuthDetails([]byte(s)); err == nil {
			t.Errorf("%.80s: accepted", s)
		}
	}
}

func TestNormAuthDetails(t *testing.T) {
	t.Parallel()
	for _, s := range []string{``, `  `, `[]`} {
		if got, err := NormAuthDetails([]byte(s)); err != nil || got != nil {
			t.Errorf("%q: %s %v", s, got, err)
		}
	}
	// compact, keys sorted, numbers and < > & as written
	got, err := NormAuthDetails([]byte(`[ {"type": "a", "n": 1.50, "z": "<&>", "b": {"y": "{{sub}}", "x": ["{{org}}/{{tenant}}"]}} ]`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"b":{"x":["{{org}}/{{tenant}}"],"y":"{{sub}}"},"n":1.50,"type":"a","z":"<&>"}]`; string(got) != want {
		t.Fatalf("got %s", got)
	}
	for _, s := range []string{`[{"type":"a","t":"{{user}}"}]`, `[{"type":"a","t":["x{{"]}]`, `[{"type":"{{sub}"}]`} {
		if _, err := NormAuthDetails([]byte(s)); err == nil {
			t.Errorf("%s: accepted", s)
		}
	}
	// keys are not placeholders
	if _, err := NormAuthDetails([]byte(`[{"type":"a","{{k}}":1}]`)); err != nil {
		t.Errorf("placeholder-like key: %v", err)
	}
}

func TestExpandAuthDetails(t *testing.T) {
	t.Parallel()
	raw, err := NormAuthDetails([]byte(`[{"type":"m","topics":[{"match":"https://x/u/{{sub}}"},{"match":"https://x/{{org}}/{{tenant}}/{id}"}]},
		{"type":"n","locations":["https://api/{{tenant}}","urn:a"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	ds, err := ExpandAuthDetails(raw, AuthDetailVars{Sub: `u"1`, Org: "o1", Tenant: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 || ds[0].Type != "m" || ds[1].Type != "n" {
		t.Fatalf("got %+v", ds)
	}
	// substituted values are JSON-escaped, never spliced into the JSON text; RFC 6570 expressions are left alone
	if want := `{"topics":[{"match":"https://x/u/u\"1"},{"match":"https://x/o1/t1/{id}"}],"type":"m"}`; string(ds[0].JSON) != want {
		t.Fatalf("got %s", ds[0].JSON)
	}
	if len(ds[1].Locations) != 2 || ds[1].Locations[0] != "https://api/t1" || ds[1].Locations[1] != "urn:a" {
		t.Fatalf("locations %v", ds[1].Locations)
	}
	if !json.Valid(ds[1].JSON) || ds[0].Locations != nil {
		t.Fatalf("got %+v", ds)
	}
	if ds, err := ExpandAuthDetails(nil, AuthDetailVars{}); ds != nil || err != nil {
		t.Fatalf("none: %v %v", ds, err)
	}
}

// The stored records keep the details through the store's encoding.
func TestAuthDetailsMsgpack(t *testing.T) {
	t.Parallel()
	in := TenantAccess{TenantID: "t", AuthorizationDetails: json.RawMessage(`[{"type":"a"}]`)}
	b, err := msgpack.Marshal(&in)
	if err != nil {
		t.Fatal(err)
	}
	var out TenantAccess
	if err := msgpack.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if string(out.AuthorizationDetails) != `[{"type":"a"}]` {
		t.Fatalf("got %q", out.AuthorizationDetails)
	}
	c := Client{AuthorizationDetailsTypes: []string{"a"}, AuthorizationDetails: json.RawMessage(`[{"type":"a"}]`)}
	if b, err = msgpack.Marshal(&c); err != nil {
		t.Fatal(err)
	}
	var c2 Client
	if err := msgpack.Unmarshal(b, &c2); err != nil || string(c2.AuthorizationDetails) != `[{"type":"a"}]` || c2.AuthorizationDetailsTypes[0] != "a" {
		t.Fatalf("client: %v %+v", err, c2)
	}
}
