package scim

import (
	"strings"
	"testing"
)

func TestParsePath(t *testing.T) {
	good := map[string]attrPath{
		"userName":                          {Name: "userName"},
		"name.givenName":                    {Name: "name", Sub: "givenName"},
		"meta.lastModified":                 {Name: "meta", Sub: "lastModified"},
		schemaUser:                          {URN: schemaUser},
		schemaEnterprise + ":department":    {URN: schemaEnterprise, Name: "department"},
		schemaEnterprise + ":manager.value": {URN: schemaEnterprise, Name: "manager", Sub: "value"},
		schemaUser + ":userName":            {URN: schemaUser, Name: "userName"},
		"emails.value":                      {Name: "emails", Sub: "value"},
		"$ref":                              {Name: "$ref"},
		"groups.$ref":                       {Name: "groups", Sub: "$ref"},
	}
	for in, want := range good {
		got, err := parsePath(in)
		if err != nil || got.URN != want.URN || got.Name != want.Name || got.Sub != want.Sub || got.Filter != nil {
			t.Errorf("%q: got %+v err %v", in, got, err)
		}
	}
	p, err := parsePath(`emails[type eq "work" and primary eq true].value`)
	if err != nil || p.Name != "emails" || p.Sub != "value" || p.Filter == nil {
		t.Fatalf("value path: %+v %v", p, err)
	}
	if a, ok := p.Filter.(*andNode); !ok || a.l.(*cmpNode).path.Name != "type" {
		t.Errorf("value filter AST %#v", p.Filter)
	}
	p, err = parsePath(`members[value eq "a.b:c]d"]`)
	if err != nil || p.Name != "members" || p.Sub != "" {
		t.Errorf("bracket in string: %+v %v", p, err)
	}
	for _, bad := range []string{"", ".", "a.", ".a", "a..b", "1a", "a b", "a[", "a]", `a[b eq "x"`, `a[b eq "x"]x`, `a[b eq "x"].`, ":x", "a.b.c",
		`a[]`, `a[(]`, strings.Repeat("a", 100)} {
		if _, err := parsePath(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestFilterPrecedenceAndShape(t *testing.T) {
	n, err := parseFilter(`a eq 1 or b eq 2 and c eq 3`)
	if err != nil {
		t.Fatal(err)
	}
	o, ok := n.(*orNode)
	if !ok {
		t.Fatalf("top is %T", n)
	}
	if _, ok := o.r.(*andNode); !ok {
		t.Errorf("and should bind tighter than or: %#v", o.r)
	}
	n, _ = parseFilter(`(a eq 1 or b eq 2) and not (c pr)`)
	a, ok := n.(*andNode)
	if !ok {
		t.Fatalf("top is %T", n)
	}
	if _, ok := a.l.(*orNode); !ok {
		t.Error("parens")
	}
	if nn, ok := a.r.(*notNode); !ok || nn.n.(*cmpNode).op != "pr" {
		t.Errorf("not: %#v", a.r)
	}
	// literals
	n, _ = parseFilter(`a eq true`)
	if n.(*cmpNode).val != true {
		t.Error("true literal")
	}
	n, _ = parseFilter(`a eq null`)
	if c := n.(*cmpNode); c.val != nil || c.op != "eq" {
		t.Error("null literal")
	}
	n, _ = parseFilter(`a gt 1.5e2`)
	if n.(*cmpNode).val != 150.0 {
		t.Errorf("number: %v", n.(*cmpNode).val)
	}
	n, _ = parseFilter(`a eq "tab\there é"`)
	if n.(*cmpNode).val != "tab\there é" {
		t.Errorf("escapes: %q", n.(*cmpNode).val)
	}
	// Keywords are case-insensitive.
	if _, err := parseFilter(`A Eq "x" AND NOT (b PR) OR c Sw "y"`); err != nil {
		t.Error(err)
	}
}

// Malformed filters are refused by the parser (list_test.go:TestInvalidFilters checks the handlers answer them with
// scimType invalidFilter).
func TestParseFilterRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", " ", "a", "a eq", "a eq 1 and", "(a eq 1", "a eq 1)", `a eq 0x10`, `a eq +1`, `a eq 1_0`, `a eq NaN`, `a eq Inf`,
		`a eq "x" b eq "y"`, `not a eq 1`, `a eq 1 or or b eq 2`, "a eq \"x\x00", `a lol 1`, `)`, `(`, `()`, `a eq (1)`,
		`userName eq "unterminated`, `and userName eq "a"`, `userName eq "\`, `userName eq "a\u00zz"`, `userName pr "x"`, `userName eq tru`,
		`userName co 5 5`, `1bad eq "x"`, `urn:x: eq "y"`, `name.givenName.x eq "a"`, `emails[type eq "work"`, `emails]type eq "work"[`,
		`emails[]`, `emails[type eq "work"][type eq "x"]`, strings.Repeat("a eq 1 and ", 2000) + "a eq 1",
	} {
		if _, err := parseFilter(bad); err == nil {
			t.Errorf("%.40q should not parse", bad)
		}
	}
}

// Filters in unusual but valid spellings parse.
func TestParseFilterAcceptsUnusualSyntax(t *testing.T) {
	for _, f := range unusualFilters {
		if _, err := parseFilter(f); err != nil {
			t.Errorf("%q: %v", f, err)
		}
	}
}

var unusualFilters = []string{
	`NOT (userName eq "a")`, `userName EQ "a"`, `userName eq "a" AND active eq true`, `userName pr and active pr`,
	`emails[type eq "work" and primary eq true].value pr`, `userName eq true`, `userName eq false`, `userName eq null`,
	`userName eq -1.5e3`, `userName eq "a\"b"`, `meta.lastModified ge "2000-01-01T00:00:00.5Z"`,
}

func doc() map[string]any {
	return map[string]any{
		"userName": "Jensen", "externalId": "ExT", "active": true, "count": 3.0,
		"name": map[string]any{"givenName": "Barbara", "familyName": "Jensen"},
		"emails": []any{
			map[string]any{"value": "bjensen@example.com", "type": "work", "primary": true},
			map[string]any{"value": "babs@jensen.org", "type": "home"},
		},
		"meta":           map[string]any{"created": "2011-05-13T04:42:34Z", "lastModified": "2011-05-13T05:42:34+01:00"},
		schemaEnterprise: map[string]any{"department": "Tech", "manager": map[string]any{"value": "M1"}},
	}
}

func TestEvalAgainstDocument(t *testing.T) {
	cases := map[string]bool{
		`userName eq "jensen"`:        true,
		`userName eq "JENSEN"`:        true,
		`externalId eq "ext"`:         false, // case exact
		`externalId eq "ExT"`:         true,
		`userName ne "jensen"`:        false,
		`userName ne "other"`:         true,
		`missing ne "x"`:              true,
		`missing eq "x"`:              false,
		`missing eq null`:             true,
		`userName eq null`:            false,
		`userName ne null`:            true,
		`userName co "ens"`:           true,
		`userName sw "jen"`:           true,
		`userName ew "SEN"`:           true,
		`userName sw "x"`:             false,
		`userName pr`:                 true,
		`missing pr`:                  false,
		`active eq true`:              true,
		`active eq false`:             false,
		`active eq "true"`:            true,
		`active co true`:              false,
		`count gt 2`:                  true,
		`count ge 3`:                  true,
		`count lt 3`:                  false,
		`count le 3`:                  true,
		`count eq 3`:                  true,
		`count eq "3"`:                true,
		`userName gt "a"`:             true,
		`userName lt "a"`:             false,
		`name.givenName eq "barbara"`: true,
		`name.familyName pr and name.givenName pr`: true,
		`name pr`:                                                      true,
		`emails.value co "jensen"`:                                     true,
		`emails.value eq "babs@jensen.org"`:                            true,
		`emails eq "bjensen@example.com"`:                              true,
		`emails.type eq "home"`:                                        true,
		`emails[type eq "work"].value eq "babs@jensen.org"`:            false,
		`emails[type eq "home"].value eq "babs@jensen.org"`:            true,
		`emails[type eq "work" and primary eq true]`:                   true,
		`emails[type eq "home" and primary eq true]`:                   false,
		`emails[type eq "other"]`:                                      false,
		`emails.value ew ".org" and emails.type eq "work"`:             true,
		`meta.created lt "2012-01-01T00:00:00Z"`:                       true,
		`meta.created gt "2012-01-01T00:00:00Z"`:                       false,
		`meta.lastModified eq "2011-05-13T04:42:34Z"`:                  true, // same instant in another zone
		`meta.lastModified gt "2011-05-13T04:42:34Z"`:                  false,
		schemaEnterprise + `:department eq "tech"`:                     true,
		schemaEnterprise + `:manager.value eq "M1"`:                    true,
		schemaEnterprise + `:manager eq "M1"`:                          true,
		`urn:other:thing:x pr`:                                         false,
		`not (userName eq "jensen")`:                                   false,
		`not (not (userName eq "jensen"))`:                             true,
		`userName eq "a" or active eq true`:                            true,
		`userName eq "a" and active eq true`:                           false,
		`(userName eq "a" or userName eq "jensen") and active eq true`: true,
	}
	for f, want := range cases {
		n, err := parseFilter(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if got := evalNode(n, doc(), userSchemas); got != want {
			t.Errorf("%s: got %v want %v", f, got, want)
		}
	}
}

func TestPatchRulesDirect(t *testing.T) {
	rl := &patchRules{sch: userSchemas, readOnly: map[string]bool{"id": true}}
	res := map[string]any{"userName": "x", "emails": []any{map[string]any{"value": "a@b.c", "type": "work", "primary": true}}}
	apply := func(op patchOp) {
		t.Helper()
		if e := rl.apply(res, op); e != nil {
			t.Fatalf("%+v: %v", op, e)
		}
	}
	p := func(s string) *attrPath {
		v, err := parsePath(s)
		if err != nil {
			t.Fatal(err)
		}
		return &v
	}
	apply(patchOp{op: "add", path: p("emails"), value: map[string]any{"value": "n@b.c", "type": "home", "primary": "true"}, hasValue: true})
	em := res["emails"].([]any)
	if len(em) != 2 || em[0].(map[string]any)["primary"] != false || em[1].(map[string]any)["primary"] != true {
		t.Errorf("primary handling: %v", em)
	}
	apply(patchOp{op: "add", path: p("emails"), value: []any{map[string]any{"value": "n@b.c"}}, hasValue: true})
	if len(res["emails"].([]any)) != 2 {
		t.Error("duplicate value added")
	}
	apply(patchOp{op: "replace", path: p(`emails[type eq "home"]`), value: map[string]any{"value": "z@b.c"}, hasValue: true})
	if got := res["emails"].([]any)[1].(map[string]any); got["value"] != "z@b.c" || got["type"] != nil {
		t.Errorf("replace by filter: %v", got)
	}
	apply(patchOp{op: "remove", path: p(`emails[type eq "work"]`)})
	if len(res["emails"].([]any)) != 1 {
		t.Errorf("remove by filter: %v", res["emails"])
	}
	apply(patchOp{op: "remove", path: p("emails.value")})
	if _, has := res["emails"].([]any)[0].(map[string]any)["value"]; has {
		t.Error("remove sub-attribute")
	}
	apply(patchOp{op: "replace", path: p("ID"), value: "zzz", hasValue: true})
	if _, has := res["id"]; has {
		t.Error("read-only set")
	}
	apply(patchOp{op: "replace", path: p("USERNAME"), value: "y", hasValue: true})
	if res["userName"] != "y" || len(res) != 2 {
		t.Errorf("canonical key: %v", res)
	}

	// Multi-valued and complex attributes.
	emails := func() []any { return res["emails"].([]any) }
	email := func(value string) map[string]any {
		for _, e := range emails() {
			if em := e.(map[string]any); em["value"] == value {
				return em
			}
		}
		t.Fatalf("no email %s in %v", value, emails())
		return nil
	}
	res = map[string]any{"emails": []any{map[string]any{"value": "a@b.c", "type": "work", "primary": true},
		map[string]any{"value": "h@b.c", "type": "home"}}}
	// adding an element that exists updates it
	apply(patchOp{op: "add", path: p("emails"), value: []any{map[string]any{"value": "h@b.c", "type": "other"}}, hasValue: true})
	if len(emails()) != 2 || email("h@b.c")["type"] != "other" {
		t.Errorf("add existing: %v", emails())
	}
	// a replacement with several primaries: the last one wins
	apply(patchOp{op: "replace", path: p("emails"), value: []any{map[string]any{"value": "a1@b.c", "primary": true},
		map[string]any{"value": "a2@b.c", "primary": "true"}}, hasValue: true})
	if email("a1@b.c")["primary"] != false || email("a2@b.c")["primary"] != true {
		t.Errorf("several primaries: %v", emails())
	}
	// a filtered sub-attribute is set on the elements matched, and a primary there clears the others
	apply(patchOp{op: "replace", path: p(`emails[value eq "a1@b.c"].primary`), value: "true", hasValue: true})
	if email("a1@b.c")["primary"] != true || email("a2@b.c")["primary"] != false {
		t.Errorf("filtered primary: %v", emails())
	}
	// a filter that matches nothing adds the element it describes
	apply(patchOp{op: "add", path: p(`emails[type eq "home"].value`), value: "home@b.c", hasValue: true})
	if len(emails()) != 3 || email("home@b.c")["type"] != "home" {
		t.Errorf("filtered add of a sub-attribute: %v", emails())
	}
	apply(patchOp{op: "add", path: p(`emails[type eq "other"]`), value: map[string]any{"value": "o@b.c", "primary": "true"}, hasValue: true})
	if o := email("o@b.c"); len(emails()) != 4 || o["type"] != "other" || o["primary"] != true || email("a1@b.c")["primary"] != false {
		t.Errorf("filtered add of an element: %v", emails())
	}
	// removing a filtered sub-attribute keeps the element
	apply(patchOp{op: "remove", path: p(`emails[type eq "home"].type`)})
	if h := email("home@b.c"); h["type"] != nil || len(emails()) != 4 {
		t.Errorf("filtered remove of a sub-attribute: %v", emails())
	}
	// a sub-attribute of a multi-valued attribute without a filter: set on the first element, removed from all
	apply(patchOp{op: "replace", path: p("emails.type"), value: "work", hasValue: true})
	if emails()[0].(map[string]any)["type"] != "work" {
		t.Errorf("set emails.type: %v", emails())
	}
	apply(patchOp{op: "remove", path: p("emails.type")})
	for _, e := range emails() {
		if e.(map[string]any)["type"] != nil {
			t.Errorf("remove emails.type: %v", emails())
		}
	}
	// removing with a value list removes those elements
	apply(patchOp{op: "remove", path: p("emails"), value: []any{map[string]any{"value": "a2@b.c"}}, hasValue: true})
	if len(emails()) != 3 || containsElem(emails(), map[string]any{"value": "a2@b.c"}) {
		t.Errorf("remove listed value: %v", emails())
	}
	// add of an absent complex attribute creates it; removing its sub-attribute clears that
	apply(patchOp{op: "add", path: p("name"), value: map[string]any{"familyName": "Added"}, hasValue: true})
	if n, _ := res["name"].(map[string]any); n["familyName"] != "Added" {
		t.Errorf("add name: %v", res["name"])
	}
	apply(patchOp{op: "remove", path: p("name.familyName")})
	if n, _ := res["name"].(map[string]any); n == nil || n["familyName"] != nil {
		t.Errorf("remove name.familyName: %v", res["name"])
	}
}

func FuzzParseFilter(f *testing.F) {
	for _, s := range []string{
		`userName eq "bjensen"`, `name.familyName co "O'Malley"`, `userName sw "J"`, `urn:ietf:params:scim:schemas:core:2.0:User:userName sw "J"`,
		`title pr`, `meta.lastModified gt "2011-05-13T04:42:34Z"`, `meta.lastModified ge "2011-05-13T04:42:34Z"`,
		`title pr and userType eq "Employee"`, `title pr or userType eq "Intern"`, `schemas eq "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`,
		`userType eq "Employee" and (emails co "example.com" or emails.value co "example.org")`,
		`userType ne "Employee" and not (emails co "example.com" or emails.value co "example.org")`,
		`userType eq "Employee" and (emails.type eq "work")`, `userType eq "Employee" and emails[type eq "work" and value co "@example.com"]`,
		`emails[type eq "work" and value co "@example.com"] or ims[type eq "xmpp" and value co "@foo.com"]`,
		`emails[type eq "work"].value ew "x"`, `a eq null`, `a eq 1.5e-3`, `not (a pr)`, `(((a pr)))`, `a eq "é\n\\"`,
		`members[value eq "x"]`, `a EQ "x" AND b Pr`, "a\teq\n\"x\"",
	} {
		f.Add(s)
	}
	for _, s := range unusualFilters {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		n, err := parseFilter(in)
		if err != nil {
			return
		}
		// Anything that parses must evaluate without panicking, on a rich and on an empty document.
		evalNode(n, doc(), userSchemas)
		evalNode(n, map[string]any{}, userSchemas)
		referencesAttr(n, "groups")
		conjuncts(n)
	})
}

func FuzzParsePath(f *testing.F) {
	for _, s := range []string{"userName", "name.givenName", `emails[type eq "work"].value`, schemaEnterprise + ":manager.value", schemaUser,
		`members[value eq "a"]`, "a[b", "[", "]", ".", "a.b.c", "urn:", ":"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		p, err := parsePath(in)
		if err != nil {
			return
		}
		_ = p.String()
		resolve(doc(), p, userSchemas)
		rl := &patchRules{sch: userSchemas}
		res := doc()
		for _, op := range []string{"add", "replace", "remove"} {
			_ = rl.apply(res, patchOp{op: op, path: &p, value: "v", hasValue: true})
		}
		project(doc(), []string{in}, nil, userSchemas)
		project(doc(), nil, []string{in}, userSchemas)
	})
}
