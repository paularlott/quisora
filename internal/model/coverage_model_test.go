package model

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var t0 = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

// Every kind's Index fields are registered in its schema, with the declared type, and the index never panics on a
// zero entity.
func TestIndexMatchesSchema(t *testing.T) {
	for _, k := range Kinds() {
		e := NewEntity(k)
		ix := e.Index()
		s := Schemas[k]
		for name, v := range ix.Fields {
			f, ok := s.Field(name)
			if !ok {
				t.Errorf("%s: index field %q is not in the schema", k, name)
				continue
			}
			var ok2 bool
			switch f.Type {
			case FieldString:
				_, ok2 = v.(string)
			case FieldInt:
				_, ok2 = v.(int64)
			case FieldBool:
				_, ok2 = v.(bool)
			case FieldTime:
				_, ok2 = v.(time.Time)
			}
			if !ok2 {
				t.Errorf("%s.%s: value %T does not match field type %d", k, name, v, f.Type)
			}
		}
		if e.GetMeta() == nil {
			t.Errorf("%s: nil meta", k)
		}
	}
	if NewEntity("nope") != nil {
		t.Error("unknown kind gave an entity")
	}
	if !Unscoped(KindOrg) || Unscoped(KindUser) {
		t.Error("Unscoped")
	}
	if _, ok := Schemas[KindUser].Field("nope"); ok {
		t.Error("Field found a missing field")
	}
}

func TestMetaHelpers(t *testing.T) {
	if Lower("  AbC ") != "abc" {
		t.Error("Lower")
	}
	if a, b := NewID(), NewID(); a == b || uuid.Validate(a) != nil {
		t.Errorf("NewID %q %q", a, b)
	}
	for _, k := range []Kind{KindUser, KindGrant, KindLink, KindOrg} {
		if !QuorumCAS(k) {
			t.Errorf("%s should be quorum", k)
		}
	}
	for _, k := range []Kind{KindSession, KindAudit, KindEphemeral, KindKey} {
		if QuorumCAS(k) {
			t.Errorf("%s should not be quorum", k)
		}
	}
	m := &Meta{ID: "x"}
	if m.GetMeta() != m {
		t.Error("GetMeta")
	}
	if !IsBootstrapRecord(KindOrg, PrimaryOrgID, BootstrapVersion) || IsBootstrapRecord(KindOrg, PrimaryOrgID, 2) ||
		IsBootstrapRecord(KindUser, PrimaryOrgID, BootstrapVersion) {
		t.Error("IsBootstrapRecord")
	}
	for _, c := range []struct {
		k  Kind
		id string
		ok bool
	}{{KindOrg, PrimaryOrgID, true}, {KindUser, BootstrapAdminID, true}, {KindTenant, PrimaryTenantID, true},
		{KindUser, PrimaryOrgID, false}, {KindOrg, "other", false}} {
		if IsBootstrapID(c.k, c.id) != c.ok {
			t.Errorf("IsBootstrapID(%s,%s)", c.k, c.id)
		}
	}
}

func TestDue(t *testing.T) {
	end := t0.Add(time.Hour)
	if got, ok := Due(KindUser, map[string]any{"expiring": true, "active": true, "valid_until": end}); !ok || !got.Equal(end) {
		t.Errorf("due = %v %v", got, ok)
	}
	for name, f := range map[string]map[string]any{
		"inactive":     {"expiring": true, "active": false, "valid_until": end},
		"not expiring": {"expiring": false, "active": true, "valid_until": end},
		"no time":      {"expiring": true, "active": true},
	} {
		if _, ok := Due(KindUser, f); ok {
			t.Errorf("%s: due", name)
		}
	}
	if _, ok := Due(KindGroup, map[string]any{"expiring": true, "active": true, "valid_until": end}); ok {
		t.Error("group due")
	}
}

func TestMFA(t *testing.T) {
	for _, c := range []struct {
		amr []string
		ok  bool
	}{
		{nil, false}, {[]string{"mfa"}, true}, {[]string{"pwd"}, false}, {[]string{"pwd", "otp"}, true},
		{[]string{"otp"}, false}, {[]string{"hwk"}, false}, {[]string{"hwk", "user"}, true},
		{[]string{"swk", "user"}, true}, {[]string{"user"}, false}, {[]string{"pwd", "hwk"}, false},
	} {
		if MFA(c.amr) != c.ok {
			t.Errorf("MFA(%v) = %v", c.amr, !c.ok)
		}
	}
}

func TestNormalizeLocale(t *testing.T) {
	for in, want := range map[string]string{"": "", "  ": "", "en_gb": "en-GB", "EN-GB": "en-GB", "fr": "fr"} {
		if got, ok := NormalizeLocale(in); !ok || got != want {
			t.Errorf("NormalizeLocale(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"!!", "en gb", strings.Repeat("a", 40), "12345"} {
		if got, ok := NormalizeLocale(in); ok {
			t.Errorf("NormalizeLocale(%q) accepted as %q", in, got)
		}
	}
}

func TestValidTimeZone(t *testing.T) {
	for _, z := range []string{"", "UTC", "Europe/London", "America/New_York"} {
		if !ValidTimeZone(z) {
			t.Errorf("%q rejected", z)
		}
	}
	for _, z := range []string{"Local", "Not/AZone", "Europe London", "../etc", `a\b`, strings.Repeat("a", 65)} {
		if ValidTimeZone(z) {
			t.Errorf("%q accepted", z)
		}
	}
}

func TestWorkAndEnabled(t *testing.T) {
	if !(Work{}).Empty() || (Work{Title: "x"}).Empty() {
		t.Error("Empty")
	}
	past, future := t0.Add(-time.Hour), t0.Add(time.Hour)
	for _, c := range []struct {
		u  User
		ok bool
	}{
		{User{Active: true}, true}, {User{}, false}, {User{Active: true, ValidUntil: &future}, true},
		{User{Active: true, ValidUntil: &past}, false}, {User{Active: true, ValidUntil: &t0}, false},
	} {
		if c.u.Enabled(t0) != c.ok {
			t.Errorf("Enabled(%+v) = %v", c.u, !c.ok)
		}
	}
}

func TestSignOutCurrent(t *testing.T) {
	want := SignOutStamp{Server: 2, Org: 3}
	for _, c := range []struct {
		s  SignOutStamp
		ok bool
	}{{SignOutStamp{2, 3}, true}, {SignOutStamp{5, 9}, true}, {SignOutStamp{1, 3}, false}, {SignOutStamp{2, 2}, false}, {SignOutStamp{}, false}} {
		if c.s.Current(want) != c.ok {
			t.Errorf("%+v.Current = %v", c.s, !c.ok)
		}
	}
	if !(SignOutStamp{}).Current(SignOutStamp{}) {
		t.Error("zero stamp is current for zero counters")
	}
}

func TestTags(t *testing.T) {
	for _, s := range []string{"a", "dept:finance", "a.b_c-d/e", "A1", strings.Repeat("a", 64)} {
		if !ValidTag(s) {
			t.Errorf("%q invalid", s)
		}
	}
	for _, s := range []string{"", "-a", "a-", ":a", "a b", "a,b", strings.Repeat("a", 65), "é"} {
		if ValidTag(s) {
			t.Errorf("%q valid", s)
		}
	}
	if NormTags(nil) != nil || NormTags([]string{}) != nil {
		t.Error("empty must be nil")
	}
	in := []string{"b", "a", "b", "A"}
	got := NormTags(in)
	if !slices.Equal(got, []string{"A", "a", "b"}) {
		t.Errorf("NormTags = %v", got)
	}
	if !slices.Equal(in, []string{"b", "a", "b", "A"}) {
		t.Error("NormTags modified its input")
	}
	if got := MergeTags([]string{"z", "a"}, nil, []string{"a", "m"}); !slices.Equal(got, []string{"a", "m", "z"}) {
		t.Errorf("MergeTags = %v", got)
	}
	if MergeTags() != nil {
		t.Error("MergeTags() not nil")
	}
}

func TestRoles(t *testing.T) {
	order := []Role{RoleUser, RoleManager, RoleAdmin, RoleSuperAdmin}
	for i, r := range order {
		if r.Rank() != i || !r.Valid() || r.Privileged() != (i >= 1) {
			t.Errorf("%s: rank %d valid %v privileged %v", r, r.Rank(), r.Valid(), r.Privileged())
		}
	}
	if Role("root").Valid() || Role("").Valid() || Role("root").Rank() != 0 || Role("root").Privileged() {
		t.Error("unknown role")
	}
}

func TestOrgNames(t *testing.T) {
	for _, n := range []string{"acme", "a", "a-b", "a1", strings.Repeat("a", 63)} {
		if !ValidOrgName(n) {
			t.Errorf("%q rejected", n)
		}
	}
	for _, n := range []string{"", "Acme", "-a", "a-", "a_b", "admin", "api", "docs", strings.Repeat("a", 64), "a b"} {
		if ValidOrgName(n) {
			t.Errorf("%q accepted", n)
		}
	}
	if OrgNameKey(" ACME ") != "acme" {
		t.Error("OrgNameKey")
	}
	o := Org{Name: "Acme", DisplayName: "A", Primary: true}
	o.Created = t0
	ix := o.Index()
	if ix.Scope != "" || !slices.Equal(ix.Unique, []string{"acme"}) || ix.Fields["primary"] != true {
		t.Errorf("org index %+v", ix)
	}
	if d := DefaultOrgSettings(); !d.PasswordLogin || !d.PasswordReset || !d.PasskeyLogin || d.RequireMFA {
		t.Errorf("defaults %+v", d)
	}
	if d := DefaultTenantSettings(); !d.AllProviders || !d.RequireMFA || d.MembersOnly || !d.PasswordLogin {
		t.Errorf("tenant defaults %+v", d)
	}
}

func TestUserHelpers(t *testing.T) {
	u := &User{OrgID: "o", Username: "Jo", Email: "Jo@X.com", GivenName: "Jo", FamilyName: "Bloggs", ExternalID: "ext",
		LinkedEmails: []LinkedEmail{{Address: "Alt@X.com"}}, Role: RoleAdmin, Active: true, Tags: []string{"a", "b"},
		Work: Work{Department: "d", ManagerID: "m", EmployeeNumber: "7"}}
	if u.FullName() != "Jo Bloggs" {
		t.Error(u.FullName())
	}
	if (&User{GivenName: " ", Username: "un", Email: "e"}).FullName() != "un" || (&User{Email: "e"}).FullName() != "e" {
		t.Error("FullName fallbacks")
	}
	if l, ok := u.LinkedEmail("alt@x.COM"); !ok || l.Address != "Alt@X.com" {
		t.Error("LinkedEmail")
	}
	if _, ok := u.LinkedEmail("none"); ok {
		t.Error("LinkedEmail found none")
	}
	ix := u.Index()
	want := []string{"o/u/jo", "o/e/jo@x.com", "o/e/alt@x.com", "o/x/ext"}
	if ix.Scope != "o" || !slices.Equal(ix.Unique, want) {
		t.Errorf("unique %v", ix.Unique)
	}
	if ix.Fields["tags"] != "a b" || ix.Fields["admin_rank"] != true || ix.Fields["super_admin"] != false ||
		ix.Fields["expiring"] != false || ix.Fields["manager_id"] != "m" || ix.Fields["name"] != "Jo Bloggs" {
		t.Errorf("fields %v", ix.Fields)
	}
	bare := (&User{OrgID: "o", Username: "u"}).Index()
	if len(bare.Unique) != 1 {
		t.Errorf("bare unique %v", bare.Unique)
	}
	end := t0
	u.ValidUntil = &end
	if f := u.Index().Fields; f["expiring"] != true || !f["valid_until"].(time.Time).Equal(end) {
		t.Errorf("valid_until %v", f)
	}
	if u.HasTOTP() {
		t.Error("HasTOTP")
	}
	u.TOTPSecret = "s"
	if !u.HasTOTP() {
		t.Error("HasTOTP set")
	}
	u.SecurityGen = 4
	u.BumpSecurity()
	if u.SecurityGen != 5 {
		t.Error("BumpSecurity")
	}
	if UserUsernameKey("o", " A ") != "o/u/a" || UserEmailKey("o", "A@B") != "o/e/a@b" || UserExternalIDKey("o", "E") != "o/x/E" {
		t.Error("user keys")
	}
}

func TestCredentialEpochs(t *testing.T) {
	u := &User{CredEpoch: 5, SessionEpoch: 7, Removed: []Removal{{Kind: KindPasskey, ID: "gone"}}}
	if !u.Holds(5) || u.Holds(4) || !u.SessionHolds(7) || u.SessionHolds(5) {
		t.Error("Holds/SessionHolds")
	}
	mk := func(id string, epoch uint64) *Passkey { p := &Passkey{Epoch: epoch, UserID: "u"}; p.ID = id; return p }
	creds := []struct {
		name string
		c    Credential
		ok   bool
	}{
		{"current passkey", mk("p", 5), true},
		{"removed passkey", mk("gone", 5), false},
		{"old epoch passkey", mk("p", 4), false},
		{"identity", &Identity{Epoch: 5}, true},
		{"old identity", &Identity{Epoch: 1}, false},
		{"api token", &APIToken{Epoch: 5}, true},
		{"session", &Session{Epoch: 7}, true},
		{"old session", &Session{Epoch: 5}, false},
		{"grant", &Grant{Epoch: 7}, true},
		{"session removed id is irrelevant", func() Credential { s := &Session{Epoch: 7}; s.ID = "gone"; return s }(), true},
	}
	for _, c := range creds {
		if u.Counts(c.c) != c.ok {
			t.Errorf("%s: Counts = %v", c.name, !c.ok)
		}
	}
	if (&Passkey{UserID: "a"}).Owner() != "a" || (&Identity{UserID: "b"}).Owner() != "b" || (&APIToken{UserID: "c"}).Owner() != "c" ||
		(&Session{UserID: "d"}).Owner() != "d" || (&Grant{UserID: "e"}).Owner() != "e" {
		t.Error("Owner")
	}
	if e, s := (&Grant{Epoch: 3}).MadeIn(); e != 3 || !s {
		t.Error("grant MadeIn")
	}
	if e, s := (&Passkey{Epoch: 3}).MadeIn(); e != 3 || s {
		t.Error("passkey MadeIn")
	}
	u.SetCredEpoch(9)
	if u.CredEpoch != 9 || u.Removed != nil || u.SessionEpoch != 7 {
		t.Errorf("SetCredEpoch %+v", u)
	}
	if u.Counts(mk("gone", 9)) != true {
		t.Error("a new epoch clears the removals")
	}
}

func TestGroupAndMember(t *testing.T) {
	g := &Group{OrgID: "o", DisplayName: "Eng", ExternalID: "x", Tags: []string{"t1", "t2"},
		Pending: []GroupChange{{Add: []string{"a", "b"}}, {Remove: []string{"a"}}, {Add: []string{"c"}, Remove: []string{"c"}}}}
	ix := g.Index()
	if !slices.Equal(ix.Unique, []string{"o/n/eng", "o/x/x"}) || ix.Fields["pending"] != true || ix.Fields["tags"] != "t1 t2" {
		t.Errorf("group index %+v", ix)
	}
	if (&Group{OrgID: "o", DisplayName: "E"}).Index().Fields["pending"] != false {
		t.Error("pending")
	}
	for _, c := range []struct {
		user           string
		member, decide bool
	}{{"a", false, true}, {"b", true, true}, {"c", true, true}, {"zz", false, false}} {
		if m, d := g.PendingMember(c.user); m != c.member || d != c.decide {
			t.Errorf("PendingMember(%s) = %v %v", c.user, m, d)
		}
	}
	if GroupNameKey("o", " X ") != "o/n/x" || GroupExternalIDKey("o", "E") != "o/x/E" || MemberID("g", "u") != "g:u" {
		t.Error("group keys")
	}

	m := &Member{GroupID: "g", UserID: "u", OrgID: "o"}
	m.Created = t0
	if !m.Active() {
		t.Error("Active")
	}
	if ix := m.Index(); ix.Fields["group_id"] != "g" || ix.Fields["user_id"] != "u" || !ix.Expires.IsZero() || ix.Scope != "o" {
		t.Errorf("member index %+v", ix)
	}
	m.Removed = t0
	ix = m.Index()
	if m.Active() || ix.Fields["group_id"] != "" || ix.Fields["user_id"] != "" || !ix.Expires.Equal(t0.Add(RemovedMemberRetention)) {
		t.Errorf("removed member index %+v", ix)
	}
}

func TestTenant(t *testing.T) {
	tn := &Tenant{OrgID: "o", Name: "Default", Resources: []string{"https://MCP.example.com:443/mcp/"}}
	ix := tn.Index()
	if !slices.Equal(ix.Unique, []string{"o/n/default", "res/https://mcp.example.com/mcp"}) {
		t.Errorf("unique %v", ix.Unique)
	}
	if TenantNameKey("o", "N") != "o/n/n" {
		t.Error("TenantNameKey")
	}
	for in, want := range map[string]string{
		"https://Example.COM/":          "https://example.com",
		"https://example.com:443/a/b//": "https://example.com/a/b",
		"http://example.com:80/x":       "http://example.com/x",
		"http://example.com:8080/x/":    "http://example.com:8080/x",
		"https://example.com:8443":      "https://example.com:8443",
		"not a url":                     "not a url",
		"/relative/":                    "/relative/",
		"":                              "",
	} {
		if got := CanonicalResource(in); got != want {
			t.Errorf("CanonicalResource(%q) = %q, want %q", in, got, want)
		}
	}
	if TenantResourceKey("HTTPS://A.com/") != TenantResourceKey("https://a.com") {
		t.Error("resource keys differ")
	}

	a := &TenantAccess{OrgID: "o", TenantID: "t", SubjectID: "s", SubjectType: SubjectUser, Clients: []string{"c1"}}
	if a.Index().Fields["subject_type"] != "user" || AccessID("t", "s") != "t:s" {
		t.Error("access index")
	}
	if !a.Live(t0) || !a.Live(time.Time{}) {
		t.Error("no expiry is live")
	}
	a.Expires = t0
	if a.Live(t0) || !a.Live(t0.Add(-1)) {
		t.Error("Live boundary")
	}
	if !a.Covers("c1") || a.Covers("c2") {
		t.Error("Covers")
	}
	a.AllClients = true
	if !a.Covers("c2") {
		t.Error("AllClients")
	}
}

func TestClientAndProvider(t *testing.T) {
	c := &Client{AuthMethod: AuthMethodNone}
	if !c.Public() || !c.RequirePKCE() {
		t.Error("public client needs PKCE")
	}
	c = &Client{AuthMethod: AuthMethodSecretPost}
	if c.Public() || !c.RequirePKCE() {
		t.Error("confidential client PKCE by default")
	}
	c.PKCEOptional = true
	if c.RequirePKCE() {
		t.Error("PKCE optional")
	}
	c.AuthMethod = AuthMethodNone
	if !c.RequirePKCE() {
		t.Error("PKCEOptional ignored for public clients")
	}
	for _, x := range []struct {
		c  Client
		ok bool
	}{{Client{SelfRegistered: true, Meta: Meta{ID: "https://a/b"}}, true}, {Client{SelfRegistered: true, Meta: Meta{ID: "c_x"}}, false},
		{Client{Meta: Meta{ID: "https://a/b"}}, false}} {
		if x.c.IsMetadataClient() != x.ok {
			t.Errorf("IsMetadataClient(%+v)", x.c)
		}
	}
	ci := (&Client{OrgID: "o", Name: "n", TenantID: "t", AuthMethod: "x", SelfRegistered: true}).Index()
	if ci.Scope != "o" || ci.Fields["self_registered"] != true || ci.Fields["auth_method"] != "x" {
		t.Errorf("client index %+v", ci)
	}

	p := &Provider{OrgID: "o", Name: "Okta", Type: ProviderOIDC, Enabled: true, Issuer: "https://i", Tenant: "tn"}
	p.Created = time.UnixMilli(1234)
	if !p.OIDC() || (&Provider{Type: ProviderGitHub}).OIDC() {
		t.Error("OIDC")
	}
	if !slices.Equal(p.Index().Unique, []string{"o/n/okta"}) {
		t.Error("provider unique")
	}
	if got := ProviderAuthority(p); got != "oidc|https://i|tn|1234" {
		t.Errorf("authority %q", got)
	}
	u := &User{OrgID: "o", CredEpoch: 8}
	u.ID = "u1"
	p.ID = "p1"
	id := NewIdentity(u, p, "sub", "e@x", "admin")
	if id.UserID != "u1" || id.OrgID != "o" || id.ProviderID != "p1" || id.Subject != "sub" || id.Epoch != 8 ||
		id.Authority != ProviderAuthority(p) || id.Via != "admin" || id.Email != "e@x" {
		t.Errorf("identity %+v", id)
	}
	if ix := id.Index(); ix.Scope != "u1" || !slices.Equal(ix.Unique, []string{"p1/sub"}) || IdentityKey("p", "s") != "p/s" {
		t.Errorf("identity index %+v", ix)
	}
}

func TestPasskeyAndSession(t *testing.T) {
	pk := &Passkey{CredentialID: []byte{0xfb, 0xff, 0x01}, UserID: "u", UserVerified: true}
	if !pk.Usable() {
		t.Error("usable")
	}
	pk.Disabled = true
	if pk.Usable() || (&Passkey{}).Usable() {
		t.Error("unusable")
	}
	if k := PasskeyCredentialKey(pk.CredentialID); k != "-_8B" {
		t.Errorf("key %q (raw URL base64)", k)
	}
	if ix := pk.Index(); ix.Scope != "u" || ix.Unique[0] != "-_8B" {
		t.Errorf("index %+v", ix)
	}

	s := &Session{Expires: t0.Add(time.Hour), LastSeen: t0, IdleTTL: 60, UserID: "u"}
	for _, c := range []struct {
		now time.Time
		ok  bool
	}{{t0, true}, {t0.Add(60 * time.Second), true}, {t0.Add(61 * time.Second), false}, {t0.Add(2 * time.Hour), false}} {
		if s.Valid(c.now) != c.ok {
			t.Errorf("Valid(%v) = %v", c.now.Sub(t0), !c.ok)
		}
	}
	s.IdleTTL = 0
	if !s.Valid(t0.Add(59*time.Minute)) || s.Valid(t0.Add(time.Hour+1)) {
		t.Error("no idle timeout")
	}
	if ix := s.Index(); ix.Scope != "u" || !ix.Expires.Equal(s.Expires) {
		t.Errorf("session index %+v", ix)
	}
}

func TestAuditAndLinks(t *testing.T) {
	for a, want := range map[string]string{
		"login.success": "success", "login.failure": "failure", "x.refused": "failure", "x_refused": "failure",
		"x.lockout": "failure", "x.limited": "failure", "x.replay": "failure", "x.reuse": "failure", "x.clone": "failure",
		"x.failure.later": "success", "": "success",
	} {
		if got := AuditOutcome(a); got != want {
			t.Errorf("AuditOutcome(%q) = %q", a, got)
		}
	}
	a := &Audit{OrgID: "o", Action: "login.failure"}
	if a.Index().Fields["outcome"] != "failure" {
		t.Error("derived outcome")
	}
	a.Outcome = "success"
	if a.Index().Fields["outcome"] != "success" {
		t.Error("stored outcome wins")
	}

	l := &LinkToken{UserID: "u", TokenHash: "h", Purpose: "invite", Expires: t0}
	if ix := l.Index(); ix.Scope != "u" || !slices.Equal(ix.Unique, []string{"t/h"}) || !ix.Expires.Equal(t0) || LinkTokenKey("h") != "t/h" {
		t.Errorf("link index %+v", ix)
	}
	si := &SignIn{OrgID: "o", LastLogin: t0}
	if ix := si.Index(); ix.Scope != "o" || !ix.Fields["last_login"].(time.Time).Equal(t0) {
		t.Error("signin index")
	}
	if ix := (&Lock{}).Index(); ix.Scope != "" || ix.Fields != nil {
		t.Error("lock index")
	}
	if ix := (&Replay{Expires: t0}).Index(); !ix.Expires.Equal(t0) {
		t.Error("replay index")
	}
	e := &Ephemeral{Expires: t0}
	if ix := e.Index(); !ix.Expires.Equal(t0) || e.GetMeta() != &e.Meta {
		t.Error("ephemeral")
	}
	if k := (&SigningKey{Alg: "ES256", Expires: t0}).Index(); k.Fields["alg"] != "ES256" || !k.Expires.Equal(t0) {
		t.Error("key index")
	}
}

func TestReleaseUnique(t *testing.T) {
	u := &User{OrgID: "o", Username: "Jo", Email: "a@x", EmailVerified: true, ExternalID: "ext",
		LinkedEmails: []LinkedEmail{{Address: "l1@x"}, {Address: "l2@x"}}}
	u.ID = "0190aaaa-bbbb-7ccc-8ddd-eeeeeeABCDEF"
	steps := []struct {
		v     string
		check func() bool
	}{
		{UserEmailKey("o", "a@x"), func() bool { return u.Email == "" && !u.EmailVerified }},
		{UserExternalIDKey("o", "ext"), func() bool { return u.ExternalID == "" }},
		{UserEmailKey("o", "l1@x"), func() bool { return len(u.LinkedEmails) == 1 && u.LinkedEmails[0].Address == "l2@x" }},
		{UserUsernameKey("o", "Jo"), func() bool { return u.Username == "Jo-abcdef" }},
	}
	for _, s := range steps {
		if !ReleaseUnique(u, s.v) || !s.check() {
			t.Errorf("ReleaseUnique(%q) failed: %+v", s.v, u)
		}
	}
	if ReleaseUnique(u, "o/e/unknown") {
		t.Error("unknown value released")
	}

	g := &Group{OrgID: "o", DisplayName: "Eng", ExternalID: "x"}
	g.ID = "11111111-2222-7333-8444-555555666666"
	if !ReleaseUnique(g, GroupExternalIDKey("o", "x")) || g.ExternalID != "" {
		t.Error("group external id")
	}
	if !ReleaseUnique(g, GroupNameKey("o", "Eng")) || g.DisplayName != "Eng (666666)" {
		t.Errorf("group name %q", g.DisplayName)
	}
	if ReleaseUnique(g, "nope") {
		t.Error("group nope")
	}

	org := &Org{Name: "acme"}
	org.ID = "ab"
	if !ReleaseUnique(org, "acme") || org.Name != "acme-ab" || ReleaseUnique(org, "zzz") {
		t.Errorf("org %q", org.Name)
	}
	tn := &Tenant{OrgID: "o", Name: "t"}
	tn.ID = "abcdef0"
	if !ReleaseUnique(tn, TenantNameKey("o", "t")) || tn.Name != "t-bcdef0" || ReleaseUnique(tn, "x") {
		t.Errorf("tenant %q", tn.Name)
	}
	pr := &Provider{OrgID: "o", Name: "Okta"}
	pr.ID = "abcdef0"
	if !ReleaseUnique(pr, "o/n/okta") || pr.Name != "Okta (bcdef0)" || ReleaseUnique(pr, "x") {
		t.Errorf("provider %q", pr.Name)
	}
	pk := &Passkey{}
	if !ReleaseUnique(pk, "x") || !pk.Disabled || ReleaseUnique(pk, "x") {
		t.Error("passkey")
	}
	if ReleaseUnique(&Session{}, "x") {
		t.Error("session has no unique values")
	}
	if shortID("ABC-def") != "abcdef" || shortID("abcdefg") != "bcdefg" {
		t.Error("shortID")
	}
	if b64([]byte{0xfb, 0xff}) != "-_8" {
		t.Errorf("b64 %q", b64([]byte{0xfb, 0xff}))
	}
}

// ReleaseUnique removes exactly the value it was given: afterwards the entity no longer claims it.
func TestReleaseUniqueDropsClaim(t *testing.T) {
	u := &User{OrgID: "o", Username: "jo", Email: "a@x", ExternalID: "e", LinkedEmails: []LinkedEmail{{Address: "b@x"}}}
	u.ID = "abcdef123456"
	for _, v := range slices.Clone(u.Index().Unique) {
		if v == UserUsernameKey("o", "jo") {
			continue
		}
		if !ReleaseUnique(u, v) || slices.Contains(u.Index().Unique, v) {
			t.Errorf("%q still claimed after release", v)
		}
	}
	if !reflect.DeepEqual(u.Index().Unique, []string{"o/u/jo"}) {
		t.Errorf("left %v", u.Index().Unique)
	}
}

// A name that only looks different (full-width letters, a ligature, a different case) claims the same unique key.
func TestUniqueKeysFoldLookalikes(t *testing.T) {
	for _, same := range [][2]string{{"admin", "ａｄｍｉｎ"}, {"office", "oﬃce"}, {"Admin", "admin"}, {" admin ", "admin"}} {
		if UserUsernameKey("o", same[0]) != UserUsernameKey("o", same[1]) {
			t.Errorf("%q and %q are different usernames", same[0], same[1])
		}
	}
	if UserEmailKey("o", "ａ@example.com") != UserEmailKey("o", "a@example.com") {
		t.Error("a full-width address is another address")
	}
}
