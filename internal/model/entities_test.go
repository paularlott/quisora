package model

import (
	"slices"
	"strings"
	"testing"
	"time"
)

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
	// "o" is the organizations' address space; a name never looks like an id (/o/<id or name>)
	for _, n := range []string{"", "Acme", "-a", "a-", "a_b", "admin", "api", "docs", strings.Repeat("a", 64), "a b", "o",
		NewID()} {
		if ValidOrgName(n) {
			t.Errorf("%q accepted", n)
		}
	}
	// An id of only lower-case letters and digits has a name's shape: it is still refused, as an id.
	for _, n := range []string{"0abcdefghijklmnopqrstu", "1a0b1c2d3e4f5g6h7i8j9k", "000000000000000000000k"} {
		if !IsID(n) || !orgNameRe.MatchString(n) {
			t.Fatalf("setup: %q is not both an id and of a name's shape", n)
		}
		if ValidOrgName(n) {
			t.Errorf("id %q accepted as a name", n)
		}
	}
	if OrgNameKey(" ACME ") != "acme" {
		t.Error("OrgNameKey")
	}
	o := Org{Name: "Acme", DisplayName: "A"}
	o.Created = t0
	ix := o.Index()
	if ix.Scope != "" || !slices.Equal(ix.Unique, []string{"acme"}) {
		t.Errorf("org index %+v", ix)
	}
	// The primary organization alone claims PrimaryOrgKey, which no name can be.
	o.Primary = true
	if ix := o.Index(); !slices.Equal(ix.Unique, []string{"acme", PrimaryOrgKey}) || ValidOrgName(PrimaryOrgKey) {
		t.Errorf("primary org index %+v", ix)
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
	if !slices.Equal(ix.Unique, []string{"o/n/default", "o/res/https://mcp.example.com/mcp"}) {
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
	if TenantResourceKey("o", "HTTPS://A.com/") != TenantResourceKey("o", "https://a.com") {
		t.Error("resource keys differ")
	}

	a := &TenantAccess{OrgID: "o", TenantID: "t", SubjectID: "s", SubjectType: SubjectUser, Clients: []string{"c1"}}
	if a.Index().Fields["tenant_id"] != "t" || AccessID("t", "s") != "t:s" {
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

// A metadata-document application is one record per organization, named by its URL in each: the record id differs
// between organizations, is the same for the same organization and URL, fits a record id, and the client_id the
// application sees is the URL. Every other client is its own id.
func TestClientRecordID(t *testing.T) {
	const url = "https://app.example.com/oauth/client.json"
	a, b := ClientRecordID("org-a", url), ClientRecordID("org-b", url)
	if a == b || a != ClientRecordID("org-a", url) || a == url || len(a) > 191 || !strings.HasPrefix(a, metadataClientPrefix) {
		t.Errorf("record ids %q, %q", a, b)
	}
	if ClientRecordID("org-a", url+"x") == a {
		t.Error("two documents of one organization share a record")
	}
	for _, id := range []string{"c_0dk2Yv", "dyn-abc"} {
		if ClientRecordID("org-a", id) != id {
			t.Errorf("%s is not its own record id", id)
		}
	}
	md := &Client{Meta: Meta{ID: a}, MetadataURL: url}
	if md.ClientID() != url || (&Client{Meta: Meta{ID: "c_x"}}).ClientID() != "c_x" {
		t.Error("ClientID")
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
	}{{Client{SelfRegistered: true, MetadataURL: "https://a/b", Meta: Meta{ID: "md_x"}}, true}, {Client{SelfRegistered: true, Meta: Meta{ID: "c_x"}}, false},
		{Client{MetadataURL: "https://a/b", Meta: Meta{ID: "md_x"}}, false}} {
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
	if k := PasskeyCredentialKey("u", pk.CredentialID); k != "u/-_8B" {
		t.Errorf("key %q (the user id, then the raw URL base64 credential id)", k)
	}
	if PasskeyCredentialKey("v", pk.CredentialID) == PasskeyCredentialKey("u", pk.CredentialID) {
		t.Error("the same credential id of two users shares a key")
	}
	if ix := pk.Index(); ix.Scope != "u" || ix.Unique[0] != "u/-_8B" {
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
		"x.failure.later": "success", "": "success", "org.spray.start": "failure", "org.spray.end": "failure",
		"org.update": "success",
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
	if ix := si.Index(); ix.Scope != "" || ix.Partition != "o" || !Unscoped(KindSignIn) {
		t.Error("signin index")
	}
	if ix := (&Lock{}).Index(); ix.Scope != "" || ix.Fields["org_deleted"] != false {
		t.Error("lock index")
	}
	if ix := (&Lock{Holder: OrgDeleted}).Index(); ix.Fields["org_deleted"] != true {
		t.Error("a decided organization deletion's guard is not indexed")
	}
	if ix := (&Replay{Expires: t0}).Index(); !ix.Expires.Equal(t0) {
		t.Error("replay index")
	}
	e := &Ephemeral{Expires: t0}
	if ix := e.Index(); !ix.Expires.Equal(t0) || e.GetMeta() != &e.Meta {
		t.Error("ephemeral")
	}
	if k := (&SigningKey{Alg: "ES256", Expires: t0}).Index(); !k.Expires.Equal(t0) {
		t.Error("key index")
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
