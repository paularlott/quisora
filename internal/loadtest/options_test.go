package loadtest

import (
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

func TestParseURLs(t *testing.T) {
	got, err := ParseURLs([]string{"https://a:1/", "https://b:2, https://c:3", ""})
	if err != nil || len(got) != 3 || got[0] != "https://a:1" || got[2] != "https://c:3" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range [][]string{nil, {""}, {"ftp://x"}, {"localhost:8443"}, {"https://x/path"}, {"https://"}} {
		if _, err := ParseURLs(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestRunOptionsValidate(t *testing.T) {
	ok := DefaultRunOptions()
	ok.URLs = []string{"https://x"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*RunOptions){
		"no url":      func(o *RunOptions) { o.URLs = nil },
		"scenario":    func(o *RunOptions) { o.Scenario = "nope" },
		"concurrency": func(o *RunOptions) { o.Concurrency = 0 },
		"duration":    func(o *RunOptions) { o.Duration = 0 },
		"warmup":      func(o *RunOptions) { o.Warmup = -time.Second },
		"data":        func(o *RunOptions) { o.DataFile = "" },
	} {
		o := ok
		mut(&o)
		if err := o.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	d := ok
	d.Scenario, d.DataFile = "discovery", ""
	if err := d.Validate(); err != nil {
		t.Fatalf("discovery needs no data: %v", err)
	}
	for _, s := range Scenarios {
		o := ok
		o.Scenario = s
		if err := o.Validate(); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func TestSeedOptionsValidate(t *testing.T) {
	o := DefaultSeedOptions()
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	o.Sample = 99999
	if err := o.Validate(); err != nil || o.Sample != o.Orgs {
		t.Fatalf("sample clamp: %v %d", err, o.Sample)
	}
	o = DefaultSeedOptions()
	o.Groups = 0
	o.MemberPct = 50
	if err := o.Validate(); err != nil || o.MemberPct != 0 {
		t.Fatal("no groups means no memberships")
	}
	for name, mut := range map[string]func(*SeedOptions){
		"orgs":     func(o *SeedOptions) { o.Orgs = 0 },
		"users":    func(o *SeedOptions) { o.Users = 2 },
		"clients":  func(o *SeedOptions) { o.Clients = 0 },
		"pct":      func(o *SeedOptions) { o.MemberPct = 101 },
		"workers":  func(o *SeedOptions) { o.Workers = 0 },
		"password": func(o *SeedOptions) { o.Password = "short" },
	} {
		o := DefaultSeedOptions()
		mut(&o)
		if err := o.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestNamesAndIDs(t *testing.T) {
	if OrgName(1) != "org-00001" || OrgName(5000) != "org-05000" || UserName(7) != "user-0007" || UserName(12345) != "user-12345" {
		t.Fatal("names")
	}
	a, b := orgID(1), orgID(2)
	if a == b || a != orgID(1) || !(a < b) {
		t.Fatalf("ids must be deterministic and ordered: %s %s", a, b)
	}
	if !model.IsID(a) {
		t.Fatalf("not an id: %s", a)
	}
	o := DefaultSeedOptions()
	seen := map[string]bool{}
	for i := 1; i <= 3; i++ {
		for u := 1; u <= 50; u++ {
			id := o.userID(i, u)
			if seen[id] {
				t.Fatal("duplicate id")
			}
			seen[id] = true
		}
	}
	if strings.Count(clientSecret(1, 0), "qsrs_") != 1 || clientSecret(1, 0) == clientSecret(1, 1) {
		t.Fatal("secrets")
	}
}
