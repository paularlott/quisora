package loadtest

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Naming of the synthetic dataset. Everything is derived from these so a data file is not strictly needed to find a
// record, and a seed run can be repeated or resumed safely.
const (
	orgPrefix       = "org-"
	DefaultPassword = "LoadTest-Passw0rd!"
)

// OrgName returns the name of the i-th (1-based) seeded organization.
func OrgName(i int) string { return fmt.Sprintf("%s%05d", orgPrefix, i) }

// UserName returns the username of the i-th (1-based) user of an organization.
func UserName(i int) string { return fmt.Sprintf("user-%04d", i) }

// UserEmail returns the email address (the sign-in name) of the i-th user of the organization called org.
func UserEmail(org string, i int) string { return UserName(i) + "@" + org + ".test" }

// SeedOptions controls `loadtest seed` (tools/loadtest).
type SeedOptions struct {
	Orgs      int    // organizations org-00001 ...
	Users     int    // users per organization
	Groups    int    // groups per organization
	Clients   int    // OAuth clients per organization (1 web app, 2nd client_credentials, the rest more web apps)
	MemberPct int    // percentage of users that are a member of one group
	Grants    int    // size of the pool of refresh-token grants created for the refresh scenarios
	Sample    int    // organizations whose client credentials are written to the data file
	Workers   int    // parallel writers
	Password  string // password of every user
	DataFile  string // output for the run step ("" = do not write)
}

// DefaultSeedOptions returns the defaults of the command line.
func DefaultSeedOptions() SeedOptions {
	return SeedOptions{Orgs: 5000, Users: 1000, Groups: 5, Clients: 3, MemberPct: 20, Grants: 20000, Sample: 1000,
		Workers: 32, Password: DefaultPassword, DataFile: "seed.json"}
}

// Validate checks the options.
func (o *SeedOptions) Validate() error {
	var errs []error
	chk := func(ok bool, msg string) {
		if !ok {
			errs = append(errs, errors.New(msg))
		}
	}
	chk(o.Orgs >= 1 && o.Orgs <= 99999, "--orgs must be 1..99999")
	chk(o.Users >= 3 && o.Users <= 500000, "--users must be 3..500000")
	chk(o.Groups >= 0 && o.Groups <= 100, "--groups must be 0..100")
	chk(o.Clients >= 1 && o.Clients <= 100, "--clients must be 1..100")
	chk(o.MemberPct >= 0 && o.MemberPct <= 100, "--member-pct must be 0..100")
	chk(o.Grants >= 0, "--grants must be >= 0")
	chk(o.Sample >= 1, "--sample must be >= 1")
	chk(o.Workers >= 1 && o.Workers <= 1024, "--workers must be 1..1024")
	chk(len(o.Password) >= 10, "--password must be at least 10 characters")
	if o.Groups == 0 {
		o.MemberPct = 0
	}
	if o.Sample > o.Orgs {
		o.Sample = o.Orgs
	}
	return errors.Join(errs...)
}

// Scenarios are the load profiles `loadtest run` knows.
var Scenarios = []string{"refresh", "refresh_groups", "client_credentials", "introspect", "password_login", "scim_list",
	"scim_filter", "mgmt_list", "discovery"}

// RunOptions controls `loadtest run`.
type RunOptions struct {
	URLs        []string
	Scenario    string
	Concurrency int
	Duration    time.Duration
	Warmup      time.Duration
	Insecure    bool
	DataFile    string
	Conns       int    // HTTP/2 connections per URL (0 = derived from concurrency)
	HTTP1       bool   // force HTTP/1.1
	JSONOut     string // append the report as one JSON line to this file
	Label       string // free text copied to the report
}

// DefaultRunOptions returns the defaults of the command line.
func DefaultRunOptions() RunOptions {
	return RunOptions{Scenario: "refresh", Concurrency: 64, Duration: 30 * time.Second, DataFile: "seed.json"}
}

// ParseURLs splits repeated and comma separated --url values and validates each as an absolute https/http URL
// without path.
func ParseURLs(in []string) ([]string, error) {
	var out []string
	for _, v := range in {
		for p := range strings.SplitSeq(v, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			u, err := url.Parse(p)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return nil, fmt.Errorf("--url %q: must be http(s)://host[:port]", p)
			}
			if u.Path != "" && u.Path != "/" {
				return nil, fmt.Errorf("--url %q: must not contain a path", p)
			}
			out = append(out, strings.TrimSuffix(p, "/"))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("--url is required")
	}
	return out, nil
}

// Validate checks the options.
func (o *RunOptions) Validate() error {
	if len(o.URLs) == 0 {
		return errors.New("--url is required")
	}
	if !slices.Contains(Scenarios, o.Scenario) {
		return fmt.Errorf("--scenario %q: must be one of %s", o.Scenario, strings.Join(Scenarios, ", "))
	}
	if o.Concurrency < 1 || o.Concurrency > 100000 {
		return errors.New("--concurrency must be 1..100000")
	}
	if o.Duration <= 0 {
		return errors.New("--duration must be positive")
	}
	if o.Warmup < 0 {
		return errors.New("--warmup must not be negative")
	}
	if o.Scenario != "discovery" && o.DataFile == "" {
		return errors.New("--data is required for this scenario")
	}
	return nil
}
