package loadtest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/web"
)

// Report is the result of one run.
type Report struct {
	Label       string            `json:"label,omitempty"`
	Scenario    string            `json:"scenario"`
	URLs        []string          `json:"urls"`
	Concurrency int               `json:"concurrency"`
	Conns       int               `json:"conns_per_url"`
	Seconds     float64           `json:"seconds"`
	Requests    uint64            `json:"requests"`
	OK          uint64            `json:"ok"`
	RPS         float64           `json:"rps"`
	OKRPS       float64           `json:"ok_rps"`
	MeanMs      float64           `json:"mean_ms"`
	P50Ms       float64           `json:"p50_ms"`
	P90Ms       float64           `json:"p90_ms"`
	P99Ms       float64           `json:"p99_ms"`
	P999Ms      float64           `json:"p999_ms"`
	MaxMs       float64           `json:"max_ms"`
	Errors      map[string]uint64 `json:"errors,omitempty"`
	Started     time.Time         `json:"started"`
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// Print writes a human readable summary.
func (r *Report) Print(w io.Writer) {
	fmt.Fprintf(w, "scenario %s, concurrency %d (%d conn/url x %d url), %.1fs\n", r.Scenario, r.Concurrency, r.Conns,
		len(r.URLs), r.Seconds)
	fmt.Fprintf(w, "  requests %d  ok %d  errors %d  =  %.0f req/s (%.0f ok/s)\n", r.Requests, r.OK, r.Requests-r.OK, r.RPS,
		r.OKRPS)
	fmt.Fprintf(w, "  latency ms: mean %.2f  p50 %.2f  p90 %.2f  p99 %.2f  p99.9 %.2f  max %.2f\n", r.MeanMs, r.P50Ms,
		r.P90Ms, r.P99Ms, r.P999Ms, r.MaxMs)
	if len(r.Errors) > 0 {
		keys := make([]string, 0, len(r.Errors))
		for k := range r.Errors {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintln(w, "  errors:")
		for _, k := range keys {
			fmt.Fprintf(w, "    %-40s %d\n", k, r.Errors[k])
		}
	}
}

// request is one prepared call plus how to judge the answer.
type request struct {
	req    *http.Request
	status int    // expected status
	body   string // when non-empty the response body must contain it
}

// generator builds the next request of a scenario for url; rng is private to the worker.
type generator func(rng *rand.Rand, base string) *request

// newGenerator prepares scenario sc (fetching whatever it needs from the server) and returns its generator.
func newGenerator(ctx context.Context, sc string, d *Data, urls []string, hc *http.Client) (generator, error) {
	form := func(base, path, body string) *request {
		req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return &request{req: req, status: 200}
	}
	get := func(base, path string, hdr ...string) *request {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		return &request{req: req, status: 200}
	}
	orgName := func(rng *rand.Rand) string { return OrgName(1 + rng.Intn(d.Orgs)) }
	// call is one prepared request of a scenario: the organization's endpoint (each organization has its own address
	// space, /o/<org>) and its body.
	type call struct{ path, body string }
	switch sc {
	case "discovery":
		if len(d.Samples) == 0 {
			return nil, errors.New("the data file has no organizations")
		}
		return func(rng *rand.Rand, base string) *request {
			// (by id: a discovery document is served at the organization's id form only)
			return get(base, "/o/"+d.Samples[rng.Intn(len(d.Samples))].OrgID+"/.well-known/openid-configuration")
		}, nil

	case "refresh", "refresh_groups":
		var calls []call
		for _, g := range d.Grants {
			if g.Groups == (sc == "refresh_groups") {
				calls = append(calls, call{"/o/" + g.Org + "/oauth/token", "grant_type=refresh_token&client_id=" + g.ClientID +
					"&client_secret=" + g.Secret + "&refresh_token=" + g.Token})
			}
		}
		if len(calls) == 0 {
			return nil, errors.New("the data file has no refresh tokens for this scenario (seed with --grants)")
		}
		return func(rng *rand.Rand, base string) *request {
			c := calls[rng.Intn(len(calls))]
			r := form(base, c.path, c.body)
			r.body = `"access_token"`
			return r
		}, nil

	case "client_credentials":
		var calls []call
		for _, s := range d.Samples {
			if s.CCID != "" {
				calls = append(calls, call{"/o/" + s.OrgID + "/oauth/token",
					"grant_type=client_credentials&client_id=" + s.CCID + "&client_secret=" + s.CCSecret})
			}
		}
		if len(calls) == 0 {
			return nil, errors.New("the data file has no client_credentials clients (seed with --clients >= 2)")
		}
		return func(rng *rand.Rand, base string) *request {
			c := calls[rng.Intn(len(calls))]
			r := form(base, c.path, c.body)
			r.body = `"access_token"`
			return r
		}, nil

	case "introspect":
		// Mint a pool of access tokens by refreshing, then introspect them as the owning client.
		var calls []call
		for _, g := range d.Grants {
			if g.Groups || len(calls) >= 256 {
				continue
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, urls[0]+"/o/"+g.Org+"/oauth/token", strings.NewReader(
				"grant_type=refresh_token&client_id="+g.ClientID+"&client_secret="+g.Secret+"&refresh_token="+g.Token))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := hc.Do(req)
			if err != nil {
				return nil, fmt.Errorf("introspect setup: %w", err)
			}
			var tr struct {
				Access string `json:"access_token"`
			}
			err = json.NewDecoder(resp.Body).Decode(&tr)
			resp.Body.Close()
			if err != nil || tr.Access == "" {
				return nil, fmt.Errorf("introspect setup: token request answered %d", resp.StatusCode)
			}
			calls = append(calls, call{"/o/" + g.Org + "/oauth/introspect", "token=" + tr.Access + "&client_id=" + g.ClientID +
				"&client_secret=" + g.Secret})
		}
		if len(calls) == 0 {
			return nil, errors.New("the data file has no refresh tokens (seed with --grants)")
		}
		return func(rng *rand.Rand, base string) *request {
			c := calls[rng.Intn(len(calls))]
			r := form(base, c.path, c.body)
			r.body = `"active":true`
			return r
		}, nil

	case "password_login":
		return func(rng *rand.Rand, base string) *request {
			org := orgName(rng)
			// users 1 and 2 are the organization's admin and manager, who sign in with a second factor
			first, n := 1, d.Users
			if n > 2 {
				first, n = 3, n-2
			}
			body := `{"email":"` + UserEmail(org, first+rng.Intn(n)) + `","password":"` + d.Password + `","next":""}`
			req, _ := http.NewRequest(http.MethodPost, base+"/o/"+org+"/api-internal/login/password", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			tok := csrfToken(rng)
			req.Header.Set("X-CSRF-Token", tok)
			req.AddCookie(&http.Cookie{Name: "__Host-quisora_csrf", Value: tok})
			return &request{req: req, status: 200, body: `"next"`}
		}, nil

	case "scim_list":
		hdr := []string{"Authorization", "Bearer " + d.APIToken}
		return func(rng *rand.Rand, base string) *request {
			start := 1 + 50*rng.Intn(max(d.Users/50, 1))
			return get(base, fmt.Sprintf("/scim/v2/%s/Users?count=50&startIndex=%d", orgName(rng), start), hdr...)
		}, nil

	case "scim_filter":
		hdr := []string{"Authorization", "Bearer " + d.APIToken}
		return func(rng *rand.Rand, base string) *request {
			f := url.QueryEscape(`userName eq "` + UserName(1+rng.Intn(d.Users)) + `"`)
			r := get(base, "/scim/v2/"+orgName(rng)+"/Users?filter="+f, hdr...)
			r.body = `"totalResults":1`
			return r
		}, nil

	case "mgmt_list":
		hdr := []string{"Authorization", "Bearer " + d.APIToken, web.APIVersionHeader, web.APIVersionLatest}
		return func(rng *rand.Rand, base string) *request {
			off := 50 * rng.Intn(max(d.Users/50, 1))
			return get(base, fmt.Sprintf("/api/orgs/%s/users?limit=50&offset=%d&sort=username", orgName(rng), off), hdr...)
		}, nil
	}
	return nil, fmt.Errorf("unknown scenario %q", sc)
}

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// csrfToken makes a 40 character anonymous double-submit token (the server only requires cookie == header).
func csrfToken(rng *rand.Rand) string {
	b := make([]byte, 40)
	for i := range b {
		b[i] = b64Alphabet[rng.Intn(len(b64Alphabet))]
	}
	return string(b)
}

// newClients builds conns HTTP clients per URL.
func newClients(o *RunOptions, conns int) [][]*http.Client {
	out := make([][]*http.Client, len(o.URLs))
	for i := range o.URLs {
		for range conns {
			tr := &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: o.Insecure},
				ForceAttemptHTTP2:   !o.HTTP1,
				MaxIdleConns:        o.Concurrency + 16,
				MaxIdleConnsPerHost: o.Concurrency + 16,
				IdleConnTimeout:     90 * time.Second,
				DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
			}
			if o.HTTP1 {
				tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
			}
			out[i] = append(out[i], &http.Client{Transport: tr, Timeout: 60 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
		}
	}
	return out
}

func closeClients(cs [][]*http.Client) {
	for _, l := range cs {
		for _, c := range l {
			c.CloseIdleConnections()
		}
	}
}

type workerResult struct {
	h      Histogram
	total  uint64
	ok     uint64
	errors map[string]uint64
}

// Run drives load for o.Duration (after an optional warm-up) and returns the report.
func Run(ctx context.Context, o RunOptions) (*Report, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	var d *Data
	if o.DataFile != "" {
		var err error
		if d, err = LoadData(o.DataFile); err != nil {
			if o.Scenario != "discovery" {
				return nil, err
			}
			d = &Data{Orgs: 1, Users: 1}
		}
	} else {
		d = &Data{Orgs: 1, Users: 1}
	}
	conns := o.Conns
	if conns <= 0 {
		conns = max(1, o.Concurrency/32)
	}
	clients := newClients(&o, conns)
	defer closeClients(clients)
	gen, err := newGenerator(ctx, o.Scenario, d, o.URLs, clients[0][0])
	if err != nil {
		return nil, err
	}

	start := time.Now()
	measureFrom := start.Add(o.Warmup)
	deadline := measureFrom.Add(o.Duration)
	runCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	results := make([]*workerResult, o.Concurrency)
	var wg sync.WaitGroup
	for w := range o.Concurrency {
		res := &workerResult{errors: map[string]uint64{}}
		results[w] = res
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(w)*7919))
			var buf bytes.Buffer
			for n := w; runCtx.Err() == nil; n++ {
				ui := n % len(o.URLs)
				r := gen(rng, o.URLs[ui])
				r.req = r.req.WithContext(runCtx)
				t0 := time.Now()
				outcome := do(clients[ui][w%conns], r, &buf)
				if runCtx.Err() != nil && outcome != "" { // cut off by the end of the run: not a result
					return
				}
				if t0.Before(measureFrom) {
					continue
				}
				res.h.Record(time.Since(t0))
				res.total++
				if outcome == "" {
					res.ok++
				} else {
					res.errors[outcome]++
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(measureFrom)
	if elapsed > o.Duration {
		elapsed = o.Duration
	}

	var all Histogram
	rep := &Report{Label: o.Label, Scenario: o.Scenario, URLs: o.URLs, Concurrency: o.Concurrency, Conns: conns,
		Seconds: elapsed.Seconds(), Errors: map[string]uint64{}, Started: start}
	for _, r := range results {
		all.Merge(&r.h)
		rep.Requests += r.total
		rep.OK += r.ok
		for k, v := range r.errors {
			rep.Errors[k] += v
		}
	}
	if len(rep.Errors) == 0 {
		rep.Errors = nil
	}
	rep.RPS = float64(rep.Requests) / elapsed.Seconds()
	rep.OKRPS = float64(rep.OK) / elapsed.Seconds()
	rep.MeanMs, rep.P50Ms, rep.P90Ms = ms(all.Mean()), ms(all.Quantile(0.5)), ms(all.Quantile(0.9))
	rep.P99Ms, rep.P999Ms, rep.MaxMs = ms(all.Quantile(0.99)), ms(all.Quantile(0.999)), ms(all.Max())
	if o.JSONOut != "" {
		if err := appendJSON(o.JSONOut, rep); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// do performs one request and returns "" for success or a short error class.
func do(c *http.Client, r *request, buf *bytes.Buffer) string {
	resp, err := c.Do(r.req)
	if err != nil {
		return "transport: " + shortErr(err)
	}
	buf.Reset()
	_, rerr := io.Copy(buf, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != r.status {
		return fmt.Sprintf("status %d%s", resp.StatusCode, errorCode(buf.Bytes()))
	}
	if rerr != nil {
		return "transport: " + shortErr(rerr)
	}
	if r.body != "" && !bytes.Contains(buf.Bytes(), []byte(r.body)) {
		return "unexpected body"
	}
	return ""
}

// errorCode extracts the "error" member of a JSON error body (OAuth and management API errors) for the breakdown.
func errorCode(body []byte) string {
	const key = `"error":"`
	i := bytes.Index(body, []byte(key))
	if i < 0 {
		return ""
	}
	rest := body[i+len(key):]
	j := bytes.IndexByte(rest, '"')
	if j < 0 || j > 60 {
		return ""
	}
	return " (" + string(rest[:j]) + ")"
}

func shortErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 60 {
		s = s[i+2:]
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func appendJSON(path string, rep *Report) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(rep)
}
