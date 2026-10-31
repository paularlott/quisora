// Package sshcli is the client of a tenant's SSH certificate authority (`quisora ssh`): it signs a person in to
// Quisora and fetches a short-lived user certificate (login, status, logout), gets host certificates for servers
// (host-sign) and keeps a server's trust files current (fetch). It talks to Quisora over HTTP only, as the design
// (docs/design/ssh-ca.md) lays out, and needs no configuration file, master key or store.
package sshcli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Response size limits: a discovery document, a token or a certificate is small; a KRL of a busy tenant is not.
const (
	maxAPIBody = 1 << 20
	maxKRLBody = 32 << 20
)

// Env is what the commands run against. The zero value is the real thing (standard output and error, the system's
// browser, the agent in SSH_AUTH_SOCK, ~/.ssh/quisora); every field is there for tests to replace.
type Env struct {
	Out, Err io.Writer // results; progress and warnings

	Insecure bool   // do not verify the server's certificate (development)
	CACert   string // PEM file of CA certificates trusted for the server, besides the system's

	HTTP        *http.Client                                  // replaces the client made from Insecure and CACert
	OpenBrowser func(url string) error                        // opens a URL in the user's browser
	AgentSock   string                                        // ssh-agent socket; "" = $SSH_AUTH_SOCK
	Dir         string                                        // where keys and certificates are written without an agent; "" = ~/.ssh/quisora
	Now         func() time.Time                              // the clock
	Sleep       func(context.Context, time.Duration) error    // waits between device-flow polls
	Timeout     time.Duration                                 // how long the browser may take to come back; 0 = 5 minutes
	GOOS        string                                        // the operating system to behave for; "" = this one (tests)
	Hostname    func() (string, error)                        // the host's name (host-sign)
	LookupCNAME func(context.Context, string) (string, error) // resolves it to a fully qualified name (host-sign)
}

func (e *Env) out() io.Writer {
	if e.Out != nil {
		return e.Out
	}
	return os.Stdout
}

func (e *Env) errw() io.Writer {
	if e.Err != nil {
		return e.Err
	}
	return os.Stderr
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) sleep(ctx context.Context, d time.Duration) error {
	if e.Sleep != nil {
		return e.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// client is the HTTP client: timeouts, the extra CA certificates, no redirect from https to http.
func (e *Env) client() (*http.Client, error) {
	if e.HTTP != nil {
		return e.HTTP, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if e.Insecure {
		tr.TLSClientConfig.InsecureSkipVerify = true // asked for: a development server with its own certificate
		fmt.Fprintln(e.errw(), "warning: the server's certificate is not verified (--insecure)")
	}
	if e.CACert != "" {
		pem, err := os.ReadFile(e.CACert)
		if err != nil {
			return nil, fmt.Errorf("reading --ca-cert: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca-cert %s holds no PEM certificate", e.CACert)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	e.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("refusing a redirect from https to http")
			}
			return nil
		}}
	return e.HTTP, nil
}

// Discovery is the document at the tenant's SSH URL (docs/design/ssh-ca.md, "Public endpoints").
type Discovery struct {
	Issuer                      string   `json:"issuer"`
	Org                         string   `json:"org"`
	Tenant                      string   `json:"tenant"`
	TenantID                    string   `json:"tenant_id"`
	Enabled                     *bool    `json:"enabled"` // false: SSH is turned off (a server without the field is on)
	ClientID                    string   `json:"client_id"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	SignEndpoint                string   `json:"sign_endpoint"`
	UserCAEndpoint              string   `json:"user_ca_endpoint"`
	KnownHostsEndpoint          string   `json:"known_hosts_endpoint"`
	KRLEndpoint                 string   `json:"krl_endpoint"`
	HostSignEndpoint            string   `json:"host_sign_endpoint"`
	CertTTL                     int      `json:"cert_ttl"`
	MaxAuthAge                  int      `json:"max_auth_age"`
	HostCerts                   bool     `json:"host_certs"`
	HostPatterns                []string `json:"host_patterns"`
	ACRValues                   string   `json:"acr_values"`
}

// off reports whether the tenant has turned SSH off: no certificate is signed, but the CA keys and the revocation list
// are still served (which then revokes everything), so `fetch` goes on working.
func (d *Discovery) off() bool { return d.Enabled != nil && !*d.Enabled }

func errOff(d *Discovery) error {
	return fmt.Errorf("SSH certificates are turned off for the tenant %s/%s: ask its administrators to turn them on", d.Org, d.Tenant)
}

// label names the tenant the way certificates in the agent are commented: quisora:<org>/<tenant>.
func (d *Discovery) label() string { return "quisora:" + d.Org + "/" + d.Tenant }

// discover reads the discovery document at raw (the tenant's SSH URL; https:// is assumed when there is no scheme).
func (e *Env) discover(ctx context.Context, raw string) (*Discovery, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q is not a discovery URL (like https://id.example.com/o/<org>/ssh/<tenant>)", raw)
	}
	if err := requireSecure(u); err != nil {
		return nil, err
	}
	resp, err := e.get(ctx, u.String(), "application/json")
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("discovery: nothing at %s: the URL is wrong, or SSH was never enabled for the tenant", u)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: %w", readError(resp))
	}
	var d Discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(&d); err != nil {
		return nil, fmt.Errorf("discovery: not a discovery document: %w", err)
	}
	if d.Org == "" || d.Tenant == "" {
		return nil, errors.New("discovery: not a Quisora SSH discovery document (no org or tenant)")
	}
	for _, ep := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.DeviceAuthorizationEndpoint, d.SignEndpoint,
		d.UserCAEndpoint, d.KnownHostsEndpoint, d.KRLEndpoint, d.HostSignEndpoint} {
		if ep == "" {
			continue
		}
		eu, err := url.Parse(ep)
		if err != nil || eu.Host == "" {
			return nil, fmt.Errorf("discovery: bad endpoint %q", ep)
		}
		if err := requireSecure(eu); err != nil {
			return nil, fmt.Errorf("discovery: %w", err)
		}
	}
	return &d, nil
}

// requireSecure refuses a URL that would send tokens in the clear: https, or http to this machine (development).
func requireSecure(u *url.URL) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%s: only https is used (http is allowed to this machine only)", u.Redacted())
}

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// get requests rawURL with GET.
func (e *Env) get(ctx context.Context, rawURL, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return e.do(req)
}

func (e *Env) do(req *http.Request) (*http.Response, error) {
	c, err := e.client()
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "quisora-ssh")
	return c.Do(req)
}

// apiError is an error answer of the server: {"error": …, "error_description": …} with a status.
type apiError struct {
	Status int
	Code   string
	Desc   string
}

func (a *apiError) Error() string {
	switch {
	case a.Desc != "":
		return a.Desc
	case a.Code != "":
		return a.Code
	}
	return fmt.Sprintf("the server answered %d %s", a.Status, http.StatusText(a.Status))
}

// readError reads the error answer in resp (the body is not closed).
func readError(resp *http.Response) error {
	e := &apiError{Status: resp.StatusCode}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if b, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody)); err == nil && json.Unmarshal(b, &body) == nil {
		e.Code, e.Desc = body.Error, body.Description
	}
	if e.Code == "slow_down" && e.Desc == "" {
		e.Desc = "too many requests: wait a moment and try again"
	}
	return e
}
