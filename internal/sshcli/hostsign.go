package sshcli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// HostSignOptions are the arguments of `quisora ssh host-sign`.
type HostSignOptions struct {
	URL        string   // the tenant's discovery URL
	KeyFile    string   // the host's public key (…_key.pub)
	Principals []string // names the certificate is for; empty = the host's fully qualified name
	Token      string   // an access token with scope ssh:host ...
	ClientID   string   // ... or the service account whose client credentials get one
	Secret     string
	AuthMethod string // how the service account authenticates: "post", "basic" or "auto" (or ""): post, then basic
	TTLDays    int    // ask for a certificate of this many days (0: the tenant's host certificate lifetime)
}

// Authentication methods of a service account at the token endpoint (--auth-method).
const (
	AuthAuto  = "auto"
	AuthPost  = "post"
	AuthBasic = "basic"
)

// HostSign gets a host certificate for the public key in o.KeyFile and writes it beside it (…-cert.pub), then
// prints the sshd_config line that uses it.
func (e *Env) HostSign(ctx context.Context, o HostSignOptions) error {
	if o.Token == "" && (o.ClientID == "" || o.Secret == "") {
		return errors.New("give --token (or QUISORA_TOKEN), or --client-id and --client-secret (or QUISORA_CLIENT_SECRET)")
	}
	switch o.AuthMethod {
	case "", AuthAuto, AuthPost, AuthBasic:
	default:
		return fmt.Errorf("--auth-method %q: use auto, post or basic", o.AuthMethod)
	}
	if o.TTLDays < 0 {
		return errors.New("--ttl must be a number of days, at least 1")
	}
	b, err := os.ReadFile(o.KeyFile)
	if err != nil {
		return fmt.Errorf("reading the host's public key: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return fmt.Errorf("%s is not a public key: %w", o.KeyFile, err)
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return fmt.Errorf("%s is a certificate, not a public key", o.KeyFile)
	}
	d, err := e.discover(ctx, o.URL)
	if err != nil {
		return err
	}
	if d.off() {
		return errOff(d)
	}
	if !d.HostCerts || d.HostSignEndpoint == "" {
		return fmt.Errorf("host certificates are not enabled for %s/%s", d.Org, d.Tenant)
	}
	principals := o.Principals
	if len(principals) == 0 {
		name, err := e.fqdn(ctx)
		if err != nil {
			return fmt.Errorf("finding this host's name (give --principal): %w", err)
		}
		principals = []string{name}
	}

	token := o.Token
	if token == "" {
		if d.TokenEndpoint == "" {
			return errors.New("discovery has no token endpoint")
		}
		if token, err = e.clientCredentialsToken(ctx, d.TokenEndpoint, o); err != nil {
			return err
		}
	}

	cert, err := e.sign(ctx, d.HostSignEndpoint, token, signRequest{
		PublicKey:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Principals: principals,
		TTLDays:    o.TTLDays,
	}, ssh.HostCert)
	if err != nil {
		return fmt.Errorf("host certificate request: %w", err)
	}
	path := strings.TrimSuffix(o.KeyFile, ".pub") + "-cert.pub"
	if err := writeAtomic(path, authorizedLine(cert), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(e.errw(), "Host certificate for %s, valid until %s.\n", strings.Join(cert.ValidPrincipals, ", "), expiry(cert, e.now()))
	fmt.Fprintf(e.out(), "HostCertificate %s\n", path)
	return nil
}

// clientCredentialsToken gets an access token with scope ssh:host for the service account in o. A client
// authenticates at the token endpoint the way it was registered to, and a service account is registered for
// client_secret_post unless it was made otherwise, so the default is to try that and, when the server does not know the
// client that way (invalid_client), once more with client_secret_basic.
func (e *Env) clientCredentialsToken(ctx context.Context, endpoint string, o HostSignOptions) (string, error) {
	ask := func(method string) (string, error) {
		form := url.Values{"grant_type": {"client_credentials"}, "scope": {"ssh:host"}}
		var basic *basicCreds
		if method == AuthBasic {
			basic = &basicCreds{o.ClientID, o.Secret}
		} else {
			form.Set("client_id", o.ClientID)
			form.Set("client_secret", o.Secret)
		}
		var tok tokenResponse
		if err := e.postForm(ctx, endpoint, form, basic, &tok); err != nil {
			return "", err
		}
		if err := checkToken(&tok); err != nil {
			return "", err
		}
		return tok.AccessToken, nil
	}
	switch o.AuthMethod {
	case AuthPost, AuthBasic:
		tok, err := ask(o.AuthMethod)
		if err != nil {
			return "", fmt.Errorf("token request: %w", err)
		}
		return tok, nil
	}
	tok, err := ask(AuthPost)
	var ae *apiError
	if errors.As(err, &ae) && ae.Code == "invalid_client" {
		if tok, err = ask(AuthBasic); err != nil {
			return "", fmt.Errorf("token request: %w (tried client_secret_post, then client_secret_basic)", err)
		}
	}
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	return tok, nil
}

// fqdn is the host's fully qualified name, lower case: its hostname when that has a dot, else what the resolver
// says it is canonically (accepted only when it has a dot), else the bare hostname.
func (e *Env) fqdn(ctx context.Context) (string, error) {
	hostname := os.Hostname
	if e.Hostname != nil {
		hostname = e.Hostname
	}
	name, err := hostname()
	if err != nil {
		return "", err
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return "", errors.New("the host has no name")
	}
	if strings.Contains(name, ".") {
		return name, nil
	}
	lookup := e.LookupCNAME
	if lookup == nil {
		lookup = func(ctx context.Context, h string) (string, error) { return net.DefaultResolver.LookupCNAME(ctx, h) }
	}
	lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if cname, err := lookup(lctx, name); err == nil {
		if cname = strings.ToLower(strings.TrimSuffix(cname, ".")); strings.Contains(cname, ".") {
			return cname, nil
		}
	}
	return name, nil
}
