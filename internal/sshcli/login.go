package sshcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// LoginOptions are the arguments of `quisora ssh login`.
type LoginOptions struct {
	URL        string        // the tenant's discovery URL
	Device     bool          // use the device flow instead of the browser
	NoBrowser  bool          // print the URL instead of opening the browser
	Key        string        // use this key (its .pub) and write <Key>-cert.pub; "" = a fresh key for the agent
	Principals []string      // ask for these principals only
	TTL        time.Duration // ask for a shorter certificate than the tenant's default
	NoAgent    bool          // write the key to files in the Quisora directory, not to ssh-agent
}

// signRequest and issued are the sign endpoints' JSON (docs/design/ssh-ca.md, "Public endpoints").
type signRequest struct {
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals,omitempty"`
	TTL        int      `json:"ttl,omitempty"`      // user certificates: seconds
	TTLDays    int      `json:"ttl_days,omitempty"` // host certificates: days
}

type issued struct {
	Certificate string   `json:"certificate"`
	Serial      string   `json:"serial"`
	KeyID       string   `json:"key_id"`
	Principals  []string `json:"principals"`
}

// sign asks a signing endpoint (user or host) for a certificate for pub, with a bearer token, and checks that what
// comes back is a certificate of the right type for that key.
func (e *Env) sign(ctx context.Context, endpoint, token string, in signRequest, certType uint32) (*ssh.Certificate, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := e.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := readError(resp)
		if resp.StatusCode == http.StatusUnauthorized {
			if ae, ok := err.(*apiError); ok && ae.Desc == "" {
				ae.Desc = "the server did not accept the access token"
			}
		}
		return nil, err
	}
	var out issued
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(&out); err != nil {
		return nil, fmt.Errorf("unreadable answer: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(out.Certificate))
	if err != nil {
		return nil, fmt.Errorf("the server's certificate is not valid: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("the server did not return a certificate")
	}
	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(in.PublicKey))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cert.Key.Marshal(), want.Marshal()) {
		return nil, errors.New("the server signed a different key than the one sent")
	}
	if cert.CertType != certType {
		return nil, errors.New("the server returned a certificate of the wrong type")
	}
	return cert, nil
}

// Login signs in to the tenant at o.URL and gets a user certificate, which it puts in the ssh-agent (a fresh key),
// in the Quisora directory (a fresh key, no agent, or o.NoAgent) or next to the key o.Key.
func (e *Env) Login(ctx context.Context, o LoginOptions) error {
	if o.TTL < 0 || o.TTL > 0 && o.TTL < time.Minute {
		return errors.New("--ttl must be at least 60 seconds")
	}
	d, err := e.discover(ctx, o.URL)
	if err != nil {
		return err
	}
	if d.off() {
		return errOff(d)
	}
	if d.SignEndpoint == "" {
		return errors.New("discovery has no sign endpoint")
	}

	var pub ssh.PublicKey
	var priv ed25519.PrivateKey
	keyBase := strings.TrimSuffix(o.Key, ".pub")
	if o.Key != "" {
		b, err := os.ReadFile(keyBase + ".pub")
		if err != nil {
			return fmt.Errorf("reading the public key: %w", err)
		}
		if pub, _, _, _, err = ssh.ParseAuthorizedKey(b); err != nil {
			return fmt.Errorf("%s.pub is not a public key: %w", keyBase, err)
		}
		if _, isCert := pub.(*ssh.Certificate); isCert {
			return fmt.Errorf("%s.pub is a certificate, not a public key", keyBase)
		}
	} else {
		p, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if pub, err = ssh.NewPublicKey(p); err != nil {
			return err
		}
		priv = k
	}
	var tok *tokenResponse
	if o.Device {
		tok, err = e.deviceLogin(ctx, d)
	} else {
		tok, err = e.browserLogin(ctx, d, o.NoBrowser)
	}
	if err != nil {
		return err
	}

	cert, err := e.sign(ctx, d.SignEndpoint, tok.AccessToken, signRequest{
		PublicKey:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Principals: o.Principals,
		TTL:        int(o.TTL / time.Second),
	}, ssh.UserCert)
	if err != nil {
		return fmt.Errorf("certificate request: %w", err)
	}

	var where string
	switch {
	case o.Key != "":
		path := keyBase + "-cert.pub"
		if err := writeAtomic(path, authorizedLine(cert), 0o644); err != nil {
			return err
		}
		where = "Certificate written to " + path + " (ssh uses it with the key " + keyBase + ")."
	default:
		if where, err = e.keepKey(d, priv, cert, o.NoAgent); err != nil {
			return err
		}
	}

	fmt.Fprintf(e.out(), "Signed in to %s/%s.\nPrincipals: %s\nValid until: %s\n%s\n", d.Org, d.Tenant,
		strings.Join(cert.ValidPrincipals, ", "), expiry(cert, e.now()), where)
	return nil
}
