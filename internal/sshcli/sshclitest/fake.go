// Package sshclitest is a fake Quisora for the tests of the SSH command-line client (internal/sshcli, cmd): the
// discovery document, the authorization, device, token and sign endpoints, the CA keys, the known_hosts lines and a
// KRL, answering as docs/design/ssh-ca.md says, with a certificate authority of its own made with x/crypto/ssh.
package sshclitest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// Fake is a running fake Quisora. Set its fields before the client runs; the Requests it saw are read with the
// methods.
type Fake struct {
	Server *httptest.Server
	URL    string // the tenant's discovery URL

	UserCA ssh.Signer
	HostCA ssh.Signer

	// ClientID and ClientSecret are the service account host-sign signs in as. AuthMethod is how it is registered to
	// authenticate: "post" (client_secret_post, the default of a service account) or "basic" (client_secret_basic); the
	// token endpoint accepts that method only, as Quisora's does.
	ClientID, ClientSecret string
	AuthMethod             string
	// KRLVersion is the version of the KRL it serves when Body has none (0: the time now, as Quisora's is).
	KRLVersion uint64
	// Principals are what the user may have; HostPatterns what host principals must match.
	Principals   []string
	HostPatterns []string
	// Interval is the device flow's polling interval in seconds (default 5).
	Interval int
	// WrongNonce makes the ID token carry another nonce than the request's.
	WrongNonce bool
	// Off turns SSH off for the tenant: the discovery document says "enabled": false, which is all that changes (the CA
	// keys and the revocation list are still served).
	Off bool
	// Body replaces what a path ("ca.pub", "krl", "known_hosts") answers; Fail answers that status instead (also for
	// "token" and the other endpoints).
	Body map[string][]byte
	Fail map[string]int

	mu        sync.Mutex
	auth      url.Values
	codes     map[string]authCode
	devices   map[string]bool
	tokens    []url.Values
	methods   []string
	deviceReq []url.Values
	signs     []map[string]any
	paths     []string
	pollCount int
	answers   []string
}

type authCode struct {
	challenge, redirect, nonce string
}

// New starts a fake with a user CA and a host CA. The tenant is acme/prod.
func New() *Fake {
	f := &Fake{
		UserCA:       signer(),
		HostCA:       signer(),
		ClientID:     "host-svc",
		ClientSecret: "s3cr3t/+ &x", // characters that must be form-encoded, in the body and in the basic credentials
		AuthMethod:   "post",
		Principals:   []string{"paul", "ops"},
		HostPatterns: []string{"*.example.com"},
		Body:         map[string][]byte{},
		Fail:         map[string]int{},
		codes:        map[string]authCode{},
		devices:      map[string]bool{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	f.URL = f.Server.URL + "/o/org1/ssh/prod"
	return f
}

// NewTLS is New over TLS with the httptest certificate; Server.Certificate() is what --ca-cert should trust.
func NewTLS() *Fake {
	f := New()
	f.Server.Close()
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	f.URL = f.Server.URL + "/o/org1/ssh/prod"
	return f
}

// Close stops the fake.
func (f *Fake) Close() { f.Server.Close() }

func signer() ssh.Signer {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(k)
	return s
}

// SetDeviceAnswers sets the token endpoint's answers to the device-flow polls, in order: "authorization_pending",
// "slow_down", "access_denied", "expired_token", "server_error" (a 500 with a page, not JSON), "hangup" (the connection
// is dropped) or "ok" (also what follows when they run out).
func (f *Fake) SetDeviceAnswers(a ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers, f.pollCount = a, 0
}

// Auth is the query of the last authorization request.
func (f *Fake) Auth() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auth
}

// TokenForms are the form of every token request, in order.
func (f *Fake) TokenForms() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.tokens)
}

// TokenMethods is how every token request authenticated, in order: "basic" (an Authorization header), "post" (a
// client_secret in the form) or "none".
func (f *Fake) TokenMethods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.methods)
}

// DeviceForms are the form of every device authorization request, in order.
func (f *Fake) DeviceForms() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.deviceReq)
}

// SignBodies are the JSON bodies of the sign requests (user and host), in order.
func (f *Fake) SignBodies() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.signs)
}

// Paths are "METHOD /path" of every request, in order.
func (f *Fake) Paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.paths)
}

// Browse plays the browser: it follows the authorization URL (the fake redirects to the loopback redirect_uri with
// the code, which reaches the client).
func (f *Fake) Browse(authURL string) error {
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(authURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the browser ended on %s", resp.Status)
	}
	return nil
}

func (f *Fake) base() string { return f.Server.URL + "/o/org1/ssh/prod" }

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	name := path.Base(r.URL.Path)
	if st := f.Fail[name]; st != 0 {
		http.Error(w, "forced failure", st)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/o/org1/ssh/prod":
		f.discovery(w)
	case r.Method == "GET" && name == "ca.pub":
		f.text(w, "ca.pub", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f.UserCA.PublicKey())))+" quisora:acme/prod:user:k1\n")
	case r.Method == "GET" && name == "known_hosts":
		line := string(ssh.MarshalAuthorizedKey(f.HostCA.PublicKey()))
		f.text(w, "known_hosts", "@cert-authority "+strings.Join(f.HostPatterns, ",")+" "+strings.TrimSpace(line)+" quisora:acme/prod:host:k2\n")
	case r.Method == "GET" && name == "krl":
		body, ok := f.Body["krl"]
		if !ok {
			body = f.krl()
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	case r.URL.Path == "/authorize":
		f.authorize(w, r)
	case r.URL.Path == "/device":
		f.device(w, r)
	case r.URL.Path == "/token":
		f.token(w, r)
	case r.URL.Path == "/sign":
		f.sign(w, r, ssh.UserCert)
	case r.URL.Path == "/host-sign":
		f.sign(w, r, ssh.HostCert)
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) text(w http.ResponseWriter, key, def string) {
	body, ok := f.Body[key]
	if !ok {
		body = []byte(def)
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(body)
}

// krl is what Quisora serves when nothing is revoked: a section for each of the two CA keys, no serials.
func (f *Fake) krl() []byte {
	now := time.Now()
	version := f.KRLVersion
	if version == 0 {
		version = uint64(now.Unix())
	}
	k := sshca.NewKRL(version, now, "")
	k.Add(f.UserCA.PublicKey())
	k.Add(f.HostCA.PublicKey())
	return k.Marshal()
}

func (f *Fake) discovery(w http.ResponseWriter) {
	b := f.base()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": f.Server.URL + "/o/org1", "org": "acme", "tenant": "prod", "tenant_id": "t_1", "enabled": !f.Off, "client_id": "ssh-client",
		"authorization_endpoint":        f.Server.URL + "/authorize",
		"token_endpoint":                f.Server.URL + "/token",
		"device_authorization_endpoint": f.Server.URL + "/device",
		"sign_endpoint":                 f.Server.URL + "/sign",
		"user_ca_endpoint":              b + "/ca.pub", "known_hosts_endpoint": b + "/known_hosts", "krl_endpoint": b + "/krl",
		"host_sign_endpoint": f.Server.URL + "/host-sign",
		"cert_ttl":           28800, "max_auth_age": 3600, "host_certs": true, "host_patterns": f.HostPatterns,
		"acr_values": "urn:quisora:acr:mfa",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// authorize records the request and redirects to the loopback redirect_uri with a code (or, when the request is
// not one the CLI should make, an error).
func (f *Fake) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	f.auth = q
	f.mu.Unlock()
	redirect := q.Get("redirect_uri")
	ru, err := url.Parse(redirect)
	if err != nil || ru.Hostname() != "127.0.0.1" || ru.Path != "/callback" || ru.Port() == "" {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	back := url.Values{"state": {q.Get("state")}}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "ssh-client" ||
		q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		back.Set("error", "invalid_request")
		back.Set("error_description", "the request is not an authorization code request with PKCE")
	} else {
		code := randomToken()
		f.mu.Lock()
		f.codes[code] = authCode{q.Get("code_challenge"), redirect, q.Get("nonce")}
		f.mu.Unlock()
		back.Set("code", code)
	}
	http.Redirect(w, r, redirect+"?"+back.Encode(), http.StatusFound)
}

func (f *Fake) device(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.PostForm.Get("client_id") != "ssh-client" {
		oauthError(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}
	code := randomToken()
	f.mu.Lock()
	f.deviceReq = append(f.deviceReq, r.PostForm)
	f.devices[code] = true
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"device_code": code, "user_code": "WDJB-MJHT",
		"verification_uri": f.Server.URL + "/device/verify", "verification_uri_complete": f.Server.URL + "/device/verify?user_code=WDJB-MJHT",
		"expires_in": 600, "interval": cmpInt(f.Interval, 5)})
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	form := r.PostForm
	_, _, hasBasic := r.BasicAuth()
	method := "none"
	switch {
	case hasBasic:
		method = "basic"
	case form.Get("client_secret") != "":
		method = "post"
	}
	f.mu.Lock()
	f.tokens = append(f.tokens, form)
	f.methods = append(f.methods, method)
	f.mu.Unlock()
	switch form.Get("grant_type") {
	case "authorization_code":
		f.mu.Lock()
		ac, ok := f.codes[form.Get("code")]
		delete(f.codes, form.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		switch {
		case !ok:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or used code")
		case form.Get("redirect_uri") != ac.redirect || form.Get("client_id") != "ssh-client":
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri or client does not match")
		case subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(ac.challenge)) != 1:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		default:
			nonce := ac.nonce
			if f.WrongNonce {
				nonce = "other"
			}
			f.tokenAnswer(w, "user-token", nonce)
		}
	case "urn:ietf:params:oauth:grant-type:device_code":
		f.mu.Lock()
		known := f.devices[form.Get("device_code")]
		answer := "ok"
		if f.pollCount < len(f.answers) {
			answer = f.answers[f.pollCount]
		}
		f.pollCount++
		f.mu.Unlock()
		switch {
		case !known:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown device code")
		case answer == "ok":
			f.tokenAnswer(w, "user-token", "")
		case answer == "server_error":
			http.Error(w, "<html>502 Bad Gateway</html>", http.StatusBadGateway)
		case answer == "hangup":
			if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
				c.Close()
			}
		default:
			oauthError(w, http.StatusBadRequest, answer, "device flow: "+answer)
		}
	case "client_credentials":
		var id, secret string
		switch {
		case method == "basic" && f.AuthMethod == "basic":
			id, secret, _ = r.BasicAuth()
			id, _ = url.QueryUnescape(id)
			secret, _ = url.QueryUnescape(secret)
		case method == "post" && f.AuthMethod == "post":
			id, secret = form.Get("client_id"), form.Get("client_secret")
		}
		// the client authenticates the way it was registered to, nothing else
		if id != f.ClientID || secret != f.ClientSecret || secret == "" {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "bad client credentials")
			return
		}
		if form.Get("scope") != "ssh:host" {
			oauthError(w, http.StatusBadRequest, "invalid_scope", "only ssh:host")
			return
		}
		f.tokenAnswer(w, "host-token", "")
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "no such grant")
	}
}

func (f *Fake) tokenAnswer(w http.ResponseWriter, access, nonce string) {
	out := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300}
	if nonce != "" {
		enc := base64.RawURLEncoding
		payload, _ := json.Marshal(map[string]any{"iss": f.Server.URL + "/o/org1", "aud": "ssh-client", "sub": "u_1", "nonce": nonce})
		out["id_token"] = enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + "."
	}
	writeJSON(w, http.StatusOK, out)
}

// sign signs a user or a host certificate for the key in the request.
func (f *Fake) sign(w http.ResponseWriter, r *http.Request, certType uint32) {
	want := "Bearer user-token"
	ca := f.UserCA
	if certType == ssh.HostCert {
		want, ca = "Bearer host-token", f.HostCA
	}
	if r.Header.Get("Authorization") != want {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	var in struct {
		PublicKey  string   `json:"public_key"`
		Principals []string `json:"principals"`
		TTL        int      `json:"ttl"`
		TTLDays    int      `json:"ttl_days"`
	}
	var raw map[string]any
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "not JSON")
		return
	}
	f.mu.Lock()
	f.signs = append(f.signs, raw)
	f.mu.Unlock()
	b, _ := json.Marshal(raw)
	_ = json.Unmarshal(b, &in)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(in.PublicKey))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the public key does not parse")
		return
	}
	principals := in.Principals
	if certType == ssh.UserCert {
		if len(principals) == 0 {
			principals = f.Principals
		}
		for _, p := range principals {
			if !slices.Contains(f.Principals, p) {
				oauthError(w, http.StatusForbidden, "access_denied", fmt.Sprintf("principal %q is not allowed", p))
				return
			}
		}
	} else {
		if len(principals) == 0 {
			oauthError(w, http.StatusBadRequest, "invalid_request", "no principals")
			return
		}
		for _, p := range principals {
			if ok, _ := path.Match(f.HostPatterns[0], p); !ok {
				oauthError(w, http.StatusForbidden, "access_denied", fmt.Sprintf("principal %q matches no host pattern", p))
				return
			}
		}
	}
	ttl := 8 * time.Hour
	if certType == ssh.HostCert {
		ttl = 90 * 24 * time.Hour
		if in.TTLDays > 90 || in.TTLDays < 0 {
			oauthError(w, http.StatusBadRequest, "invalid_request", "ttl_days: between 1 day and the tenant's host certificate lifetime")
			return
		}
		if in.TTLDays > 0 {
			ttl = time.Duration(in.TTLDays) * 24 * time.Hour
		}
	} else if in.TTL > 0 {
		ttl = min(ttl, time.Duration(in.TTL)*time.Second)
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key: pub, Serial: binary.BigEndian.Uint64(randBytes(8)) | 1, CertType: certType,
		KeyId:           "paul@acme/u_1",
		ValidPrincipals: slices.Sorted(slices.Values(principals)),
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()), ValidBefore: uint64(now.Add(ttl).Unix()),
	}
	if certType == ssh.UserCert {
		cert.Extensions = map[string]string{"permit-pty": "", "permit-user-rc": ""}
	} else {
		cert.KeyId = "host:" + principals[0] + "@acme"
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"certificate": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))), "serial": fmt.Sprint(cert.Serial),
		"key_id": cert.KeyId, "principals": cert.ValidPrincipals,
		"valid_after":  time.Unix(int64(cert.ValidAfter), 0).UTC().Format(time.RFC3339),
		"valid_before": time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
	})
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randomToken() string { return base64.RawURLEncoding.EncodeToString(randBytes(18)) }

// EmptyKRL is a valid KRL with no sections.
func EmptyKRL() []byte {
	b := binary.BigEndian.AppendUint64(nil, 0x5353484b524c0a00)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint64(b, uint64(time.Now().Unix())) // krl_version
	b = binary.BigEndian.AppendUint64(b, uint64(time.Now().Unix())) // generated_date
	b = binary.BigEndian.AppendUint64(b, 0)                         // flags
	b = binary.BigEndian.AppendUint32(b, 0)                         // reserved
	b = binary.BigEndian.AppendUint32(b, 0)                         // comment
	return b
}

func cmpInt(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}
