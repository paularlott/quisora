// Command fakeidp is the upstream sign-in provider for the OpenID conformance run (development machines only).
// Quisora's own sign-in page needs JavaScript and the suite's browser signs in by following links, so the suite signs
// in through this provider: /authorize redirects straight back with a code (no page) and /token returns an ES256 ID
// token for a fixed user with a verified email address. It serves HTTPS with a self-signed certificate, written to
// -cert-out so Quisora can trust it (--extra-ca-file), and relays Quisora's back-channel logout posts (HTTPS on
// -relay) to the suite's own self-signed endpoint.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"
)

var b64 = base64.RawURLEncoding

func main() {
	listen := flag.String("listen", "0.0.0.0:8095", "")
	issuer := flag.String("issuer", "https://127.0.0.1:8095", "issuer, as Quisora reaches it")
	authURL := flag.String("authorize-url", "https://host.docker.internal:8095/authorize", "authorization endpoint, as the suite's browser reaches it")
	email := flag.String("email", "user@acme.test", "")
	clientID := flag.String("client-id", "quisora-upstream", "")
	relay := flag.String("relay", "0.0.0.0:8096", "back-channel logout relay")
	suiteURL := flag.String("suite", "https://localhost.emobix.co.uk:8453", "")
	certOut := flag.String("cert-out", "fakeidp.pem", "where to write the certificate for Quisora to trust")
	flag.Parse()

	cert := selfSigned(*certOut)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var mu sync.Mutex
	codes := map[string]string{} // code -> nonce
	pad := func(b *big.Int) string { out := make([]byte, 32); b.FillBytes(out); return b64.EncodeToString(out) }
	sign := func(claims map[string]any) string {
		h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "fake-1", "typ": "JWT"})
		c, _ := json.Marshal(claims)
		in := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
		d := sha256.Sum256([]byte(in))
		r, s, _ := ecdsa.Sign(rand.Reader, key, d[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return in + "." + b64.EncodeToString(sig)
	}
	j := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	m := http.NewServeMux()
	m.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"issuer": *issuer, "authorization_endpoint": *authURL, "token_endpoint": *issuer + "/token",
			"jwks_uri": *issuer + "/jwks", "response_types_supported": []string{"code"},
			"id_token_signing_alg_values_supported": []string{"ES256"}, "code_challenge_methods_supported": []string{"S256"}})
	})
	m.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "kid": "fake-1", "alg": "ES256",
			"use": "sig", "x": pad(key.X), "y": pad(key.Y)}}})
	})
	m.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		code := b64.EncodeToString(b)
		mu.Lock()
		codes[code] = q.Get("nonce")
		mu.Unlock()
		log.Printf("authorize -> %s", q.Get("redirect_uri"))
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
	})
	m.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		nonce, ok := codes[r.PostForm.Get("code")]
		delete(codes, r.PostForm.Get("code"))
		mu.Unlock()
		if r.PostForm.Get("grant_type") != "authorization_code" || !ok {
			w.WriteHeader(http.StatusBadRequest)
			j(w, map[string]string{"error": "invalid_grant"})
			return
		}
		now := time.Now()
		tok := sign(map[string]any{"iss": *issuer, "sub": "fake-user-1", "aud": *clientID, "exp": now.Add(5 * time.Minute).Unix(),
			"iat": now.Unix(), "nonce": nonce, "email": *email, "email_verified": true, "name": "Conformance User"})
		j(w, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": tok})
	})

	suite, _ := url.Parse(*suiteURL)
	rp := httputil.NewSingleHostReverseProxy(suite)
	rp.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // the suite's own dev certificate
	d := rp.Director
	rp.Director = func(r *http.Request) { d(r); r.Host = suite.Host; log.Printf("relay %s %s", r.Method, r.URL) }
	tc := &tls.Config{Certificates: []tls.Certificate{cert}}
	go func() { log.Fatal((&http.Server{Addr: *relay, Handler: rp, TLSConfig: tc}).ListenAndServeTLS("", "")) }()
	log.Fatal((&http.Server{Addr: *listen, Handler: m, TLSConfig: tc}).ListenAndServeTLS("", ""))
}

// selfSigned makes a certificate for the names Quisora and the suite's browser use, and writes it (PEM) to out.
func selfSigned(out string) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Quisora conformance fake IdP"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost", "host.docker.internal"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}
