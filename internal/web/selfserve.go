package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
)

// SelfTransport returns a RoundTripper that answers the requests this server makes to its own organizations' addresses
// (https://<public host>/o/...) itself, through the whole of its handler, and sends every other request to base. An
// organization provider signs in with another organization of this server (discovery, token, userinfo and key
// requests to its issuer): they must work wherever the server runs, whether or not it can reach its own public
// address from where it stands (behind a proxy, a load balancer, a NAT without hairpinning), and must not leave the
// process. Only /o/ paths are served this way: nothing else of the server is something it calls itself, and the
// requests are made from the loopback address, as a local caller's would be.
func (s *Server) SelfTransport(base http.RoundTripper) http.RoundTripper {
	u, err := url.Parse(s.Cfg.Server.PublicURL)
	if err != nil {
		return base
	}
	return &selfTransport{host: strings.ToLower(u.Host), scheme: u.Scheme, base: base, handler: sync.OnceValue(s.Handler)}
}

type selfTransport struct {
	host, scheme string
	base         http.RoundTripper
	handler      func() http.Handler // built on the first request: the server's modules register their routes after this is made
}

func (t *selfTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != t.scheme || strings.ToLower(r.URL.Host) != t.host || !strings.HasPrefix(r.URL.Path, "/o/") {
		return t.base.RoundTrip(r)
	}
	req := r.Clone(r.Context())
	req.RequestURI, req.RemoteAddr, req.Host = r.URL.RequestURI(), "127.0.0.1:0", r.URL.Host
	if r.Body == nil {
		req.Body = http.NoBody
	} else {
		defer r.Body.Close() // a RoundTripper closes the request's body whatever happens
	}
	rec := httptest.NewRecorder()
	t.handler().ServeHTTP(rec, req)
	res := rec.Result()
	res.Request = r
	return res, nil
}
