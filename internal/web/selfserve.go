package web

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
	rec := &selfResponse{header: http.Header{}}
	t.handler().ServeHTTP(rec, req)
	return rec.response(r), nil
}

// selfResponse collects what a handler answers, to give it back as the *http.Response of the request it served. It is
// not net/http/httptest's recorder because that package registers test flags and certificates in every binary that
// links it, and this one is linked into the server.
type selfResponse struct {
	header http.Header // what the handler sets; the response carries the copy WriteHeader took
	sent   http.Header
	status int
	body   bytes.Buffer
}

func (w *selfResponse) Header() http.Header { return w.header }

func (w *selfResponse) WriteHeader(code int) {
	if w.status == 0 {
		w.status, w.sent = code, w.header.Clone()
	}
}

func (w *selfResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
		// A server types an untyped answer from its first bytes; the caller sees the same over the network.
		if w.sent.Get("Content-Type") == "" && w.sent.Get("Content-Encoding") == "" {
			w.sent.Set("Content-Type", http.DetectContentType(b))
		}
	}
	return w.body.Write(b)
}

// Flush is here because handlers that stream ask their writer for it; everything is delivered once the handler returns.
func (w *selfResponse) Flush() { w.WriteHeader(http.StatusOK) }

func (w *selfResponse) response(r *http.Request) *http.Response {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return &http.Response{
		Status:     strconv.Itoa(w.status) + " " + http.StatusText(w.status),
		StatusCode: w.status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: w.sent, Body: io.NopCloser(&w.body), ContentLength: int64(w.body.Len()), Request: r,
	}
}
