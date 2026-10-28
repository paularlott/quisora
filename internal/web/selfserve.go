package web

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/paularlott/quisora/internal/service"
)

// SelfTransport returns a RoundTripper that answers the requests this server makes to its own organizations' addresses
// (https://<public host>/o/...) itself, through the whole of its handler, and sends every other request to base. An
// organization provider signs in with another organization of this server (discovery, token, userinfo and key
// requests to its issuer): they must work wherever the server runs, whether or not it can reach its own public
// address from where it stands (behind a proxy, a load balancer, a NAT without hairpinning), and must not leave the
// process. Only /o/ paths are served this way: nothing else of the server is something it calls itself, and the
// requests are made from the address of the client whose request caused them (see RoundTrip).
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

// RoundTrip serves an organization path itself. The request it hands the handler comes from the address of the client
// whose request caused it (the one in the context, as the request middleware recorded it), because every per-address
// limit of the endpoints it reaches (failed token requests, client authentication failures, ...) counts by that
// address: from one shared loopback address, anyone who can start a sign-in through an organization provider could
// make the upstream requests fail, from a few addresses, and so exhaust the limit that every organization provider's
// requests share. Work with no request behind it (the refresh checks of the housekeeping) has no client and comes
// from the loopback address; it is not counted with any client's, and only delays itself when it is refused.
func (t *selfTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != t.scheme || strings.ToLower(r.URL.Host) != t.host || !strings.HasPrefix(r.URL.Path, "/o/") {
		return t.base.RoundTrip(r)
	}
	// The request starts from a context of its own: what the outer request's context holds (its session, user and
	// actor) is that client's identity, and must not be inherited by a request the client's input only caused. Only
	// its end (cancelled or past its deadline) carries over.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer context.AfterFunc(r.Context(), cancel)()
	req := r.Clone(ctx)
	req.RequestURI, req.RemoteAddr, req.Host = r.URL.RequestURI(), originAddr(r), r.URL.Host
	// The address above is already the client's as trust_proxy resolved it: a forwarding header would let the caller
	// of this request name another one.
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded"} {
		req.Header.Del(h)
	}
	if r.Body == nil {
		req.Body = http.NoBody
	} else {
		defer r.Body.Close() // a RoundTripper closes the request's body whatever happens
	}
	rec := &selfResponse{header: http.Header{}}
	t.handler().ServeHTTP(rec, req)
	return rec.response(r), nil
}

// originAddr is the remote address of the in-process request made for r: the client of the request r was made for, or
// the loopback address when there is none.
func originAddr(r *http.Request) string {
	if ri := service.RequestFrom(r.Context()); ri != nil {
		if a, err := netip.ParseAddr(ri.IP); err == nil {
			return net.JoinHostPort(a.String(), "0")
		}
	}
	return "127.0.0.1:0"
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
