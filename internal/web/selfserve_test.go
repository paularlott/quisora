package web_test

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

type pingRoutes struct{}

func (pingRoutes) Register(s *web.Server) {
	s.Mux.HandleFunc("POST /o/x/ping", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Seen", r.Host+" "+r.RemoteAddr+" "+r.RequestURI)
		w.Header().Set("X-Client", web.ClientIP(r)+" "+r.Header.Get("X-Forwarded-For")+r.Header.Get("Forwarded"))
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write(b)
	})
	s.Mux.HandleFunc("GET /o/x/plain", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>hello</html>"))
		w.(http.Flusher).Flush() // a handler that streams asks for this
		w.Header().Set("X-Late", "after the status")
	})
	s.Mux.HandleFunc("GET /o/x/empty", func(http.ResponseWriter, *http.Request) {})
	s.Mux.HandleFunc("GET /elsewhere", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

type baseCalls struct{ urls []string }

func (b *baseCalls) RoundTrip(r *http.Request) (*http.Response, error) {
	b.urls = append(b.urls, r.URL.String())
	return &http.Response{StatusCode: http.StatusAccepted, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
}

// The server answers requests to its own organizations' addresses itself, through its whole handler, from the loopback
// address; everything else, including its other paths and other hosts, goes to the transport it was given.
func TestSelfTransportServesOrganizationPathsInProcess(t *testing.T) {
	e := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{pingRoutes{}} }})
	base := &baseCalls{}
	c := &http.Client{Transport: e.Server.SelfTransport(base)}

	res, err := c.Post(e.Cfg.Server.PublicURL+"/o/x/ping?a=1", "text/plain", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	host := strings.TrimPrefix(e.Cfg.Server.PublicURL, "https://")
	if res.StatusCode != http.StatusTeapot || string(b) != "body" || res.Header.Get("X-Seen") != host+" 127.0.0.1:0 /o/x/ping?a=1" ||
		res.Header.Get("X-Content-Type-Options") == "" {
		t.Fatalf("in-process: %d %q %q %q", res.StatusCode, b, res.Header.Get("X-Seen"), res.Header.Get("X-Content-Type-Options"))
	}
	for _, u := range []string{e.Cfg.Server.PublicURL + "/elsewhere", "https://other.example/o/x/ping"} {
		if res, err := c.Get(u); err != nil || res.StatusCode != http.StatusAccepted {
			t.Fatalf("%s: %v", u, err)
		}
	}
	if len(base.urls) != 2 {
		t.Fatalf("requests that reached the base transport: %v", base.urls)
	}
}

// An answer is what a server over the network would give: 200 when the handler says nothing, a content type from the
// first bytes when it sets none, and the headers as they were when the status was sent.
func TestSelfTransportResponseMatchesAServer(t *testing.T) {
	e := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{pingRoutes{}} }})
	c := &http.Client{Transport: e.Server.SelfTransport(&baseCalls{})}

	res, err := c.Get(e.Cfg.Server.PublicURL + "/o/x/plain")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Status != "200 OK" || string(b) != "<html>hello</html>" || res.ContentLength != int64(len(b)) ||
		res.Header.Get("Content-Type") != "text/html; charset=utf-8" || res.Header.Get("X-Late") != "" {
		t.Fatalf("streamed answer: %q %d %q %q %q", res.Status, res.ContentLength, b, res.Header.Get("Content-Type"), res.Header.Get("X-Late"))
	}
	res, err = c.Get(e.Cfg.Server.PublicURL + "/o/x/empty")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || len(b) != 0 {
		t.Fatalf("silent handler: %d %q", res.StatusCode, b)
	}
}

// A request made while serving a client's comes from that client's address, so the limits of the endpoints it reaches
// count the client's own requests and not those of everyone whose sign-in goes through the server's own organizations.
// What the client sent in forwarding headers does not count for it, as the address is already the one trust_proxy chose.
func TestSelfTransportRequestsComeFromTheClientTheyAreMadeFor(t *testing.T) {
	e := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{pingRoutes{}} }})
	web.SetTrustedProxies([]string{"203.0.113.0/24", "127.0.0.1"})
	t.Cleanup(func() { web.SetTrustedProxies(nil) })
	c := &http.Client{Transport: e.Server.SelfTransport(&baseCalls{})}

	for _, tc := range []struct{ ip, want string }{
		{"198.51.100.7", "198.51.100.7:0"},
		{"2001:db8::7", "[2001:db8::7]:0"},
		{"203.0.113.9", "203.0.113.9:0"}, // a trusted proxy's address: its X-Forwarded-For would be honoured if it were kept
		{"", "127.0.0.1:0"},              // work with no client behind it
		{"not an address", "127.0.0.1:0"},
	} {
		ctx := context.Background()
		if tc.ip != "" {
			ctx = service.WithRequest(ctx, &service.RequestInfo{IP: tc.ip})
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.Cfg.Server.PublicURL+"/o/x/ping", strings.NewReader(""))
		req.Header.Set("X-Forwarded-For", "192.0.2.1")
		req.Header.Set("Forwarded", "for=192.0.2.2")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		seen := strings.Fields(res.Header.Get("X-Seen"))
		if len(seen) != 3 || seen[1] != tc.want {
			t.Fatalf("%q: the handler saw the remote address %q, want %q", tc.ip, seen, tc.want)
		}
		if got, want := res.Header.Get("X-Client"), strings.TrimSuffix(tc.want, ":0"); strings.Trim(got, "[]") != strings.Trim(want, "[]")+" " {
			t.Fatalf("%q: the client address (with forwarding headers) is %q, want %q", tc.ip, got, want)
		}
	}
}

// identityRoutes make the identity of the request they serve visible, and make an in-process request from inside a
// handler of an authenticated request.
type identityRoutes struct{ self http.RoundTripper }

func (m *identityRoutes) Register(s *web.Server) {
	m.self = s.SelfTransport(nil)
	who := func(r *http.Request) string {
		if u := web.User(r); u != nil {
			return u.ID
		}
		return "anonymous"
	}
	s.Mux.Handle("GET /o/x/whoami", s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(who(r) + " " + strconv.FormatBool(web.Session(r) != nil) + " " + strconv.FormatBool(web.Actor(r) != nil)))
	})))
	// An in-process request of the self transport, made for the signed-in caller.
	s.Mux.Handle("GET /o/x/outer", s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, s.Cfg.Server.PublicURL+"/o/x/whoami", nil)
		res, err := m.self.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b, _ := io.ReadAll(res.Body)
		_, _ = w.Write([]byte(who(r) + " then " + string(b)))
	})))
	// A request that arrives with the context of a signed-in one but its own (no) cookie: WithSession must not let
	// the first one's identity through.
	s.Mux.Handle("GET /o/x/inherit", s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "/o/x/whoami", nil)
		s.Mux.ServeHTTP(w, inner)
	})))
}

// A request the server makes in-process for a signed-in caller is anonymous inside: it does not inherit the identity of
// the request that caused it, whether through the context it is made from (the transport starts a fresh one) or
// through WithSession (which sets the session values of whatever context it is given).
func TestInProcessRequestsDoNotInheritTheCallersIdentity(t *testing.T) {
	e := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&identityRoutes{}} }})
	c, _ := e.Session(e.Admin)
	get := func(path string) string {
		t.Helper()
		res, err := c.Get(e.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}
	if got := get("/o/x/whoami"); got == "anonymous false false" {
		t.Fatalf("the session of the test client is not recognised (%q): the checks below prove nothing", got)
	}
	if got, want := get("/o/x/outer"), e.Admin.ID+" then anonymous false false"; got != want {
		t.Fatalf("through the transport: %q, want %q", got, want)
	}
	if got, want := get("/o/x/inherit"), "anonymous false false"; got != want {
		t.Fatalf("through WithSession: %q, want %q", got, want)
	}
}
