package web_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

type pingRoutes struct{}

func (pingRoutes) Register(s *web.Server) {
	s.Mux.HandleFunc("POST /o/x/ping", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Seen", r.Host+" "+r.RemoteAddr+" "+r.RequestURI)
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
