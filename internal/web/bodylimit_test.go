package web_test

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

type bodyRoutes struct{}

func (bodyRoutes) Register(s *web.Server) {
	// A handler that reads its form the way the login pages do, without a limit of its own.
	s.Mux.HandleFunc("POST /o/x/form", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "unreadable", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("fields=" + strconv.Itoa(len(r.PostForm))))
	})
	s.Mux.HandleFunc("POST /o/x/raw", func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, "unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = w.Write([]byte("bytes=" + strconv.FormatInt(n, 10)))
	})
}

// Every request body is capped where the request enters, so a handler that forgets its own limit cannot be made to
// buffer megabytes by an anonymous POST: a form is a few fields, and the largest other body (JSON, SCIM) is 1 MiB.
func TestRequestBodiesAreCapped(t *testing.T) {
	e := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{bodyRoutes{}} }})
	c := e.Client()
	post := func(path, ctype, body string) (int, string) {
		t.Helper()
		res, err := c.Post(e.URL+path, ctype, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, strings.TrimSpace(string(b))
	}
	const form = "application/x-www-form-urlencoded"
	small := url.Values{"a": {"b"}}.Encode()
	big := url.Values{"a": {strings.Repeat("x", 100<<10)}}.Encode()
	if code, body := post("/o/x/form", form, small); code != http.StatusOK || body != "fields=1" {
		t.Fatalf("a small form: %d %q", code, body)
	}
	if code, body := post("/o/x/form", form+"; charset=utf-8", big); code != http.StatusBadRequest {
		t.Fatalf("a form of 100 KB: %d %q, want it refused", code, body)
	}
	if code, body := post("/o/x/raw", "application/json", strings.Repeat("x", 512<<10)); code != http.StatusOK || body != "bytes="+strconv.Itoa(512<<10) {
		t.Fatalf("a JSON body of 512 KB: %d %q", code, body)
	}
	if code, _ := post("/o/x/raw", "application/json", strings.Repeat("x", web.MaxJSONBody+1)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body over %d bytes: %d, want it refused", web.MaxJSONBody, code)
	}
}
