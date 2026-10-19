package web

import (
	"github.com/paularlott/quisora/internal/model"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://id.example.com", "https://id.example.com", true},
		{"https://id.example.com", "https://id.example.com:443", true},
		{"https://ID.Example.com", "https://id.example.com", true},
		{"https://id.example.com:8443", "https://id.example.com:8443", true},
		{"https://id.example.com:8443", "https://id.example.com", false},
		{"https://evil.example.com", "https://id.example.com", false},
		{"http://id.example.com", "https://id.example.com", false},
		{"null", "https://id.example.com", false},
	}
	for _, c := range cases {
		if got := sameOrigin(c.a, c.b); got != c.want {
			t.Errorf("sameOrigin(%q,%q)=%v", c.a, c.b, got)
		}
	}
}

func TestClientIP(t *testing.T) {
	defer SetTrustedProxies(nil)
	SetTrustedProxies([]string{"10.0.0.0/8"})
	cases := []struct {
		remote, xff, want string
	}{
		{"203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},                       // untrusted peer: header ignored
		{"10.0.0.5:1234", "198.51.100.7", "198.51.100.7"},                    // one trusted proxy
		{"10.0.0.5:1234", "6.6.6.6, 198.51.100.7, 10.0.0.9", "198.51.100.7"}, // spoofed left part skipped
		{"10.0.0.5:1234", "", "10.0.0.5"},
		{"10.0.0.5:1234", "garbage", "10.0.0.5"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := ClientIP(r); got != c.want {
			t.Errorf("remote=%s xff=%q: got %s want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestSessionIDIsHashed(t *testing.T) {
	raw := "cookie-value-abcdefghijklmnopqrstuvwxyz"
	if id := SessionID(raw); id == raw || id != SessionID(raw) || len(id) != 43 {
		t.Fatalf("SessionID must be a stable hash, got %q", id)
	}
}

func TestSessionCacheEvictByUser(t *testing.T) {
	m := &Sessions{cache: map[string]*cachedSession{}, byUser: map[string]map[string]struct{}{}}
	add := func(id, uid string) {
		m.cache[id] = &cachedSession{sess: &model.Session{}, user: &model.User{Meta: model.Meta{ID: uid}}}
		if m.byUser[uid] == nil {
			m.byUser[uid] = map[string]struct{}{}
		}
		m.byUser[uid][id] = struct{}{}
	}
	add("s1", "u1")
	add("s2", "u1")
	add("s3", "u2")
	m.Evict("", "u1")
	if len(m.cache) != 1 || m.cache["s3"] == nil || m.byUser["u1"] != nil {
		t.Fatalf("evict by user: %v %v", m.cache, m.byUser)
	}
	m.Evict("s3", "")
	if len(m.cache) != 0 || len(m.byUser) != 0 {
		t.Fatal("evict by session")
	}
}
