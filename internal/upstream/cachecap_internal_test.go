package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The JWKS and discovery caches keep one entry per URL ever seen; a rewritten issuer or a rotating jwks_uri must
// not make them grow without bound.
func TestCachesAreBounded(t *testing.T) {
	t.Parallel()
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "openid-configuration") {
			return nil, errors.New("down")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"keys":[]}`)), Request: r}, nil
	})}
	s := New(nil, nil, "https://idp.example/", client)
	ctx := context.Background()
	for i := 0; i < 2*cacheMax+5; i++ {
		if _, err := s.keysFor(ctx, fmt.Sprintf("https://up.example/%d/jwks", i), false); err != nil {
			t.Fatal(err)
		}
		base := fmt.Sprintf("https://up.example/%d", i)
		if _, err := s.discover(ctx, base, base); err == nil {
			t.Fatal("discovery should have failed")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) > cacheMax || len(s.discCalls) > cacheMax || len(s.disc) > cacheMax {
		t.Errorf("caches grew past %d: jwks %d, discovery calls %d, discovery %d", cacheMax, len(s.cache), len(s.discCalls), len(s.disc))
	}
}
