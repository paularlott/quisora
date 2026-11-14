package upstream

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A fetch of a provider's keys that panics still ends: the jwks_uri is not left marked as being fetched, so the next
// caller fetches (once jwksMinRefetch is over) instead of waiting for good on a fetch that never ends.
func TestProviderKeysFetchThatPanicsEnds(t *testing.T) {
	t.Parallel()
	var panics atomic.Bool
	panics.Store(true)
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if panics.Load() {
			panic("the fetch broke")
		}
		k := rsaJWK(2048, []byte{1, 0, 1})
		body := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"k","n":%q,"e":%q}]}`, k.N, k.E)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	s := New(nil, nil, "https://idp.example/", client)
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { return now }
	uri := "https://a.example/jwks"

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the fetch did not panic")
			}
		}()
		_, _ = s.keysFor(context.Background(), uri, false)
	}()
	panics.Store(false)
	now = now.Add(jwksMinRefetch)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if keys, err := s.keysFor(ctx, uri, false); err != nil || len(keys) != 1 {
		t.Fatalf("after a fetch that panicked: %d keys, %v", len(keys), err)
	}
}
