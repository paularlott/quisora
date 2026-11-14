package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeJWKS serves a JWKS per URL, counting the fetches of each, and fails while down is set.
type fakeJWKS struct {
	mu    sync.Mutex
	hits  map[string]int
	down  atomic.Bool
	delay time.Duration
}

func (f *fakeJWKS) client() *http.Client {
	return &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		f.hits[r.URL.String()]++
		f.mu.Unlock()
		time.Sleep(f.delay)
		if f.down.Load() {
			return nil, errors.New("down")
		}
		k := rsaJWK(2048, []byte{1, 0, 1})
		body := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"k","n":%q,"e":%q}]}`, k.N, k.E)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
}

func (f *fakeJWKS) count(u string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[u]
}

// A provider is asked for its keys at most once per jwksMinRefetch, however many sign-ins ask, whatever kids their
// tokens name, and whether or not it answers; the interval is seconds, so a rotation stalls its sign-ins only that
// long; and one provider's refetches cost no other provider its own.
func TestProviderKeysRefetchIsBoundedPerProvider(t *testing.T) {
	t.Parallel()
	f := &fakeJWKS{hits: map[string]int{}, delay: 20 * time.Millisecond}
	s := New(nil, nil, "https://idp.example/", f.client())
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	ctx := context.Background()
	a, b := "https://a.example/jwks", "https://b.example/jwks"

	// A burst of sign-ins with nothing cached yet (after a restart): one fetch, every caller gets its keys.
	var wg sync.WaitGroup
	var failed atomic.Int32
	for range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if keys, err := s.keysFor(ctx, a, false); err != nil || len(keys) != 1 {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := f.count(a); n != 1 || failed.Load() != 0 {
		t.Fatalf("burst with an empty cache: %d fetches, %d callers without keys", n, failed.Load())
	}

	// Tokens naming unknown kids, many and at once: nothing more inside the interval.
	for range 30 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.keysFor(ctx, a, true) }()
	}
	wg.Wait()
	if n := f.count(a); n != 1 {
		t.Fatalf("unknown kids inside the interval fetched: %d fetches", n)
	}

	// Seconds later (not a minute) a rotation is picked up, once however many ask.
	advance(5 * time.Second)
	for range 30 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.keysFor(ctx, a, true) }()
	}
	wg.Wait()
	if n := f.count(a); n != 2 {
		t.Fatalf("5s later: %d fetches, want 2", n)
	}

	// Another provider is not held back by the first's refetch.
	if _, err := s.keysFor(ctx, b, true); err != nil || f.count(b) != 1 {
		t.Fatalf("another provider: %v, %d fetches", err, f.count(b))
	}

	// A provider that fails is asked once per interval too; the keys held are served meanwhile.
	f.down.Store(true)
	advance(5 * time.Second)
	for range 20 {
		if keys, err := s.keysFor(ctx, a, true); err != nil || len(keys) != 1 {
			t.Fatalf("held keys not served through a failure: %v %d", err, len(keys))
		}
	}
	if n := f.count(a); n != 3 {
		t.Fatalf("a failing provider: %d fetches, want 3", n)
	}

	// One never reached costs one fetch per interval, and its sign-ins fail at once in between.
	c := "https://c.example/jwks"
	for range 20 {
		if _, err := s.keysFor(ctx, c, true); err == nil {
			t.Fatal("keys from a provider never reached")
		}
	}
	advance(5 * time.Second)
	if _, err := s.keysFor(ctx, c, false); err == nil || f.count(c) != 2 {
		t.Fatalf("never reached: %v, %d fetches, want 2", err, f.count(c))
	}
}

// Past its cap the JWKS cache drops the entry asked for longest ago, not every provider's: a churn of new URLs
// (one organization administrator rewriting an issuer again and again) does not make every other provider's sign-ins
// fetch their keys again.
func TestProviderKeysCacheEvictsOneEntry(t *testing.T) {
	t.Parallel()
	f := &fakeJWKS{hits: map[string]int{}}
	s := New(nil, nil, "https://idp.example/", f.client())
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); now = now.Add(time.Millisecond); return now }
	ctx := context.Background()
	hot := "https://hot.example/jwks"
	for i := range 3 * cacheMax {
		if _, err := s.keysFor(ctx, fmt.Sprintf("https://churn.example/%d/jwks", i), false); err != nil {
			t.Fatal(err)
		}
		if i%(cacheMax/2) == 0 {
			if _, err := s.keysFor(ctx, hot, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n := f.count(hot); n != 1 {
		t.Fatalf("a provider in use was dropped by others' churn: %d fetches", n)
	}
	s.mu.Lock()
	n := len(s.cache)
	s.mu.Unlock()
	if n > cacheMax {
		t.Fatalf("cache grew to %d", n)
	}
}
