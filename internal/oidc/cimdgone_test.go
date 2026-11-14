package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	logtesting "github.com/paularlott/logger/testing"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// A document read and shared for the minute may be evicted from the caches by newer reads (other documents, which
// anyone may have read within their address's limit). The next sign-in to the application in that minute finds the
// minute's read over and nothing shared: it reads the document again at once, rather than waiting metadataAwait for
// a copy that is never coming and then being told the application is unknown. Reads again are bounded per URL and
// minute; past them a caller is answered at once too.
func TestEvictedMetadataReadIsReadAgainAtOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	local := h.env.Server.Eph.(*ephemeral.Local)
	local.CacheBudget = 64 << 10
	redirect := "http://127.0.0.1:44190/callback"
	srv, hits := metadataDocServer(t, redirect, 0, nil)
	h.p.HTTP = srv.Client()
	cl := &model.Client{Meta: model.Meta{ID: srv.URL + "/app.json"}, RedirectURIs: []string{redirect}}
	_, ch := pkce()
	if rec := h.startFrom("198.51.100.120", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
		t.Fatalf("first sign-in: %d", rec.Code)
	}
	evict := func(round int) { // other documents read meanwhile turn the caches over
		for i := range 40 {
			if err := local.Set(ctx, nsCIMD, "https://other.example/"+strconv.Itoa(round)+"/"+strconv.Itoa(i), make([]byte, 4<<10), time.Minute); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := local.Get(ctx, nsCIMD, cl.ID); err == nil {
			t.Fatal("the document was not evicted")
		}
	}
	for i := range metadataRereadsPerMin {
		evict(i)
		start := time.Now()
		rec := h.startFrom("198.51.100."+strconv.Itoa(121+i), authzQuery(cl, ch, url.Values{"resource": {mcpResource}}))
		if rec.Code != http.StatusFound || time.Since(start) > 3*time.Second {
			t.Fatalf("sign-in %d after the shared read was evicted: %d after %v", i+2, rec.Code, time.Since(start).Round(time.Millisecond))
		}
	}
	if got := hits.Load(); got != 1+metadataRereadsPerMin {
		t.Fatalf("%d reads, want the minute's and one again for each eviction", got)
	}
	// past the reads again of the minute: refused, at once
	evict(metadataRereadsPerMin)
	start := time.Now()
	if rec := h.startFrom("198.51.100.200", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code == http.StatusFound ||
		time.Since(start) > 3*time.Second {
		t.Fatalf("past the minute's reads again: %d after %v", rec.Code, time.Since(start).Round(time.Millisecond))
	}
	if got := hits.Load(); got != 1+metadataRereadsPerMin {
		t.Fatalf("%d reads past the minute's reads again", got)
	}
}

// A note that a minute's read found no valid document can outlive that minute (a read that failed late). The next
// minute's read removes it as it begins: a caller waiting for that read on another node is not told "unknown" by
// the earlier minute's note, but gets what the new read finds.
func TestStaleFailureNoteRemovedByTheNextRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44191/callback"
	g := newGate(t)
	srv, _ := metadataDocServer(t, redirect, 0, g.hold)
	defer g.open() // before the server's cleanup, which waits for the read it holds
	h.p.HTTP = srv.Client()
	org := h.env.Primary.ID
	cl := &model.Client{Meta: model.Meta{ID: srv.URL + "/app.json"}, RedirectURIs: []string{redirect}}
	// the last minute's read failed late: its note is still there, its counter gone
	if err := h.env.Server.Eph.Set(ctx, nsCIMD, metadataFailedKey(org, cl.ID), []byte{1}, time.Minute); err != nil {
		t.Fatal(err)
	}
	_, ch := pkce()
	done := make(chan int, 1)
	go func() { // this minute's read, here, held at the document's server
		done <- h.startFrom("198.51.100.122", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})).Code
	}()
	g.waitHeld(t)
	got := make(chan []byte, 1)
	go func() { got <- h.p.awaitShared(ctx, org, cl.ID) }() // a caller on another node, which found the minute spent
	time.Sleep(300 * time.Millisecond)
	g.open()
	select {
	case doc := <-got:
		if doc == nil {
			t.Fatal("a caller waiting for the minute's read was answered by the last minute's note")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read shared nothing")
	}
	if code := <-done; code != http.StatusFound {
		t.Fatalf("the sign-in that made the read: %d", code)
	}
}

// panicTransport panics on every request, as a fault in the read's code would.
type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) { panic("a fault in the read") }

// A metadata read runs in a goroutine of its own, which no request's recovery covers: a panic there is recovered and
// logged, the request waiting for it is refused (not left waiting), the server goes on, and the read's entry goes, so
// a later request starts a read of its own.
func TestMetadataReadPanicIsRecovered(t *testing.T) {
	t.Parallel()
	log := logtesting.New()
	h := setupLogged(t, nil, nil, log)
	h.mcpTenant("mcp", true)
	h.p.HTTP = &http.Client{Transport: panicTransport{}}
	redirect := "http://127.0.0.1:44192/callback"
	cl := &model.Client{Meta: model.Meta{ID: "https://panic.example/app.json"}, RedirectURIs: []string{redirect}}
	_, ch := pkce()
	start := time.Now()
	if rec := h.startFrom("198.51.100.123", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code == http.StatusFound ||
		time.Since(start) > 3*time.Second {
		t.Fatalf("a sign-in whose read panicked: %d after %v", rec.Code, time.Since(start).Round(time.Millisecond))
	}
	h.p.metadataMu.Lock()
	left := len(h.p.metadataReads)
	h.p.metadataMu.Unlock()
	if left != 0 {
		t.Fatalf("%d reads left under way", left)
	}
	logged := false
	for _, en := range log.GetEntries() {
		logged = logged || strings.Contains(en.Message, "panicked") && en.Level == "error"
	}
	if !logged {
		t.Fatalf("the panic was not logged: %v", log.GetEntries())
	}
	// the server goes on: another application's document is read
	srv, _ := metadataDocServer(t, redirect, 0, nil)
	h.p.HTTP = srv.Client()
	other := &model.Client{Meta: model.Meta{ID: srv.URL + "/app.json"}, RedirectURIs: []string{redirect}}
	if rec := h.startFrom("198.51.100.124", authzQuery(other, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
		t.Fatalf("a sign-in after a read panicked: %d", rec.Code)
	}
}

// What a sign-in keeps of an application's document says when the document was read: the application stored at
// consent is as old as that read, not as the consent, and is read again a day after the read.
func TestMetadataAppStoredWithItsReadTime(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	tn := h.mcpTenant("mcp", true)
	const id = "https://app.example/read-time.json"
	doc := `{"client_id":"` + id + `","client_name":"Gen","redirect_uris":["http://127.0.0.1:44193/callback"]}`
	read, err := service.ParseMetadata(h.env.Primary.ID, id, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	read.MetadataFetched = time.Now().Add(-40 * time.Minute).UTC() // the sign-in began 40 minutes ago
	sum := service.MetadataSummary(read)
	ce, _, err := h.p.appClient(context.Background(), nil, h.env.Primary.ID, id, sum)
	if err != nil {
		t.Fatal(err)
	}
	if d := ce.c.MetadataFetched.Sub(read.MetadataFetched); d < -time.Second || d > time.Second {
		t.Fatalf("the application from the sign-in's summary was read at %v, want %v", ce.c.MetadataFetched, read.MetadataFetched)
	}
	if err := h.env.Svc.NoteSelfRegisteredUse(context.Background(), service.InTenant(ce.c, tn), tn); err != nil {
		t.Fatal(err)
	}
	stored, err := h.env.Svc.Clients.Get(context.Background(), model.ClientRecordID(h.env.Primary.ID, id))
	if err != nil {
		t.Fatal(err)
	}
	if d := stored.MetadataFetched.Sub(read.MetadataFetched); d < -time.Second || d > time.Second {
		t.Fatalf("stored as read at %v, want %v", stored.MetadataFetched, read.MetadataFetched)
	}
}

// statusDocServer serves, at any path, a valid metadata document naming that URL with redirect as its one redirect
// URI while mode holds 200 (as it starts), else answers with mode's status.
func statusDocServer(t *testing.T, redirect string) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	mode := &atomic.Int32{}
	mode.Store(http.StatusOK)
	srv, hits := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if m := int(mode.Load()); m != http.StatusOK {
			http.Error(w, "no", m)
			return
		}
		id := "https://" + r.Host + r.URL.Path
		_, _ = w.Write([]byte(`{"client_id":"` + id + `","client_name":"Gen","redirect_uris":["` + redirect + `"]}`))
	})
	return srv, hits, mode
}

// A stored application whose document is over the redirect URI caps when it is read again is not refreshed (a
// deliberate limit), and that is logged apart from other refusals, naming the caps: its administrators can tell why the
// application becomes unknown once its stored copy is a week old.
func TestMetadataOverRedirectCapsLoggedDistinctly(t *testing.T) {
	t.Parallel()
	log := logtesting.New()
	h := setupLogged(t, nil, nil, log)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44194/callback"
	var long atomic.Bool
	srv, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		id := "https://" + r.Host + r.URL.Path
		ru := redirect
		if long.Load() {
			ru = "https://app.example/" + strings.Repeat("x", service.MaxSelfRedirectLen)
		}
		_, _ = w.Write([]byte(`{"client_id":"` + id + `","client_name":"Gen","redirect_uris":["` + ru + `"]}`))
	})
	h.p.HTTP = srv.Client()
	cl, rid := h.storedDocApp(srv.URL, redirect, 25*time.Hour)
	long.Store(true)
	_, ch := pkce()
	if rec := h.startFrom("198.51.100.125", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
		t.Fatalf("a stored application due a refresh: %d", rec.Code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var found *logtesting.LogEntry
		for _, en := range log.GetEntries() {
			if strings.Contains(en.Message, "redirect URIs are over the length caps") {
				found = &en
			}
		}
		if found != nil {
			if kv := fmt.Sprint(found.KeysAndValues); !strings.Contains(kv, strconv.Itoa(service.MaxSelfRedirectLen)) ||
				!strings.Contains(kv, strconv.Itoa(service.MaxSelfRedirectsLen)) || !strings.Contains(kv, cl.ID) {
				t.Fatalf("the entry does not name the caps and the application: %v", found.KeysAndValues)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the refused refresh was not logged distinctly: %v", log.GetEntries())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c, err := h.env.Svc.Clients.Get(context.Background(), rid); err != nil || time.Since(c.MetadataFetched) < 24*time.Hour {
		t.Fatalf("the stored copy was replaced, or removed: %+v %v", c, err)
	}
}

// A stored application whose document's server answers 404 or 410 when it is read again has been withdrawn by its
// author: it ends as an administrator's Revoke ends one (every user's grants, then the application), recorded by the
// system with the reason. A server error, or a server not answering, leaves the stored copy: only the document's own
// server saying it is gone decides it.
func TestStoredMetadataAppEndsWhenItsDocumentIsGone(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusNotFound, http.StatusGone} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			h := setup(t, nil)
			h.mcpTenant("mcp", true)
			redirect := "http://127.0.0.1:44195/callback"
			srv, _, mode := statusDocServer(t, redirect)
			h.p.HTTP = srv.Client()
			cl, rid := h.storedDocApp(srv.URL, redirect, 25*time.Hour)
			grants := func() int {
				gs, _, err := h.env.Svc.Grants.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "client_id", Value: rid}}})
				if err != nil {
					t.Fatal(err)
				}
				return len(gs)
			}
			if grants() == 0 {
				t.Fatal("the sign-in made no grant")
			}
			mode.Store(int32(status))
			_, ch := pkce()
			// The first answer only starts the grace: a CDN edge or a deploy may answer 404 for a moment.
			if rec := h.startFrom("198.51.100.126", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
				t.Fatalf("a stored application due a refresh: %d", rec.Code) // answered from the stored copy
			}
			gone := metadataGoneKey(h.env.Primary.ID, cl.ID)
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := h.env.Server.Eph.Get(ctx, nsCIMDGone, gone); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the first gone answer was not noted")
				}
				time.Sleep(20 * time.Millisecond)
			}
			if _, err := h.env.Svc.Clients.Get(ctx, rid); err != nil || grants() == 0 {
				t.Fatalf("one gone answer ended the application: %v", err)
			}
			// Still gone a grace later (the note made to look that old, and a minute later): the application ends.
			old := strconv.FormatInt(time.Now().Add(-metadataGoneGrace-time.Second).UnixNano(), 10)
			if err := h.env.Server.Eph.Set(ctx, nsCIMDGone, gone, []byte(old), time.Hour); err != nil {
				t.Fatal(err)
			}
			_ = h.env.Server.Eph.Delete(ctx, nsRateOIDC, metadataReadKey(h.env.Primary.ID, cl.ID))
			if rec := h.startFrom("198.51.100.127", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
				t.Fatalf("a stored application read again: %d", rec.Code)
			}
			deadline = time.Now().Add(5 * time.Second)
			for {
				if _, err := h.env.Svc.Clients.Get(ctx, rid); errors.Is(err, store.ErrNotFound) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the application whose document is gone is still stored")
				}
				time.Sleep(20 * time.Millisecond)
			}
			if n := grants(); n != 0 {
				t.Fatalf("%d grants to an application whose document is gone", n)
			}
			ev := h.auditEvents("client.self_registered.revoke")
			if len(ev) != 1 || !strings.Contains(ev[0].Detail["reason"], strconv.Itoa(status)) {
				t.Fatalf("revocation events: %+v", ev)
			}
		})
	}
	t.Run("transient", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		h := setup(t, nil)
		h.mcpTenant("mcp", true)
		redirect := "http://127.0.0.1:44196/callback"
		srv, hits, mode := statusDocServer(t, redirect)
		h.p.HTTP = srv.Client()
		cl, rid := h.storedDocApp(srv.URL, redirect, 25*time.Hour)
		_, ch := pkce()
		// a server error, then no server at all
		for i, fail := range []func(){func() { mode.Store(http.StatusInternalServerError) }, srv.Close} {
			fail()
			before := hits.Load()
			_ = h.env.Server.Eph.Delete(ctx, nsRateOIDC, metadataReadKey(h.env.Primary.ID, cl.ID)) // a minute later
			if rec := h.startFrom("198.51.100.13"+strconv.Itoa(i), authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
				t.Fatalf("a stored application due a refresh: %d", rec.Code)
			}
			time.Sleep(300 * time.Millisecond) // the refresh in the background
			if i == 0 && hits.Load() == before {
				t.Fatal("the document was not read again")
			}
			if _, err := h.env.Svc.Clients.Get(ctx, rid); err != nil {
				t.Fatalf("a transient failure ended the application: %v", err)
			}
		}
	})
}

// A document gone once and then found again was a hiccup: the note of the first answer goes with the read that finds
// it, so a 404 later starts the grace afresh rather than ending the application.
func TestMetadataGoneThenFoundStartsTheGraceAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44197/callback"
	srv, _, mode := statusDocServer(t, redirect)
	h.p.HTTP = srv.Client()
	cl, rid := h.storedDocApp(srv.URL, redirect, 25*time.Hour)
	_, ch := pkce()
	gone := metadataGoneKey(h.env.Primary.ID, cl.ID)
	old := strconv.FormatInt(time.Now().Add(-metadataGoneGrace-time.Second).UnixNano(), 10)
	if err := h.env.Server.Eph.Set(ctx, nsCIMDGone, gone, []byte(old), time.Hour); err != nil { // gone a grace ago
		t.Fatal(err)
	}
	mode.Store(http.StatusOK) // and found now
	if rec := h.startFrom("198.51.100.140", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
		t.Fatalf("a stored application due a refresh: %d", rec.Code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := h.env.Server.Eph.Get(ctx, nsCIMDGone, gone); errors.Is(err, ephemeral.ErrNotFound) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the document found again left the note of its first gone answer")
		}
		time.Sleep(20 * time.Millisecond)
	}
	mode.Store(http.StatusNotFound)
	_ = h.env.Server.Eph.Delete(ctx, nsRateOIDC, metadataReadKey(h.env.Primary.ID, cl.ID))
	if rec := h.startFrom("198.51.100.141", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
		t.Fatalf("a stored application read again: %d", rec.Code)
	}
	time.Sleep(300 * time.Millisecond) // the refresh in the background
	if _, err := h.env.Svc.Clients.Get(ctx, rid); err != nil {
		t.Fatalf("a 404 after the document was found again ended the application: %v", err)
	}
}
