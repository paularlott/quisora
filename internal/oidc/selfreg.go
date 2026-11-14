package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// Self-registered applications (service/selfreg.go): dynamic client registration (RFC 7591) at /o/<org>/oauth/register,
// and clients whose client_id is the https URL of their Client ID Metadata Document, read on first use. Each belongs to
// the organization it registered or was authorized in; forResources places one in the tenant of that organization that
// owns the resources a request names.

// Registration is unauthenticated, so it is limited per address and minute, per address and organization a day (an
// unused registration is kept a day: one address alone cannot fill the organization's cap of unused ones,
// service.MaxSelfRegistered), and per organization and minute from every address together (how fast anyone can fill
// that cap, and how often registrations write to the store).
//
// The organization's minute is shared by every address, so a few of them at their own minute's limit could spend it
// all and keep everyone else's application from registering. Its last registerOrgReserve are kept for addresses that
// have made no registration at the organization in the last day (their day's count is 0): an address that has
// registered today stops at registerPerOrgMin - registerOrgReserve, so the few that flood spend at most that much,
// and keeping the reserve spent too takes registerOrgReserve fresh addresses a minute, each of which can then use
// only the rest. An application registers once; the address that it registers from has nothing yet.
//
// An IPv6 address is counted by its /64 (web.RateKeyIP) and by its /48 (web.RateNetIP) as well: the minute and the
// day each have a share for the /48, web.NetShareFactor times the address's, and an address is new today only when
// its /48 has made no registration at the organization either. Counted by /64 alone, sixty /64s of one /48 (of its
// 65,536), each registering once, were each new, and spent the organization's minute, reserve included.
//
// The day's counts are created only by a registration made (and read before, which creates nothing): a request
// refused (an organization that takes no registrations, bad metadata, a limit) writes no counter that lasts a day.
// Counters have a cap per node (limits.ephemeral_mb, ephemeral.Local): were every request to make one for a day,
// requests from enough distinct addresses (an IPv6 network has millions of /64s) naming any organization would fill it
// within a day, after which every new counter refuses (fails closed) for everyone. Made only by registrations, they
// number at most two for each of registerPerOrgMin a minute at each organization that accepts them.
const (
	registerPerIPMin   = 10
	registerPerIPDay   = 100
	registerPerNetMin  = registerPerIPMin * web.NetShareFactor
	registerPerNetDay  = registerPerIPDay * web.NetShareFactor
	registerPerOrgMin  = 60
	registerOrgReserve = 20
)

// forResources returns the client as the request sees it: itself for an administrator's client; for a
// self-registered one, a copy in the tenant of its organization that owns resources (service.InTenant), with that
// tenant. An error means the resources accept no self-registered application (none named, not one tenant's of the
// organization, or the tenant does not allow them).
func (p *Provider) forResources(ctx context.Context, c *model.Client, resources []string) (*model.Client, *model.Tenant, error) {
	if !c.SelfRegistered {
		return c, nil, nil
	}
	t, err := p.svc.TenantForResources(ctx, c.OrgID, resources)
	if err != nil {
		return nil, nil, err
	}
	return service.InTenant(c, t), t, nil
}

// metadataURL reports whether id is a Client ID Metadata Document URL: https, with a path, no fragment, query or
// credentials, and short enough to be a client id everywhere.
func metadataURL(id string) bool {
	if !strings.HasPrefix(id, "https://") || len(id) > service.MaxMetadataURL {
		return false
	}
	u, err := url.Parse(id)
	return err == nil && u.Host != "" && u.User == nil && u.Fragment == "" && u.RawQuery == "" && u.Path != "" && u.Path != "/"
}

// Metadata documents are read only for a sign-in, and each one's memory is paid for by the sign-in that read it, never
// by the short-lived state every sign-in shares: the requests that name made-up documents are unauthenticated, and a
// document kept for one of them in the sign-in state (up to service.MaxMetadataBytes, metadataPerIPMin a minute per
// address) would let a few hundred addresses fill a node's limits.ephemeral_mb, after which no sign-in starts and no
// code is issued. So:
//
//   - What the document a sign-in read said is kept in its flow (flow.Doc: the fields an application is made from,
//     encoded again, service.MetadataSummary, never the document as its author wrote it), which its address's
//     limits.flows_per_ip and limits.held_kb count, and goes with it: resume and consent read it from there, not from
//     the URL again. Every sign-in to an application not stored yet counts against its address's metadataPerIPMin,
//     whether the document was read for it or found shared.
//   - What every caller shares is only the last minute's read of each URL, in nsCIMD, a cache namespace
//     (ephemeral.IsCache): a node keeps it under a cap of its own, apart from the sign-in state, and at that cap the
//     newest reads take the room of the oldest (ephemeral.Local evicts), so a full cache refuses no sign-in: the read
//     just shared is there for the next caller of the minute.
//   - A URL is read at most once a minute per organization (the requests of one organization cannot keep another's
//     document unread: they spend their own organization's read, and what they read is shared with everyone).
//     Callers on one node that need a document being read wait for that read (readMetadataOnce), and one that finds
//     the minute's read spent by another node waits for what that node shares (awaitShared). A caller that finds the
//     minute's read over (metadataDoneKey) and nothing of it shared (its copy evicted from the caches, or never kept)
//     does not wait: it reads the document again, at most metadataRereadsPerMin times a minute per URL and
//     organization, and for an application not stored, within its address's metadataPerIPMin.

// nsCIMD holds the metadata documents read in the last metadataShareTTL, by URL, valid ones only: a caller of any
// organization that needs one of them uses it instead of reading the URL again (which its once-a-minute limit would
// refuse). It is a cache (ephemeral.CachePrefix): what it holds never counts against the sign-in state. Beside them,
// under metadataFailedKey, it notes the reads of the minute that found no valid document, by organization: what a
// caller waiting for another node's read (awaitShared) stops at.
const nsCIMD = ephemeral.CachePrefix + "oauth.cimd"

// metadataFailedKey is the nsCIMD key noting that organization orgID's read of the document at id this minute found
// no valid document (no URL begins with "!"). It is kept for what is left of the minute the read began in (never past
// the minute's counter, metadataReadKey), and the next minute's read removes any left: a note of one minute's read
// that failed late is not taken for the next one's.
func metadataFailedKey(orgID, id string) string { return "!" + orgID + "|" + id }

// metadataReadKey is the nsRateOIDC counter of organization orgID's reads of the document at id this minute: the
// first caller of the minute reads it (fetchMetadata).
func metadataReadKey(orgID, id string) string { return "cimd|" + orgID + "|" + id }

// metadataDoneKey is the nsRateOIDC counter that notes, for what is left of the minute, that organization orgID's read
// of the document at id this minute is over (what it read shared, or noted as failed): a caller that then finds
// nothing shared knows nothing more is coming, rather than waiting metadataAwait for it. A counter, not a cache entry:
// counters are never evicted to make room (ephemeral.Local), and the caches' eviction is what it is there for.
func metadataDoneKey(orgID, id string) string { return "cimd-done|" + orgID + "|" + id }

// metadataRereadsPerMin bounds the reads again of a document within the minute of its organization's read, made when
// that read is over and its copy is gone from the caches (fetchMetadata): an attacker who turns the caches over
// (reading documents of their own, within their address's limit) makes the document's server answer a few more
// requests a minute, not one for every sign-in.
const metadataRereadsPerMin = 5

// metadataAwait bounds how long a caller waits for a document another node is reading (awaitShared): the fetch timeout
// (fetch), and a second for the node to share what it read.
const metadataAwait = 9 * time.Second

// metadataShareTTL is how long a document read is shared: the window of the URL's one read, after which anyone may
// read it again.
const metadataShareTTL = time.Minute

// metadataPerIPMin bounds the metadata documents read per address and minute for applications not stored yet.
const metadataPerIPMin = 20

// appClient is the client of a sign-in (authorize, resume, consent) in organization orgID. A client_id that is a
// metadata document URL is the stored application when the organization has authorized it before, else the
// application the document describes, not stored: doc (the document the sign-in read when it began, kept in its flow)
// when there is one, else one read now. The document of an application not stored is returned too, for the flow to
// keep.
//
// A stored application's document is read again once MetadataRefresh old, in the background: the request that finds
// it due, and every other one meanwhile, is answered from the stored copy at once (it is good for MetadataStale), and
// the copy read replaces it when it comes (refreshMetadata). Nobody waits for that read: the requests naming a stored
// application are not limited per address, so requests that waited for a document server that never answers would
// hold their slots (limits.max_in_flight) for as long as anyone kept sending them, and a slow server would slow every
// sign-in to the application. Only past MetadataStale, with no copy left to answer from, is the document read as for
// an application not stored: within the address's limit, waited for.
func (p *Provider) appClient(ctx context.Context, r *http.Request, orgID, id string, doc []byte) (*clientEntry, []byte, error) {
	if !metadataURL(id) {
		ce, err := p.client(ctx, orgID, id)
		return ce, nil, err
	}
	if ce, err := p.client(ctx, orgID, id); err == nil {
		age := time.Since(ce.c.MetadataFetched)
		if !ce.c.SelfRegistered || age < service.MetadataRefresh {
			return ce, nil, nil
		}
		if age < service.MetadataStale {
			p.refreshMetadata(ctx, orgID, id)
			return ce, nil, nil
		}
		fresh, _, rerr := p.readMetadata(ctx, r, orgID, id, true)
		if fresh == nil {
			if rerr != nil {
				return nil, nil, rerr
			}
			return nil, nil, store.ErrNotFound
		}
		// kept even if the request hangs up now: the URL's one read a minute was spent on it
		c, err := p.svc.RefreshMetadataClient(context.WithoutCancel(ctx), fresh)
		if err != nil {
			return nil, nil, unavailable(err)
		}
		p.clients.Del(c.ID)
		return &clientEntry{c: c}, nil, nil
	}
	if doc != nil { // the flow's summary, which says when the document was read: what the application stored at consent keeps
		if c, err := service.ParseMetadataSummary(orgID, id, doc); err == nil {
			return &clientEntry{c: c}, doc, nil
		}
	}
	c, _, err := p.readMetadata(ctx, r, orgID, id, true)
	if c != nil {
		// What the flow keeps is not the document (up to service.MaxMetadataBytes of whatever its author put there,
		// held once for every flow that names it) but what the application is made from, encoded again.
		if sum := service.MetadataSummary(c); sum != nil {
			return &clientEntry{c: c}, sum, nil
		}
		return nil, nil, store.ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return nil, nil, store.ErrNotFound
}

// readMetadata returns the application of organization orgID that the document at id describes, and the document: the
// one read in the last minute by any caller (nsCIMD), else one read now and waited for (at most once a minute per URL
// and organization, and with unstored, for an application not stored yet or one whose stored copy is too old to use,
// metadataPerIPMin per address). Nil when it cannot be read or is
// not a valid document. The error is set only when a counter could not be used: nothing was fetched (a limit never
// fails open), but the document was not judged either, so the caller reports "unavailable", not "unknown application".
func (p *Provider) readMetadata(ctx context.Context, r *http.Request, orgID, id string, unstored bool) (*model.Client, []byte, error) {
	// The caller's own budget first: one over it must not spend the document's one read a minute, which every other
	// caller then goes without (an application nobody could sign in to while someone kept asking for it). It is
	// counted before the shared copy is looked for, not only before a read: a sign-in to an application not stored
	// keeps what the document said in its flow, and one document read once a minute would otherwise serve flows
	// without number, from any number of addresses, none of them counted.
	if unstored && r != nil {
		n, err := p.s.Eph.Incr(ctx, nsRateOIDC, "cimd-ip|"+web.RateKeyIP(r), 1, time.Minute)
		if err != nil {
			return nil, nil, unavailable(err)
		}
		if n > metadataPerIPMin {
			return nil, nil, nil
		}
	}
	if doc, err := p.s.Eph.Get(ctx, nsCIMD, id); err == nil {
		if c, err := service.ParseMetadata(orgID, id, doc); err == nil {
			return c, doc, nil
		}
	}
	doc, err := p.readMetadataOnce(ctx, orgID, id, false)
	if doc == nil {
		return nil, nil, err
	}
	c, err := service.ParseMetadata(orgID, id, doc)
	if err != nil { // checked as it was read: not reached
		return nil, nil, nil
	}
	return c, doc, nil
}

// metadataRead is a read of a metadata document under way (readMetadataOnce).
type metadataRead struct {
	done chan struct{} // closed once doc and err are set
	doc  []byte
	err  error
	// refresh is set (under metadataMu) when a stored application due a refresh asked for the read: what it reads
	// then replaces the stored copy (refreshMetadata), as nobody waits for it to do that.
	refresh bool
}

// readMetadataOnce reads the document at id for organization orgID, or, when a read of it for that organization is
// already under way on this node, waits for that one and shares what it read: concurrent first requests for one URL
// make one read, and none of them goes without the document because another spent the URL's read a minute. A read is
// waited for only by its own organization's requests, as it spends that organization's read a minute alone (another
// organization's request reads for its own, or finds what was read shared in nsCIMD once it is done).
//
// The read is this minute's for every caller, not one request's: it runs apart from the requests (to the end, or the
// fetch timeout), and keeps what it read even when every request waiting for it hangs up meanwhile; each of them
// stops waiting when it does. With refresh set the caller does not wait at all: the read only starts, if none is under
// way, and replaces the stored application's copy when it is done (refreshMetadata).
func (p *Provider) readMetadataOnce(ctx context.Context, orgID, id string, refresh bool) ([]byte, error) {
	key := orgID + "|" + id
	p.metadataMu.Lock()
	rd := p.metadataReads[key]
	if rd == nil {
		rd = &metadataRead{done: make(chan struct{})}
		p.metadataReads[key] = rd
		go p.runMetadataRead(context.WithoutCancel(ctx), key, rd, orgID, id)
	}
	rd.refresh = rd.refresh || refresh
	p.metadataMu.Unlock()
	if refresh {
		return nil, nil
	}
	select {
	case <-rd.done:
		return rd.doc, rd.err
	case <-ctx.Done():
		return nil, nil // the caller hung up; the read goes on for the others
	}
}

// runMetadataRead is the read rd of the document at id for organization orgID (readMetadataOnce): the copy shared in
// the last minute when there is one, else fetchMetadata's. A stored application that asked for it (rd.refresh) gets
// its copy replaced by what was read.
//
// It runs in a goroutine of its own, which no request's recovery covers: a panic in it is recovered here and logged,
// and ends the read as one that could not be made (its waiters are answered "unavailable", and the next request
// starts a read again), rather than ending the process and leaving the read's entry for every later caller to wait on.
func (p *Provider) runMetadataRead(ctx context.Context, key string, rd *metadataRead, orgID, id string) {
	finished := false
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		p.log.Error("oidc: reading a client metadata document panicked", "client_id", id, "panic", v, "stack", string(debug.Stack()))
		if finished {
			return // the read was answered: only what came after it failed
		}
		p.metadataMu.Lock()
		if p.metadataReads[key] == rd {
			delete(p.metadataReads, key)
		}
		p.metadataMu.Unlock()
		rd.doc, rd.err = nil, unavailable(fmt.Errorf("reading a client metadata document: panic: %v", v))
		close(rd.done)
	}()
	doc, err := p.s.Eph.Get(ctx, nsCIMD, id)
	if err != nil || len(doc) == 0 {
		doc, err = p.fetchMetadata(ctx, orgID, id)
	}
	p.metadataMu.Lock()
	delete(p.metadataReads, key)
	refresh := rd.refresh
	p.metadataMu.Unlock()
	rd.doc, rd.err = doc, err
	finished = true
	close(rd.done)
	if !refresh || doc == nil {
		return // a refresh that read nothing leaves the stored copy (good until service.MetadataStale)
	}
	fresh, err := service.ParseMetadata(orgID, id, doc)
	if err != nil {
		return // a shared copy is checked when it was read: not reached
	}
	if c, err := p.svc.RefreshMetadataClient(ctx, fresh); err == nil {
		p.clients.Del(c.ID)
	} else if !gone(err) {
		p.log.Warn("oidc: keeping a client metadata document read again", "client_id", id, "error", err)
	}
}

// refreshMetadata has the document of the stored application id of organization orgID, due a refresh, read again in
// the background, unless a read of it is under way already, and returns at once: what is read replaces the stored copy
// (runMetadataRead), and the caller goes on with the copy it has (appClient). One read at a time per application and
// node, at most once a minute per organization (fetchMetadata): requests naming a stored application, which no
// per-address limit bounds, never wait for its document server.
func (p *Provider) refreshMetadata(ctx context.Context, orgID, id string) {
	_, _ = p.readMetadataOnce(ctx, orgID, id, true)
}

// fetchMetadata reads the document at id, at most once a minute per URL and organization, and returns it when it is a
// valid document, shared for the next minute (nsCIMD). Past the minute's read, it is what was read and shared
// meanwhile, waited for when it is not there yet (awaitShared): the read that spent the minute may be another node's,
// still under way.
func (p *Provider) fetchMetadata(ctx context.Context, orgID, id string) ([]byte, error) {
	// Per organization: a URL's read a minute is not a slot that requests naming any organization (anyone may send
	// them) can take from every other, keeping an application one organization uses from being read again. start is
	// taken before the counter is: the minute's notes (metadataFailedKey, metadataDoneKey) are kept for what is left of
	// the counter's minute, and the counter began no earlier than start.
	start := time.Now()
	n, err := p.s.Eph.Incr(ctx, nsRateOIDC, metadataReadKey(orgID, id), 1, metadataShareTTL)
	if err != nil {
		return nil, unavailable(err)
	}
	if n > 1 {
		return p.awaitShared(ctx, orgID, id), nil
	}
	// The minute's read is this one: a failure noted by an earlier minute's read (one that failed late, when its note
	// could outlive its minute) is not this read's, and would answer this read's waiters at once.
	_ = p.s.Eph.Delete(ctx, nsCIMD, metadataFailedKey(orgID, id))
	doc := p.readMetadataDoc(ctx, orgID, id)
	left := metadataShareTTL - time.Since(start) // what is left of the counter's minute, at most
	if doc == nil && left > 0 {
		// Noted for the minute, for the callers waiting for this read on other nodes: they answer at once.
		_ = p.s.Eph.Set(ctx, nsCIMD, metadataFailedKey(orgID, id), []byte{1}, left)
	}
	if left > 0 {
		_, _ = p.s.Eph.Incr(ctx, nsRateOIDC, metadataDoneKey(orgID, id), 1, left)
	}
	return doc, nil
}

// readMetadataDoc fetches the document at id for organization orgID and returns it when it is a valid document,
// shared for the next minute (nsCIMD); nil otherwise, logged. The caller has counted the read (fetchMetadata). A
// stored application whose document's server answers that it is gone has ended (endGoneMetadataApp).
func (p *Provider) readMetadataDoc(ctx context.Context, orgID, id string) []byte {
	doc, err := p.fetch(ctx, id, service.MaxMetadataBytes)
	switch {
	case errors.Is(err, errFetchGone):
		p.log.Warn("oidc: a client metadata document is gone", "client_id", id, "error", err)
		p.endGoneMetadataApp(ctx, orgID, id, err)
		return nil
	case err != nil:
		p.log.Warn("oidc: reading a client metadata document", "client_id", id, "error", err)
		return nil
	}
	if _, perr := service.ParseMetadata(orgID, id, doc); errors.Is(perr, service.ErrRedirectCaps) {
		// A deliberate limit, distinct in the log: a stored application whose document was within the caps when it
		// was stored, and is not now (or was stored before they applied), is no longer refreshed, and is unknown once
		// its stored copy is service.MetadataStale old.
		p.log.Warn("oidc: client metadata document refused: its redirect URIs are over the length caps; "+
			"a stored application with this document is no longer refreshed, and is unknown once its stored copy is a week old",
			"client_id", id, "max_redirect_uri", service.MaxSelfRedirectLen, "max_redirect_uris_total", service.MaxSelfRedirectsLen,
			"error", perr)
		return nil
	} else if perr != nil {
		p.log.Warn("oidc: client metadata document refused", "client_id", id, "error", perr)
		return nil
	}
	_ = p.s.Eph.Delete(ctx, nsCIMDGone, metadataGoneKey(orgID, id)) // found again: a 404 before it was transient
	// At the caches' cap the oldest entries make room for it (ephemeral.Local): the read just made is the one the
	// minute's other callers look for. Not kept only when the store cannot keep it now: the next caller in the minute
	// then finds the read over and nothing shared, and reads again (awaitShared).
	_ = p.s.Eph.Set(ctx, nsCIMD, id, doc, metadataShareTTL)
	return doc
}

// nsCIMDGone notes, per organization and URL, when a stored application's document was first answered 404 or 410
// (metadataGoneMark), so that one such answer does not end it: a CDN edge that has not got the file yet, or a deploy
// that serves 404 for a moment, would otherwise end every user's access to the app, at a moment anyone can choose
// (anyone can start a sign-in that makes the read). Only a stored application's URL is noted, so the notes are bounded
// by the applications stored; a read that finds the document again removes its note.
const nsCIMDGone = "oauth.cimd.gone"

// metadataGoneGrace is how long a stored application's document must have been gone, by the first and a later read
// of it, before the application ends; metadataGoneMark how long the first answer is remembered (a later read past it
// starts the grace again).
const (
	metadataGoneGrace = 10 * time.Minute
	metadataGoneMark  = 2 * time.Hour
)

func metadataGoneKey(orgID, id string) string { return orgID + "|" + id }

// endGoneMetadataApp ends organization orgID's stored application id, whose document's server answered this server's
// own read of that exact URL with 404 or 410 (errFetchGone, cause): its author has taken it down, which is how an
// application is withdrawn. As service.RevokeSelfRegisteredApp does, every user's grants to it end and it is removed
// (a later sign-in naming the URL reads it again, as for an application never stored). Nothing else ends one: a
// network error, a timeout or any other answer leaves the stored copy (good until service.MetadataStale), and nobody
// but whoever serves the URL decides what it answers (no redirect is followed: secure.OutboundClient, fetch).
//
// Not on the first such answer: the first is noted (nsCIMDGone), and the application ends only when a read at least
// metadataGoneGrace later is answered so again, with no read in between that found the document. Meanwhile it is
// served from its stored copy as for any read that fails.
func (p *Provider) endGoneMetadataApp(ctx context.Context, orgID, id string, cause error) {
	c, err := p.svc.Clients.Get(ctx, model.ClientRecordID(orgID, id))
	if err != nil || !c.SelfRegistered || !c.IsMetadataClient() || c.OrgID != orgID || c.MetadataURL != id {
		return // not a stored application of this organization's: nothing to end, nothing to note
	}
	key := metadataGoneKey(orgID, id)
	b, err := p.s.Eph.Get(ctx, nsCIMDGone, key)
	if err != nil {
		if errors.Is(err, ephemeral.ErrNotFound) {
			_ = p.s.Eph.Set(ctx, nsCIMDGone, key, []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), metadataGoneMark)
			p.log.Warn("oidc: a stored application's metadata document is gone; the application ends if it is still gone "+
				"when read again after the grace", "client_id", id, "grace", metadataGoneGrace, "error", cause)
		}
		return
	}
	if first, perr := strconv.ParseInt(string(b), 10, 64); perr != nil || time.Since(time.Unix(0, first)) < metadataGoneGrace {
		return
	}
	err = p.svc.EndGoneMetadataApp(ctx, orgID, id, cause.Error())
	_ = p.s.Eph.Delete(ctx, nsCIMDGone, key)
	switch {
	case err == nil:
		p.clients.Del(model.ClientRecordID(orgID, id))
	case !gone(err):
		p.log.Error("oidc: ending a self-registered application whose metadata document is gone", "client_id", id, "error", err)
	}
}

// awaitShared returns the document at id that another caller read this minute for organization orgID, waiting for it
// up to metadataAwait when it is not shared yet: in a cluster the read that spent the minute may be under way on
// another node (the counter is the cluster's, the single read of readMetadataOnce each node's), and a caller that
// gave up at once would be told the application is unknown. Nil once that read is noted as having found no valid
// document (metadataFailedKey), or when nothing comes in time. Bounded: one wait at a time per organization, URL and
// node (readMetadataOnce), and for an application not stored, the requests waiting are within their address's limit.
//
// When the minute's read is over (metadataDoneKey) and nothing of it is shared - its copy evicted from the caches by
// newer reads, or never kept - nothing more is coming, and waiting would only end in "unknown application": the
// document is read again instead, at most metadataRereadsPerMin times a minute per URL and organization.
func (p *Provider) awaitShared(ctx context.Context, orgID, id string) []byte {
	deadline := time.Now().Add(metadataAwait)
	for step := 50 * time.Millisecond; ; step = min(2*step, 500*time.Millisecond) {
		if doc, err := p.s.Eph.Get(ctx, nsCIMD, id); err == nil && len(doc) > 0 {
			return doc // checked when it was read
		}
		if _, err := p.s.Eph.Get(ctx, nsCIMD, metadataFailedKey(orgID, id)); err == nil {
			return nil
		}
		if over, err := p.s.Eph.Incr(ctx, nsRateOIDC, metadataDoneKey(orgID, id), 0, metadataShareTTL); err == nil && over > 0 {
			if doc, err := p.s.Eph.Get(ctx, nsCIMD, id); err == nil && len(doc) > 0 {
				return doc // shared between the two looks
			}
			again, err := p.s.Eph.Incr(ctx, nsRateOIDC, "cimd-again|"+orgID+"|"+id, 1, metadataShareTTL)
			if err != nil || again > metadataRereadsPerMin {
				return nil
			}
			return p.readMetadataDoc(ctx, orgID, id)
		}
		left := time.Until(deadline)
		if left <= 0 {
			return nil
		}
		t := time.NewTimer(min(step, left))
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return nil
		}
	}
}

// handleRegister is dynamic client registration (RFC 7591): public clients with PKCE for user sign-in only, at an
// organization with a tenant that accepts them, limited per address and organization and capped in total; see
// service.RegisterClient.
func (p *Provider) handleRegister(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	addr, wide := web.RateKeyIP(r), web.RateNetIP(r)
	n, err := p.s.Eph.Incr(r.Context(), nsRateOIDC, "register|"+addr, 1, time.Minute)
	over := n > registerPerIPMin
	if err == nil && !over && wide != "" { // and the address's /48 (an IPv4 address has none)
		n, err = p.s.Eph.Incr(r.Context(), nsRateOIDC, "register-net|"+wide, 1, time.Minute)
		over = n > registerPerNetMin
	}
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	if over {
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down", desc: "too many registrations from this address"})
		return
	}
	var in service.RegistrationInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
		writeOAuthError(w, oerr("invalid_client_metadata", "the request body must be a JSON object"))
		return
	}
	orgID := web.Org(r).ID
	// The address's daily allowance first: an address past its own does not reach what every other address shares.
	// Both are only read here (which creates no counter), and counted below for a registration made: one refused (no
	// tenant accepts them, metadata refused, the cap reached) writes nothing that lasts, and must not spend what every
	// address shares, or a few addresses sending bad requests would block everyone's. The address's /48 has its own
	// day (registerPerNetDay), and the address is new today only when the /48 has made no registration either.
	dayKey, netDayKey := "register-day|"+orgID+"|"+addr, ""
	day, err := p.s.Eph.Incr(r.Context(), nsRateOIDC, dayKey, 0, 24*time.Hour)
	overDay := day >= registerPerIPDay
	if err == nil && !overDay && wide != "" {
		netDayKey = "register-day-net|" + orgID + "|" + wide
		var netDay int64
		netDay, err = p.s.Eph.Incr(r.Context(), nsRateOIDC, netDayKey, 0, 24*time.Hour)
		overDay = netDay >= registerPerNetDay
		day = max(day, netDay) // new today (0) only when neither has registered
	}
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	if overDay {
		w.Header().Set("Retry-After", "3600")
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down", desc: "too many registrations from this address"})
		return
	}
	orgKey := "register-org|" + orgID
	n, err = p.s.Eph.Incr(r.Context(), nsRateOIDC, orgKey, 0, time.Minute)
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	// The reserve (registerOrgReserve) is for an address that has not registered here today, nor has its /48.
	if n >= registerPerOrgMin || n >= registerPerOrgMin-registerOrgReserve && day > 0 {
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down", desc: "too many registrations at this organization"})
		return
	}
	in.ClientID = ""
	c, err := p.svc.RegisterClient(r.Context(), orgID, in)
	var re *service.RegistrationError
	switch {
	case errors.As(err, &re):
		writeOAuthError(w, oerr(re.Code, re.Description))
		return
	case errors.Is(err, service.ErrForbidden):
		writeOAuthError(w, &oauthError{status: http.StatusForbidden, code: "access_denied",
			desc: "this organization does not accept self-registered applications"})
		return
	case err != nil:
		writeOAuthError(w, serverError(err))
		return
	}
	// Registrations at the same moment can each pass the reads above, so the organization's minute and the address's
	// day can be overrun by as many as arrive together (at most registerPerIPMin from one address); they bound the
	// rate, not each request. The application is made: a counter that cannot be written now does not undo it.
	_, _ = p.s.Eph.Incr(r.Context(), nsRateOIDC, orgKey, 1, time.Minute)
	_, _ = p.s.Eph.Incr(r.Context(), nsRateOIDC, dayKey, 1, 24*time.Hour)
	if netDayKey != "" {
		_, _ = p.s.Eph.Incr(r.Context(), nsRateOIDC, netDayKey, 1, 24*time.Hour)
	}
	web.WriteJSON(w, http.StatusCreated, map[string]any{
		"client_id": c.ID, "client_id_issued_at": c.Created.Unix(), "client_name": c.Name,
		"redirect_uris": c.RedirectURIs, "grant_types": c.GrantTypes, "response_types": []string{"code"},
		"token_endpoint_auth_method": model.AuthMethodNone, "scope": strings.Join(c.Scopes, " "),
	})
}
