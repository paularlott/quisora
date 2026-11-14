// Package vlogs sends audit events to VictoriaLogs and reads them back for the audit pages.
//
// Events are JSON lines posted to /insert/jsonline in batches by a background writer (a sign-in never waits for
// VictoriaLogs). With a spool (Spool, as the server runs) WriteAudit returns only once the event is fsynced to disk
// (writes arriving together share one fsync), and a separate deliverer sends spooled segments and removes each once
// VictoriaLogs has taken it, so neither an outage nor a shutdown or crash loses an accepted event. Without one
// (commands) a batch VictoriaLogs does not take is retried a few times and then written in full to the structured log
// (audit.undelivered).
// Each event carries app="quisora" and the organization id as stream fields, so a page reads one
// organization's events by stream. Reads use LogsQL over /select/logsql/query: every value taken from a request goes
// into the query quoted (strconv.Quote) and searches are regular expressions of the escaped text.
package vlogs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

const (
	app        = "quisora"
	batchSize  = 500
	queueSize  = 20000
	maxRetries = 5
)

// flushEvery is how often the writer sends its batch and the deliverer replays the spool; firstRetryWait is the wait
// before a batch without a spool is tried again (doubling with each try). Variables so tests can shorten them.
var (
	flushEvery     = time.Second
	firstRetryWait = 500 * time.Millisecond
)

// Client writes to and reads from one VictoriaLogs server.
type Client struct {
	base *url.URL
	node string
	// boot and seq number this process's events (boot is random per start, seq counts from 1): a gap in a node's
	// sequence of one boot is an event VictoriaLogs does not hold (see docs/SOC2.md).
	boot string
	seq  atomic.Uint64
	http *http.Client
	log  logger.Logger

	queue   chan []byte // without a spool: events (JSON lines) for the writer
	commits chan commit // with a spool: events waiting to be fsynced
	done    chan struct{}
	ctx     context.Context // cancelled by Close: ends a request to VictoriaLogs still in flight
	cancel  context.CancelFunc
	stopped sync.Once
	started bool
	dropped int64
	mu      sync.Mutex
	// diskStuck says an event waited spoolWait for the spool's fsync in vain, and the spooler has not had an event
	// on disk within spoolWait of its being queued since: the disk is hung (or too slow for events to wait for), so
	// WriteAudit does not wait for it (see WriteAudit, spooler).
	diskStuck atomic.Bool

	// The delivery state below belongs to the writer (without a spool) or the deliverer (with one).
	spool    *spool
	retryAt  time.Time     // VictoriaLogs failed: until then the spool is not replayed
	backoff  time.Duration // the wait after the next failure
	spooling bool          // VictoriaLogs is not taking events (logged once per outage)
	closing  bool          // shutting down (no spool): the last batch is tried once briefly
}

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

// Spool writes every event to dir before WriteAudit returns and keeps it there, at most maxMB megabytes (0 = 256),
// until VictoriaLogs takes it: an outage, a shutdown or a crash then loses no accepted audit event unless an outage
// outlasts the space (the oldest go first, logged as undelivered). Call before Start. dir must belong to this process
// alone (one per node).
func (c *Client) Spool(dir string, maxMB int) error {
	s, err := newSpool(dir, maxMB)
	if err != nil {
		return err
	}
	c.spool, c.commits = s, make(chan commit, queueSize)
	if !s.empty() {
		c.log.Info("audit events spooled before a restart will be sent to VictoriaLogs", "dir", dir)
	}
	return nil
}

// New returns a client for the VictoriaLogs base URL (user:password in it is sent as basic authentication); node is
// written with every event. Start runs the writer.
func New(base, node string, log logger.Logger) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("vlogs: %q is not an http(s) URL", base)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{base: u, node: node, http: &http.Client{Timeout: 10 * time.Second}, log: log.WithGroup("victorialogs"),
		queue: make(chan []byte, queueSize), done: make(chan struct{}), ctx: ctx, cancel: cancel,
		boot: secure.RandomToken(6)}, nil
}

// Start runs the background writer (with a spool, the spooler and the deliverer) until Close.
func (c *Client) Start() {
	c.started = true
	// The structured log records every boot, independently of VictoriaLogs: a boot none of whose events reached it,
	// or whose last events did not, shows there (docs/SOC2.md, completeness).
	c.log.Info("audit events from this start are numbered", "node", c.node, "boot", c.boot)
	if c.spool == nil {
		go c.run()
		return
	}
	stopped := make(chan struct{})
	go func() { c.spooler(); close(stopped) }()
	go func() { c.deliver(); <-stopped; close(c.done) }()
}

// Close stops the writer once every accepted event is on disk (with a spool, which sends the rest after the next
// start) or sent to VictoriaLogs or the structured log (without one, waiting for VictoriaLogs at most closeWait).
func (c *Client) Close() {
	c.stopped.Do(func() {
		if c.spool != nil {
			close(c.commits) // the spooler fsyncs what is left, then stops
		} else {
			close(c.queue)
			if c.started {
				select {
				case <-c.done:
				case <-time.After(closeWait):
				}
			}
		}
		c.cancel()
		if c.started {
			<-c.done
			c.log.Info("audit writer stopped", "node", c.node, "boot", c.boot, "last_seq", c.seq.Load())
		}
	})
}

// commit is an event waiting for the spooler since at; done is closed once it is on disk (or logged as undelivered).
type commit struct {
	line []byte
	done chan struct{}
	at   time.Time
}

// WriteAudit queues an event (service.AuditWriter). With a spool it returns once the event is fsynced to disk, so a
// crash right after loses nothing, or after spoolWait at most: a slow or hung disk must not stall every audited
// request, so the event is then also logged in full (audit.undelivered) and still spooled once the disk answers
// (the event is then in the log and in VictoriaLogs, never in neither: every event has its id, and duplicates are
// accepted, never silent loss). A batch the spool cannot write (store undoes the failed append, so nothing of it is
// replayed) is logged in full by the spooler. An event the queue has no room for (VictoriaLogs unreachable for long,
// without a spool), or that comes after Close, is logged in full instead.
//
// One wait in vain is enough to know the disk is hung: until the spooler next has an event on disk within spoolWait
// of its being queued (diskStuck), every event goes the way the one that waited went, without the wait. It is queued
// for the spool (the queue is bounded: past it, "queue full" as ever) and logged in full at once, so a hung disk
// costs the first request spoolWait and the rest nothing, and no event is lost or uncounted on the way (each one
// logged is counted in quisora_audit_undelivered_total, though it reaches VictoriaLogs as well once the disk answers;
// the log says when the disk stops and starts answering).
func (c *Client) WriteAudit(e *model.Audit) {
	b, _ := json.Marshal(c.row(e)) // numbered here: every event accepted has its place in the sequence
	defer func() {
		if recover() != nil { // queue closed at shutdown
			c.undelivered("the audit writer has shut down", [][]byte{b})
		}
	}()
	if c.spool != nil {
		cm := commit{line: append(b, '\n'), done: make(chan struct{}), at: time.Now()}
		select {
		case c.commits <- cm:
			if c.diskStuck.Load() {
				c.undelivered("the audit spool disk has not answered in time since an earlier event (the event is "+
					"spooled once it does)", [][]byte{b})
				return
			}
			t := time.NewTimer(spoolWait)
			defer t.Stop()
			select {
			case <-cm.done:
			case <-t.C:
				if c.diskStuck.CompareAndSwap(false, true) {
					c.log.Warn("the audit spool disk did not answer in time: audit events are logged as "+
						"audit.undelivered without waiting for it until it does", "dir", c.spool.dir, "wait", spoolWait)
				}
				c.undelivered("the audit spool disk did not answer in time (the event is spooled once it does)",
					[][]byte{b})
			}
		default:
			c.undelivered("the audit spool queue is full", [][]byte{b})
		}
		return
	}
	select {
	case c.queue <- b:
	default:
		c.undelivered("the VictoriaLogs queue is full", [][]byte{b})
	}
}

// spooler writes queued events to the spool: every event waiting when it starts a write goes into that one write
// and fsync (group commit), and each writer is released once its event is on disk. A write that ends (written or
// failed: the disk answers) within spoolWait of the queueing of the oldest event in it ends a hung disk's fast path
// (diskStuck): that is the wait WriteAudit gives up on, so the fast path ends exactly when an event that waited would
// have been answered in time. The time the write itself took is not the measure: an event queued while one write is
// under way waits for that one and for its own, so a disk whose writes each take a little under spoolWait still
// keeps events waiting longer than it, and the flag would be raised by each such event and cleared by the write
// that carried it, over and over, with a pair of log lines and a run of false audit.undelivered each time. It stops
// once Close has closed the queue and the rest is written.
func (c *Client) spooler() {
	var body []byte
	var waiting []chan struct{}
	for cm := range c.commits {
		body, waiting = append(body[:0], cm.line...), append(waiting[:0], cm.done)
		oldest := cm.at // the queue is in order: the first event of a write has waited longest
	more:
		for len(waiting) < batchSize {
			select {
			case cm, ok := <-c.commits:
				if !ok {
					break more
				}
				body, waiting = append(body, cm.line...), append(waiting, cm.done)
			default:
				break more
			}
		}
		c.toSpool(body)
		if time.Since(oldest) < spoolWait && c.diskStuck.CompareAndSwap(true, false) {
			c.log.Info("the audit spool disk answers again: audit events wait for it again", "dir", c.spool.dir)
		}
		for _, w := range waiting {
			close(w)
		}
	}
}

// deliver sends spooled segments to VictoriaLogs every flushEvery until Close.
func (c *Client) deliver() {
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.replay()
		}
	}
}

// undelivered writes every event VictoriaLogs will never get to the structured log, in full, as "audit.undelivered"
// with the reason, so a log shipper still captures it. It is the last place an audit event can go.
func (c *Client) undelivered(reason string, lines [][]byte) {
	if len(lines) == 0 {
		return
	}
	metrics.AuditUndelivered.Add(uint64(len(lines)))
	c.mu.Lock()
	c.dropped += int64(len(lines))
	n := c.dropped
	c.mu.Unlock()
	for _, l := range lines {
		var ev map[string]any
		if json.Unmarshal(l, &ev) != nil {
			ev = map[string]any{"raw": string(l)}
		}
		c.log.Error("audit.undelivered", "reason", reason, "event", ev)
	}
	c.log.Error("audit events not delivered to VictoriaLogs: logged as audit.undelivered", "reason", reason,
		"events", len(lines), "undelivered_total", n)
}

// run is the writer without a spool: it batches queued events and posts them.
func (c *Client) run() {
	defer close(c.done)
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	batch := make([][]byte, 0, batchSize)
	flush := func() {
		if len(batch) > 0 {
			c.send(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case e, ok := <-c.queue:
			if !ok {
				c.closing = true
				flush()
				return
			}
			if batch = append(batch, e); len(batch) >= batchSize {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// row is one event as stored in VictoriaLogs, given the next number of this process's sequence.
func (c *Client) row(e *model.Audit) map[string]any {
	r := map[string]any{"_time": e.Created.UTC().Format(time.RFC3339Nano), "_msg": "audit " + e.Action, "app": app,
		"node": c.node, "boot": c.boot, "seq": c.seq.Add(1), "id": e.ID, "org": e.OrgID, "action": e.Action, "actor": e.Actor, "actor_id": e.ActorID,
		"target": e.Target, "ip": e.IP, "outcome": e.Outcome, "super_admin": strconv.FormatBool(e.SuperAdmin)}
	for k, v := range map[string]string{"target_id": e.TargetID, "request_id": e.RequestID, "user_agent": e.UserAgent,
		"session_id": e.SessionID} {
		if v != "" {
			r[k] = v
		}
	}
	for k, v := range e.Detail {
		r["detail."+k] = v
	}
	return r
}

func (c *Client) insertURL() string {
	u := *c.base
	u.Path += "/insert/jsonline"
	u.RawQuery = url.Values{"_stream_fields": {"app,org"}, "_time_field": {"_time"}, "_msg_field": {"_msg"}}.Encode()
	return u.String()
}

func (c *Client) send(batch [][]byte) {
	body := append(bytes.Join(batch, []byte("\n")), '\n')
	if c.closing { // Close waits only so long: one short try, then the structured log
		if err := c.postTimeout(c.insertURL(), body, closeTimeout); err != nil {
			c.undelivered("VictoriaLogs did not take them at shutdown: "+err.Error(), jsonLines(body))
		}
		return
	}
	wait := firstRetryWait
	for try := 1; ; try++ {
		err := c.post(c.insertURL(), body)
		if err == nil {
			return
		}
		if rejectedErr(err) {
			// Only the lines VictoriaLogs refuses are given up (sift). One it stops answering for part-way is an
			// outage, and what it has not taken by then is given up as after the last try (a command does not wait).
			refused, why, rest, err := c.sift(jsonLines(body), err)
			c.undelivered(errText(why), refused)
			if err != nil {
				c.undelivered("VictoriaLogs did not take them: "+err.Error(), rest)
			}
			return
		}
		if try == maxRetries || c.ctx.Err() != nil {
			c.undelivered("VictoriaLogs did not take them: "+err.Error(), jsonLines(body))
			return
		}
		select {
		case <-time.After(wait):
		case <-c.ctx.Done():
		}
		wait *= 2
	}
}

// toSpool stores a batch; one the spool could not write (a full or failing disk) is logged in full instead, and
// since store keeps nothing of a failed append the log is that batch's one place.
func (c *Client) toSpool(body []byte) {
	evicted, err := c.spool.store(body)
	if err != nil {
		c.undelivered("the VictoriaLogs spool cannot be written: "+err.Error(), jsonLines(body))
		return
	}
	c.undelivered("the VictoriaLogs spool is full: the oldest events were removed from it", evicted)
}

// replay sends spooled segments, oldest first, while VictoriaLogs takes them. A segment VictoriaLogs rejects for its
// content (rejected) is sifted (sift): the lines it takes are delivered, and only the lines it refuses, with the
// segment's lines that are not JSON (corrupt on disk), can never be delivered. Those are logged in full as
// audit.undelivered and the segment leaves the spool, so they do not hold back the events after them; a segment holds
// every organization's events of its moment, so one bad line must not take the others with it. Anything else
// (unreachable, a server error, wrong credentials), before the sifting or during it, is an outage: the segment stays,
// and is tried again in full after a back-off (what the sifting delivered is then sent twice: delivery is at least
// once).
func (c *Client) replay() {
	if c.spool == nil || time.Now().Before(c.retryAt) || c.ctx.Err() != nil {
		return
	}
	for range replayPerTick {
		name, body, bad, err := c.spool.oldest()
		if err != nil {
			c.failed(err)
			return
		}
		if name == "" {
			if c.spooling {
				c.spooling = false
				c.log.Info("spooled audit events sent to VictoriaLogs")
			}
			return
		}
		var refused [][]byte
		var why error
		if len(body) > 0 {
			err := c.post(c.insertURL(), body)
			if rejectedErr(err) {
				refused, why, _, err = c.sift(jsonLines(body), err)
			}
			if err != nil {
				if c.ctx.Err() == nil { // not just Close ending the request
					c.failed(err)
				}
				return
			}
		}
		// Logged before the segment goes: a crash between the two logs them twice, never not at all.
		c.undelivered(errText(why), refused)
		c.undelivered("the line in the VictoriaLogs spool is not JSON (corrupt on disk)", bad)
		if err := c.spool.remove(name); err != nil {
			c.failed(err)
			return
		}
		c.delivered()
	}
}

// siftPosts and siftMaxPosts bound the requests sift makes for one batch VictoriaLogs rejected. siftPosts is what it
// starts with, and every part VictoriaLogs takes earns siftCredit more. Each part it rejects is halved into two
// requests, and each part it takes pays for two, so a batch with k refused lines ends 2k-2 requests short of what
// it earned, wherever the lines lie and however large the batch: the 64 are enough to find 33 bad lines scattered
// through a full segment (some 2,000 to 3,500 events), and only those lines are lost. A batch VictoriaLogs refuses
// wholesale (a field it will not index in every line, say) earns nothing, since no part of it is taken, and is not
// sent line by line: what is still unsifted once the requests are spent is given one last request per part (sift)
// and given up where that is rejected, as a rejected batch always was (logged in full). siftMaxPosts is the ceiling
// on the search whatever it earned (33 bad lines far apart in a large batch take about 2·33·log2 of it). Variables
// so tests can lower them.
var (
	siftPosts    = 64
	siftMaxPosts = 512
)

const siftCredit = 2

// sift finds the lines VictoriaLogs refuses among lines, a batch it rejected for its content (first is that answer),
// by halves: each half is posted on its own, a half it takes is delivered, and a half it rejects is halved again,
// down to single lines, which are the ones it refuses (refused, with its last answer why). Only a rejection is sifted:
// any other answer (unreachable, a server error, wrong credentials, Close) stops the sifting at once (err, with rest
// the lines neither delivered nor refused yet), since an outage says nothing about the lines and splitting the batch
// would only multiply the requests to a server that is down. The requests are bounded (siftPosts, siftMaxPosts). Once
// they are spent, each part left is posted once more, whole, and not halved again, even when a part of that last pass
// is taken (what it would earn is not spent: the search is over): one VictoriaLogs takes is delivered, so only the
// parts that do hold a line it refuses are refused whole, with the answer that rejected them.
// The parts left are at most one per halving on the way down, log2 of the batch and a few, so that last pass adds a
// dozen requests, not another search; and no line is sent more often than the batch can be halved, however the
// requests fall.
func (c *Client) sift(lines [][]byte, first error) (refused [][]byte, why error, rest [][]byte, err error) {
	if len(lines) <= 1 {
		return lines, first, nil, nil
	}
	type part struct {
		lines  [][]byte
		reason error // VictoriaLogs' answer to the part this one is half of
	}
	// Last in, first out, the first half pushed last: the lines are sent, and refused, in their order.
	var stack []part
	halve := func(lines [][]byte, reason error) {
		h := len(lines) / 2
		stack = append(stack, part{lines[h:], reason}, part{lines[:h], reason})
	}
	halve(lines, first)
	why = first
	last := false // the requests are spent: no part is halved again, whatever the last pass earns
	for posts, spent := siftPosts, 0; len(stack) > 0; spent++ {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		last = last || posts == 0 || spent >= siftMaxPosts
		if !last {
			posts--
		}
		switch e := c.post(c.insertURL(), append(bytes.Join(p.lines, []byte("\n")), '\n')); {
		case e == nil:
			posts += siftCredit
		case !rejectedErr(e):
			rest = append(rest, p.lines...)
			for i := len(stack) - 1; i >= 0; i-- {
				rest = append(rest, stack[i].lines...)
			}
			return refused, why, rest, e
		case len(p.lines) == 1 || last:
			refused, why = append(refused, p.lines...), e
		default:
			halve(p.lines, e)
		}
	}
	return refused, why, nil, nil
}

// errText is err's message, "" for nil.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (c *Client) delivered() { c.retryAt, c.backoff = time.Time{}, 0 }

// failed holds off VictoriaLogs for a while (doubling up to maxBackoff), so an unreachable server is not waited for
// on every batch.
func (c *Client) failed(err error) {
	c.backoff = min(max(c.backoff*2, minBackoff), maxBackoff)
	c.retryAt = time.Now().Add(c.backoff)
	if !c.spooling {
		c.spooling = true
		c.log.WithError(err).Warn("VictoriaLogs is not taking audit events: spooling them to disk", "dir", c.spool.dir)
	}
}

// spoolWait is how long WriteAudit waits for the spool's fsync before it logs the event instead and returns.
var spoolWait = 2 * time.Second

const (
	closeTimeout = 2 * time.Second // the one try of a last batch without a spool
	closeWait    = 5 * time.Second // how long Close waits for VictoriaLogs without a spool
)

func (c *Client) post(u string, body []byte) error { return c.postTimeout(u, body, c.http.Timeout) }

func (c *Client) postTimeout(u string, body []byte, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/stream+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge ||
		resp.StatusCode == http.StatusUnprocessableEntity:
		return &rejected{status: resp.Status, msg: clip(msg)}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("VictoriaLogs refused the request (%s): check the credentials in audit.victorialogs_url "+
			"and the proxy in front of VictoriaLogs (vmauth): %s", resp.Status, clip(msg))
	default:
		return fmt.Errorf("VictoriaLogs answered %s: %s", resp.Status, clip(msg))
	}
}

// rejected is VictoriaLogs refusing a request for what is in it (400, 413, 422): the same events will never be taken,
// so trying them again would only hold back every event after them.
type rejected struct{ status, msg string }

func (e *rejected) Error() string {
	return "VictoriaLogs rejected the events (" + e.status + "): " + e.msg
}

func rejectedErr(err error) bool {
	var r *rejected
	return errors.As(err, &r)
}

// clip shortens an answer's body for a log line.
func clip(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// ReadAudit reads one page of the audit log from VictoriaLogs (service.AuditReader).
func (c *Client) ReadAudit(ctx context.Context, q service.AuditQuery) (service.AuditPage, error) {
	filter := Filter(q)
	order := "_time desc"
	if !q.Desc {
		order = "_time"
	}
	if q.Sort == "action" {
		dir := ""
		if q.Desc {
			dir = " desc"
		}
		order = "action" + dir + ", " + order
	}
	// Delivery is at least once, so VictoriaLogs may hold an event twice: each id is kept once (every event has one)
	// before the page is cut, and counted once, so the pages and the total agree.
	rows, err := c.query(ctx, fmt.Sprintf("%s | sort by (_time desc) partition by (id) limit 1 | sort by (%s) | offset %d | limit %d",
		filter, order, max(q.Offset, 0), max(q.Limit, 1)))
	if err != nil {
		return service.AuditPage{}, err
	}
	counts, err := c.query(ctx, filter+" | stats count_uniq(id) n")
	if err != nil {
		return service.AuditPage{}, err
	}
	page := service.AuditPage{Items: make([]*model.Audit, 0, len(rows)), Nodes: 1, Answered: 1, Source: "victorialogs"}
	if len(counts) == 1 {
		page.Total, _ = strconv.Atoi(counts[0]["n"])
	}
	for _, r := range rows {
		page.Items = append(page.Items, fromRow(r))
	}
	return page, nil
}

// Filter is the LogsQL filter of a page: this application's events, of one organization unless q.Org is "", whose
// action, actor or target contains q.Search (case-insensitive), narrowed by q's filters.
func Filter(q service.AuditQuery) string {
	var b strings.Builder
	b.WriteString(`app:=` + strconv.Quote(app))
	if q.Org != "" {
		b.WriteString(` org:=` + strconv.Quote(q.Org))
	}
	if !q.From.IsZero() {
		b.WriteString(` _time:>=` + q.From.UTC().Format(time.RFC3339Nano))
	}
	if !q.To.IsZero() {
		b.WriteString(` _time:<` + q.To.UTC().Format(time.RFC3339Nano))
	}
	if q.ActionPrefix != "" {
		b.WriteString(` action:~` + strconv.Quote("(?i)^"+regexp.QuoteMeta(q.ActionPrefix)))
	}
	if q.Action != "" {
		b.WriteString(` action:=` + strconv.Quote(q.Action))
	}
	if q.Outcome != "" {
		b.WriteString(` outcome:=` + strconv.Quote(q.Outcome))
	}
	if q.NoSuperAdmins { // an event without the field (none should be) is left out too: hidden unless known not to be
		b.WriteString(` super_admin:="false"`)
	}
	if s := strings.TrimSpace(q.Search); s != "" {
		re := strconv.Quote("(?i)" + regexp.QuoteMeta(s))
		fmt.Fprintf(&b, ` (actor:~%s or target:~%s or ip:~%s)`, re, re, re)
	}
	return b.String()
}

func (c *Client) query(ctx context.Context, q string) ([]map[string]string, error) {
	u := *c.base
	u.Path += "/select/logsql/query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(url.Values{"query": {q}}.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VictoriaLogs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("VictoriaLogs answered %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var out []map[string]string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m map[string]string
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, fmt.Errorf("VictoriaLogs: %w", err)
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return out, nil
}

func fromRow(r map[string]string) *model.Audit {
	e := &model.Audit{OrgID: r["org"], ActorID: r["actor_id"], Actor: r["actor"], Action: r["action"], Target: r["target"], IP: r["ip"],
		Outcome: r["outcome"], RequestID: r["request_id"], UserAgent: r["user_agent"], SessionID: r["session_id"],
		TargetID: r["target_id"], SuperAdmin: r["super_admin"] == "true"}
	e.ID = r["id"]
	if t, err := time.Parse(time.RFC3339Nano, r["_time"]); err == nil {
		e.Created = t
	}
	for k, v := range r {
		if d, ok := strings.CutPrefix(k, "detail."); ok {
			if e.Detail == nil {
				e.Detail = map[string]string{}
			}
			e.Detail[d] = v
		}
	}
	return e
}

// SpoolBytes is the disk space the spool uses now (0 without one): a growing spool means VictoriaLogs is not
// taking events.
func (c *Client) SpoolBytes() int64 {
	if c.spool == nil {
		return 0
	}
	_, total := c.spool.segments()
	return total
}
