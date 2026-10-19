// Package vlogs sends audit events to VictoriaLogs and reads them back for the audit pages.
//
// Events are JSON lines posted to /insert/jsonline in batches by a background writer (a sign-in never waits for
// VictoriaLogs). Without a spool a batch VictoriaLogs does not take is retried a few times and then dropped (the
// events are in the structured log either way); with one (Spool) it is kept on disk until VictoriaLogs takes it.
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
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

const (
	app        = "quisora"
	batchSize  = 500
	flushEvery = time.Second
	queueSize  = 20000
	maxRetries = 5
)

// Client writes to and reads from one VictoriaLogs server.
type Client struct {
	base *url.URL
	node string
	http *http.Client
	log  logger.Logger

	queue   chan *model.Audit
	done    chan struct{}
	stopped sync.Once
	dropped int64
	mu      sync.Mutex

	// The spool and the delivery state below belong to the writer goroutine.
	spool    *spool
	retryAt  time.Time     // VictoriaLogs failed: until then batches go straight to the spool
	backoff  time.Duration // the wait after the next failure
	spooling bool          // batches are being spooled (logged once per outage)
	closing  bool          // shutting down: the last batch waits briefly, then goes to the spool
}

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

// Spool keeps batches VictoriaLogs does not take in dir, at most maxMB megabytes (0 = 256), until it takes them:
// an outage then loses no audit events unless it outlasts the space (the oldest go first, logged as dropped). Call
// before Start. dir must belong to this process alone (one per node).
func (c *Client) Spool(dir string, maxMB int) error {
	s, err := newSpool(dir, maxMB)
	if err != nil {
		return err
	}
	c.spool = s
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
	return &Client{base: u, node: node, http: &http.Client{Timeout: 10 * time.Second}, log: log.WithGroup("victorialogs"),
		queue: make(chan *model.Audit, queueSize), done: make(chan struct{})}, nil
}

// Start runs the background writer until Close.
func (c *Client) Start() { go c.run() }

// Close sends what is queued (waiting at most a few seconds) and stops the writer.
func (c *Client) Close() {
	c.stopped.Do(func() {
		close(c.queue)
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			c.log.Warn("audit events still queued for VictoriaLogs at shutdown were not sent")
		}
	})
}

// WriteAudit queues an event (service.AuditWriter). An event the queue has no room for (VictoriaLogs unreachable
// for long, without a spool) is logged in full instead (audit.undelivered).
func (c *Client) WriteAudit(e *model.Audit) {
	defer func() { _ = recover() }() // queue closed at shutdown
	select {
	case c.queue <- e:
	default:
		b, _ := json.Marshal(c.row(e))
		c.undelivered("the VictoriaLogs queue is full", [][]byte{b})
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

func (c *Client) run() {
	defer close(c.done)
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	batch := make([]*model.Audit, 0, batchSize)
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
			c.replay()
		}
	}
}

// row is one event as stored in VictoriaLogs.
func (c *Client) row(e *model.Audit) map[string]any {
	r := map[string]any{"_time": e.Created.UTC().Format(time.RFC3339Nano), "_msg": "audit " + e.Action, "app": app,
		"node": c.node, "id": e.ID, "org": e.OrgID, "action": e.Action, "actor": e.Actor, "actor_id": e.ActorID,
		"target": e.Target, "ip": e.IP, "outcome": e.Outcome}
	for k, v := range map[string]string{"request_id": e.RequestID, "user_agent": e.UserAgent, "session_id": e.SessionID} {
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

func (c *Client) send(batch []*model.Audit) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range batch {
		_ = enc.Encode(c.row(e))
	}
	body := buf.Bytes()
	if c.spool != nil {
		c.sendSpooled(body)
		return
	}
	if c.closing { // Close waits only so long: one short try, then the structured log
		if err := c.postTimeout(c.insertURL(), body, closeTimeout); err != nil {
			c.undelivered("VictoriaLogs did not take them at shutdown: "+err.Error(), jsonLines(body))
		}
		return
	}
	wait := 500 * time.Millisecond
	for try := 1; ; try++ {
		err := c.post(c.insertURL(), body)
		if err == nil {
			return
		}
		if try == maxRetries {
			c.undelivered("VictoriaLogs did not take them: "+err.Error(), jsonLines(body))
			return
		}
		time.Sleep(wait)
		wait *= 2
	}
}

// sendSpooled posts body once; when VictoriaLogs does not take it (or failed moments ago) it goes to the spool, and
// replay sends it later. Retrying here would only hold up the events queued behind it.
func (c *Client) sendSpooled(body []byte) {
	if time.Now().After(c.retryAt) {
		timeout := c.http.Timeout
		if c.closing {
			timeout = closeTimeout // Close waits only so long; the spool keeps the batch for the next start
		}
		err := c.postTimeout(c.insertURL(), body, timeout)
		if err == nil {
			c.delivered()
			c.replay()
			return
		}
		c.failed(err)
	}
	c.toSpool(body)
}

func (c *Client) toSpool(body []byte) {
	evicted, err := c.spool.store(body)
	if err != nil {
		c.undelivered("the VictoriaLogs spool cannot be written: "+err.Error(), jsonLines(body))
		return
	}
	c.undelivered("the VictoriaLogs spool is full: the oldest events were removed from it", evicted)
}

// replay sends spooled segments, oldest first, while VictoriaLogs takes them.
func (c *Client) replay() {
	if c.spool == nil || time.Now().Before(c.retryAt) {
		return
	}
	for range replayPerTick {
		name, body := c.spool.oldest()
		if name == "" {
			if c.spooling {
				c.spooling = false
				c.log.Info("spooled audit events sent to VictoriaLogs")
			}
			return
		}
		if err := c.post(c.insertURL(), body); err != nil {
			c.failed(err)
			return
		}
		c.spool.remove(name)
		c.delivered()
	}
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

const closeTimeout = 2 * time.Second

func (c *Client) post(u string, body []byte) error { return c.postTimeout(u, body, c.http.Timeout) }

func (c *Client) postTimeout(u string, body []byte, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("VictoriaLogs answered %s", resp.Status)
	}
	return nil
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
	rows, err := c.query(ctx, fmt.Sprintf("%s | sort by (%s) | offset %d | limit %d", filter, order, max(q.Offset, 0), max(q.Limit, 1)))
	if err != nil {
		return service.AuditPage{}, err
	}
	counts, err := c.query(ctx, filter+" | stats count() n")
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
// action, actor or target contains q.Search (case-insensitive).
func Filter(q service.AuditQuery) string {
	var b strings.Builder
	b.WriteString(`app:=` + strconv.Quote(app))
	if q.Org != "" {
		b.WriteString(` org:=` + strconv.Quote(q.Org))
	}
	if s := strings.TrimSpace(q.Search); s != "" {
		re := strconv.Quote("(?i)" + regexp.QuoteMeta(s))
		fmt.Fprintf(&b, ` (action:~%s or actor:~%s or target:~%s)`, re, re, re)
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
		Outcome: r["outcome"], RequestID: r["request_id"], UserAgent: r["user_agent"], SessionID: r["session_id"]}
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
