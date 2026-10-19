// Package vlogs sends audit events to VictoriaLogs and reads them back for the audit pages.
//
// Events are JSON lines posted to /insert/jsonline in batches by a background writer (a sign-in never waits for
// VictoriaLogs); each carries app="quisora" and the organization id as stream fields, so a page reads one
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

// WriteAudit queues an event (service.AuditWriter). A full queue (VictoriaLogs unreachable for long) drops it with
// an error log line; the event is in the structured log either way.
func (c *Client) WriteAudit(e *model.Audit) {
	defer func() { _ = recover() }() // queue closed at shutdown
	select {
	case c.queue <- e:
	default:
		c.mu.Lock()
		c.dropped++
		n := c.dropped
		c.mu.Unlock()
		c.log.Error("audit event dropped: the VictoriaLogs queue is full", "action", e.Action, "dropped", n)
	}
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

// row is one event as stored in VictoriaLogs.
func (c *Client) row(e *model.Audit) map[string]any {
	r := map[string]any{"_time": e.Created.UTC().Format(time.RFC3339Nano), "_msg": "audit " + e.Action, "app": app,
		"node": c.node, "id": e.ID, "org": e.OrgID, "action": e.Action, "actor": e.Actor, "actor_id": e.ActorID,
		"target": e.Target, "ip": e.IP}
	for k, v := range e.Detail {
		r["detail."+k] = v
	}
	return r
}

func (c *Client) send(batch []*model.Audit) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range batch {
		_ = enc.Encode(c.row(e))
	}
	u := *c.base
	u.Path += "/insert/jsonline"
	u.RawQuery = url.Values{"_stream_fields": {"app,org"}, "_time_field": {"_time"}, "_msg_field": {"_msg"}}.Encode()
	body := buf.Bytes()
	wait := 500 * time.Millisecond
	for try := 1; ; try++ {
		err := c.post(u.String(), body)
		if err == nil {
			return
		}
		if try == maxRetries {
			c.log.WithError(err).Error("audit events not sent to VictoriaLogs", "events", len(batch))
			return
		}
		time.Sleep(wait)
		wait *= 2
	}
}

func (c *Client) post(u string, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
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
	e := &model.Audit{OrgID: r["org"], ActorID: r["actor_id"], Actor: r["actor"], Action: r["action"], Target: r["target"], IP: r["ip"]}
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
