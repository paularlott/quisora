// Package metrics keeps the server's counters and gauges and writes them in the Prometheus text exposition format
// (GET /metrics, see web.Server). It is small on purpose: counters with fixed label names, one latency histogram,
// and gauges read when scraped. Label values come from a bounded set (status classes, audit actions), never from
// request input.
package metrics

import (
	"fmt"
	"io"
	"math"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a monotonically increasing count, with one series per combination of label values.
type Counter struct {
	name, help string
	labels     []string
	series     sync.Map // joined label values -> *atomic.Uint64
}

// Inc adds one to the series of the label values (one per label name, in order).
func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

// Add adds n to the series of the label values.
func (c *Counter) Add(n uint64, values ...string) {
	key := strings.Join(values, "\x00")
	v, ok := c.series.Load(key)
	if !ok {
		v, _ = c.series.LoadOrStore(key, new(atomic.Uint64))
	}
	v.(*atomic.Uint64).Add(n)
}

// Value returns the count of the label values (tests).
func (c *Counter) Value(values ...string) uint64 {
	if v, ok := c.series.Load(strings.Join(values, "\x00")); ok {
		return v.(*atomic.Uint64).Load()
	}
	return 0
}

// Histogram counts observations into fixed buckets (seconds).
type Histogram struct {
	name, help string
	bounds     []float64
	mu         sync.Mutex
	counts     []uint64 // per bucket (not cumulative), plus +Inf
	sum        float64
	n          uint64
}

// Observe records one value.
func (h *Histogram) Observe(v float64) {
	i, _ := slices.BinarySearch(h.bounds, v)
	h.mu.Lock()
	h.counts[i]++
	h.sum += v
	h.n++
	h.mu.Unlock()
}

// Gauge is a value read when scraped.
type gauge struct {
	name, help string
	labels     []string
	read       func() []Sample
}

// Sample is one series of a gauge: its label values and value.
type Sample struct {
	Labels []string
	Value  float64
}

// Registry holds the metrics of a process.
type Registry struct {
	mu         sync.Mutex
	counters   []*Counter
	histograms []*Histogram
	gauges     []*gauge
	start      time.Time
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{start: time.Now()} }

// Default is the process's registry.
var Default = NewRegistry()

// NewCounter registers a counter.
func (r *Registry) NewCounter(name, help string, labels ...string) *Counter {
	c := &Counter{name: name, help: help, labels: labels}
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
	return c
}

// NewHistogram registers a histogram with the bucket upper bounds (ascending).
func (r *Registry) NewHistogram(name, help string, bounds ...float64) *Histogram {
	h := &Histogram{name: name, help: help, bounds: bounds, counts: make([]uint64, len(bounds)+1)}
	r.mu.Lock()
	r.histograms = append(r.histograms, h)
	r.mu.Unlock()
	return h
}

// Gauge registers (or replaces) a gauge read by fn when scraped.
func (r *Registry) Gauge(name, help string, labels []string, fn func() []Sample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges = slices.DeleteFunc(r.gauges, func(g *gauge) bool { return g.name == name })
	r.gauges = append(r.gauges, &gauge{name: name, help: help, labels: labels, read: fn})
}

// Value is a gauge function of one unlabelled value.
func Value(fn func() float64) func() []Sample {
	return func() []Sample { return []Sample{{Value: fn()}} }
}

// Bool is 1 for true, 0 for false.
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// The server's metrics, registered in Default.
var (
	HTTPRequests = Default.NewCounter("quisora_http_requests_total", "HTTP requests answered, by status class.", "code")
	HTTPDuration = Default.NewHistogram("quisora_http_request_duration_seconds", "Time to answer an HTTP request.",
		0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)
	HTTPShed    = Default.NewCounter("quisora_http_shed_total", "Requests refused with 503 because too many were in progress.")
	AuditEvents = Default.NewCounter("quisora_audit_events_total",
		"Audit events recorded, by action and outcome: login.failure, login.lockout, login.limited, "+
			"oauth.refresh.reuse, oauth.code.replay, oauth.client_auth.limited and the others (docs/RUNNING.md).",
		"action", "outcome")
	AuditUndelivered = Default.NewCounter("quisora_audit_undelivered_total",
		"Audit events VictoriaLogs will never receive (logged in full as audit.undelivered).")
	BackchannelFailed = Default.NewCounter("quisora_backchannel_logout_failed_total",
		"Back-channel logouts given up on: the relying party did not take them after every retry (or none could be queued), "+
			"or they were dropped unsent past their discard horizon.")
	MailFailed = Default.NewCounter("quisora_mail_failed_total",
		"Emails that never reached the mail server, by reason: given_up (every retry failed), dropped (kept past the "+
			"queue's discard horizon, or unreadable) and expired (the code or link in it had expired while it was queued).",
		"reason")
)

// Write writes every metric in the Prometheus text exposition format (0.0.4).
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	counters, histograms, gauges := slices.Clone(r.counters), slices.Clone(r.histograms), slices.Clone(r.gauges)
	r.mu.Unlock()
	var b strings.Builder
	head := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, escapeHelp(help), name, typ)
	}
	for _, c := range counters {
		head(c.name, c.help, "counter")
		var keys []string
		c.series.Range(func(k, _ any) bool { keys = append(keys, k.(string)); return true })
		slices.Sort(keys)
		if len(keys) == 0 && len(c.labels) == 0 {
			fmt.Fprintf(&b, "%s 0\n", c.name)
		}
		for _, k := range keys {
			v, _ := c.series.Load(k)
			var vals []string
			if len(c.labels) > 0 {
				vals = strings.Split(k, "\x00")
			}
			fmt.Fprintf(&b, "%s%s %d\n", c.name, labelSet(c.labels, vals, "", ""), v.(*atomic.Uint64).Load())
		}
	}
	for _, h := range histograms {
		head(h.name, h.help, "histogram")
		h.mu.Lock()
		var cum uint64
		for i, bound := range h.bounds {
			cum += h.counts[i]
			fmt.Fprintf(&b, "%s_bucket{le=%q} %d\n", h.name, strconv.FormatFloat(bound, 'g', -1, 64), cum)
		}
		cum += h.counts[len(h.bounds)]
		fmt.Fprintf(&b, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %s\n%s_count %d\n", h.name, cum, h.name,
			strconv.FormatFloat(h.sum, 'g', -1, 64), h.name, h.n)
		h.mu.Unlock()
	}
	gauges = append(gauges, runtimeGauges(r.start)...)
	for _, g := range gauges {
		head(g.name, g.help, "gauge")
		for _, s := range g.read() {
			fmt.Fprintf(&b, "%s%s %s\n", g.name, labelSet(g.labels, s.Labels, "", ""), formatFloat(s.Value))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func runtimeGauges(start time.Time) []*gauge {
	return []*gauge{
		{name: "quisora_uptime_seconds", help: "Seconds since the process started.",
			read: Value(func() float64 { return time.Since(start).Seconds() })},
		{name: "quisora_goroutines", help: "Goroutines.", read: Value(func() float64 { return float64(runtime.NumGoroutine()) })},
		{name: "quisora_memory_heap_bytes", help: "Heap memory in use.", read: Value(func() float64 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			return float64(m.HeapInuse)
		})},
	}
}

func labelSet(names, values []string, extraName, extraValue string) string {
	if len(names) == 0 && extraName == "" {
		return ""
	}
	var parts []string
	for i, n := range names {
		v := ""
		if i < len(values) {
			v = values[i]
		}
		parts = append(parts, n+"="+quote(v))
	}
	if extraName != "" {
		parts = append(parts, extraName+"="+quote(extraValue))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// quote is a label value as the exposition format writes it: backslash, double quote and line feed escaped.
func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
