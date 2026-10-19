package metrics

import (
	"strings"
	"testing"
)

// Counters, histograms and gauges are written in the Prometheus text format, label values escaped.
func TestExposition(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("q_events_total", "Events.", "action", "outcome")
	c.Inc("login.failure", "failure")
	c.Add(2, "login.failure", "failure")
	c.Inc(`we"ird`, "success")
	plain := r.NewCounter("q_plain_total", "Plain.")
	_ = plain
	h := r.NewHistogram("q_seconds", "Durations.", 0.1, 1)
	h.Observe(0.05)
	h.Observe(0.5)
	h.Observe(5)
	r.Gauge("q_ready", "Ready.", nil, Value(func() float64 { return 1 }))
	var b strings.Builder
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# TYPE q_events_total counter",
		`q_events_total{action="login.failure",outcome="failure"} 3`,
		`q_events_total{action="we\"ird",outcome="success"} 1`,
		"q_plain_total 0",
		`q_seconds_bucket{le="0.1"} 1`,
		`q_seconds_bucket{le="1"} 2`,
		`q_seconds_bucket{le="+Inf"} 3`,
		"q_seconds_count 3",
		"# TYPE q_ready gauge\nq_ready 1",
		"quisora_goroutines ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if c.Value("login.failure", "failure") != 3 {
		t.Fatal("Value")
	}
}
