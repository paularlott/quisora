package service_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// recLog records level and message of every entry, through any With/WithGroup child.
type recLog struct {
	mu      *sync.Mutex
	entries *[]string
}

func newRecLog() recLog { return recLog{mu: &sync.Mutex{}, entries: &[]string{}} }
func (r recLog) add(level, msg string) {
	r.mu.Lock()
	*r.entries = append(*r.entries, level+" "+msg)
	r.mu.Unlock()
}
func (r recLog) has(entry string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(*r.entries, entry)
}
func (r recLog) Trace(m string, _ ...any)       { r.add("trace", m) }
func (r recLog) Debug(m string, _ ...any)       { r.add("debug", m) }
func (r recLog) Info(m string, _ ...any)        { r.add("info", m) }
func (r recLog) Warn(m string, _ ...any)        { r.add("warn", m) }
func (r recLog) Error(m string, _ ...any)       { r.add("error", m) }
func (r recLog) Fatal(m string, _ ...any)       { r.add("fatal", m) }
func (r recLog) With(string, any) logger.Logger { return r }
func (r recLog) WithError(error) logger.Logger  { return r }
func (r recLog) WithGroup(string) logger.Logger { return r }

// failingAudits refuses audit records (a store that is down for them).
type failingAudits struct{ store.Store }

func (f failingAudits) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindAudit {
		return errors.New("disk full")
	}
	return f.Store.Put(ctx, r)
}

// Every audit event goes to the structured log; one the store cannot keep is logged as an error, not dropped.
func TestAuditEventsReachTheLog(t *testing.T) {
	e := newEnv(t)
	log := newRecLog()
	e.svc.Log = log
	e.svc.Audit(e.ctx, nil, e.primary.ID, "user.update", "pat", map[string]string{"tags": "a"})
	if !log.has("info audit") || log.has("error audit event not stored") {
		t.Fatalf("stored event: %v", *log.entries)
	}
	e.svc.Audits = store.NewTable[model.Audit](failingAudits{e.svc.Store})
	e.svc.Audit(e.ctx, nil, e.primary.ID, "user.delete", "pat", nil)
	if !log.has("error audit event not stored") {
		t.Fatalf("a lost audit event was not logged: %v", *log.entries)
	}
}
