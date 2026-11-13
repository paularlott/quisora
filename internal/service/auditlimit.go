package service

import (
	"strconv"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/metrics"
)

// Refusal events (apitoken.refused, api.request.refused) are throttled: whoever triggers them can repeat them as
// fast as they like, and an audit event per attempt would turn the audit log, its spool and VictoriaLogs into the
// target. One event per subject and reason goes through per refusalWindow on each node; the next one that does says
// how many were held back meanwhile (detail.suppressed). Keys name real tokens or authenticated callers, so their
// number is bounded by the data; refusalKeys caps it anyway. While a limiter is full of live keys, a refusal of a new
// key is held back too, but not without a trace: it is counted (quisora_audit_refusals_dropped_total{limiter}) and the
// node warns of it at most once a minute per limiter. That goes to the operator, not into an organization's audit
// log: the key held back may be any organization's, and the next event let through another's. The sign-in pages'
// lockout refusals (AuditLoginRefusal) have limiters of their own: their keys are chosen by whoever is refused (a
// login that names no account, an address), and a flood of them must not fill the other refusals' limiter and
// silence those; nor, in the same way, the refusals of real accounts, which have a limiter apart from the rest.
const (
	refusalWindow = time.Minute
	refusalKeys   = 10_000
)

type refusalLimiter struct {
	mu   sync.Mutex
	seen map[string]*refusalSeen
	// warned is when the node last warned that this limiter held refusals back because it was full.
	warned time.Time
}

type refusalSeen struct {
	until      time.Time
	suppressed int
}

// allow reports whether a refusal event for key is recorded now, how many of key's were held back since its last
// one, and whether it was held back because the limiter is full of other live keys (warn: and the node should warn
// of it now, the first time in a minute).
func (l *refusalLimiter) allow(key string, now time.Time) (ok bool, held int, full, warn bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string]*refusalSeen{}
	}
	if s := l.seen[key]; s != nil {
		if now.Before(s.until) {
			s.suppressed++
			return false, 0, false, false
		}
		n := s.suppressed
		s.until, s.suppressed = now.Add(refusalWindow), 0
		return true, n, false, false
	}
	if len(l.seen) >= refusalKeys {
		for k, s := range l.seen {
			if !now.Before(s.until) {
				delete(l.seen, k)
			}
		}
		if len(l.seen) >= refusalKeys { // full of live keys: hold this one back too, counted
			warn = now.Sub(l.warned) >= time.Minute
			if warn {
				l.warned = now
			}
			return false, 0, true, warn
		}
	}
	l.seen[key] = &refusalSeen{until: now.Add(refusalWindow)}
	return true, 0, false, false
}

// auditRefusal records a refusal event through the limiter: key is the subject (a token, a caller) and the reason.
func (s *Service) auditRefusal(key string, record func(detail map[string]string)) {
	s.limitedRefusal(&s.refusals, "refusals", key, record)
}

// limitedRefusal records a refusal event through l (named name in the metric and the warning).
func (s *Service) limitedRefusal(l *refusalLimiter, name, key string, record func(detail map[string]string)) {
	ok, held, full, warn := l.allow(key, time.Now())
	if full {
		metrics.AuditRefusalsDropped.Inc(name)
		if warn && s.Log != nil {
			s.Log.Warn("audit: refusal events held back: this node already tracks "+strconv.Itoa(refusalKeys)+
				" refusing keys at once (a flood of refused requests); counted in quisora_audit_refusals_dropped_total",
				"limiter", name)
		}
	}
	if !ok {
		return
	}
	detail := map[string]string{}
	if held > 0 {
		detail["suppressed"] = strconv.Itoa(held)
	}
	record(detail)
}

// AuditLoginRefusal is auditRefusal for the sign-in pages' lockout refusals, which anyone can repeat against an
// account or from an address for as long as it stays locked, through limiters of their own: account says that key
// names an existing account (whose keys whoever is refused cannot make up), which keeps those refusals apart from
// the ones whose keys they choose (a login that names no account, an address).
func (s *Service) AuditLoginRefusal(account bool, key string, record func(detail map[string]string)) {
	if account {
		s.limitedRefusal(&s.accountRefusals, "login_accounts", key, record)
		return
	}
	s.limitedRefusal(&s.loginRefusals, "login", key, record)
}
