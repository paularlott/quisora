package service

import (
	"strconv"
	"sync"
	"time"
)

// Refusal events (apitoken.refused, api.request.refused) are throttled: whoever triggers them can repeat them as
// fast as they like, and an audit event per attempt would turn the audit log, its spool and VictoriaLogs into the
// target. One event per subject and reason goes through per refusalWindow on each node; the next one that does says
// how many were held back meanwhile (detail.suppressed). Keys name real tokens or authenticated callers, so their
// number is bounded by the data; refusalKeys caps it anyway. The sign-in pages' lockout refusals (AuditLoginRefusal)
// have a limiter of their own: their keys (a login that names no account, an address) are chosen by whoever is
// refused, and a flood of them must not fill the other refusals' limiter and silence those.
const (
	refusalWindow = time.Minute
	refusalKeys   = 10_000
)

type refusalLimiter struct {
	mu   sync.Mutex
	seen map[string]*refusalSeen
}

type refusalSeen struct {
	until      time.Time
	suppressed int
}

// allow reports whether a refusal event for key is recorded now, and how many were held back since the last one.
func (l *refusalLimiter) allow(key string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string]*refusalSeen{}
	}
	if s := l.seen[key]; s != nil {
		if now.Before(s.until) {
			s.suppressed++
			return false, 0
		}
		n := s.suppressed
		s.until, s.suppressed = now.Add(refusalWindow), 0
		return true, n
	}
	if len(l.seen) >= refusalKeys {
		for k, s := range l.seen {
			if !now.Before(s.until) {
				delete(l.seen, k)
			}
		}
		if len(l.seen) >= refusalKeys {
			return false, 0 // full of live keys: hold this one back too
		}
	}
	l.seen[key] = &refusalSeen{until: now.Add(refusalWindow)}
	return true, 0
}

// auditRefusal records a refusal event through the limiter: key is the subject (a token, a caller) and the reason.
func (s *Service) auditRefusal(key string, record func(detail map[string]string)) {
	limitedRefusal(&s.refusals, key, record)
}

func limitedRefusal(l *refusalLimiter, key string, record func(detail map[string]string)) {
	ok, held := l.allow(key, time.Now())
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
// account or from an address for as long as it stays locked, through a limiter of their own.
func (s *Service) AuditLoginRefusal(key string, record func(detail map[string]string)) {
	limitedRefusal(&s.loginRefusals, key, record)
}
