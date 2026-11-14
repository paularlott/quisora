package service

import (
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/metrics"
)

// Refusal events (apitoken.refused, api.request.refused) are throttled: whoever triggers them can repeat them as
// fast as they like, and an audit event per attempt would turn the audit log, its spool and VictoriaLogs into the
// target. One event per subject and reason goes through per refusalWindow on each node; the next one that does says
// how many were held back meanwhile (detail.suppressed). Keys name real tokens or authenticated callers, so their
// number is bounded by the data; refusalKeys caps it anyway, and refusalKeysPerOrg what one organization's keys may
// take of it, so that a flood in one organization leaves the others' events alone. While a limiter (or an
// organization's share of it) is full of live keys, a refusal of a new key is held back too, but not without a
// trace: it is counted (quisora_audit_refusals_dropped_total{limiter}) and the node warns of it at most once a minute
// per limiter. That goes to the operator, not into an organization's audit log: the key held back may be any
// organization's, and the next event let through another's. The sign-in pages' lockout refusals
// (AuditLoginRefusal) have limiters of their own: their keys are chosen by whoever is refused (a login that names no
// account, an address), and a flood of them must not fill the other refusals' limiter and silence those; nor, in the
// same way, the refusals of real accounts, which have a limiter apart from the rest. The sign-in pages' wrong
// credentials (AuditLoginFailure) are throttled the same way, through limiters of their own (logins that name no
// account; real accounts), apart from the lockout refusals'. Both of those are keyed by the client address as well
// (loginEvent), so that every address that tries is named in the audit log, whoever tried first, up to what one
// address and one organization may have recorded.
// So are the device sign-ins public clients start (AuditDeviceStart), which anyone can make: a limiter of their
// own again.
const (
	refusalWindow     = time.Minute
	refusalKeys       = 10_000
	refusalKeysPerOrg = refusalKeys / 4
	// LoginRowsPerAddress is how many events about real accounts one client address (an IPv6 address by its /48) can
	// have recorded in an organization per refusalWindow on each node, wrong credentials and lockout refusals each
	// (loginEvent), and LoginRowsPerAddressUnknown how many about logins that name no account: fewer, since those
	// logins are made up by whoever sends them, and the events are a sample of what an address tries.
	LoginRowsPerAddress        = 20
	LoginRowsPerAddressUnknown = 5
	// LoginAddressRowsPerOrg is how many of those events naming an address one organization can have recorded per
	// refusalWindow on each node, in each of the four kinds (wrong credentials and lockout refusals, of real
	// accounts and of the rest), however many addresses send them; past it an event is recorded as one that cannot
	// name its address (loginEvent).
	LoginAddressRowsPerOrg = 200
)

type refusalLimiter struct {
	mu    sync.Mutex
	seen  map[string]*refusalSeen
	count keyCount
}

type refusalSeen struct {
	keyLife
	suppressed int
}

// keyLife is what every limiter keeps of a key to bound how many it holds: whose it is (the organization) and when
// its window ends.
type keyLife struct {
	org   string
	until time.Time
}

func (k *keyLife) life() *keyLife { return k }

// keyCount bounds the keys of a limiter: refusalKeys on the node, and refusalKeysPerOrg of one organization, so that
// one organization's flood (of addresses, say, which whoever sends the requests chooses) fills only its own share,
// and every other organization's events are recorded as before.
type keyCount struct {
	orgs map[string]int // keys held, by organization
	// next is when the first key held can expire: a sweep before it would find nothing to drop, and swept is when
	// the last one ran. Sweeps are at most one a second (sweepEvery), so a flood that keeps a share full pays for one
	// pass over the keys a second, not one a request.
	next, swept time.Time
	// warned is when the node last warned that this limiter held events back because it (or an organization's share
	// of it) was full.
	warned time.Time
}

const sweepEvery = time.Second

func (c *keyCount) add(org string) {
	if c.orgs == nil {
		c.orgs = map[string]int{}
	}
	c.orgs[org]++
}

func (c *keyCount) fits(n int, org string) bool {
	return n < refusalKeys && c.orgs[org] < refusalKeysPerOrg
}

// room reports whether m, a limiter's keys counted by c, has room for another key of org: below refusalKeys and
// org's share, after dropping the keys whose window is over if it is not. When it has none the event is held back
// (counted by the caller), and warn says the node should warn of it now, the first time in a minute.
func room[V interface{ life() *keyLife }](m map[string]V, c *keyCount, org string, now time.Time) (ok, warn bool) {
	if c.fits(len(m), org) {
		return true, false
	}
	if !now.Before(c.next) && now.Sub(c.swept) >= sweepEvery {
		c.swept, c.next = now, time.Time{}
		for k, v := range m {
			l := v.life()
			if !now.Before(l.until) {
				delete(m, k)
				if c.orgs[l.org]--; c.orgs[l.org] <= 0 {
					delete(c.orgs, l.org)
				}
				continue
			}
			if c.next.IsZero() || l.until.Before(c.next) {
				c.next = l.until
			}
		}
		if c.fits(len(m), org) {
			return true, false
		}
	}
	warn = now.Sub(c.warned) >= time.Minute
	if warn {
		c.warned = now
	}
	return false, warn
}

// allow reports whether a refusal event for key (of the organization org) is recorded now, how many of key's were
// held back since its last one, and whether it was held back because the limiter, or org's share of it, is full of
// other live keys (warn: and the node should warn of it now, the first time in a minute).
func (l *refusalLimiter) allow(org, key string, now time.Time) (ok bool, held int, full, warn bool) {
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
	if ok, warn := room(l.seen, &l.count, org, now); !ok { // full of live keys: hold this one back too, counted
		return false, 0, true, warn
	}
	l.seen[key] = &refusalSeen{keyLife: keyLife{org, now.Add(refusalWindow)}}
	l.count.add(org)
	return true, 0, false, false
}

// live reports whether key is within its window, in which case this event of it is counted as held back, as allow
// would have: the question allow answers, asked without starting a window for a key that has none.
func (l *refusalLimiter) live(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.seen[key]
	if s == nil || !now.Before(s.until) {
		return false
	}
	s.suppressed++
	return true
}

// addrAllowance bounds the sign-in events that one client address can have recorded in an organization: so many per
// refusalWindow (take's limit), then one more that says the allowance is spent (the summary), then none until the
// window is over; what was held back is told by the address's next event. It bounds what an organization can have
// recorded naming addresses as well: LoginAddressRowsPerOrg events per window, however many addresses send them.
// The keys are addresses, which whoever sends the requests chooses, so their number is capped as a refusalLimiter's
// is.
type addrAllowance struct {
	mu    sync.Mutex
	seen  map[string]*addrSeen
	count keyCount
	orgs  map[string]*orgRows
}

type addrSeen struct {
	keyLife
	rows       int  // events let through in this window
	summarized bool // the summary of this window was let through
	held       int  // events held back and not yet told
	// unnamedIn is the end of the organization's window in which its cap held the address back, counted once there
	// (orgRows.unnamed).
	unnamedIn time.Time
}

// orgRows is what an organization has had recorded naming addresses in its window.
type orgRows struct {
	until   time.Time
	rows    int // events naming an address (rows and summaries) let through
	unnamed int // addresses held back by the cap, each counted once (as far as the allowance holds them)
}

// addrTake is what take let an event of an address do.
type addrTake int

const (
	addrRow     addrTake = iota // one of the address's allowance
	addrSummary                 // the event that says the allowance is spent
	addrSpent                   // held back: the allowance is spent and told
	addrCapped                  // held back: the organization's events naming addresses for the window are spent
	addrFull                    // held back: the allowance (or the organization's share of it) holds no more addresses
)

// take asks for one event of the address addr in org, whose allowance is limit. held is how many of the address's
// were held back since its last event (told by a row or a summary, whichever comes first); unnamed, for an event held
// back by the organization's cap or a full allowance, how many addresses the cap has held back in the window so far
// (those the allowance holds: past its share of them an address is not told apart from the next); warn, for an event
// held back by the cap or a full allowance, that the node should warn of it now. An event held back is not counted
// against the address here: hold does that, once the caller knows it was not recorded some other way.
func (a *addrAllowance) take(org, addr string, limit int, now time.Time) (t addrTake, held, unnamed int, warn bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seen == nil {
		a.seen, a.orgs = map[string]*addrSeen{}, map[string]*orgRows{}
	}
	o := a.orgs[org]
	if o == nil || !now.Before(o.until) {
		o = &orgRows{until: now.Add(refusalWindow)}
		a.orgs[org] = o
	}
	key := org + "|" + addr
	s := a.seen[key]
	if s != nil && !now.Before(s.until) { // a new window: what was held back is still to be told
		*s = addrSeen{keyLife: keyLife{org, now.Add(refusalWindow)}, held: s.held}
	}
	if s == nil {
		ok, w := room(a.seen, &a.count, org, now)
		if !ok {
			return addrFull, 0, o.unnamed, w
		}
		s = &addrSeen{keyLife: keyLife{org, now.Add(refusalWindow)}}
		a.seen[key] = s
		a.count.add(org)
	}
	if s.rows >= limit && s.summarized {
		return addrSpent, 0, 0, false
	}
	if o.rows >= LoginAddressRowsPerOrg {
		warn = now.Sub(a.count.warned) >= time.Minute
		if warn {
			a.count.warned = now
		}
		return addrCapped, 0, o.unnamed, warn
	}
	o.rows++
	held, s.held = s.held, 0
	if s.rows < limit {
		s.rows++
		return addrRow, held, 0, false
	}
	s.summarized = true
	return addrSummary, held, 0, false
}

// hold counts an event of the address addr in org as held back (told by the address's next event), and, when its
// organization's cap held it back (capped), the address as one of those the cap left unnamed in the window.
func (a *addrAllowance) hold(org, addr string, capped bool, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.seen[org+"|"+addr]
	if s == nil {
		return
	}
	s.held++
	if o := a.orgs[org]; capped && o != nil && now.Before(o.until) && !s.unnamedIn.Equal(o.until) {
		s.unnamedIn = o.until
		o.unnamed++
	}
}

// wideAddr is the address an allowance is kept for: addr as rate limits count it (web.RateKeyIP), but an IPv6 /64 by
// its /48. A provider hands a customer a /48 as readily as a /64, and counted by /64 one such allocation would bring
// 65,536 allowances; the events still name the address itself, and are keyed by it.
func wideAddr(addr string) string {
	var a netip.Addr
	if p, err := netip.ParsePrefix(addr); err == nil {
		if p.Bits() < 48 {
			return addr
		}
		a = p.Addr()
	} else if a, err = netip.ParseAddr(addr); err != nil {
		return addr
	}
	if !a.Is6() || a.Is4In6() {
		return addr
	}
	if p, err := a.Prefix(48); err == nil {
		return p.String()
	}
	return addr
}

// auditRefusal records a refusal event through the limiter: key is the subject (a token, a caller) and the reason,
// and orgID the organization whose event it is.
func (s *Service) auditRefusal(orgID, key string, record func(detail map[string]string)) {
	s.limitedRefusal(&s.refusals, "refusals", orgID, key, record)
}

// refusalDropped counts an event held back because the limiter named name was full (or orgID's share of it, or
// orgID's events naming addresses for the minute were spent), and warns of it when warn says it is time to.
func (s *Service) refusalDropped(name, orgID string, warn bool) {
	metrics.AuditRefusalsDropped.Inc(name)
	if warn && s.Log != nil {
		s.Log.Warn("audit: refusal events held back: a flood of refused requests filled this node's limiter ("+
			strconv.Itoa(refusalKeys)+" keys, "+strconv.Itoa(refusalKeysPerOrg)+" of one organization; sign-in events "+
			strconv.Itoa(LoginAddressRowsPerOrg)+" a minute naming addresses in one organization); counted in "+
			"quisora_audit_refusals_dropped_total", "limiter", name, "org", orgID)
	}
}

// limitedRefusal records a refusal event of orgID through l (named name in the metric and the warning), and reports
// whether it did.
func (s *Service) limitedRefusal(l *refusalLimiter, name, orgID, key string, record func(detail map[string]string)) bool {
	ok, held, full, warn := l.allow(orgID, key, time.Now())
	if full {
		s.refusalDropped(name, orgID, warn)
	}
	if !ok {
		return false
	}
	detail := map[string]string{}
	if held > 0 {
		detail["suppressed"] = strconv.Itoa(held)
	}
	record(detail)
	return true
}

// loginLimiters are the limiters of one kind of sign-in event that anyone can repeat (wrong credentials, or lockout
// refusals), for the events of existing accounts or for those that name none: see loginEvent.
type loginLimiters struct {
	keys  refusalLimiter // (organization, subject, kind, address)
	addrs addrAllowance  // (organization, address by its /48): what one address may have recorded
	// flooded is keyed without the address: (organization, subject, kind) for an existing account's events,
	// (organization, kind) for the others'. It takes the events that could not name their address.
	flooded refusalLimiter
}

// loginEvent records a sign-in event that anyone can repeat through l, and reports whether it did; name names l in
// the metric and the warning. Every client address that causes one is named by an event in each refusalWindow, up to
// its allowance and its organization's; every existing account by one in each refusalWindow and kind whatever the
// addresses do; and how many events there are is bounded by the addresses (and the accounts), not by the requests.
//
// The event is keyed by the organization, its subject (an account's lockout key, a login that names no account, an
// address under spray), kind (the reason and sign-in step) and the client address: one event per key and window,
// the next saying how many were held back (detail.suppressed). Each address so gets its own first event of the
// window for a subject: an address that sends one attempt first cannot take the only event and leave the address
// that sends the rest unnamed. One address could then have an event recorded per account, or per login it makes up,
// so it has an allowance in each organization (addrAllowance, an IPv6 address by its /48): limit events per window,
// then one that names it once more and says the allowance is spent (detail.address_limit), and the next event of the
// address says how many were held back (detail.address_suppressed). An organization has an allowance too:
// LoginAddressRowsPerOrg events naming addresses per window, so that a flood from many addresses (an IPv6 range, a
// botnet) costs it that many events, not one per address.
//
// An event that cannot name its address (its allowance is spent, its organization's is, or l is full) goes through
// flooded instead, keyed without the address: an existing account's (account) by the account and kind, so that a
// real account is named once per window and kind, by whichever address got there first, rather than not at all (an
// address cannot spend its allowance on decoy accounts and then guess at its target unrecorded); any other by the
// organization and kind, so that the kind is seen once per window, with how many were held back, however many
// made-up logins crowd it. That event says how many addresses its organization's allowance left unnamed in the
// window so far (detail.addresses_unnamed). What it adds is bounded by the real accounts and kinds, not by the
// addresses: one per existing account and kind per window (refusalKeysPerOrg of them in an organization), and one
// per organization and kind for the rest.
func (s *Service) loginEvent(l *loginLimiters, name string, limit int, account bool, orgID, addr, subject, kind string, record func(detail map[string]string)) bool {
	now := time.Now()
	key := orgID + "|" + subject + "|" + kind + "|" + addr
	if l.keys.live(key, now) {
		return false
	}
	wide := wideAddr(addr)
	t, over, unnamed, warn := l.addrs.take(orgID, wide, limit, now)
	detail := map[string]string{}
	if over > 0 || t == addrSummary {
		detail["address_suppressed"] = strconv.Itoa(over)
	}
	switch t {
	case addrRow:
		ok, held, full, keysWarn := l.keys.allow(orgID, key, now)
		if held > 0 {
			detail["suppressed"] = strconv.Itoa(held)
		}
		if ok {
			record(detail)
			return true
		}
		if !full { // another request of the same key got there first: held back in its window
			return false
		}
		s.refusalDropped(name, orgID, keysWarn)
	case addrSummary:
		detail["address_limit"] = strconv.Itoa(limit)
		record(detail)
		return true
	case addrCapped, addrFull:
		s.refusalDropped(name, orgID, warn)
	}
	fk := orgID + "|" + kind
	if account {
		fk = orgID + "|" + subject + "|" + kind
	}
	if s.limitedRefusal(&l.flooded, name, orgID, fk, func(d map[string]string) {
		if unnamed > 0 {
			d["addresses_unnamed"] = strconv.Itoa(unnamed)
		}
		record(d)
	}) {
		return true
	}
	l.addrs.hold(orgID, wide, t == addrCapped, now)
	return false
}

// loginEventOf is loginEvent through the limiters of existing accounts' events (accounts, named accountsName) or of
// those that name no account (logins, loginsName), each with its allowance per address. The two are apart so that
// a flood of made-up logins and addresses can fill only its own limiters and spend only its own allowance.
func (s *Service) loginEventOf(logins, accounts *loginLimiters, loginsName, accountsName string, account bool, orgID, addr, subject, kind string, record func(detail map[string]string)) bool {
	if account {
		return s.loginEvent(accounts, accountsName, LoginRowsPerAddress, true, orgID, addr, subject, kind, record)
	}
	return s.loginEvent(logins, loginsName, LoginRowsPerAddressUnknown, false, orgID, addr, subject, kind, record)
}

// AuditLoginRefusal is auditRefusal for the sign-in pages' lockout refusals, which anyone can repeat against an
// account or from an address for as long as it stays locked, through limiters of their own (loginEvent): account
// says that subject names an existing account's lockout key, which keeps those refusals apart from the ones of
// logins that name no account and of addresses (subject: the login's lockout key, the address's). addr is the
// client address as rate limits count it, and kind the reason and sign-in step. A refusal checks no credential, but
// the address that keeps trying a locked account is as much evidence as the one that guessed, so it is named in the
// same way. record records a login.failure (reason locked or address locked), and every refusal held back, in its
// window, past its address's allowance or by a full limiter, is still counted in
// quisora_audit_events_total{action="login.failure"}, as AuditLoginFailure counts the failures it holds back: an
// alert keyed on that rate sees sustained hammering of a locked account, not one event a minute.
func (s *Service) AuditLoginRefusal(account bool, orgID, addr, subject, kind string, record func(detail map[string]string)) {
	if !s.loginEventOf(&s.loginRefusals, &s.accountRefusals, "login", "login_accounts", account, orgID, addr, subject, kind, record) {
		metrics.AuditEvents.Inc("login.failure", "failure")
	}
}

// AuditDeviceStart records the start of a public client's device sign-in (oauth.device.start, with audit.tokens)
// through a limiter of its own: anyone can start them, so key (the client and the address) gets one event per
// refusalWindow on each node, the next saying how many were held back (detail.suppressed), and a flood of them
// fills neither the audit log nor the other limiters.
func (s *Service) AuditDeviceStart(orgID, key string, record func(detail map[string]string)) {
	s.limitedRefusal(&s.deviceStarts, "device_starts", orgID, key, record)
}

// AuditLoginFailure records a sign-in attempt whose credential was checked and found wrong (login.failure: a wrong
// password, authenticator code, recovery code or emailed code, or a login that names no account) as
// AuditLoginRefusal records a lockout refusal (loginEvent), through limiters of their own. With
// limits.lockout_attempts = 0 (never locked) nothing else bounds them but the request budgets, and a lockout refusal
// is no reason to drop a failure, nor the reverse, so neither can fill the other's limiters or spend the other's
// allowance. account says, as there, that subject names an existing account, whose failures a flood of made-up
// logins cannot then crowd out. The first event of a window for a subject and address is the one recorded; the
// lockout itself (login.lockout, when the failure that trips it is held back too) never goes through here. Every
// failure held back, in its window, past its address's allowance or by a full limiter, is still counted in
// quisora_audit_events_total{action="login.failure"}, so the alerts on password guessing see each attempt, as
// before; only the audit log is spared the repeats.
func (s *Service) AuditLoginFailure(account bool, orgID, addr, subject, kind string, record func(detail map[string]string)) {
	if !s.loginEventOf(&s.loginFailures, &s.accountFailures, "login_failures", "login_account_failures", account, orgID, addr, subject, kind, record) {
		metrics.AuditEvents.Inc("login.failure", "failure")
	}
}
