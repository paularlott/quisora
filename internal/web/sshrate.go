package web

import (
	"context"
	"net/http"
	"time"
)

// The rate limits of a tenant's SSH certificate authority (docs/design/ssh-ca.md). They are counted per minute in the
// namespace of the OAuth endpoints' counters, so a test that takes that counter away takes these too. Every request
// counts, what is refused as well, and a counter that cannot be read is an error, not a verdict.
const (
	SSHSignsPerUser      = 20  // user certificates signed per user and minute, on the sign endpoint and the account page together
	SSHSignsPerIP        = 60  // ... per address and minute, likewise
	SSHHostSignsPerActor = 120 // host certificates signed per administrator or service account and minute
	SSHRevokesPerUser    = 60  // certificates revoked on the account page per user and minute

	// The public documents of a tenant (discovery, CA keys, revocation list) are counted per address and tenant (by
	// its id; the paths that name no tenant share one counter per address), in units a minute: a request answered 304 Not Modified (or refused) costs SSHFetchCost304, one answered with the
	// document SSHFetchCost. Servers behind one NAT address share the budget: a `quisora ssh fetch` a minute is at most
	// four documents, so it allows a thousand servers fetching every minute (four times that while nothing changes and
	// they revalidate). Serving the documents is cheap: the revocation list is made once per tenant and node.
	SSHFetchUnitsPerIP = 16000
	SSHFetchCost       = 4
	SSHFetchCost304    = 1

	sshRateNS = "oauth.rate"
)

// SSHSignAllowed counts a request for a user certificate for user userID from r, and reports whether it is within the
// limits. The sign endpoint and the account page both ask it, so what a person asks for in either counts against the
// same budget.
func (s *Server) SSHSignAllowed(ctx context.Context, r *http.Request, userID string) (bool, error) {
	if s.Eph == nil {
		return true, nil
	}
	n, err := s.Eph.Incr(ctx, sshRateNS, "ssh-sign|user|"+userID, 1, time.Minute)
	if err != nil {
		return false, err
	}
	nIP, err := s.Eph.Incr(ctx, sshRateNS, "ssh-sign|ip|"+RateKeyIP(r), 1, time.Minute)
	if err != nil {
		return false, err
	}
	return n <= SSHSignsPerUser && nIP <= SSHSignsPerIP, nil
}

// SSHHostSignAllowed counts a request for a host certificate by actor (a service account's client id, or a user id),
// and reports whether it is within the limit.
func (s *Server) SSHHostSignAllowed(ctx context.Context, actor string) (bool, error) {
	if s.Eph == nil {
		return true, nil
	}
	n, err := s.Eph.Incr(ctx, sshRateNS, "ssh-host|"+actor, 1, time.Minute)
	return n <= SSHHostSignsPerActor, err
}

// SSHRevokeAllowed counts a revocation of a certificate by its owner, user userID (the account page), and reports
// whether it is within the limit: each revoked certificate stays on the tenant's revocation list until it expires.
func (s *Server) SSHRevokeAllowed(ctx context.Context, userID string) (bool, error) {
	if s.Eph == nil {
		return true, nil
	}
	n, err := s.Eph.Incr(ctx, sshRateNS, "ssh-revoke|user|"+userID, 1, time.Minute)
	return n <= SSHRevokesPerUser, err
}

// sshFetchKey is the counter of the public SSH documents of tenant tenantID (its id: "" for a path that names no
// tenant, which share one counter) asked for from r's address.
func sshFetchKey(r *http.Request, tenantID string) string {
	if tenantID == "" {
		tenantID = "?"
	}
	return "ssh-get|ip|" + RateKeyIP(r) + "|" + tenantID
}

// SSHFetchAllowed counts a request from r for one of the public SSH documents (discovery, CA keys, revocation list) of
// tenant tenantID (the tenant's id, whether the path names it by id or by name; "" for a path that names no tenant) at
// the cost of a 304 answer, and reports whether its address is within the limit for that tenant. SSHFetchServed counts
// the rest when the document is sent.
func (s *Server) SSHFetchAllowed(ctx context.Context, r *http.Request, tenantID string) (bool, error) {
	if s.Eph == nil {
		return true, nil
	}
	n, err := s.Eph.Incr(ctx, sshRateNS, sshFetchKey(r, tenantID), SSHFetchCost304, time.Minute)
	return n <= SSHFetchUnitsPerIP, err
}

// SSHFetchServed counts the rest of the cost of a request SSHFetchAllowed let through that is answered with the
// document, not 304. Best effort: the answer is sent, and a counter that cannot be written only lets the next requests
// through more cheaply.
func (s *Server) SSHFetchServed(ctx context.Context, r *http.Request, tenantID string) {
	if s.Eph != nil {
		_, _ = s.Eph.Incr(ctx, sshRateNS, sshFetchKey(r, tenantID), SSHFetchCost-SSHFetchCost304, time.Minute)
	}
}
