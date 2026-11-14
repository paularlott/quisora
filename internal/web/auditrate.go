package web

import (
	"context"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
)

// The audit pages (the console's, the management API's and the MCP server's query_audit_log, which all read through
// GET /api/orgs/{org}/audit or /api/audit) read one log that every organization shares: VictoriaLogs, or in a gossip
// cluster every node's store. Each page is two queries over it (the page and its count), and a search over a long
// range scans much of it, so the organizations' administrators share it by budgets: AuditReadsPerMinute pages a
// minute per budget, counted across the cluster in the OAuth counters' namespace, as the SSH and mail limits are (a
// counter that cannot be read is an error, not a verdict). An organization's administrators share its budget, and
// each of them may spend AuditReadsPerMinuteActor of it, so that one administrator (or one script holding their
// token) cannot spend all of it and hold the others out of their own log; each super admin has a budget of their
// own. How many pages are read at once is bounded on each node too (admin: AuditReadsInFlight, of which
// AuditReadsInFlightSuper are kept for the super admins, and AuditReadsInFlightPerBudget), and how long one may take
// (AuditReadTimeout), so a few slow searches cannot take every query the log answers, nor every place for good. A
// page is counted only once it has a place: one refused for want of a place, or by its administrator's own
// allowance, spends none of the organization's budget.
const (
	AuditReadsPerMinute         = 120 // audit pages a minute per organization (its administrators together) or super admin
	AuditReadsPerMinuteActor    = 60  // ... of an organization's, per administrator
	AuditReadsInFlight          = 16  // audit pages being read at once on a node, every budget together
	AuditReadsInFlightSuper     = 4   // ... of which only the super admins' pages may take these
	AuditReadsInFlightPerBudget = 2   // ... of one budget
)

// AuditReadTimeout is how long an audit page may take to read, whichever log it is read from, and how long counting it
// against its budget may take before that: past either the page is given up (503) and its place is free again.
// VictoriaLogs has 10 seconds for each of a page's two queries besides, and a gossip cluster waits 3 seconds for its
// nodes; this is the bound that holds for every reader on the node that reads the page. In a gossip cluster the page
// asks every other node too, outside this node's places: each node answers others within the asker's wait (4 seconds
// at most) and only so many at once, refusing the rest as busy (cluster.handleAudit), so the pages abandoned at the
// wait cannot pile up as queries on the other nodes. A variable so tests can lower it.
var AuditReadTimeout = 15 * time.Second

// AuditBudgetOrg and AuditBudgetSuper are the budgets of the audit pages: an organization's (its administrators'),
// and a super admin's own.
func AuditBudgetOrg(orgID string) string    { return "audit-read|org|" + orgID }
func AuditBudgetSuper(userID string) string { return "audit-read|super|" + userID }

// AuditReadVerdict is what AuditReadAllowed found.
type AuditReadVerdict int

const (
	AuditReadOK          AuditReadVerdict = iota // counted, and within the budget
	AuditReadActorSpent                          // the reader's own allowance of the budget is spent
	AuditReadBudgetSpent                         // the budget is spent
)

// AuditReadAllowed counts an audit page read against budget (AuditBudgetOrg, AuditBudgetSuper) and, when actor names
// one of several readers who share it (an organization's administrator: "" for a super admin, whose budget is their
// own), against actor's allowance of it, and reports whether it is within AuditReadsPerMinuteActor and
// AuditReadsPerMinute. The allowance is counted first, and a page it refuses is not counted against the budget; a
// page the budget refuses is given back to the allowance, so an administrator held out by the others' reading has
// not spent their own as well.
//
// A count the counters could not keep (ephemeral.Contended: this node's counters are at their cap, or the counter
// is too contended to update) is let through, where the other rate limits refuse. Those limits stand between
// anyone and something worth guessing, and must fail closed. This one is between an authenticated administrator
// and their own audit log, the counters' cap is reached by a flood of other people's counters (addresses, logins
// that name no account), and that flood is when the log is needed: failing closed would let whoever floods the
// sign-in pages take the audit log away as well, with a message blaming the administrator's own reading. The load
// on the log stays bounded without the count: by the places (AuditReadsInFlightPerBudget of a budget at once on a
// node) and AuditReadTimeout.
func (s *Server) AuditReadAllowed(ctx context.Context, budget, actor string) (AuditReadVerdict, error) {
	if s.Eph == nil {
		return AuditReadOK, nil
	}
	actorKey := budget + "|by|" + actor
	if actor != "" {
		n, err := s.Eph.Incr(ctx, sshRateNS, actorKey, 1, time.Minute)
		if err != nil {
			return AuditReadOK, err
		}
		if n > AuditReadsPerMinuteActor && n < ephemeral.Contended {
			return AuditReadActorSpent, nil
		}
	}
	n, err := s.Eph.Incr(ctx, sshRateNS, budget, 1, time.Minute)
	if err == nil && (n <= AuditReadsPerMinute || n >= ephemeral.Contended) {
		return AuditReadOK, nil
	}
	if actor != "" { // not read: given back to the reader's allowance
		_, _ = s.Eph.Incr(context.WithoutCancel(ctx), sshRateNS, actorKey, -1, time.Minute)
	}
	return AuditReadBudgetSpent, err
}
