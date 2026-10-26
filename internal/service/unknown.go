package service

import (
	"context"
	"errors"

	"github.com/paularlott/quisora/internal/store"
)

// OutcomeUnknown is the outcome of the audit event of a change whose outcome is not known (auditUnknown).
const OutcomeUnknown = "unknown"

type outcomeKey struct{}

// auditUnknown records the audit event of a change whose write returned err, when the outcome of that write is not known
// (store.ErrUnconfirmed, ErrOutcomeUnknown: the change was sent and the node deciding it was lost before it answered;
// the next owner settles it, made once or never). The event is the one the change records when it succeeds, with outcome
// "unknown": a change that did take effect is never missing from the audit log. Any other error records nothing (nothing
// was changed).
func (s *Service) auditUnknown(ctx context.Context, err error, a *Actor, orgID, action, target string, detail map[string]string) {
	if errors.Is(err, store.ErrUnconfirmed) || errors.Is(err, ErrOutcomeUnknown) {
		s.Audit(context.WithValue(ctx, outcomeKey{}, OutcomeUnknown), a, orgID, action, target, detail)
	}
}
