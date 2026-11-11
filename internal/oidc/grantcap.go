package oidc

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// The refresh grants one user may hold: the organization's own (model.OrgSettings.GrantsPerUser), else
// limits.grants_per_user (1,000 by default). Each code exchange makes one (userGrant), lasting tokens.refresh_ttl: an
// application that signs in again silently (prompt=none) whenever its access token expires makes one every ten
// minutes, thousands a month, and every listing of the user's grants (sign out everywhere, the account's
// applications) reads them all. Past the cap the excess is ended, the grants a user is least likely to miss first
// (evictsBefore), down to a tenth below it, so the grants are counted again only some hundred grants later.
const (
	// grantRoomTTL is how long a node trusts its count of a user's grants (grantRoom): grants made on other nodes
	// meanwhile can take the user past the cap until a node counts again.
	grantRoomTTL = 10 * time.Minute
)

// noteGrant is told of a refresh grant (keep) made for user userID of organization orgID. When this node may have
// made enough of the user's grants since it last counted them to take the user past the cap, it counts them again
// and ends the excess (capGrants), in the background: the token response does not wait for it. One count at a time
// per user; the exchanges that come meanwhile leave theirs to it.
func (p *Provider) noteGrant(ctx context.Context, orgID, userID, keep string) {
	if r, ok := p.grantRoom.Get(userID); ok && r.Add(-1) >= 0 {
		return
	}
	if _, busy := p.grantCounting.LoadOrStore(userID, struct{}{}); busy {
		return
	}
	p.svc.Background(ctx, service.BackgroundShort, func(ctx context.Context) {
		defer p.grantCounting.Delete(userID)
		n, limit, err := p.capGrants(ctx, orgID, userID, keep)
		if err != nil {
			p.log.Warn("oidc: capping a user's refresh grants", "user", userID, "error", err)
			return // counted again at the user's next grant
		}
		room := &atomic.Int64{}
		room.Store(int64(limit - n))
		p.grantRoom.Put(userID, room)
	})
}

// capGrants ends user userID's refresh grants past the cap (the organization's, read as stored now: a change applies
// at the next count), never keep (the grant just made), and returns how many are left and the cap. They are ended as a revocation ends a grant (revokeGrant: deleted, then their SSH
// certificates revoked), and nothing else of the user is: not their sessions, not their other grants. Each is
// audited (oauth.grant.evict).
func (p *Provider) capGrants(ctx context.Context, orgID, userID, keep string) (left, limit int, err error) {
	o, err := p.svc.OrgPolicy(ctx, orgID)
	if err != nil {
		return 0, 0, err // nothing ended: the server's cap may be far below the organization's
	}
	limit = p.svc.GrantsPerUser(o)
	grants, err := p.svc.Grants.All(ctx, userID)
	if err != nil || len(grants) <= limit {
		return len(grants), limit, err
	}
	slices.SortFunc(grants, evictsBefore)
	excess := len(grants) - (limit - limit/10)
	var ended []*model.Grant
	for _, g := range grants {
		if len(ended) == excess {
			break
		}
		if g.ID != keep {
			ended = append(ended, g)
		}
	}
	if len(ended) == 0 {
		return len(grants), limit, nil
	}
	// The SSH application's grants, which can have certificates, apart from the others (revokeGrant).
	var sshIDs, otherIDs []string
	for _, g := range ended {
		if e, err := p.loadClient(ctx, g.ClientID); err != nil || e.c.SSHApp { // unknown: as if it could
			sshIDs = append(sshIDs, g.ID)
		} else {
			otherIDs = append(otherIDs, g.ID)
		}
	}
	var rerr error
	if len(sshIDs) > 0 {
		rerr = p.revokeGrant(ctx, orgID, userID, true, sshIDs...)
	}
	if len(otherIDs) > 0 {
		rerr = errors.Join(rerr, p.revokeGrant(ctx, orgID, userID, false, otherIDs...))
	}
	u := p.svc.AuditTargetUser(ctx, orgID, userID)
	revoked := revokedText(rerr)
	for _, g := range ended {
		p.svc.AuditUser(ctx, service.System, u, "oauth.grant.evict", map[string]string{"grant": g.ID, "user_id": userID,
			"client": g.ClientID, "scopes": strings.Join(g.Scopes, " "), "grant_revoked": revoked, "cap": strconv.Itoa(limit)})
	}
	return len(grants) - len(ended), limit, rerr
}

// evictsBefore orders a user's grants by which goes first past the cap: those without offline_access (they last only
// as long as their browser session, and an application that signs in again silently leaves the earlier ones unused),
// then those with it; each the least recently used first: the latest of when it was made and when its refresh token
// last rotated (a grant whose token does not rotate records no use).
func evictsBefore(a, b *model.Grant) int {
	if ao, bo := slices.Contains(a.Scopes, "offline_access"), slices.Contains(b.Scopes, "offline_access"); ao != bo {
		if ao {
			return 1
		}
		return -1
	}
	return lastUsed(a).Compare(lastUsed(b))
}

func lastUsed(g *model.Grant) time.Time {
	if g.Rotated.After(g.Created) {
		return g.Rotated
	}
	return g.Created
}
