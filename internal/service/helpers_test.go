package service_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// env is a service over a memory store with the primary org bootstrapped.
type env struct {
	t       testing.TB
	ctx     context.Context
	svc     *service.Service
	primary *model.Org
	super   *model.User
	seq     int
}

func newEnv(t testing.TB) *env {
	t.Helper()
	st := memstore.New()
	t.Cleanup(func() { _ = st.Close() })
	return newEnvOn(t, st)
}

// newEnvOn is newEnv over the store st.
func newEnvOn(t testing.TB, st store.Store) *env {
	t.Helper()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 4
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(cfg, st, sealer)
	ctx := context.Background()
	super, _, err := svc.Bootstrap(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	primary, err := svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, ctx: ctx, svc: svc, primary: primary, super: super}
	e.primary = e.setAPITokens(primary.ID, model.APITokensEveryone)
	return e
}

// setAPITokens sets who may make api tokens in organization orgID (and which groups, for the groups mode). The
// environments let everyone, as the tokens most tests make are not what they are about; tests of the setting change it.
// It returns the organization as saved.
func (e *env) setAPITokens(orgID, mode string, groups ...string) *model.Org {
	e.t.Helper()
	o, err := e.svc.GetOrg(e.ctx, nil, orgID)
	if err != nil {
		e.t.Fatal(err)
	}
	st := o.Settings
	st.APITokens, st.APITokenGroups = mode, groups
	upd, err := e.svc.UpdateOrg(e.ctx, service.System, orgID, service.OrgInput{Settings: &st})
	if err != nil {
		e.t.Fatalf("set api tokens %q: %v", mode, err)
	}
	return upd
}

func ptr[T any](v T) *T { return &v }

func (e *env) org(name string) *model.Org {
	e.t.Helper()
	o, err := e.svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: &name})
	if err != nil {
		e.t.Fatalf("create org %s: %v", name, err)
	}
	return e.setAPITokens(o.ID, model.APITokensEveryone)
}

// user creates a user directly as the system actor (primary-org super admins included).
func (e *env) user(orgID, username string, role model.Role) *model.User {
	e.t.Helper()
	in := service.UserInput{Username: &username, GivenName: ptr(username), Role: &role, Email: ptr(username + "@example.com")}
	u, err := e.svc.CreateUser(e.ctx, service.System, orgID, in)
	if err != nil {
		e.t.Fatalf("create user %s: %v", username, err)
	}
	return u
}

func (e *env) next(prefix string) string {
	e.seq++
	return prefix + string(rune('a'+e.seq%26)) + strconv.Itoa(e.seq)
}

func actor(u *model.User) *service.Actor { return service.ActorForUser(u, "127.0.0.1") }

// fieldOf returns the field a validation error names ("" for any other error).
func fieldOf(err error) string {
	var fe *service.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

// outcome classifies an error for matrix tests.
func outcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, service.ErrForbidden):
		return "forbidden"
	case errors.Is(err, service.ErrNotFound):
		return "notfound"
	case errors.Is(err, service.ErrInvalid):
		return "invalid"
	case errors.Is(err, service.ErrConflict):
		return "conflict"
	case errors.Is(err, service.ErrStale):
		return "stale"
	}
	return "other:" + err.Error()
}

// session makes a stamped browser session for u, as the web layer does.
func (e *env) session(u *model.User) *model.Session {
	e.t.Helper()
	st, err := e.svc.SessionStamp(e.ctx, u.OrgID)
	if err != nil {
		e.t.Fatal(err)
	}
	s := &model.Session{UserID: u.ID, OrgID: u.OrgID, Expires: time.Now().Add(time.Hour), LastSeen: time.Now(), Stamp: st}
	if err := e.svc.Sessions.Create(e.ctx, s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

// grant makes a stamped refresh grant for u, as the OIDC provider does.
func (e *env) grant(u *model.User, sessionID string) *model.Grant {
	e.t.Helper()
	st, err := e.svc.SessionStamp(e.ctx, u.OrgID)
	if err != nil {
		e.t.Fatal(err)
	}
	g := &model.Grant{UserID: u.ID, OrgID: u.OrgID, ClientID: "c1", SessionID: sessionID, Expires: time.Now().Add(time.Hour), Stamp: st}
	if err := e.svc.Grants.Create(e.ctx, g); err != nil {
		e.t.Fatal(err)
	}
	return g
}

// apiToken makes a personal API token for u through the service; it returns the presented form.
func (e *env) apiToken(u *model.User) string {
	e.t.Helper()
	_, plain, err := e.svc.CreateAPIToken(e.ctx, actor(u), service.APITokenInput{Name: e.next("t"), Scopes: []string{service.ScopeAPI}})
	if err != nil {
		e.t.Fatal(err)
	}
	return plain
}

func (e *env) sessionLive(s *model.Session) bool {
	got, err := e.svc.Sessions.Get(e.ctx, s.ID)
	return err == nil && e.svc.SessionCurrent(e.ctx, got.OrgID, got.Stamp)
}

// sessionCounts reports whether the session s of userID still signs them in (service.SessionUsable, on the account as
// it is now: a user gone, disabled or in a new session epoch counts it for nothing).
func (e *env) sessionCounts(s *model.Session, userID string) bool {
	got, err := e.svc.Sessions.Get(e.ctx, s.ID)
	if err != nil {
		return false
	}
	u, err := e.svc.Users.Get(e.ctx, userID)
	if err != nil {
		return false
	}
	ok, err := e.svc.SessionUsable(e.ctx, got, u)
	return err == nil && ok
}

func (e *env) grantLive(g *model.Grant) bool {
	got, err := e.svc.Grants.Get(e.ctx, g.ID)
	return err == nil && e.svc.SessionCurrent(e.ctx, got.OrgID, got.Stamp)
}

func (e *env) tokenLive(plain string) bool {
	_, _, err := e.svc.ValidateAPIToken(e.ctx, plain)
	return err == nil
}

// audited returns the audit events of action in org, as a super admin reads them.
func (e *env) audited(orgID, action string) []*model.Audit {
	e.t.Helper()
	page, err := e.svc.ListAudit(e.ctx, actor(e.super), orgID, service.AuditQuery{Action: action})
	if err != nil {
		e.t.Fatal(err)
	}
	return page.Items
}

func (e *env) fresh(u *model.User) *model.User {
	e.t.Helper()
	got, err := e.svc.Users.Get(e.ctx, u.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) passkey(u *model.User, name string) *model.Passkey {
	e.t.Helper()
	pk := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: name, CredentialID: []byte(name), UserVerified: true, Epoch: e.fresh(u).CredEpoch}
	if err := e.svc.Passkeys.Create(e.ctx, pk); err != nil {
		e.t.Fatal(err)
	}
	return pk
}

func (e *env) link(u *model.User, p *model.Provider, subject string) *model.Identity {
	e.t.Helper()
	i := model.NewIdentity(e.fresh(u), p, subject, subject+"@example.com", "admin")
	if err := e.svc.Identities.Create(e.ctx, i); err != nil {
		e.t.Fatal(err)
	}
	return i
}

// establish gives u a password so that their sign-in counts as established (privileged-account rules apply).
func (e *env) establish(u *model.User) *model.User {
	e.t.Helper()
	got, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Password: ptr("correct horse battery")})
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func isInvalid(err error) bool { return errors.Is(err, service.ErrInvalid) }

func mustSealer(t *testing.T) *secure.Sealer {
	t.Helper()
	s, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func tokenFrom(link string) string { return link[strings.Index(link, "token=")+len("token="):] }

// activeMembers counts the organization's memberships that are not removed (a removed one is kept until it expires).
func activeMembers(t *testing.T, svc *service.Service, orgID string) int {
	t.Helper()
	ms, err := svc.Members.All(context.Background(), orgID)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, m := range ms {
		if m.Active() {
			n++
		}
	}
	return n
}

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

func (r recLog) Trace(m string, _ ...any) { r.add("trace", m) }

func (r recLog) Debug(m string, _ ...any) { r.add("debug", m) }

func (r recLog) Info(m string, _ ...any) { r.add("info", m) }

func (r recLog) Warn(m string, _ ...any) { r.add("warn", m) }

func (r recLog) Error(m string, _ ...any) { r.add("error", m) }

func (r recLog) Fatal(m string, _ ...any) { r.add("fatal", m) }

func (r recLog) With(string, any) logger.Logger { return r }

func (r recLog) WithError(error) logger.Logger { return r }

func (r recLog) WithGroup(string) logger.Logger { return r }

// sortedIDs is ids in order, as GroupMembers lists them.
func sortedIDs(ids ...string) []string { return slices.Sorted(slices.Values(ids)) }

// group creates a group in the organization, with members when any are given (created in one commit).
func (e *env) group(orgID, name string, members ...*model.User) *model.Group {
	e.t.Helper()
	in := service.GroupInput{DisplayName: &name}
	var (
		g   *model.Group
		err error
	)
	if len(members) == 0 {
		g, err = e.svc.CreateGroup(e.ctx, service.System, orgID, in)
	} else {
		ids := make([]string, len(members))
		for i, m := range members {
			ids[i] = m.ID
		}
		g, err = e.svc.CreateGroupWithMembers(e.ctx, service.System, orgID, in, ids)
	}
	if err != nil {
		e.t.Fatalf("create group %s: %v", name, err)
	}
	return g
}

// changeGroupAsync runs ChangeGroup in the background; its result arrives on the channel.
func (e *env) changeGroupAsync(g *model.Group, in service.GroupInput, add, remove []string) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, g, in, add, remove)
		done <- err
	}()
	return done
}

// ways reads what can sign u in, from the stored account.
func (e *env) ways(u *model.User) *service.Ways {
	e.t.Helper()
	ways, err := e.svc.UserWays(e.ctx, e.fresh(u))
	if err != nil {
		e.t.Fatal(err)
	}
	return ways
}

// current reads the stored group again.
func (e *env) current(g *model.Group) *model.Group {
	e.t.Helper()
	got, err := e.svc.Groups.Get(e.ctx, g.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

// audits returns the audit events of action in every organization, read from the store directly, oldest first.
func (e *env) audits(action string) []*model.Audit {
	e.t.Helper()
	all, _, err := e.svc.Audits.List(e.ctx, store.ListQuery{Filters: []store.Filter{{Field: "action", Value: action}}})
	if err != nil {
		e.t.Fatal(err)
	}
	slices.SortStableFunc(all, func(a, b *model.Audit) int { return a.Created.Compare(b.Created) })
	return all
}

// lastAudit returns the newest audit event of action; the test fails if there is none.
func (e *env) lastAudit(action string) *model.Audit {
	e.t.Helper()
	all := e.audits(action)
	if len(all) == 0 {
		e.t.Fatalf("no %s event", action)
	}
	return all[len(all)-1]
}

// badScopes are no valid scope tokens (RFC 6749): blanks, quotes, backslashes, non-ASCII or control characters, or
// longer than 100.
var badScopes = []string{"has space", `quo"te`, `back\slash`, "caf\u00e9", "tab\there", strings.Repeat("x", 101)}

// auditSink collects the audit events a service hands to its AuditWriter.
type auditSink struct {
	mu     sync.Mutex
	events []*model.Audit
}

func (s *auditSink) WriteAudit(e *model.Audit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

// of returns the events of action in order.
func (s *auditSink) of(action string) []*model.Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*model.Audit
	for _, e := range s.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}
