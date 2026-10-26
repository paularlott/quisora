package vlogs

import (
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

// Values from a request never become LogsQL syntax: quotes, pipes and regular-expression characters are escaped.
func TestFilterEscapes(t *testing.T) {
	f := Filter(service.AuditQuery{Org: `x" | delete`, Search: `a.*") or app:*`})
	for _, bad := range []string{`org:="x" |`, `.*")`, `or app:*`} {
		if strings.Contains(f, bad) {
			t.Fatalf("unescaped request text in %s", f)
		}
	}
	if !strings.HasPrefix(f, `app:="quisora" org:="x\" | delete"`) || !strings.Contains(f, `actor:~"(?i)a\\.\\*\"\\) or app:\\*"`) {
		t.Fatalf("filter %s", f)
	}
	if Filter(service.AuditQuery{}) != `app:="quisora"` {
		t.Fatal("empty query")
	}
}

// The filters become LogsQL conditions: a time range, an action family (escaped, case-insensitive), one action, an
// outcome; the search covers actor, target and IP address, not the action.
func TestFilterConditions(t *testing.T) {
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	f := Filter(service.AuditQuery{From: from, To: to, ActionPrefix: "user.", Action: "user.update", Outcome: "failure", Search: "10.0"})
	for _, want := range []string{`_time:>=2026-10-01T00:00:00Z`, `_time:<2026-10-02T00:00:00Z`, `action:~"(?i)^user\\."`,
		`action:="user.update"`, `outcome:="failure"`, `(actor:~"(?i)10\\.0" or target:~"(?i)10\\.0" or ip:~"(?i)10\\.0")`} {
		if !strings.Contains(f, want) {
			t.Errorf("filter %s lacks %s", f, want)
		}
	}
}
