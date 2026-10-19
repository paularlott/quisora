package vlogs

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/model"
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
	if !strings.HasPrefix(f, `app:="quisora" org:="x\" | delete"`) || !strings.Contains(f, `action:~"(?i)a\\.\\*\"\\) or app:\\*"`) {
		t.Fatalf("filter %s", f)
	}
	if Filter(service.AuditQuery{}) != `app:="quisora"` {
		t.Fatal("empty query")
	}
}

// Against a real VictoriaLogs (QUISORA_TEST_VICTORIALOGS=http://127.0.0.1:9428): events written by the client are
// read back per organization, newest first, searched, paged and counted.
func TestVictoriaLogsRoundTrip(t *testing.T) {
	addr := os.Getenv("QUISORA_TEST_VICTORIALOGS")
	if addr == "" {
		t.Skip("QUISORA_TEST_VICTORIALOGS not set")
	}
	c, err := New(addr, "node-1", logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	orgA, orgB, mark := model.NewID(), model.NewID(), "mark"+model.NewID()[24:]
	base := time.Now().Add(-time.Minute).UTC()
	for i := range 5 {
		c.WriteAudit(&model.Audit{Meta: model.Meta{ID: model.NewID(), Created: base.Add(time.Duration(i) * time.Second)},
			OrgID: orgA, Action: "user.update", Actor: "ada", Target: mark + "-" + string(rune('a'+i)), IP: "192.0.2.1",
			Detail: map[string]string{"tags": "x y"}})
	}
	c.WriteAudit(&model.Audit{Meta: model.Meta{ID: model.NewID(), Created: base}, OrgID: orgB, Action: "user.delete", Actor: "bob", Target: mark})
	c.Close() // flushes
	ctx := context.Background()
	var pg service.AuditPage
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) { // VictoriaLogs makes new rows searchable within a second or so
		pg, err = c.ReadAudit(ctx, service.AuditQuery{Org: orgA, Sort: "created", Desc: true, Limit: 2})
		if err == nil && pg.Total == 5 && len(pg.Items) == 2 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil || pg.Total != 5 || len(pg.Items) != 2 || pg.Source != "victorialogs" {
		t.Fatalf("org a: %+v %v", pg, err)
	}
	if pg.Items[0].Target != mark+"-e" || pg.Items[1].Target != mark+"-d" || pg.Items[0].Detail["tags"] != "x y" ||
		pg.Items[0].IP != "192.0.2.1" || pg.Items[0].OrgID != orgA || pg.Items[0].ID == "" {
		t.Fatalf("org a newest first: %+v %+v", pg.Items[0], pg.Items[1])
	}
	page2, _ := c.ReadAudit(ctx, service.AuditQuery{Org: orgA, Sort: "created", Desc: true, Offset: 2, Limit: 2})
	if len(page2.Items) != 2 || page2.Items[0].Target != mark+"-c" {
		t.Fatalf("second page: %+v", page2.Items)
	}
	other, _ := c.ReadAudit(ctx, service.AuditQuery{Org: orgB, Sort: "created", Desc: true, Limit: 10})
	if other.Total != 1 || other.Items[0].Action != "user.delete" {
		t.Fatalf("org b: %+v", other)
	}
	// every organization, by search (case-insensitive substring)
	all, _ := c.ReadAudit(ctx, service.AuditQuery{Search: strings.ToUpper(mark), Sort: "created", Desc: true, Limit: 50})
	if all.Total != 6 {
		t.Fatalf("search across organizations: %d", all.Total)
	}
}
