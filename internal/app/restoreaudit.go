package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A restore happens before the service can write (at start-up, or offline with "quisora restore"), so it is noted
// in the data directory and written to the primary organization's audit log (backup.restore) once this node may
// write, like a forced start. The note stays until then, across restarts.
const restoreAuditFile = "restore-audit.json"

type restoreNote struct {
	At      time.Time         `json:"at"`
	File    string            `json:"file"`
	Records int               `json:"records"`
	Forced  bool              `json:"forced,omitempty"`
	Origin  map[string]string `json:"origin"` // who restored it, where (service.CommandOrigin)
}

func noteRestore(c *config.Config, file string, records int, forced bool, command string) {
	b, _ := json.Marshal(restoreNote{At: time.Now().UTC(), File: file, Records: records, Forced: forced,
		Origin: service.CommandOrigin(command)})
	_ = os.WriteFile(filepath.Join(c.Server.DataDir, restoreAuditFile), b, 0o600)
}

// auditRestore writes a noted restore to the audit log once this node may write, then removes the note.
func (a *App) auditRestore(ctx context.Context) {
	path := filepath.Join(a.Cfg.Server.DataDir, restoreAuditFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var n restoreNote
	if json.Unmarshal(b, &n) != nil {
		_ = os.Remove(path)
		return
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for !a.Node.Writable() {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
	org := model.PrimaryOrgID
	if o, err := a.Svc.PrimaryOrg(ctx); err == nil {
		org = o.ID
	}
	detail := map[string]string{"file": n.File, "records": strconv.Itoa(n.Records), "at": n.At.Format(time.RFC3339),
		"node": a.Node.ID()}
	if n.Forced {
		detail["forced"] = "true"
	}
	for k, v := range n.Origin {
		detail[k] = v
	}
	actor := "cli:" + n.Origin["os_user"] + "@" + n.Origin["host"]
	a.Svc.Audit(ctx, &service.Actor{Name: actor, Role: model.RoleSuperAdmin, Unscoped: true}, org, "backup.restore", "store", detail)
	_ = os.Remove(path)
}
