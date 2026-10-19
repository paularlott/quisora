package admin

import (
	"context"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// backupRunning allows one backup per node at a time: each one reads the whole store.
var backupRunning atomic.Bool

// downloadBackup streams a backup of the whole store (GET /api/v1/backup; super admins only; ?encrypt=1 encrypts
// it with a key derived from the master key). It reads a point-in-time view of the store where the backend has one
// (otherwise the live store page by page) while the server keeps serving; see package backup.
func (m *Module) downloadBackup(w http.ResponseWriter, r *http.Request) {
	a := web.Actor(r)
	if !a.IsSuper() {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	// A node that is catching up, resynchronising or cut off would back up a partial or stale store.
	if h := m.s.Health; h != nil {
		if ok, why := h.Ready(); !ok {
			w.Header().Set("Retry-After", "10")
			web.WriteJSON(w, http.StatusServiceUnavailable, web.ErrorBody{Error: "This server is not ready (" + why + "); back up through another one."})
			return
		}
	}
	if !backupRunning.CompareAndSwap(false, true) {
		w.Header().Set("Retry-After", "30")
		web.WriteJSON(w, http.StatusConflict, web.ErrorBody{Error: "A backup is already running on this server."})
		return
	}
	defer backupRunning.Store(false)
	// A large store takes longer than the server's write timeout; this response has none.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	name := "quisora-" + time.Now().UTC().Format("20060102-150405") + ".bak"
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	enc := r.URL.Query().Get("encrypt")
	if enc == "1" || enc == "true" {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	stats, err := backup.WriteWith(r.Context(), m.s.Svc.Store, m.s.Svc.Sealer, w,
		backup.Options{Encrypt: enc == "1" || enc == "true"})
	detail := map[string]string{"records": strconv.Itoa(stats.Total()), "complete": strconv.FormatBool(err == nil)}
	if err != nil {
		// The status line is gone by now; the client sees a stream without the trailer, which restore rejects.
		m.s.Log.Warn("backup not completed", "error", err)
		detail["error"] = err.Error()
	}
	// Recorded even when the download was abandoned (its request context is cancelled by then): whoever took part
	// of the store should show up in the audit log.
	m.s.Svc.Audit(context.WithoutCancel(r.Context()), a, a.OrgID, "backup.download", "store", detail)
}
