package admin

import (
	"net/http"
	"sort"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// keyView is a signing key's public metadata and its state: "signing" (the key that signs for its algorithm now),
// "next" (published, signing from not_before) or "previous" (no longer signing, published until expires so the
// tokens it signed still verify).
type keyView struct {
	*model.SigningKey
	State string `json:"state"`
}

// listKeys lists the signing keys (public metadata only), newest first. Super admins only.
func (m *Module) listKeys(w http.ResponseWriter, r *http.Request) {
	if !web.Actor(r).IsSuper() {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	keys, _, err := m.s.Svc.Keys.List(r.Context(), store.ListQuery{})
	if err != nil {
		web.WriteError(w, err)
		return
	}
	now := time.Now()
	// The signer of an algorithm is chosen as the token code chooses it: the newest key that has started and not
	// retired, else the newest that has started.
	sort.Slice(keys, func(i, j int) bool {
		if c := keys[i].NotBefore.Compare(keys[j].NotBefore); c != 0 {
			return c < 0
		}
		return keys[i].Created.Before(keys[j].Created)
	})
	signer := map[string]string{}
	fallback := map[string]string{}
	for _, k := range keys {
		if k.NotBefore.After(now) {
			continue
		}
		fallback[k.Alg] = k.ID
		if now.Before(k.RetireAt) {
			signer[k.Alg] = k.ID
		}
	}
	items := make([]keyView, 0, len(keys))
	for i := len(keys) - 1; i >= 0; i-- {
		k := keys[i]
		state := "previous"
		switch {
		case k.NotBefore.After(now):
			state = "next"
		case k.ID == signer[k.Alg] || signer[k.Alg] == "" && k.ID == fallback[k.Alg]:
			state = "signing"
		}
		items = append(items, keyView{SigningKey: k, State: state})
	}
	writeList(w, items, len(items))
}

// rotateKeys mints a new signing key now (the previous keys stay published until their tokens expire).
func (m *Module) rotateKeys(w http.ResponseWriter, r *http.Request) {
	a := web.Actor(r)
	if !a.IsSuper() {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	if m.RotateKeys == nil {
		web.WriteJSON(w, http.StatusNotImplemented, web.ErrorBody{Error: "Key rotation is not available."})
		return
	}
	if err := m.RotateKeys(r.Context()); err != nil {
		web.WriteError(w, err)
		return
	}
	m.s.Svc.Audit(r.Context(), a, a.OrgID, "keys.rotate", "signing keys", nil)
	web.WriteJSON(w, http.StatusOK, map[string]bool{"rotated": true})
}

// clusterStatus reports this node's cluster status (GET /api/v1/cluster). Super admins only.
func (m *Module) clusterStatus(w http.ResponseWriter, r *http.Request) {
	if !web.Actor(r).IsSuper() {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	if m.ClusterStatus == nil {
		web.WriteJSON(w, http.StatusOK, map[string]bool{"standalone": true})
		return
	}
	web.WriteJSON(w, http.StatusOK, m.ClusterStatus())
}

// masterKeyStatus reports where a master key rotation stands (service.RotationStatus). Super admins only.
func (m *Module) masterKeyStatus(w http.ResponseWriter, r *http.Request) {
	if !web.Actor(r).IsSuper() {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	st, err := m.s.Svc.RotationStatus(r.Context())
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, st)
}
