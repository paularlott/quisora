package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// MaxJSONBody limits request bodies decoded by DecodeJSON.
const MaxJSONBody = 1 << 20

// WriteJSON writes v as JSON with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ErrorBody is the JSON error shape of the UI API: {"error": "...", "field": "..."}.
type ErrorBody struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

// WriteError maps service errors to HTTP statuses and writes an ErrorBody.
func WriteError(w http.ResponseWriter, err error) {
	var fe *service.FieldError
	switch {
	case errors.As(err, &fe):
		status := http.StatusUnprocessableEntity
		if errors.Is(err, service.ErrConflict) {
			status = http.StatusConflict
		}
		WriteJSON(w, status, ErrorBody{Error: fe.Msg, Field: fe.Field})
	case errors.Is(err, service.ErrForbidden):
		noteDenied(w) // audited by RequireManagement
		WriteJSON(w, http.StatusForbidden, ErrorBody{Error: "You do not have permission to do that."})
	case errors.Is(err, service.ErrNotFound):
		WriteJSON(w, http.StatusNotFound, ErrorBody{Error: "Not found."})
	case errors.Is(err, service.ErrConflict):
		WriteJSON(w, http.StatusConflict, ErrorBody{Error: "That already exists."})
	case errors.Is(err, service.ErrStale), errors.Is(err, store.ErrStale): // (a raw store error too)
		WriteJSON(w, http.StatusConflict, ErrorBody{Error: "Someone else changed this. Reload and try again."})
	case errors.Is(err, service.ErrTooLarge):
		WriteJSON(w, http.StatusRequestEntityTooLarge, ErrorBody{Error: Capitalise(err.Error()) + "."})
	case errors.Is(err, service.ErrNotEmpty), errors.Is(err, service.ErrPrimaryOrg),
		errors.Is(err, service.ErrTenantInUse):
		WriteJSON(w, http.StatusConflict, ErrorBody{Error: Capitalise(err.Error()) + "."})
	case errors.Is(err, service.ErrOutcomeUnknown), errors.Is(err, store.ErrUnconfirmed): // (a raw store error too)
		w.Header().Set("Retry-After", "5")
		WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "This server lost contact with the part of the cluster that decides this change before it answered, so the change may or may not have been made. Check, then try again."})
	case service.IsUnavailable(err):
		w.Header().Set("Retry-After", "5")
		WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "This server cannot make changes right now (it cannot reach enough of its cluster). Nothing was changed; please try again shortly."})
	case errors.Is(err, service.ErrInvalid):
		WriteJSON(w, http.StatusUnprocessableEntity, ErrorBody{Error: Capitalise(err.Error())})
	default:
		WriteJSON(w, http.StatusInternalServerError, ErrorBody{Error: "Something went wrong. Please try again."})
	}
}

// Capitalise upper-cases the first letter of an error message (Go error strings start lower-case) for showing it.
func Capitalise(s string) string {
	if s == "" {
		return s
	}
	if s[0] >= 'a' && s[0] <= 'z' {
		return string(s[0]-32) + s[1:]
	}
	return s
}

// DecodeJSON decodes a size-limited JSON body into v, rejecting unknown fields.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			WriteJSON(w, http.StatusRequestEntityTooLarge, ErrorBody{Error: "The request is too large."})
			return false
		}
		WriteJSON(w, http.StatusBadRequest, ErrorBody{Error: "The request could not be read."})
		return false
	}
	return true
}

// WriteReauth answers 403 {"field":"reauth"}: the change needs a recent re-authentication. Pages turn it into the
// "Confirm it is you" dialog and retry.
func WriteReauth(w http.ResponseWriter) {
	WriteJSON(w, http.StatusForbidden, ErrorBody{Error: "Confirm it is you with your password or a passkey first.", Field: "reauth"})
}
