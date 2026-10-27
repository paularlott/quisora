package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Service errors become a status and a message fit to show; the text of an unexpected error never reaches the caller.
func TestWriteErrorMapsServiceErrors(t *testing.T) {
	wrap := func(e error) error { return fmt.Errorf("context: %w", e) }
	check := func(t *testing.T, rec *httptest.ResponseRecorder, status int, msg, field string) {
		t.Helper()
		if rec.Code != status {
			t.Fatalf("status %d, want %d (%s)", rec.Code, status, rec.Body)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("headers %v", rec.Header())
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"error":"`+msg) {
			t.Fatalf("body %s, want %q", body, msg)
		}
		if field != "" && !strings.Contains(body, `"field":"`+field+`"`) {
			t.Fatalf("body %s lacks field", body)
		}
	}
	for name, tc := range map[string]struct {
		err    error
		status int
		msg    string
		field  string
	}{
		"field error":      {&service.FieldError{Field: "email", Msg: "is not valid"}, 422, "is not valid", "email"},
		"forbidden":        {wrap(service.ErrForbidden), 403, "You do not have permission to do that.", ""},
		"not found":        {service.ErrNotFound, 404, "Not found.", ""},
		"conflict":         {wrap(service.ErrConflict), 409, "That already exists.", ""},
		"stale":            {service.ErrStale, 409, "Someone else changed this. Reload and try again.", ""},
		"not empty":        {service.ErrNotEmpty, 409, "Organization still has users.", ""},
		"outcome unknown":  {service.ErrOutcomeUnknown, 503, "This server lost contact", ""},
		"raw unconfirmed":  {wrap(store.ErrUnconfirmed), 503, "This server lost contact", ""},
		"raw not writable": {wrap(store.ErrUnavailable), 503, "This server cannot make changes right now", ""},
		"unavailable":      {service.ErrUnavailable, 503, "This server cannot make changes right now", ""},
		"unknown error":    {errors.New("secret detail: db password is hunter2"), 500, "Something went wrong. Please try again.", ""},
		"too large":        {service.ErrTooLarge, 413, "A change may add or remove at most", ""},
		"invalid":          {service.ErrInvalid, 422, "Invalid", ""},
		"primary org":      {service.ErrPrimaryOrg, 409, "The primary organization cannot be deleted.", ""},
		"tenant in use":    {service.ErrTenantInUse, 409, "The tenant still has clients.", ""},
		"wrapped not-null": {wrap(wrap(service.ErrNotFound)), 404, "Not found.", ""},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteError(rec, tc.err)
			check(t, rec, tc.status, tc.msg, tc.field)
			if strings.Contains(rec.Body.String(), "hunter2") {
				t.Fatalf("internal error text leaked: %s", rec.Body)
			}
			if tc.status == 503 && rec.Header().Get("Retry-After") == "" {
				t.Fatal("no Retry-After")
			}
		})
	}
	// A change that needs a recent re-authentication is refused with the field the pages turn into the dialog.
	t.Run("reauth", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteReauth(rec)
		check(t, rec, 403, "Confirm it is you", "reauth")
	})
}

func TestDecodeJSON(t *testing.T) {
	type body struct {
		A string `json:"a"`
	}
	run := func(payload string) (body, int, bool) {
		rec := httptest.NewRecorder()
		var b body
		ok := DecodeJSON(rec, httptest.NewRequest("POST", "/", strings.NewReader(payload)), &b)
		return b, rec.Code, ok
	}
	if b, _, ok := run(`{"a":"x"}`); !ok || b.A != "x" {
		t.Fatalf("valid body: %+v %v", b, ok)
	}
	for name, payload := range map[string]string{
		"unknown field": `{"a":"x","b":1}`,
		"not json":      `nope`,
		"empty":         ``,
		"wrong type":    `{"a":5}`,
	} {
		if _, code, ok := run(payload); ok || code != http.StatusBadRequest {
			t.Errorf("%s: ok=%v code=%d", name, ok, code)
		}
	}
	// a body over the limit is refused as too large (413), not as unreadable
	if _, code, ok := run(`{"a":"` + strings.Repeat("x", MaxJSONBody) + `"}`); ok || code != http.StatusRequestEntityTooLarge {
		t.Errorf("too large: ok=%v code=%d", ok, code)
	}
}

// http.ErrAbortHandler is how a handler aborts a response on purpose: it must reach net/http.
func TestRecovererRepanicsAbortHandler(t *testing.T) {
	h := recoverer(logger.NewNullLogger(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Fatalf("recovered %v", v)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	t.Fatal("no panic")
}
