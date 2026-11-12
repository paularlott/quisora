package web

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

// orgPicture serves a user's profile picture, GET (and HEAD) /o/{org}/pictures/{id}, to anyone: applications show it in
// an <img> on their own pages, so it carries no session and is read from any origin. Its random id is what keeps it
// from those who were not given it; a picture that is not a user's current one, or not of the organization the path
// names (by id or by name), is not found, nor is any while the organization's pictures are off. A new picture is a new
// id, so each is cached for good.
func (s *Server) orgPicture(w http.ResponseWriter, r *http.Request) {
	o := Org(r)
	if !s.Svc.PicturesOn(o) {
		http.NotFound(w, r)
		return
	}
	p, err := s.Svc.ServedPicture(r.Context(), o.ID, r.PathValue("id"))
	if errors.Is(err, service.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", p.Type)
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	h.Set("ETag", `"`+p.ID+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(p.Data)) // answers HEAD, If-None-Match and ranges
}
