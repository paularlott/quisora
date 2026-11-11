package scim

import (
	"cmp"
	"errors"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A user's photos (RFC 7643 §4.1.2) are their profile picture: rendered as the URL the server serves it at, and set
// from a value that is an https URL (fetched once, through the guarded outbound client) or a data: URI of a JPEG, PNG
// or WebP image, which the server makes into its own picture before the user is changed, and writes with the rest of
// the change (service.UserInput.Picture): a refused image changes nothing. The picture's own URL sent back changes
// nothing, nor does the URL or image it was made from; photos left out of a PUT leave the picture as it is, and photos
// present without a value (null, [], or removed by a PATCH) remove it. In an organization whose pictures are off
// (model.OrgSettings.Pictures) photos are left out of every user, and ignored when written: a directory's sync goes on.

// photosValue renders u's picture as the photos attribute; nil when u has none.
func (rq *request) photosValue(u *model.User) []any {
	url := rq.m.srv.Svc.PictureURL(rq.ctx, u)
	if url == "" {
		return nil
	}
	return []any{map[string]any{"value": url, "type": "photo", "primary": true}}
}

// keepPhotos makes a patched user carry photos (null when the PATCH removed them), so that removing the attribute
// removes the picture while a PUT that does not mention it leaves it alone.
func keepPhotos(res map[string]any) {
	if _, ok := keyOf(res, "photos"); !ok {
		res["photos"] = nil
	}
}

// photoChange works out what res's photos ask of u's picture (u nil: a user being created), and makes the picture
// they set (fetched and made once a request: a retry of the change finds it made); nil asks nothing, as do photos
// in an organization whose pictures are off. The value is the primary (else first) one other than the picture's own
// URL. A value that is neither an https URL nor a data: URI, or an image that cannot be made, is refused.
func (rq *request) photoChange(res map[string]any, u *model.User) (*service.PictureChange, error) {
	k, present := keyOf(res, "photos")
	if !present || !rq.org.Settings.PicturesOn() {
		return nil, nil
	}
	cur := rq.m.srv.Svc.PictureURL(rq.ctx, u)
	var first, primary string
	for _, e := range asSlice(res[k]) {
		var val string
		isPrimary := false
		switch t := e.(type) {
		case string:
			val = t
		case map[string]any:
			s, _, err := str(t, "value")
			if err != nil {
				return nil, badValue("photos.value must be a string")
			}
			val = s
			if p := getCI(t, "primary"); p != nil {
				b, err := parseBool(p, "photos.primary")
				if err != nil {
					return nil, err
				}
				isPrimary = b
			}
		default:
			return nil, badValue("photos must be a list of objects")
		}
		if val = strings.TrimSpace(val); val == "" || val == cur {
			continue
		}
		first = cmp.Or(first, val)
		if isPrimary {
			primary = cmp.Or(primary, val)
		}
	}
	val := cmp.Or(primary, first)
	if val == "" {
		if cur != "" && !photosHave(res[k], cur) {
			return &service.PictureChange{}, nil // removed
		}
		return nil, nil
	}
	var raw []byte
	source := val
	switch {
	case strings.HasPrefix(val, "data:"):
		var err error
		if raw, err = service.DataURIImage(val); err != nil {
			return nil, photoError(err)
		}
		source = service.HashSource(raw)
	case strings.HasPrefix(strings.ToLower(val), "https://"):
	default:
		return nil, badValue("photos: give the picture as an https URL or a data: URI of a JPEG, PNG or WebP image")
	}
	if u != nil && rq.m.srv.Svc.SamePicture(rq.ctx, u, source) {
		return nil, nil // made from this already
	}
	if rq.made.img == nil || rq.made.source != source {
		var img *service.PictureImage
		var err error
		if raw != nil {
			img, err = service.MakePicture(rq.ctx, raw, source)
		} else {
			img, err = rq.m.srv.Svc.FetchPicture(rq.ctx, val)
		}
		if err != nil {
			return nil, photoError(err)
		}
		rq.made.source, rq.made.img = source, img
	}
	return &service.PictureChange{Image: rq.made.img}, nil
}

// photosHave reports whether photos v hold value url.
func photosHave(v any, url string) bool {
	for _, e := range asSlice(v) {
		if m, ok := e.(map[string]any); ok {
			if s, _, _ := str(m, "value"); strings.TrimSpace(s) == url {
				return true
			}
		} else if s, ok := e.(string); ok && strings.TrimSpace(s) == url {
			return true
		}
	}
	return false
}

// photoError is a refused picture as a SCIM error (invalidValue); other errors pass as they are.
func photoError(err error) error {
	var fe *service.FieldError
	if errors.As(err, &fe) {
		return badValue("photos: %s", fe.Msg)
	}
	return err
}
