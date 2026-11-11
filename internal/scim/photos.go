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
// or WebP image, which the server makes into its own picture (service.SetPicture). The picture's own URL sent back
// changes nothing, nor does the URL or image it was made from; photos left out of a PUT leave the picture as it is,
// and photos present without a value (null, [], or removed by a PATCH) remove it.

// photosValue renders u's picture as the photos attribute; nil when u has none.
func (rq *request) photosValue(u *model.User) []any {
	url := rq.m.srv.Svc.PictureURL(u)
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

// photoChange is a change of a user's picture asked for by photos: remove it (make nil), or set the one make makes.
type photoChange struct {
	make func() (*service.PictureImage, error)
}

// photoChange works out what res's photos ask of u's picture (u nil: a user being created); nil asks nothing. The
// value is the primary (else first) one other than the picture's own URL; an image given in it is decoded here, and
// fetched or made only when the change is made. A value that is neither an https URL nor a data: URI is refused.
func (rq *request) photoChange(res map[string]any, u *model.User) (*photoChange, *Error) {
	k, present := keyOf(res, "photos")
	if !present {
		return nil, nil
	}
	cur := rq.m.srv.Svc.PictureURL(u)
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
			return &photoChange{}, nil // removed
		}
		return nil, nil
	}
	var pc photoChange
	source := val
	switch {
	case strings.HasPrefix(val, "data:"):
		raw, err := service.DataURIImage(val)
		if err != nil {
			return nil, photoError(err).(*Error)
		}
		source = service.HashSource(raw)
		pc.make = func() (*service.PictureImage, error) {
			img, err := service.MakePicture(raw, source)
			return img, photoError(err)
		}
	case strings.HasPrefix(strings.ToLower(val), "https://"):
		pc.make = func() (*service.PictureImage, error) {
			img, err := rq.m.srv.Svc.FetchPicture(rq.ctx, val)
			return img, photoError(err)
		}
	default:
		return nil, badValue("photos: give the picture as an https URL or a data: URI of a JPEG, PNG or WebP image")
	}
	if u != nil && rq.m.srv.Svc.SamePicture(rq.ctx, u, source) {
		return nil, nil // made from this already
	}
	return &pc, nil
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
