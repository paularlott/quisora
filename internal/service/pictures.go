package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/picture"
	"github.com/paularlott/quisora/internal/store"
)

// Users' profile pictures (model.UserPicture). A picture is made by package picture from an image given as a data: URI
// (the account page, the management API, SCIM) or fetched once from an https URL (SCIM, a sign-in provider), and served
// at its own random address, /o/<org id>/pictures/<id>, to anyone who has it: applications show it in an <img>. A
// change makes a new record with a new id, points the user at it, then removes the old one; the user record decides
// which picture is theirs, so a picture it does not name (a failure part-way) is served to nobody and swept.

// PictureChangesPerHour bounds the changes of one user's picture, from wherever they come: each stores a new image.
const PictureChangesPerHour = 20

// pictureRateNS is the namespace of the picture change counters (Counters).
const pictureRateNS = "picture.rate"

// pictureTypes are the image types a picture may be given as.
var pictureTypes = []string{"image/jpeg", "image/png", "image/webp"}

// ErrPictureRate refuses a picture change past PictureChangesPerHour.
var ErrPictureRate = fmt.Errorf("%w: the picture was changed too often; try again in an hour", ErrLimit)

// PictureImage is a picture made (package picture) and ready to store.
type PictureImage struct {
	Data []byte
	Type string // image/jpeg or image/png
	// Source names what it was made from (model.UserPicture.Source).
	Source string
}

// MakePicture makes a picture of raw, an image as it was given, made from source (PictureImage.Source); a refusal is
// Invalid("image", ...).
func MakePicture(raw []byte, source string) (*PictureImage, error) {
	data, typ, err := picture.Process(raw)
	if err != nil {
		return nil, Invalid("image", err.Error())
	}
	return &PictureImage{Data: data, Type: typ, Source: source}, nil
}

// HashSource is the Source of a picture made from an image given as bytes ("sha256:" and their hash).
func HashSource(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// DataURIImage decodes an image given as a data: URI of a JPEG, PNG or WebP image (data:image/png;base64,...), of at
// most picture.MaxBytes. A refusal is Invalid("image", ...).
func DataURIImage(uri string) ([]byte, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(uri), "data:")
	typ, data, ok2 := strings.Cut(rest, ";base64,")
	if !ok || !ok2 {
		return nil, Invalid("image", "give the image as a data: URI (data:image/jpeg;base64,...)")
	}
	if !slices.Contains(pictureTypes, strings.ToLower(typ)) {
		return nil, Invalid("image", "use a JPEG, PNG or WebP image")
	}
	if base64.StdEncoding.DecodedLen(len(data)) > picture.MaxBytes+3 {
		return nil, Invalid("image", picture.ErrTooLarge.Error())
	}
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, Invalid("image", "the image is not valid base64")
	}
	return b, nil
}

// PictureFromDataURI makes a picture of an image given as a data: URI (DataURIImage).
func PictureFromDataURI(uri string) (*PictureImage, error) {
	raw, err := DataURIImage(uri)
	if err != nil {
		return nil, err
	}
	return MakePicture(raw, HashSource(raw))
}

// pictureFetchTimeout bounds the fetch of a picture from a URL.
const pictureFetchTimeout = 15 * time.Second

// FetchPicture makes a picture of the image at rawURL, an https URL, fetched once through PictureClient (the guarded
// outbound client: no private address unless the server allows it, no redirect, at most picture.MaxBytes). A refusal is
// Invalid("image", ...), saying why.
func (s *Service) FetchPicture(ctx context.Context, rawURL string) (*PictureImage, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, Invalid("image", "give the picture as an https URL or a data: URI")
	}
	if s.PictureClient == nil {
		return nil, Invalid("image", "this server does not fetch pictures")
	}
	ctx, cancel := context.WithTimeout(ctx, pictureFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, Invalid("image", "give the picture as an https URL or a data: URI")
	}
	req.Header.Set("Accept", "image/jpeg, image/png, image/webp")
	req.Header.Set("User-Agent", "quisora")
	resp, err := s.PictureClient.Do(req)
	if err != nil {
		return nil, Invalid("image", "the picture could not be fetched: "+err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, Invalid("image", fmt.Sprintf("the picture could not be fetched: its server answered %d", resp.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, picture.MaxBytes+1))
	if err != nil {
		return nil, Invalid("image", "the picture could not be fetched: "+err.Error())
	}
	return MakePicture(raw, rawURL)
}

// PictureURL is the absolute URL of u's picture, "" when u has none.
func (s *Service) PictureURL(u *model.User) string {
	if u == nil || u.Picture == "" {
		return ""
	}
	return strings.TrimSuffix(s.Cfg.Server.PublicURL, "/") + model.OrgPath(u.OrgID, "/pictures/"+u.Picture)
}

// ServedPicture returns picture id of organization orgID to serve: ErrNotFound unless it is there, of that
// organization, and the current picture of a user who is there.
func (s *Service) ServedPicture(ctx context.Context, orgID, id string) (*model.UserPicture, error) {
	if !model.IsID(id) {
		return nil, ErrNotFound
	}
	p, err := s.Pictures.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	if p.OrgID != orgID {
		return nil, ErrNotFound
	}
	u, err := s.Users.GetIn(ctx, orgID, p.UserID)
	if err != nil {
		return nil, mapStore(err)
	}
	if u.OrgID != orgID || u.Picture != p.ID {
		return nil, ErrNotFound
	}
	return p, nil
}

// SamePicture reports whether u's picture was made from source (PictureImage.Source): a directory sending it again
// changes nothing. A picture that cannot be read is not the same.
func (s *Service) SamePicture(ctx context.Context, u *model.User, source string) bool {
	if u.Picture == "" || source == "" {
		return false
	}
	p, err := s.Pictures.Get(ctx, u.Picture)
	return err == nil && p.Source == source
}

// MaySetPicture reports whether a may set or remove u's picture (maySetPicture), for pages deciding what to show.
func (s *Service) MaySetPicture(ctx context.Context, a *Actor, u *model.User) bool {
	return s.maySetPicture(ctx, a, u) == nil
}

// maySetPicture is who may set or remove u's picture: whoever may manage u (managers and above, service accounts,
// the directory), and u themselves unless their organization has its administrators set pictures.
func (s *Service) maySetPicture(ctx context.Context, a *Actor, u *model.User) error {
	if s.canManageUser(a, u) {
		return nil
	}
	if a.UserID != u.ID {
		return s.denied(a, u)
	}
	o, err := s.Orgs.Get(ctx, u.OrgID)
	if err != nil {
		return mapStore(err)
	}
	if o.Settings.PicturesByAdmins {
		return ErrForbidden
	}
	return nil
}

// pictureRate counts a change of user userID's picture and refuses one past PictureChangesPerHour. A counter that
// cannot be read refuses the change: it is not a verdict either way, and the change can wait.
func (s *Service) pictureRate(ctx context.Context, userID string) error {
	if s.Counters == nil {
		return nil
	}
	n, err := s.Counters.Incr(ctx, pictureRateNS, userID, 1, time.Hour)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if n > PictureChangesPerHour {
		return ErrPictureRate
	}
	return nil
}

// SetPicture gives user userID the picture newPicture makes, or removes theirs (newPicture nil), as a: see maySetPicture. A change
// counts against PictureChangesPerHour before the picture is made, so a refusal costs nothing. Audited as
// user.picture.set or user.picture.remove. It returns the user as written.
func (s *Service) SetPicture(ctx context.Context, a *Actor, userID string, newPicture func() (*PictureImage, error)) (*model.User, error) {
	return s.setPicture(ctx, a, userID, newPicture, false)
}

// setPicture is SetPicture; keep (a copy made by the system: CopyPicture) changes nothing when the user has a picture
// as the write finds them, and is neither checked nor counted.
func (s *Service) setPicture(ctx context.Context, a *Actor, userID string, newPicture func() (*PictureImage, error), keep bool) (*model.User, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	if !keep {
		if err := s.maySetPicture(ctx, a, u); err != nil {
			return nil, err
		}
	}
	var rec *model.UserPicture
	action := "user.picture.remove"
	if newPicture != nil {
		if !keep {
			if err := s.pictureRate(ctx, u.ID); err != nil {
				return nil, err
			}
		}
		img, err := newPicture()
		if err != nil {
			return nil, err
		}
		rec = &model.UserPicture{Meta: model.Meta{ID: model.NewRandomID()}, OrgID: u.OrgID, UserID: u.ID, Type: img.Type,
			Data: img.Data, Source: img.Source}
		if err := s.Pictures.Create(ctx, rec); err != nil {
			return nil, mapStore(err)
		}
		action = "user.picture.set"
	} else if u.Picture == "" {
		return u, nil // none to remove
	}
	// The user is written as read (a compare-and-swap), so a change made meanwhile is never undone: read again, and
	// checked again, it is tried a few times.
	for attempt := 0; ; attempt++ {
		if keep && u.Picture != "" {
			s.dropPicture(ctx, rec.ID)
			return u, nil
		}
		old := u.Picture
		u.Picture = ""
		if rec != nil {
			u.Picture = rec.ID
		}
		err = s.AuditedUser(ctx, a, u, action, nil, func() error { return s.Users.Update(ctx, u) })
		if err == nil {
			s.dropPicture(ctx, old)
			return u, nil
		}
		if !errors.Is(err, store.ErrStale) || attempt == 2 {
			break
		}
		if u, err = s.Users.Get(ctx, userID); err != nil {
			break
		}
		if !keep {
			if err = s.maySetPicture(ctx, a, u); err != nil {
				break
			}
		}
	}
	if rec != nil && !outcomeUnknown(err) { // a write that may have landed may name it
		s.dropPicture(ctx, rec.ID)
	}
	return nil, mapStore(err)
}

// dropPicture removes picture id ("": none), which no user names: tidying, which the orphan sweep does when it fails.
func (s *Service) dropPicture(ctx context.Context, id string) {
	if id == "" {
		return
	}
	if err := s.Pictures.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.Log.Warn("removing a picture no user names (the sweep removes it later)", "picture", id, "error", err)
	}
}

// CopyPicture gives user userID, an account a sign-in provider (by: "provider:<name>") just created or linked, the
// picture the provider has for them at rawURL, when they have none: fetched once, in the background, and stored like
// any other (never shown from the provider's address). A failure is logged and changes nothing; a picture the user
// or an administrator set is never replaced.
func (s *Service) CopyPicture(ctx context.Context, userID, rawURL, by string) {
	if rawURL == "" {
		return
	}
	s.Background(ctx, 2*pictureFetchTimeout, func(ctx context.Context) {
		u, err := s.Users.Get(ctx, userID)
		if err != nil || u.Picture != "" {
			return
		}
		a := &Actor{OrgID: u.OrgID, Role: model.RoleManager, Name: by}
		_, err = s.setPicture(ctx, a, userID, func() (*PictureImage, error) { return s.FetchPicture(ctx, rawURL) }, true)
		if err != nil {
			s.Log.Info("the picture of a sign-in provider's account was not copied", "user", userID, "by", by, "error", err)
		}
	})
}
