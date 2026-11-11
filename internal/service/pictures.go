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
// which picture is theirs, so a picture it does not name (a failure part-way) is served to nobody and swept. Every
// change goes one way: checked before the image is made (PictureAllowed), then written as a change of the user
// (UserInput.Picture, UpdateUser or CreateUserLinked), in the one write of the user.

// PictureChangesPerHour bounds the changes of one user's picture, from wherever they come: each stores a new image.
const PictureChangesPerHour = 20

// pictureRateNS is the namespace of the picture change counters (Counters).
const pictureRateNS = "picture.rate"

// pictureTypes are the image types a picture may be given as.
var pictureTypes = []string{"image/jpeg", "image/png", "image/webp"}

// ErrPictureRate refuses a picture change past PictureChangesPerHour.
var ErrPictureRate = fmt.Errorf("%w: the picture was changed too often; try again in an hour", ErrLimit)

// ErrPictureBusy refuses a picture this server has no turn for now (picture.ErrBusy): try again in a few seconds.
var ErrPictureBusy = fmt.Errorf("%w: it is making other pictures; try again in a few seconds", ErrBusy)

// ErrPicturesOff refuses a picture change in an organization whose profile pictures are off (OrgSettings.Pictures).
var ErrPicturesOff = fmt.Errorf("%w: profile pictures are turned off in this organization", ErrForbidden)

// PictureChange changes a user's picture with the rest of a change of the user (UserInput.Picture): to the picture
// Image (made beforehand: MakePicture), or to none (Image nil).
type PictureChange struct {
	Image *PictureImage
}

// PictureImage is a picture made (package picture) and ready to store.
type PictureImage struct {
	Data []byte
	Type string // image/jpeg or image/png
	// Source names what it was made from (model.UserPicture.Source).
	Source string
}

// MakePicture makes a picture of raw, an image as it was given, made from source (PictureImage.Source); a refusal is
// Invalid("image", ...). Waiting for its turn (picture.Process) is refused at once with ErrPictureBusy when too many
// wait, and ends with ctx: ErrPictureBusy too when its deadline passed (a fetch's), else ctx.Err() (the caller left).
func MakePicture(ctx context.Context, raw []byte, source string) (*PictureImage, error) {
	data, typ, err := picture.Process(ctx, raw)
	switch {
	case errors.Is(err, picture.ErrBusy), errors.Is(err, context.DeadlineExceeded):
		return nil, ErrPictureBusy
	case errors.Is(err, context.Canceled):
		return nil, err
	case err != nil:
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
func PictureFromDataURI(ctx context.Context, uri string) (*PictureImage, error) {
	raw, err := DataURIImage(uri)
	if err != nil {
		return nil, err
	}
	return MakePicture(ctx, raw, HashSource(raw))
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
	return MakePicture(ctx, raw, rawURL)
}

// PictureURL is the absolute URL of u's picture, "" when u has none or their organization's pictures are off (as
// read within orgTTL: Org) or cannot be read.
func (s *Service) PictureURL(ctx context.Context, u *model.User) string {
	if u == nil || u.Picture == "" {
		return ""
	}
	if o, err := s.Org(ctx, u.OrgID); err != nil || !o.Settings.PicturesOn() {
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

// MaySetPicture reports whether a may set or remove u's picture at all (pictureRule; nothing is counted), for pages
// deciding what to show.
func (s *Service) MaySetPicture(ctx context.Context, a *Actor, u *model.User) bool {
	return s.pictureRule(ctx, a, u) == nil
}

// pictureRule is who may change u's picture, by the organization's setting (OrgSettings.Pictures, as stored now):
// nobody while its pictures are off (ErrPicturesOff); else whoever may manage u (managers and above, service accounts,
// the directory, the system), and u themselves unless the organization has its administrators set pictures.
func (s *Service) pictureRule(ctx context.Context, a *Actor, u *model.User) error {
	o, err := s.Orgs.Get(ctx, u.OrgID)
	if err != nil {
		return mapStore(err)
	}
	switch {
	case !o.Settings.PicturesOn():
		return ErrPicturesOff
	case s.canManageUser(a, u):
		return nil
	case a.UserID != u.ID:
		return s.denied(a, u)
	case o.Settings.Pictures == model.PicturesAdmins:
		return ErrForbidden
	}
	return nil
}

// PictureAllowed checks a change of u's picture by a before its image is decoded or fetched, so a refusal costs
// nothing: pictureRule, and for a new picture (set) the hourly limit, counted here, once for each attempt (one whose
// image then fails counts too, so nobody keeps the decoder busy past it): past PictureChangesPerHour it is refused
// (ErrPictureRate), and a counter that cannot be read refuses it too (ErrUnavailable: not a verdict either way, and
// the change can wait). Removing a picture is not counted. The change itself (UpdateUser) checks pictureRule again.
func (s *Service) PictureAllowed(ctx context.Context, a *Actor, u *model.User, set bool) error {
	if err := s.pictureRule(ctx, a, u); err != nil {
		return err
	}
	if !set || s.Counters == nil {
		return nil
	}
	n, err := s.Counters.Incr(ctx, pictureRateNS, u.ID, 1, time.Hour)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if n > PictureChangesPerHour {
		return ErrPictureRate
	}
	return nil
}

// SetPicture gives user userID the picture of image, a data: URI (DataURIImage), or removes theirs (image nil), as a:
// checked before the image is made (PictureAllowed), then written as any change of the user is (UserInput.Picture,
// UpdateUser). A change of the picture alone loses nobody's edit, so a user changed meanwhile is read again and the
// change tried again (a few times), with the image already made. It returns the user as written.
func (s *Service) SetPicture(ctx context.Context, a *Actor, userID string, image *string) (*model.User, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	if err := s.PictureAllowed(ctx, a, u, image != nil); err != nil {
		return nil, err
	}
	pc := &PictureChange{}
	if image != nil {
		if pc.Image, err = PictureFromDataURI(ctx, *image); err != nil {
			return nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		u, err = s.UpdateUser(ctx, a, userID, UserInput{Picture: pc})
		if attempt == 2 || !errors.Is(err, ErrStale) && !errors.Is(err, store.ErrStale) {
			return u, err
		}
	}
}

// storePicture stores img as a new picture of u, which no user names yet: the user's write that names it comes next,
// and one that fails leaves it to dropPicture (or to the orphan sweep).
func (s *Service) storePicture(ctx context.Context, u *model.User, img *PictureImage) (*model.UserPicture, error) {
	rec := &model.UserPicture{Meta: model.Meta{ID: model.NewRandomID()}, OrgID: u.OrgID, UserID: u.ID, Type: img.Type,
		Data: img.Data, Source: img.Source}
	if err := s.Pictures.Create(ctx, rec); err != nil {
		return nil, mapStore(err)
	}
	return rec, nil
}

// pictureInput checks in.Picture, the change of u's picture that comes with a change of u (as a: pictureRule), and
// stores the picture it sets (storePicture), pointing u at it, or points u at none: the caller's one write of u then
// makes the change with the rest, and pictureWritten finishes it. It returns the picture u named before and the one
// stored, and the change ("set" or "remove"); nothing when in.Picture is nil or changes nothing.
func (s *Service) pictureInput(ctx context.Context, a *Actor, u *model.User, in UserInput) (old, made, change string, err error) {
	pc := in.Picture
	if pc == nil || pc.Image == nil && u.Picture == "" {
		return "", "", "", nil
	}
	if err := s.pictureRule(ctx, a, u); err != nil {
		return "", "", "", err
	}
	old, change = u.Picture, "remove"
	u.Picture = ""
	if pc.Image != nil {
		rec, err := s.storePicture(ctx, u, pc.Image)
		if err != nil {
			u.Picture = old
			return "", "", "", err
		}
		u.Picture, made, change = rec.ID, rec.ID, "set"
	}
	return old, made, change, nil
}

// pictureWritten finishes a change of a user's picture (pictureInput) once the user's write ended with err: done, the
// picture it named before goes; refused, the new one goes (unless the write may have landed: it may name it).
func (s *Service) pictureWritten(ctx context.Context, old, made string, err error) {
	switch {
	case err == nil:
		s.dropPicture(ctx, old)
	case !outcomeUnknown(err):
		s.dropPicture(ctx, made)
	}
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
// picture the provider has for them at rawURL, when they have none: fetched once, in the background, and written as
// any change of the user is (UpdateUser, by the system under the name by), to the user only as read without one. A
// failure is logged and changes nothing; a picture the user or an administrator set is never replaced.
func (s *Service) CopyPicture(ctx context.Context, userID, rawURL, by string) {
	if rawURL == "" {
		return
	}
	s.Background(ctx, 2*pictureFetchTimeout, func(ctx context.Context) {
		u, err := s.Users.Get(ctx, userID)
		if err != nil || u.Picture != "" {
			return
		}
		if o, err := s.Orgs.Get(ctx, u.OrgID); err != nil || !o.Settings.PicturesOn() {
			return // the organization's pictures are off: none is fetched
		}
		sys := *System
		sys.Name = by
		if err := s.PictureAllowed(ctx, &sys, u, true); err != nil { // counted, once for the account
			s.Log.Info("the picture of a sign-in provider's account was not copied", "user", userID, "by", by, "error", err)
			return
		}
		img, err := s.FetchPicture(ctx, rawURL)
		// Written only to the user as read without a picture (IfVersion): one changed meanwhile is read again.
		for attempt := 0; err == nil && attempt < 3; attempt++ {
			_, err = s.UpdateUser(ctx, &sys, userID, UserInput{Picture: &PictureChange{Image: img}, IfVersion: u.Version})
			if !errors.Is(err, ErrStale) && !errors.Is(err, store.ErrStale) {
				break
			}
			if u, err = s.Users.Get(ctx, userID); err != nil || u.Picture != "" {
				return
			}
		}
		if err != nil {
			s.Log.Info("the picture of a sign-in provider's account was not copied", "user", userID, "by", by, "error", err)
		}
	})
}
