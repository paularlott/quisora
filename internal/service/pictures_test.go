package service_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// testPNG is a small PNG of colour c.
func testPNG(t testing.TB, c color.NRGBA) []byte {
	t.Helper()
	m := image.NewNRGBA(image.Rect(0, 0, 12, 8))
	for y := range 8 {
		for x := range 12 {
			m.SetNRGBA(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func dataURI(b []byte) string { return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b) }

// fromURI is the picture maker of a data: URI, as the account page and the management API give it.
func fromURI(uri string) func() (*service.PictureImage, error) {
	return func() (*service.PictureImage, error) { return service.PictureFromDataURI(context.Background(), uri) }
}

// setPictures sets the organization's pictures setting (model.OrgSettings.Pictures).
func (e *env) setPictures(orgID string, v string) {
	e.t.Helper()
	o, err := e.svc.GetOrg(e.ctx, nil, orgID)
	if err != nil {
		e.t.Fatal(err)
	}
	st := o.Settings
	st.Pictures = v
	if _, err := e.svc.UpdateOrg(e.ctx, service.System, orgID, service.OrgInput{Settings: &st}); err != nil {
		e.t.Fatal(err)
	}
}

// served reports whether the picture with id is served for organization orgID.
func (e *env) served(orgID, id string) bool {
	_, err := e.svc.ServedPicture(e.ctx, orgID, id)
	if err != nil && !errors.Is(err, service.ErrNotFound) {
		e.t.Fatal(err)
	}
	return err == nil
}

// pictureStored reports whether the picture record id is there.
func (e *env) pictureStored(id string) bool {
	_, err := e.svc.Pictures.Get(e.ctx, id)
	return err == nil
}

func TestPictureSetReplaceRemove(t *testing.T) {
	e := newEnv(t)
	o := e.org("pics")
	u := e.user(o.ID, "pat", model.RoleUser)
	got, err := e.svc.SetPicture(e.ctx, actor(u), u.ID, fromURI(dataURI(testPNG(t, color.NRGBA{200, 10, 10, 255}))))
	if err != nil {
		t.Fatal(err)
	}
	first := got.Picture
	if !model.IsID(first) || e.fresh(u).Picture != first {
		t.Fatalf("picture id %q", first)
	}
	if want := e.svc.Cfg.Server.PublicURL + "/o/" + o.ID + "/pictures/" + first; e.svc.PictureURL(e.ctx, got) != want {
		t.Fatalf("URL %q, want %q", e.svc.PictureURL(e.ctx, got), want)
	}
	p, err := e.svc.ServedPicture(e.ctx, o.ID, first)
	if err != nil || p.Type != "image/png" && p.Type != "image/jpeg" || len(p.Data) == 0 || p.UserID != u.ID {
		t.Fatalf("served %+v, %v", p, err)
	}
	if e.served(e.primary.ID, first) {
		t.Fatal("served under another organization")
	}
	if len(e.audited(o.ID, "user.picture.set")) != 1 {
		t.Fatal("not audited")
	}

	// A new picture is a new record at a new address; the old one is gone.
	got, err = e.svc.SetPicture(e.ctx, actor(u), u.ID, fromURI(dataURI(testPNG(t, color.NRGBA{10, 200, 10, 255}))))
	if err != nil {
		t.Fatal(err)
	}
	if got.Picture == first || got.Picture == "" || e.pictureStored(first) || e.served(o.ID, first) || !e.served(o.ID, got.Picture) {
		t.Fatalf("replace: %q (old stored %v)", got.Picture, e.pictureStored(first))
	}

	second := got.Picture
	if got, err = e.svc.SetPicture(e.ctx, actor(u), u.ID, nil); err != nil || got.Picture != "" || e.svc.PictureURL(e.ctx, got) != "" {
		t.Fatalf("remove: %v %q", err, got.Picture)
	}
	if e.pictureStored(second) || e.served(o.ID, second) || len(e.audited(o.ID, "user.picture.remove")) != 1 {
		t.Fatal("the removed picture is still there")
	}

	// A refused image changes nothing and stores nothing.
	before, _, _ := e.svc.Pictures.List(e.ctx, store.ListQuery{})
	_, err = e.svc.SetPicture(e.ctx, actor(u), u.ID, fromURI("data:image/png;base64,"+base64.StdEncoding.EncodeToString([]byte("not an image"))))
	if fieldOf(err) != "image" {
		t.Fatalf("junk: %v", err)
	}
	if _, err = e.svc.SetPicture(e.ctx, actor(u), u.ID, fromURI("data:image/svg+xml;base64,PHN2Zy8+")); fieldOf(err) != "image" {
		t.Fatalf("svg: %v", err)
	}
	after, _, _ := e.svc.Pictures.List(e.ctx, store.ListQuery{})
	if len(after) != len(before) || e.fresh(u).Picture != "" {
		t.Fatal("a refused image left something behind")
	}
}

func TestPicturePermissions(t *testing.T) {
	e := newEnv(t)
	o := e.org("perm")
	user := e.user(o.ID, "user", model.RoleUser)
	other := e.user(o.ID, "other", model.RoleUser)
	mgr := e.user(o.ID, "mgr", model.RoleManager)
	adm := e.user(o.ID, "adm", model.RoleAdmin)
	img := fromURI(dataURI(testPNG(t, color.NRGBA{1, 2, 3, 255})))

	if _, err := e.svc.SetPicture(e.ctx, actor(user), other.ID, img); !errors.Is(err, service.ErrNotFound) && !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("a user set another's picture: %v", err)
	}
	if _, err := e.svc.SetPicture(e.ctx, actor(mgr), user.ID, img); err != nil {
		t.Fatalf("a manager sets a user's: %v", err)
	}
	if _, err := e.svc.SetPicture(e.ctx, actor(mgr), adm.ID, img); err == nil {
		t.Fatal("a manager set an administrator's picture")
	}
	// The super admin is hidden from the organization's administrators: not found, not forbidden.
	padm := e.user(e.primary.ID, "padm", model.RoleAdmin)
	if _, err := e.svc.SetPicture(e.ctx, actor(padm), e.super.ID, img); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("an administrator set the super admin's picture: %v", err)
	}
	if _, err := e.svc.SetPicture(e.ctx, actor(e.super), padm.ID, img); err != nil {
		t.Fatalf("the super admin sets an administrator's: %v", err)
	}

	// Self-service off: users and managers no longer set their own; administrators (who manage themselves), those
	// above them and the directory still do.
	e.setPictures(o.ID, model.PicturesAdmins)
	for _, u := range []*model.User{user, mgr} {
		if _, err := e.svc.SetPicture(e.ctx, actor(u), u.ID, img); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("%s set their own picture with pictures admins: %v", u.Username, err)
		}
		if _, err := e.svc.SetPicture(e.ctx, actor(u), u.ID, nil); u.Picture == "" && err != nil && !errors.Is(err, service.ErrForbidden) {
			t.Fatal(err)
		}
		if e.svc.MaySetPicture(e.ctx, actor(u), e.fresh(u)) {
			t.Fatalf("%s: MaySetPicture with pictures admins", u.Username)
		}
	}
	if _, err := e.svc.SetPicture(e.ctx, actor(user), user.ID, nil); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("a user removed their own picture with pictures admins: %v", err)
	}
	if _, err := e.svc.SetPicture(e.ctx, actor(adm), adm.ID, img); err != nil {
		t.Fatalf("an administrator's own: %v", err)
	}
	if _, err := e.svc.SetPicture(e.ctx, actor(mgr), other.ID, img); err != nil {
		t.Fatalf("a manager sets a user's with pictures admins: %v", err)
	}
	e.setPictures(o.ID, model.PicturesEveryone)
	if !e.svc.MaySetPicture(e.ctx, actor(user), e.fresh(user)) {
		t.Fatal("MaySetPicture: the default lets users set their own")
	}
	if _, err := e.svc.SetPicture(e.ctx, actor(user), user.ID, img); err != nil {
		t.Fatalf("a user's own, back on: %v", err)
	}
}

func TestPictureRateLimit(t *testing.T) {
	e := newEnv(t)
	eph := ephemeral.NewLocal("n1")
	t.Cleanup(eph.Close)
	e.svc.Counters = eph
	o := e.org("rate")
	u := e.user(o.ID, "busy", model.RoleUser)
	img := fromURI(dataURI(testPNG(t, color.NRGBA{9, 9, 9, 255})))
	for i := range service.PictureChangesPerHour {
		if _, err := e.svc.SetPicture(e.ctx, actor(u), u.ID, img); err != nil {
			t.Fatalf("change %d: %v", i+1, err)
		}
	}
	cur := e.fresh(u).Picture
	if _, err := e.svc.SetPicture(e.ctx, actor(u), u.ID, img); !errors.Is(err, service.ErrPictureRate) || !errors.Is(err, service.ErrLimit) {
		t.Fatalf("change %d: %v", service.PictureChangesPerHour+1, err)
	}
	if e.fresh(u).Picture != cur {
		t.Fatal("the refused change changed the picture")
	}
	// Removing is not counted: it stores nothing.
	if _, err := e.svc.SetPicture(e.ctx, actor(u), u.ID, nil); err != nil {
		t.Fatal(err)
	}
	// Another user has their own count.
	v := e.user(o.ID, "calm", model.RoleUser)
	if _, err := e.svc.SetPicture(e.ctx, actor(v), v.ID, img); err != nil {
		t.Fatal(err)
	}
}

func TestPictureGoesWithUserAndOrg(t *testing.T) {
	e := newEnv(t)
	o := e.org("leaving")
	u := e.user(o.ID, "gone", model.RoleUser)
	v := e.user(o.ID, "stays", model.RoleUser)
	img := fromURI(dataURI(testPNG(t, color.NRGBA{9, 90, 9, 255})))
	pu, err := e.svc.SetPicture(e.ctx, service.System, u.ID, img)
	if err != nil {
		t.Fatal(err)
	}
	pv, err := e.svc.SetPicture(e.ctx, service.System, v.ID, img)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteUser(e.ctx, service.System, u.ID); err != nil {
		t.Fatal(err)
	}
	if e.pictureStored(pu.Picture) || e.served(o.ID, pu.Picture) {
		t.Fatal("a deleted user's picture is still there")
	}
	if !e.served(o.ID, pv.Picture) {
		t.Fatal("another user's picture went too")
	}

	// A picture its user does not name (a change that failed part-way) is served to nobody, and swept.
	stray := &model.UserPicture{Meta: model.Meta{ID: model.NewRandomID()}, OrgID: o.ID, UserID: v.ID, Type: "image/png", Data: []byte{1}}
	if err := e.svc.Pictures.Create(e.ctx, stray); err != nil {
		t.Fatal(err)
	}
	if e.served(o.ID, stray.ID) {
		t.Fatal("a picture its user does not name is served")
	}
	if _, err := e.svc.SweepAll(e.ctx); err != nil {
		t.Fatal(err)
	}
	if e.pictureStored(stray.ID) || !e.pictureStored(pv.Picture) {
		t.Fatalf("sweep: stray kept %v, current kept %v", e.pictureStored(stray.ID), e.pictureStored(pv.Picture))
	}

	// Deleting the organization takes its users' pictures: served no more at once, removed by the sweep.
	if err := e.svc.DeleteOrg(e.ctx, actor(e.super), o.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SweepAll(e.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SweepAll(e.ctx); err != nil { // users first, then what was theirs
		t.Fatal(err)
	}
	if e.pictureStored(pv.Picture) {
		t.Fatal("a deleted organization's user's picture is still there")
	}
}

// pictureServer serves a PNG at /a.png, 404 elsewhere, and a body over the limit at /big.
func pictureServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a.png":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(body)
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte{0x89}, 6<<20))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchPicture(t *testing.T) {
	e := newEnv(t)
	body := testPNG(t, color.NRGBA{0, 0, 200, 255})
	srv := pictureServer(t, body)
	if _, err := e.svc.FetchPicture(e.ctx, srv.URL+"/a.png"); fieldOf(err) != "image" {
		t.Fatalf("without a client: %v", err)
	}
	e.svc.PictureClient = srv.Client()
	img, err := e.svc.FetchPicture(e.ctx, srv.URL+"/a.png")
	if err != nil || len(img.Data) == 0 || img.Source != srv.URL+"/a.png" {
		t.Fatalf("fetch: %+v %v", img, err)
	}
	for _, bad := range []string{srv.URL + "/missing", srv.URL + "/big", "http://example.com/a.png", "ftp://x/y", "https://user:pw@example.com/a.png", "not a url"} {
		if _, err := e.svc.FetchPicture(e.ctx, bad); fieldOf(err) != "image" {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestCopyPicture(t *testing.T) {
	e := newEnv(t)
	srv := pictureServer(t, testPNG(t, color.NRGBA{0, 120, 200, 255}))
	e.svc.PictureClient = srv.Client()
	o := e.org("copied")
	u := e.user(o.ID, "fresh", model.RoleAdmin) // a privileged account connecting a provider gets it too
	e.svc.CopyPicture(e.ctx, u.ID, srv.URL+"/a.png", "provider:test")
	e.svc.WaitBackground()
	got := e.fresh(u)
	if got.Picture == "" || !e.served(o.ID, got.Picture) {
		t.Fatal("the provider's picture was not copied")
	}
	ev := e.audited(o.ID, "user.picture.set")
	if len(ev) != 1 || !strings.Contains(ev[0].Actor, "provider:test") {
		t.Fatalf("audit: %+v", ev)
	}
	// One the account has is never replaced; a failure changes nothing.
	e.svc.CopyPicture(e.ctx, u.ID, srv.URL+"/a.png", "provider:test")
	e.svc.CopyPicture(e.ctx, u.ID, srv.URL+"/missing", "provider:test")
	e.svc.WaitBackground()
	if e.fresh(u).Picture != got.Picture {
		t.Fatal("the copy replaced the account's picture")
	}
	v := e.user(o.ID, "nopic", model.RoleUser)
	e.svc.CopyPicture(e.ctx, v.ID, srv.URL+"/missing", "provider:test")
	e.svc.WaitBackground()
	if e.fresh(v).Picture != "" {
		t.Fatal("a failed copy set a picture")
	}
	// The copy is the directory's: self-service off does not stop it.
	e.setPictures(o.ID, model.PicturesAdmins)
	e.svc.CopyPicture(e.ctx, v.ID, srv.URL+"/a.png", "provider:test")
	e.svc.WaitBackground()
	if e.fresh(v).Picture == "" {
		t.Fatal("pictures \"admins\" stopped the provider's copy")
	}
}

func TestSamePicture(t *testing.T) {
	e := newEnv(t)
	o := e.org("same")
	u := e.user(o.ID, "s", model.RoleUser)
	raw := testPNG(t, color.NRGBA{5, 5, 5, 255})
	got, err := e.svc.SetPicture(e.ctx, service.System, u.ID, fromURI(dataURI(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if !e.svc.SamePicture(e.ctx, got, service.HashSource(raw)) || e.svc.SamePicture(e.ctx, got, "https://example.com/x") {
		t.Fatal("SamePicture")
	}
}

// With an organization's pictures off nobody sets one (not even the system), none is shown or copied, and the sweep
// deletes those held, however new, and clears the users' pointers: turned on again, there are none.
func TestPicturesOff(t *testing.T) {
	e := newEnv(t)
	srv := pictureServer(t, testPNG(t, color.NRGBA{0, 120, 200, 255}))
	e.svc.PictureClient = srv.Client()
	o := e.org("nopics")
	other := e.org("pics")
	u := e.user(o.ID, "u", model.RoleUser)
	adm := e.user(o.ID, "adm", model.RoleAdmin)
	w := e.user(other.ID, "w", model.RoleUser)
	img := fromURI(dataURI(testPNG(t, color.NRGBA{1, 2, 3, 255})))
	for _, x := range []*model.User{u, adm, w} {
		if _, err := e.svc.SetPicture(e.ctx, service.System, x.ID, img); err != nil {
			t.Fatal(err)
		}
	}
	held := e.fresh(u).Picture
	if _, err := e.svc.UpdateOrg(e.ctx, service.System, o.ID, service.OrgInput{Settings: &model.OrgSettings{Pictures: "sometimes"}}); fieldOf(err) != "pictures" {
		t.Fatalf("an unknown value: %v", err)
	}
	e.setPictures(o.ID, model.PicturesOff)
	e.svc.InvalidateOrgs()

	for _, a := range []*service.Actor{actor(u), actor(adm), actor(e.super), service.System} {
		if _, err := e.svc.SetPicture(e.ctx, a, u.ID, img); !errors.Is(err, service.ErrPicturesOff) || !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("%s set a picture with pictures off: %v", a.Name, err)
		}
		if _, err := e.svc.SetPicture(e.ctx, a, u.ID, nil); !errors.Is(err, service.ErrPicturesOff) {
			t.Fatalf("%s removed a picture with pictures off: %v", a.Name, err)
		}
	}
	if e.svc.MaySetPicture(e.ctx, actor(adm), e.fresh(u)) {
		t.Fatal("MaySetPicture with pictures off")
	}
	pic, err := service.PictureFromDataURI(e.ctx, dataURI(testPNG(t, color.NRGBA{4, 5, 6, 255})))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Picture: &service.PictureChange{Image: pic}}); !errors.Is(err, service.ErrPicturesOff) {
		t.Fatalf("an update with a picture: %v", err)
	}
	if e.svc.PictureURL(e.ctx, e.fresh(u)) != "" || e.svc.PictureURL(e.ctx, e.fresh(w)) == "" {
		t.Fatal("PictureURL: none with pictures off, and another organization's as it was")
	}
	fresh := e.user(o.ID, "new", model.RoleUser)
	e.svc.CopyPicture(e.ctx, fresh.ID, srv.URL+"/a.png", "provider:test")
	e.svc.WaitBackground()
	if e.fresh(fresh).Picture != "" {
		t.Fatal("a provider's picture was copied with pictures off")
	}

	// One pass of the sweep (pictures made a moment ago included) deletes them all and clears the pointers.
	if _, err := e.svc.SweepAll(e.ctx); err != nil {
		t.Fatal(err)
	}
	for _, x := range []*model.User{u, adm} {
		if e.fresh(x).Picture != "" {
			t.Fatalf("%s still names a picture", x.Username)
		}
	}
	if e.pictureStored(held) {
		t.Fatal("a picture of an organization with pictures off is still stored")
	}
	if p := e.fresh(w).Picture; p == "" || !e.pictureStored(p) {
		t.Fatal("the sweep took another organization's picture")
	}

	// On again: none held, and they can be set.
	e.setPictures(o.ID, model.PicturesEveryone)
	if _, err := e.svc.SetPicture(e.ctx, actor(u), u.ID, img); err != nil {
		t.Fatal(err)
	}
}

// A picture that comes with a change of the user (UserInput.Picture) is written with it: the user names it, the old
// one goes, and the audit entry says so.
func TestPictureWithUpdate(t *testing.T) {
	e := newEnv(t)
	o := e.org("upd")
	u := e.user(o.ID, "u", model.RoleUser)
	first, err := e.svc.SetPicture(e.ctx, service.System, u.ID, fromURI(dataURI(testPNG(t, color.NRGBA{7, 7, 7, 255}))))
	if err != nil {
		t.Fatal(err)
	}
	pic, err := service.PictureFromDataURI(e.ctx, dataURI(testPNG(t, color.NRGBA{8, 8, 8, 255})))
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{GivenName: ptr("Pat"), Picture: &service.PictureChange{Image: pic}})
	if err != nil {
		t.Fatal(err)
	}
	if got.GivenName != "Pat" || got.Picture == "" || got.Picture == first.Picture || e.pictureStored(first.Picture) || !e.served(o.ID, got.Picture) {
		t.Fatalf("after: %q (old stored %v)", got.Picture, e.pictureStored(first.Picture))
	}
	if ev := e.audited(o.ID, "user.update"); len(ev) == 0 || ev[len(ev)-1].Detail["picture"] != "set" {
		t.Fatalf("audit: %+v", ev)
	}
	got, err = e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Picture: &service.PictureChange{}})
	if err != nil || got.Picture != "" {
		t.Fatalf("remove: %q %v", got.Picture, err)
	}
}
