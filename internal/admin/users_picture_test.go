package admin_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/png"
	"io"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func pictureURI(t *testing.T, shade uint8) string {
	t.Helper()
	m := image.NewNRGBA(image.Rect(0, 0, 6, 6))
	for i := range m.Pix {
		m.Pix[i] = shade
		if i%4 == 3 {
			m.Pix[i] = 255
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
}

func TestUserPictureAPI(t *testing.T) {
	w := newWorld(t)
	mgr := w.as("manager")
	user := w.users["user"]
	path := "/api/orgs/acme/users/" + user.ID

	r := mgr.put(path+"/picture", map[string]any{"image": pictureURI(t, 40)})
	want(t, r, 200)
	url := r.str("picture")
	if !strings.HasPrefix(url, w.env.Cfg.Server.PublicURL+"/o/"+w.acme.ID+"/pictures/") {
		t.Fatalf("picture %q", url)
	}
	if got := mgr.get(path); got.str("picture") != url {
		t.Fatalf("GET user: picture %q", got.str("picture"))
	}
	found := false
	for _, it := range mgr.get("/api/orgs/acme/users").items() {
		if m := it.(map[string]any); m["id"] == user.ID && m["picture"] == url {
			found = true
		}
	}
	if !found {
		t.Fatal("the list does not show the picture")
	}
	if len(auditActions(t, w, "user.picture.set")) != 1 {
		t.Fatal("not audited")
	}

	// Refused: an image that is not one, and anything but the image.
	wantField(t, mgr.put(path+"/picture", map[string]any{"image": "data:image/png;base64,AAAA"}), 422, "image")
	want(t, mgr.put(path+"/picture", map[string]any{"image": pictureURI(t, 1), "url": "x"}), 400)

	// Never a user above the caller: an administrator for a manager, a super admin for an administrator (hidden).
	if r := mgr.put("/api/orgs/acme/users/"+w.users["admin"].ID+"/picture", map[string]any{"image": pictureURI(t, 2)}); r.Status != 403 && r.Status != 404 {
		t.Fatalf("a manager set an administrator's picture: %d", r.Status)
	}
	padm, err := w.env.Svc.CreateUser(context.Background(), service.System, w.env.Primary.ID, service.UserInput{GivenName: ptr("P"),
		Username: ptr("padm"), Email: ptr("padm@x.example"), Role: ptr(model.RoleAdmin), Password: ptr("correct horse battery")})
	if err != nil {
		t.Fatal(err)
	}
	w.users["padm"] = padm
	r = w.as("padm").put("/api/orgs/"+w.env.Primary.ID+"/users/"+w.env.Admin.ID+"/picture", map[string]any{"image": pictureURI(t, 3)})
	want(t, r, 404)
	if u, _ := w.env.Svc.Users.Get(context.Background(), w.env.Admin.ID); u.Picture != "" {
		t.Fatal("the super admin's picture was set")
	}
	// Another organization's user is not found.
	want(t, w.as("other").put(path+"/picture", map[string]any{"image": pictureURI(t, 4)}), 404)

	r = mgr.delete(path + "/picture")
	want(t, r, 200)
	if _, has := r.JSON["picture"]; has {
		t.Fatalf("after delete: %v", r.JSON)
	}
	if len(auditActions(t, w, "user.picture.remove")) != 1 {
		t.Fatal("removal not audited")
	}
}

func TestUserPictureRateLimit(t *testing.T) {
	w := newWorld(t)
	adm := w.as("admin")
	path := "/api/orgs/acme/users/" + w.users["user"].ID + "/picture"
	for i := range service.PictureChangesPerHour {
		want(t, adm.put(path, map[string]any{"image": pictureURI(t, uint8(i))}), 200)
	}
	r := adm.put(path, map[string]any{"image": pictureURI(t, 99)})
	want(t, r, 429)
	if r.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
}

// settings.pictures is who sets pictures: everyone (the default), admins (managers and above still set users'), or
// off (nobody, and no user shows one). Anything else is refused.
func TestPicturesSetting(t *testing.T) {
	w := newWorld(t)
	adm := w.as("super") // organization settings are the super admins'
	mgr := w.as("manager")
	userPath := "/api/orgs/acme/users/" + w.users["user"].ID
	org := adm.get("/api/orgs/acme")
	want(t, org, 200)
	st := org.JSON["settings"].(map[string]any)
	if st["pictures"] != model.PicturesEveryone {
		t.Fatalf("default pictures: %v", st["pictures"])
	}
	want(t, mgr.put(userPath+"/picture", map[string]any{"image": pictureURI(t, 6)}), 200)
	set := func(v string) {
		t.Helper()
		st["pictures"] = v
		r := adm.patch("/api/orgs/acme", map[string]any{"settings": st})
		want(t, r, 200)
		if r.JSON["settings"].(map[string]any)["pictures"] != v {
			t.Fatalf("after patch: %v", r.JSON["settings"])
		}
		w.env.Svc.InvalidateOrgs()
	}
	st["pictures"] = "sometimes"
	wantField(t, adm.patch("/api/orgs/acme", map[string]any{"settings": st}), 422, "pictures")

	// Managers still set the pictures of the users they manage.
	set(model.PicturesAdmins)
	want(t, mgr.put(userPath+"/picture", map[string]any{"image": pictureURI(t, 7)}), 200)
	if got := mgr.get(userPath); got.str("picture") == "" || got.JSON["pictures_enabled"] != true {
		t.Fatalf("with pictures admins: %v", got.JSON)
	}

	// Off: nobody sets or removes one, and no user shows one.
	set(model.PicturesOff)
	for _, who := range []string{"manager", "admin", "super"} {
		r := w.as(who).put(userPath+"/picture", map[string]any{"image": pictureURI(t, 8)})
		want(t, r, 403)
		if !strings.Contains(r.str("error"), "turned off") {
			t.Fatalf("%s: %v", who, r.JSON)
		}
		want(t, w.as(who).delete(userPath+"/picture"), 403)
	}
	if got := mgr.get(userPath).JSON; got["picture"] != nil || got["pictures_enabled"] != false {
		t.Fatalf("a user with pictures off: picture %v, pictures_enabled %v", got["picture"], got["pictures_enabled"])
	}
	for _, it := range mgr.get("/api/orgs/acme/users").items() {
		if _, has := it.(map[string]any)["picture"]; has {
			t.Fatal("the list shows a picture with pictures off")
		}
	}
	set(model.PicturesEveryone)
}

// By default the console offers the organization's pictures setting; with --disable-pictures (server.disable_pictures)
// every organization behaves as if its pictures were off: nobody sets one, no user shows one or says pictures are
// enabled, the picture's address answers 404, and the console does not offer the setting.
func TestDisablePicturesHidesThem(t *testing.T) {
	page := func(w *world) string {
		t.Helper()
		res, err := w.as("super").c.Get(w.env.URL + "/admin/orgs")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}
	if on := newWorld(t); !strings.Contains(page(on), `id="f-pictures"`) {
		t.Fatal("the organization dialog does not offer the setting by default")
	}

	w := newWorld(t)
	mgr := w.as("manager")
	userPath := "/api/orgs/acme/users/" + w.users["user"].ID
	want(t, mgr.put(userPath+"/picture", map[string]any{"image": pictureURI(t, 6)}), 200)
	pic := mgr.get(userPath).str("picture")
	if pic == "" {
		t.Fatal("no picture")
	}
	served := func() int {
		t.Helper()
		res, err := w.as("manager").c.Get(w.env.URL + pic[strings.Index(pic, "/o/"):])
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if served() != 200 {
		t.Fatal("a picture is not served by default")
	}

	// Switched off as a restart with the flag would (the page's site block is read from the config at start).
	off := newWorldWith(t, func(c *config.Config) { c.Server.DisablePictures = true })
	if strings.Contains(page(off), `id="f-pictures"`) {
		t.Error("the organization dialog offers the setting")
	}
	for _, who := range []string{"manager", "admin", "super"} {
		want(t, off.as(who).put("/api/orgs/acme/users/"+off.users["user"].ID+"/picture", map[string]any{"image": pictureURI(t, 8)}), 403)
	}
	got := off.as("manager").get("/api/orgs/acme/users/" + off.users["user"].ID).JSON
	if got["picture"] != nil || got["pictures_enabled"] != false {
		t.Fatalf("a user with the server's pictures off: picture %v, pictures_enabled %v", got["picture"], got["pictures_enabled"])
	}

	// A picture already held is not served once the server turns them off.
	w.env.Svc.Cfg.Server.DisablePictures = true
	if served() != 404 {
		t.Fatal("a held picture is served with the server's pictures off")
	}
}
