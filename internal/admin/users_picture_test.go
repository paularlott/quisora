package admin_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/png"
	"strings"
	"testing"

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

func TestPicturesByAdminsSetting(t *testing.T) {
	w := newWorld(t)
	adm := w.as("super") // organization settings are the super admins'
	org := adm.get("/api/orgs/acme")
	want(t, org, 200)
	st := org.JSON["settings"].(map[string]any)
	if st["pictures_by_admins"] != false {
		t.Fatalf("default pictures_by_admins: %v", st["pictures_by_admins"])
	}
	st["pictures_by_admins"] = true
	r := adm.patch("/api/orgs/acme", map[string]any{"settings": st})
	want(t, r, 200)
	if r.JSON["settings"].(map[string]any)["pictures_by_admins"] != true {
		t.Fatalf("after patch: %v", r.JSON["settings"])
	}
	// Managers still set the pictures of the users they manage.
	want(t, w.as("manager").put("/api/orgs/acme/users/"+w.users["user"].ID+"/picture", map[string]any{"image": pictureURI(t, 7)}), 200)
}
