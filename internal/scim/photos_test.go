package scim_test

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func photoURI(t *testing.T, shade uint8) string {
	t.Helper()
	m := image.NewNRGBA(image.Rect(0, 0, 5, 5))
	for i := range m.Pix {
		m.Pix[i] = shade
	}
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
}

// photoOf is the value of the user resource's first photo, "" for none.
func photoOf(r resp) string {
	l := r.list("photos")
	if len(l) == 0 {
		return ""
	}
	m := l[0].(map[string]any)
	if m["type"] != "photo" || m["primary"] != true {
		return "bad: " + string(r.Raw)
	}
	s, _ := m["value"].(string)
	return s
}

func TestUserPhotos(t *testing.T) {
	e := newEnv(t)
	fetched := 0
	img, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(photoURI(t, 90), "data:image/png;base64,"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/me.png" {
			http.NotFound(w, r)
			return
		}
		fetched++
		_, _ = w.Write(img)
	}))
	t.Cleanup(srv.Close)
	e.Svc.PictureClient = srv.Client()

	// Created with a data: URI: the server's own picture, at its own URL.
	r := e.createUser("acme", e.admA, map[string]any{"userName": "pic", "photos": []any{map[string]any{"value": photoURI(t, 10), "type": "photo"}}})
	wantStatus(t, "create", r, 201)
	id := r.str("id")
	url := photoOf(r)
	if !strings.HasPrefix(url, e.Cfg.Server.PublicURL+"/o/"+e.orgA.ID+"/pictures/") {
		t.Fatalf("photos: %s", r.Raw)
	}
	pic := func() string {
		u, err := e.Svc.Users.Get(e.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return u.Picture
	}
	first := pic()

	// The resource written back as read changes nothing; a PUT that leaves photos out neither.
	g := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	wantStatus(t, "put back", e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, g.Body), 200)
	body := map[string]any{"userName": "pic", "emails": mail("pic@acme.test")}
	wantStatus(t, "put without photos", e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, body), 200)
	if pic() != first {
		t.Fatal("the picture changed")
	}

	// An https URL is fetched once, and the same URL again changes nothing.
	r = e.patch(id, op("replace", "photos", []any{map[string]any{"value": srv.URL + "/me.png", "type": "photo", "primary": true}}))
	wantStatus(t, "patch url", r, 200)
	second := pic()
	if second == first || second == "" || photoOf(r) == url || fetched != 1 {
		t.Fatalf("after the URL: %q (fetched %d) %s", second, fetched, r.Raw)
	}
	r = e.patch(id, op("replace", "photos", []any{map[string]any{"value": srv.URL + "/me.png", "type": "photo"}}))
	wantStatus(t, "patch same url", r, 200)
	if pic() != second || fetched != 1 {
		t.Fatalf("the same URL again: fetched %d", fetched)
	}

	// Removed by a PATCH, by a filtered path too, and by a PUT with no photos.
	wantStatus(t, "remove", e.patch(id, op("remove", `photos[type eq "photo"]`, nil)), 200)
	if pic() != "" {
		t.Fatal("photos[type eq photo] removal kept the picture")
	}
	r = e.patch(id, op("add", "photos", []any{map[string]any{"value": photoURI(t, 30), "type": "photo"}}))
	wantStatus(t, "add", r, 200)
	if pic() == "" || photoOf(r) == "" {
		t.Fatalf("add: %s", r.Raw)
	}
	wantStatus(t, "remove all", e.patch(id, op("remove", "photos", nil)), 200)
	if pic() != "" {
		t.Fatal("remove kept the picture")
	}
	wantStatus(t, "add again", e.patch(id, op("add", "photos", []any{map[string]any{"value": photoURI(t, 31)}})), 200)
	body["photos"] = []any{}
	wantStatus(t, "put empty photos", e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, body), 200)
	if pic() != "" {
		t.Fatal("an empty photos kept the picture")
	}

	// Refused values: invalidValue, and nothing changes; a refused create creates nobody.
	for _, bad := range []string{"ftp://example.com/a.png", "http://example.com/a.png", "data:image/gif;base64,R0lGOD",
		"data:image/png;base64,bm90IGFuIGltYWdl", srv.URL + "/missing.png"} {
		r = e.patch(id, op("replace", "photos", []any{map[string]any{"value": bad}}))
		if r.Status != 400 || r.str("scimType") != "invalidValue" {
			t.Errorf("%s: %d %s", bad, r.Status, r.Raw)
		}
	}
	r = e.createUser("acme", e.admA, map[string]any{"userName": "nopic", "photos": []any{map[string]any{"value": "javascript:alert(1)"}}})
	wantStatus(t, "bad create", r, 400)
	if l := e.do("GET", "/scim/v2/acme/Users?filter="+qs(`userName eq "nopic"`), e.admA, nil); l.total() != 0 {
		t.Fatal("a refused create created the user")
	}

	// Deleting the user deletes the picture.
	wantStatus(t, "add for delete", e.patch(id, op("add", "photos", []any{map[string]any{"value": photoURI(t, 32)}})), 200)
	last := pic()
	wantStatus(t, "delete", e.do("DELETE", "/scim/v2/acme/Users/"+id, e.admA, nil), 204)
	if _, err := e.Svc.Pictures.Get(e.ctx, last); err == nil {
		t.Fatal("the deleted user's picture is still stored")
	}
}

func TestPhotosInSchema(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/scim/v2/acme/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "", nil)
	wantStatus(t, "schema", r, 200)
	if !strings.Contains(string(r.Raw), `"name":"photos"`) || !strings.Contains(string(r.Raw), `"thumbnail"`) {
		t.Fatalf("the User schema lacks photos: %s", r.Raw)
	}
}
