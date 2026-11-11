package login_test

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"math/rand/v2"
	"net/http"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

// noisePNG is a w×h PNG of noise: it does not compress, so a large one is a large request.
func noisePNG(t testing.TB, w, h int) []byte {
	t.Helper()
	r := rand.New(rand.NewPCG(3, 4))
	m := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := range m.Pix {
		m.Pix[i] = uint8(r.IntN(256))
		if i%4 == 3 {
			m.Pix[i] = 255
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func smallPNG(t testing.TB, c color.NRGBA) string {
	t.Helper()
	m := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	for i := 0; i < len(m.Pix); i += 4 {
		m.Pix[i], m.Pix[i+1], m.Pix[i+2], m.Pix[i+3] = c.R, c.G, c.B, c.A
	}
	var b bytes.Buffer
	_ = png.Encode(&b, m)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
}

// pictureGet fetches a picture by its absolute URL (the public URL's path at the test server), with header h.
func (b *browser) pictureGet(method, url string, h hdrs) *http.Response {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.e.URL+strings.TrimPrefix(strings.TrimPrefix(url, b.e.Cfg.Server.PublicURL), b.e.URL), nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	res, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func TestAccountPicture(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "pics", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)

	res, out := b.api("GET", "/api-internal/account", nil)
	wantStatus(t, res, out, 200)
	if out["can_change_picture"] != true || out["user"].(map[string]any)["picture"] != nil {
		t.Fatalf("account: %v", out["_raw"])
	}

	// A photo of more than the usual 1 MB request limit is taken.
	big := noisePNG(t, 900, 700)
	if len(big) < 1<<20 {
		t.Fatalf("test image too small: %d", len(big))
	}
	res, out = b.api("PUT", "/api-internal/account/picture", map[string]any{"image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(big)})
	wantStatus(t, res, out, 200)
	url := str(out["user"].(map[string]any), "picture")
	if !strings.HasPrefix(url, e.Cfg.Server.PublicURL+"/o/"+org.ID+"/pictures/") {
		t.Fatalf("picture URL %q", url)
	}
	id := url[strings.LastIndex(url, "/")+1:]
	if len(e.audits(t, "user.picture.set")) != 1 {
		t.Fatal("not audited")
	}

	// Served to anyone, with no session, as an image that cannot be anything else.
	anon := e.browser(t)
	res = anon.pictureGet("GET", url, nil)
	if res.StatusCode != 200 {
		t.Fatalf("GET picture: %d", res.StatusCode)
	}
	h := res.Header
	if ct := h.Get("Content-Type"); ct != "image/jpeg" && ct != "image/png" {
		t.Errorf("Content-Type %q", ct)
	}
	for k, v := range map[string]string{
		"Cache-Control": "public, max-age=31536000, immutable", "X-Content-Type-Options": "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox", "Cross-Origin-Resource-Policy": "cross-origin", "ETag": `"` + id + `"`,
	} {
		if h.Get(k) != v {
			t.Errorf("%s: %q, want %q", k, h.Get(k), v)
		}
	}
	if res.Header.Get("Set-Cookie") != "" {
		t.Error("the picture sets a cookie")
	}
	if res = anon.pictureGet("HEAD", url, nil); res.StatusCode != 200 || res.ContentLength <= 0 {
		t.Errorf("HEAD: %d %d", res.StatusCode, res.ContentLength)
	}
	if res = anon.pictureGet("GET", url, hdrs{"If-None-Match": `"` + id + `"`}); res.StatusCode != 304 {
		t.Errorf("If-None-Match: %d", res.StatusCode)
	}
	// By the organization's name too; never under another organization, nor an id that is not a current picture.
	if res = anon.pictureGet("GET", e.URL+"/o/pics/pictures/"+id, nil); res.StatusCode != 200 {
		t.Errorf("by name: %d", res.StatusCode)
	}
	for _, p := range []string{"/o/" + e.Primary.ID + "/pictures/" + id, "/o/" + org.ID + "/pictures/" + model.NewRandomID(),
		"/o/" + org.ID + "/pictures/" + pat.ID, "/o/" + org.ID + "/pictures/x", "/o/nosuchorg/pictures/" + id} {
		if res = anon.pictureGet("GET", e.URL+p, nil); res.StatusCode != 404 {
			t.Errorf("%s: %d", p, res.StatusCode)
		}
	}

	// A new picture is a new URL; the old one is gone.
	res, out = b.api("PUT", "/api-internal/account/picture", map[string]any{"image": smallPNG(t, color.NRGBA{0, 0, 255, 128})})
	wantStatus(t, res, out, 200)
	url2 := str(out["user"].(map[string]any), "picture")
	if url2 == url || url2 == "" {
		t.Fatalf("new URL %q", url2)
	}
	if res = anon.pictureGet("GET", url, nil); res.StatusCode != 404 {
		t.Errorf("old URL: %d", res.StatusCode)
	}
	if res = anon.pictureGet("GET", url2, nil); res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" {
		t.Errorf("transparent picture: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}

	// Refused images.
	for _, bad := range []string{"", "https://example.com/a.png", "data:image/gif;base64,R0lGODlhAQABAAAAACw=",
		"data:image/png;base64,bm90IGFuIGltYWdl", "data:image/png;base64,***"} {
		res, out = b.api("PUT", "/api-internal/account/picture", map[string]any{"image": bad})
		if res.StatusCode != 422 || out["field"] != "image" {
			t.Errorf("%.40q: %d %v", bad, res.StatusCode, out["_raw"])
		}
	}
	res, out = b.api("PUT", "/api-internal/account/picture", map[string]any{"image": smallPNG(t, color.NRGBA{1, 1, 1, 255}), "user_id": "x"})
	wantStatus(t, res, out, 400) // the strict decoder: nothing but the image

	// Session and CSRF, as every account endpoint.
	res, out = b.do("PUT", "/api-internal/account/picture", map[string]any{"image": smallPNG(t, color.NRGBA{1, 1, 1, 255})}, hdrs{"X-CSRF-Token": ""})
	wantStatus(t, res, out, 403)
	res, out = anon.do("DELETE", "/api-internal/account/picture", nil, nil)
	wantStatus(t, res, out, 401)

	res, out = b.api("DELETE", "/api-internal/account/picture", nil)
	wantStatus(t, res, out, 200)
	if out["user"].(map[string]any)["picture"] != nil {
		t.Fatalf("after delete: %v", out["_raw"])
	}
	if res = anon.pictureGet("GET", url2, nil); res.StatusCode != 404 {
		t.Errorf("removed picture: %d", res.StatusCode)
	}

	// The organization has its administrators set pictures: refused, and the page is told.
	e.setSettings(t, org, func(s *model.OrgSettings) { s.Pictures = model.PicturesAdmins })
	res, out = b.api("PUT", "/api-internal/account/picture", map[string]any{"image": smallPNG(t, color.NRGBA{1, 1, 1, 255})})
	wantStatus(t, res, out, 403)
	res, out = b.api("GET", "/api-internal/account", nil)
	wantStatus(t, res, out, 200)
	if out["can_change_picture"] != false || out["pictures_enabled"] != true {
		t.Fatalf("with pictures admins: can_change_picture %v, pictures_enabled %v", out["can_change_picture"], out["pictures_enabled"])
	}

	// Pictures off: refused with the reason, the page is told to show none, and the one held is served no more.
	e.setSettings(t, org, func(s *model.OrgSettings) { s.Pictures = model.PicturesEveryone })
	res, out = b.api("PUT", "/api-internal/account/picture", map[string]any{"image": smallPNG(t, color.NRGBA{3, 3, 3, 255})})
	wantStatus(t, res, out, 200)
	held, _ := out["user"].(map[string]any)["picture"].(string)
	if res = anon.pictureGet("GET", held, nil); res.StatusCode != 200 {
		t.Fatalf("the picture held: %d", res.StatusCode)
	}
	e.setSettings(t, org, func(s *model.OrgSettings) { s.Pictures = model.PicturesOff })
	res, out = b.api("PUT", "/api-internal/account/picture", map[string]any{"image": smallPNG(t, color.NRGBA{1, 1, 1, 255})})
	wantStatus(t, res, out, 403)
	if msg, _ := out["error"].(string); !strings.Contains(msg, "turned off") {
		t.Fatalf("refusal: %v", out)
	}
	res, out = b.api("DELETE", "/api-internal/account/picture", nil)
	wantStatus(t, res, out, 403)
	res, out = b.api("GET", "/api-internal/account", nil)
	wantStatus(t, res, out, 200)
	if out["can_change_picture"] != false || out["pictures_enabled"] != false || out["user"].(map[string]any)["picture"] != nil {
		t.Fatalf("with pictures off: %v", out["_raw"])
	}
	if res = anon.pictureGet("GET", held, nil); res.StatusCode != 404 {
		t.Fatalf("a picture served with pictures off: %d", res.StatusCode)
	}
}
