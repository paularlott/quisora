package scim_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
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

// A change that comes with a photo takes effect with it or not at all: a refused image, or a failure to write the
// user, leaves the resource exactly as it was (here: a disabled account a PATCH would enable).
func TestPhotoRefusedChangesNothing(t *testing.T) {
	fs := &failingWrites{Store: memstore.New()}
	e := newEnvStore(t, fs)
	id := e.mk("off", map[string]any{"active": false, "photos": []any{map[string]any{"value": photoURI(t, 40)}}})
	before, err := e.Svc.Users.Get(e.ctx, id)
	if err != nil || before.Active || before.Picture == "" {
		t.Fatalf("set up: %+v %v", before, err)
	}
	unchanged := func(what string) {
		t.Helper()
		u, err := e.Svc.Users.Get(e.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if u.Active || u.Picture != before.Picture || u.Version != before.Version {
			t.Fatalf("%s changed the user: active %v, picture %q (was %q)", what, u.Active, u.Picture, before.Picture)
		}
		if _, err := e.Svc.Pictures.Get(e.ctx, before.Picture); err != nil {
			t.Fatalf("%s: the picture is gone: %v", what, err)
		}
	}
	enable := op("replace", "active", true)

	// A refused image: PATCH and PUT.
	r := e.patch(id, enable, op("replace", "photos", []any{map[string]any{"value": "data:image/png;base64,bm90IGFuIGltYWdl"}}))
	wantStatus(t, "patch with a bad image", r, 400)
	unchanged("a PATCH with a bad image")
	put := map[string]any{"userName": "off", "active": true, "emails": mail("off@acme.test"),
		"photos": []any{map[string]any{"value": "data:image/png;base64,bm90IGFuIGltYWdl"}}}
	wantStatus(t, "put with a bad image", e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, put), 400)
	unchanged("a PUT with a bad image")

	// A good image whose picture, or whose user, cannot be written: the user is as it was, and the new picture (when it
	// was stored) is named by nobody.
	for _, kind := range []model.Kind{model.KindUserPicture, model.KindUser} {
		fs.fail.Store(kind)
		r = e.patch(id, enable, op("replace", "photos", []any{map[string]any{"value": photoURI(t, 41)}}))
		fs.fail.Store(model.Kind(""))
		if r.Status != 503 || r.Header.Get("Retry-After") == "" {
			t.Fatalf("a failed %s write answered %d %s", kind, r.Status, r.Raw)
		}
		unchanged("a PATCH whose " + string(kind) + " write failed")
	}

	// A refused create creates nobody, and a create's picture comes in the one write.
	r = e.createUser("acme", e.admA, map[string]any{"userName": "badpic", "photos": []any{map[string]any{"value": "data:image/png;base64,bm90IGFuIGltYWdl"}}})
	wantStatus(t, "create with a bad image", r, 400)
	if l := e.do("GET", "/scim/v2/acme/Users?filter="+qs(`userName eq "badpic"`), e.admA, nil); l.total() != 0 {
		t.Fatal("a refused create created the user")
	}

	// And the same change with a good image works, in one write.
	r = e.patch(id, enable, op("replace", "photos", []any{map[string]any{"value": photoURI(t, 42)}}))
	wantStatus(t, "patch", r, 200)
	u, _ := e.Svc.Users.Get(e.ctx, id)
	if !u.Active || u.Picture == "" || u.Picture == before.Picture {
		t.Fatalf("after the patch: active %v picture %q", u.Active, u.Picture)
	}
	if _, err := e.Svc.Pictures.Get(e.ctx, before.Picture); err == nil {
		t.Fatal("the replaced picture is still stored")
	}
}

// failingWrites fails every write of the kind it is armed with (the store refuses: nothing is written).
type failingWrites struct {
	store.Store
	fail atomic.Value // model.Kind
}

func (f *failingWrites) refuse(kind model.Kind) error {
	if k, _ := f.fail.Load().(model.Kind); k != "" && kind == k {
		return fmt.Errorf("write: %w", store.ErrUnavailable)
	}
	return nil
}

func (f *failingWrites) Put(ctx context.Context, rec *store.Record) error {
	if err := f.refuse(rec.Kind); err != nil {
		return err
	}
	return f.Store.Put(ctx, rec)
}

func (f *failingWrites) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if err := f.refuse(rec.Kind); err != nil {
		return err
	}
	return f.Store.CompareAndPut(ctx, rec, expect)
}

func (f *failingWrites) Tx(ctx context.Context, ops []store.Op) error {
	for _, o := range ops {
		if err := f.refuse(o.Rec.Kind); err != nil {
			return err
		}
	}
	return f.Store.Tx(ctx, ops)
}

// With the organization's pictures off, photos are left out of every user and ignored when written: a directory's
// sync goes on, and nothing is stored.
func TestPhotosOff(t *testing.T) {
	e := newEnv(t)
	id := e.mk("pic", map[string]any{"photos": []any{map[string]any{"value": photoURI(t, 50)}}})
	st := e.orgA.Settings
	st.Pictures = model.PicturesOff
	if _, err := e.Svc.UpdateOrg(e.ctx, service.System, e.orgA.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	e.Svc.InvalidateOrgs()
	stored := func() int {
		l, _, err := e.Svc.Pictures.List(e.ctx, store.ListQuery{})
		if err != nil {
			t.Fatal(err)
		}
		return len(l)
	}
	before := stored()

	r := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	if wantStatus(t, "get", r, 200); r.list("photos") != nil {
		t.Fatalf("photos with pictures off: %s", r.Raw)
	}
	r = e.patch(id, op("replace", "photos", []any{map[string]any{"value": photoURI(t, 51)}}), op("replace", "displayName", "Pat"))
	if wantStatus(t, "patch", r, 200); r.list("photos") != nil {
		t.Fatalf("patch: %s", r.Raw)
	}
	wantStatus(t, "remove", e.patch(id, op("remove", "photos", nil)), 200)
	r = e.createUser("acme", e.admA, map[string]any{"userName": "new", "photos": []any{map[string]any{"value": "not even a URL"}}})
	if wantStatus(t, "create", r, 201); r.list("photos") != nil {
		t.Fatalf("create: %s", r.Raw)
	}
	if n := stored(); n != before {
		t.Fatalf("pictures stored with pictures off: %d, was %d", n, before)
	}
}
