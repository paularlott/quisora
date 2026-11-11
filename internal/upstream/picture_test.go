package upstream_test

import (
	"bytes"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	ut "github.com/paularlott/quisora/internal/upstream/upstreamtest"
)

// avatars serves a PNG at /a.png (counting the fetches) and 404 elsewhere; the service fetches pictures through a
// client that trusts it.
func (e *env) avatars(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var b bytes.Buffer
	_ = png.Encode(&b, image.NewNRGBA(image.Rect(0, 0, 4, 4)))
	n := &atomic.Int32{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/a.png" {
			http.NotFound(w, r)
			return
		}
		n.Add(1)
		_, _ = w.Write(b.Bytes())
	}))
	t.Cleanup(srv.Close)
	e.svc.PictureClient = ut.HTTPClient()
	return srv, n
}

func (e *env) pictureOf(t *testing.T, id string) string {
	t.Helper()
	e.svc.WaitBackground()
	u, err := e.svc.Users.Get(e.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return u.Picture
}

// An account a provider creates gets the provider's picture, copied once and served from here.
func TestProvisionCopiesPicture(t *testing.T) {
	e := setup(t)
	srv, n := e.avatars(t)

	p := e.oidcProvider(t, nil)
	claims := std("sub-pic", "pic@example.com")
	claims["picture"] = srv.URL + "/a.png"
	res, err := e.signIn(p, claims)
	if err != nil || !res.Provisioned {
		t.Fatal(err)
	}
	pic := e.pictureOf(t, res.User.ID)
	if pic == "" || n.Load() != 1 {
		t.Fatalf("picture %q, fetched %d", pic, n.Load())
	}
	if _, err := e.svc.ServedPicture(e.ctx, e.org.ID, pic); err != nil {
		t.Fatal(err)
	}
	// Later sign-ins copy nothing: the account's picture is its own from now on.
	if _, err := e.signIn(p, claims); err != nil {
		t.Fatal(err)
	}
	if e.pictureOf(t, res.User.ID) != pic || n.Load() != 1 {
		t.Fatal("a later sign-in fetched the picture again")
	}

	// GitHub's avatar_url.
	gh := e.githubProvider(t, nil)
	e.gh.AvatarURL = srv.URL + "/a.png"
	res, err = e.signIn(gh, nil)
	if err != nil || !res.Provisioned {
		t.Fatal(err)
	}
	if e.pictureOf(t, res.User.ID) == "" {
		t.Fatal("the GitHub avatar was not copied")
	}

	// A picture that cannot be fetched is left out; the sign-in works.
	claims = std("sub-nopic", "nopic@example.com")
	claims["picture"] = srv.URL + "/missing.png"
	res, err = e.signIn(p, claims)
	if err != nil || !res.Provisioned {
		t.Fatal(err)
	}
	if e.pictureOf(t, res.User.ID) != "" {
		t.Fatal("a failed copy set a picture")
	}

	// With the organization's pictures off, nothing is fetched or copied.
	st := e.org.Settings
	st.Pictures = model.PicturesOff
	if _, err := e.svc.UpdateOrg(e.ctx, service.System, e.org.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	before := n.Load()
	claims = std("sub-off", "off@example.com")
	claims["picture"] = srv.URL + "/a.png"
	if res, err = e.signIn(p, claims); err != nil || !res.Provisioned {
		t.Fatal(err)
	}
	if e.pictureOf(t, res.User.ID) != "" || n.Load() != before {
		t.Fatal("a provider's picture was copied with pictures off")
	}
}

// Linking an existing account copies the provider's picture only when the account has none.
func TestLinkCopiesPictureOnlyWhenNone(t *testing.T) {
	e := setup(t)
	srv, n := e.avatars(t)
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false); in.LinkByEmail = ptr(true) })

	bare := e.mkUser(t, "bare", "bare@example.com", true)
	claims := std("sub-bare", "bare@example.com")
	claims["picture"] = srv.URL + "/a.png"
	if res, err := e.signIn(p, claims); err != nil || res.User.ID != bare.ID {
		t.Fatalf("link: %v", err)
	}
	if e.pictureOf(t, bare.ID) == "" {
		t.Fatal("the linked account got no picture")
	}

	has := e.mkUser(t, "has", "has@example.com", true)
	var b bytes.Buffer
	_ = png.Encode(&b, image.NewGray(image.Rect(0, 0, 3, 3)))
	img, err := service.MakePicture(e.ctx, b.Bytes(), "own")
	if err != nil {
		t.Fatal(err)
	}
	own, err := e.svc.UpdateUser(e.ctx, service.System, has.ID, service.UserInput{Picture: &service.PictureChange{Image: img}})
	if err != nil {
		t.Fatal(err)
	}
	before := n.Load()
	claims = std("sub-has", "has@example.com")
	claims["picture"] = srv.URL + "/a.png"
	if _, err := e.signIn(p, claims); err != nil {
		t.Fatal(err)
	}
	if e.pictureOf(t, has.ID) != own.Picture || n.Load() != before {
		t.Fatal("the account's own picture was replaced, or the provider's fetched for nothing")
	}
}
