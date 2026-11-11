package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/png"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// The picture claim (Core §5.1) is the absolute URL of the user's picture: in the ID token and at userinfo with the
// profile scope, and through the claims parameter; never when the user has none.
func TestPictureClaim(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)

	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile"}})
	if id := claimsOf(t, r.str("id_token")); id["picture"] != nil {
		t.Fatalf("picture claim of a user with none: %v", id["picture"])
	}
	if ui := h.userinfo(r.str("access_token")); ui["picture"] != nil {
		t.Fatalf("userinfo picture of a user with none: %v", ui["picture"])
	}

	m := image.NewNRGBA(image.Rect(0, 0, 3, 3))
	var b bytes.Buffer
	_ = png.Encode(&b, m)
	u, err := h.env.Svc.SetPicture(context.Background(), service.System, h.user.ID, func() (*service.PictureImage, error) {
		return service.PictureFromDataURI(context.Background(), "data:image/png;base64,"+base64.StdEncoding.EncodeToString(b.Bytes()))
	})
	if err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(u.ID) // as the change feed does
	want := h.env.Svc.PictureURL(context.Background(), u)
	if !strings.HasPrefix(want, "https://") || !strings.Contains(want, "/pictures/") {
		t.Fatalf("picture URL %q", want)
	}

	r, _ = h.login(cl, secret, url.Values{"scope": {"openid profile"}})
	if id := claimsOf(t, r.str("id_token")); id["picture"] != want {
		t.Fatalf("ID token picture %v, want %s", id["picture"], want)
	}
	if ui := h.userinfo(r.str("access_token")); ui["picture"] != want {
		t.Fatalf("userinfo picture %v", ui["picture"])
	}
	// Without the profile scope: only when asked for by name.
	r, _ = h.login(cl, secret, url.Values{"scope": {"openid email"}})
	if id := claimsOf(t, r.str("id_token")); id["picture"] != nil {
		t.Fatalf("picture without the profile scope: %v", id["picture"])
	}
	r, _ = h.login(cl, secret, url.Values{"scope": {"openid"}, "claims": {`{"id_token":{"picture":null},"userinfo":{"picture":null}}`}})
	if id := claimsOf(t, r.str("id_token")); id["picture"] != want {
		t.Fatalf("picture through the claims parameter: %v", id["picture"])
	}
	if ui := h.userinfo(r.str("access_token")); ui["picture"] != want {
		t.Fatalf("userinfo picture through the claims parameter: %v", ui["picture"])
	}

	// With the organization's pictures off there is no picture claim at all.
	o, err := h.env.Svc.Orgs.Get(context.Background(), u.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	st := o.Settings
	st.Pictures = model.PicturesOff
	if _, err := h.env.Svc.UpdateOrg(context.Background(), service.System, o.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	h.env.Svc.InvalidateOrgs()
	r, _ = h.login(cl, secret, url.Values{"scope": {"openid profile"}})
	if id := claimsOf(t, r.str("id_token")); id["picture"] != nil {
		t.Fatalf("picture claim with pictures off: %v", id["picture"])
	}
	if ui := h.userinfo(r.str("access_token")); ui["picture"] != nil {
		t.Fatalf("userinfo picture with pictures off: %v", ui["picture"])
	}
}
