package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
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
	uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
	u, err := h.env.Svc.SetPicture(context.Background(), service.System, h.user.ID, &uri)
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

// With server.disable_pictures there is no picture claim (ID token, userinfo, claims parameter), discovery does not
// list it, and the profile scope's consent text does not promise one.
func TestPictureClaimServerOff(t *testing.T) {
	t.Parallel()
	h := setup(t, func(c *config.Config) { c.Server.DisablePictures = true })
	cl, secret := h.newClient(nil)
	consenting, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })

	var d map[string]any
	if err := json.Unmarshal([]byte(body(h.get(h.http, h.orgBase+"/.well-known/openid-configuration"))), &d); err != nil {
		t.Fatal(err)
	}
	if got := strsOf(d["claims_supported"]); slices.Contains(got, "picture") || !slices.Contains(got, "given_name") {
		t.Fatalf("claims_supported: %v", got)
	}

	// A picture set before the server turned them off (as through the service directly) is not sent.
	h.env.Svc.Cfg.Server.DisablePictures = false
	m := image.NewNRGBA(image.Rect(0, 0, 3, 3))
	var b bytes.Buffer
	_ = png.Encode(&b, m)
	uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
	u, err := h.env.Svc.SetPicture(context.Background(), service.System, h.user.ID, &uri)
	if err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(u.ID)
	h.env.Svc.Cfg.Server.DisablePictures = true
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile"}, "claims": {`{"id_token":{"picture":null},"userinfo":{"picture":null}}`}})
	if id := claimsOf(t, r.str("id_token")); id["picture"] != nil {
		t.Fatalf("picture claim with the server's pictures off: %v", id["picture"])
	}
	if ui := h.userinfo(r.str("access_token")); ui["picture"] != nil {
		t.Fatalf("userinfo picture with the server's pictures off: %v", ui["picture"])
	}

	c, _ := h.session(h.user)
	v, ch := pkce()
	_ = v
	loc := h.authorize(c, authzQuery(consenting, ch, nil))
	page := body(h.get(c, loc.RequestURI()))
	if !strings.Contains(page, "Your name, username, language and time zone") || strings.Contains(page, "picture") {
		t.Fatalf("consent page: %s", page)
	}
}
