package login_test

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var formField = regexp.MustCompile(`name="(csrf|token)" value="([^"]*)"`)

// verifyLink follows an emailed verification link as a person does: opens it (a page that uses nothing up), then
// presses its button. It returns the answer to the press.
func (b *browser) verifyLink(path string) (*http.Response, string) {
	b.t.Helper()
	res, page := b.get(path)
	if res.StatusCode != http.StatusOK {
		return res, page
	}
	form := url.Values{}
	for _, m := range formField.FindAllStringSubmatch(page, -1) {
		form.Set(m[1], strings.ReplaceAll(m[2], "&amp;", "&"))
	}
	res, err := b.c.PostForm(b.e.URL+"/verify-email", form)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

// Opening a verification link (a mail scanner, a link preview) verifies nothing and uses nothing up; pressing the
// button on its page does.
func TestVerifyLinkOpenedIsNotUsed(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", "user")
	res, out := e.signedIn(t, pat).post("/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 200)
	link := linkPath(t, e.nextMail(t))
	for range 3 { // a scanner, a preview, the person
		if res, _ := e.browser(t).get(link); res.StatusCode != http.StatusOK {
			t.Fatalf("open: %d", res.StatusCode)
		}
	}
	if u, _ := e.Svc.Users.Get(t.Context(), pat.ID); u.EmailVerified {
		t.Fatal("opening the link verified the address")
	}
	if res, _ := e.browser(t).verifyLink(link); res.Header.Get("Location") != "/account?email=verified#profile" {
		t.Fatalf("confirm: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// A press from another site (no matching CSRF cookie) is refused.
	form := url.Values{"token": {tokenOf(link)}, "csrf": {"x"}}
	if res, err := e.browser(t).c.PostForm(e.URL+"/verify-email", form); err != nil || res.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site press: %v %v", res, err)
	}
}
