package admin_test

import (
	"net/http"
	"net/url"
	"testing"
)

func TestUserLinkedEmailsAPI(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	uid := w.users["user"].ID
	E := AU + "/" + uid + "/emails"

	// GET returns the (empty) list and the full name
	r := ad.get(AU + "/" + uid)
	want(t, r, 200)
	if le, ok := r.JSON["linked_emails"].([]any); !ok || len(le) != 0 || r.str("name") != "T" || r.JSON["display_name"] != nil {
		t.Fatalf("user view: %s", r.Raw)
	}
	// add without email set up: verified at once (nobody could verify it), 201 with the user
	r = ad.post(E, map[string]any{"address": "Paul@The7thDream.com"})
	want(t, r, 201)
	le := r.JSON["linked_emails"].([]any)
	m := le[0].(map[string]any)
	if len(le) != 1 || m["address"] != "Paul@The7thDream.com" || m["verified"] != true || m["added"] == nil {
		t.Fatalf("add: %s", r.Raw)
	}
	// the same list shows up in the list view
	if r = ad.get(AU + "?q=" + url.QueryEscape("alan")); r.total() != 1 {
		t.Fatalf("list: %s", r.Raw)
	}
	wantField(t, ad.post(E, map[string]any{"address": "paul@the7thdream.com"}), 409, "email")
	wantField(t, ad.post(E, map[string]any{"address": w.users["manager"].Email}), 409, "email")
	wantField(t, ad.post(E, map[string]any{"address": "nope"}), 422, "email")
	want(t, ad.post(E, map[string]any{"address": "x@x.example", "extra": 1}), 400)
	// make primary swaps; the old primary becomes linked
	r = ad.post(E+"/"+url.PathEscape("paul@the7thdream.com")+"/primary", nil)
	want(t, r, 200)
	if r.str("email") != "Paul@The7thDream.com" || r.JSON["linked_emails"].([]any)[0].(map[string]any)["address"] != "alan@x.example" {
		t.Fatalf("primary: %s", r.Raw)
	}
	want(t, ad.post(E+"/nobody@x.example/primary", nil), 404)
	// the primary cannot be removed; a linked address can
	wantField(t, ad.delete(E+"/"+url.PathEscape("Paul@The7thDream.com")), 422, "email")
	r = ad.delete(E + "/" + url.PathEscape("alan@x.example"))
	want(t, r, 200)
	if len(r.JSON["linked_emails"].([]any)) != 0 {
		t.Fatalf("delete: %s", r.Raw)
	}
	want(t, ad.delete(E+"/"+url.PathEscape("alan@x.example")), 404)

	// RBAC: a manager manages plain users' addresses but not an admin's; other orgs' admins see 404; users 403
	want(t, w.as("manager").post(E, map[string]any{"address": "m1@x.example"}), 201)
	want(t, w.as("manager").post(AU+"/"+w.users["admin"].ID+"/emails", map[string]any{"address": "m2@x.example"}), 403)
	want(t, w.as("other").post(E, map[string]any{"address": "m3@x.example"}), 404)
	want(t, w.as("user").post(E, map[string]any{"address": "m4@x.example"}), 403)
	want(t, w.anon().post(E, map[string]any{"address": "m5@x.example"}), 401)
}

// With email set up, an address added from the admin page starts unverified and the user is mailed a link to verify
// it (a mistyped address then matches no sign-in); the link can be sent again by whoever manages the user.
func TestUserLinkedEmailsWithMail(t *testing.T) {
	w := newWorld(t)
	m := &fakeMailer{}
	w.mod.Mailer = m
	w.env.Server.Site.Mail = true
	ad := w.as("admin")
	E := AU + "/" + w.users["user"].ID + "/emails"

	r := ad.post(E, map[string]any{"address": "Pending@X.example"})
	want(t, r, 201)
	if l := r.JSON["linked_emails"].([]any)[0].(map[string]any); l["verified"] != false {
		t.Fatalf("add with mail: %s", r.Raw)
	}
	if len(m.sent) != 1 || m.sent[0] != "verify alan Pending@X.example" {
		t.Fatalf("mailed: %v", m.sent)
	}
	// not primary until verified
	wantField(t, ad.post(E+"/"+url.PathEscape("Pending@X.example")+"/primary", nil), 422, "email")
	// resend: managers of the user, and the user themselves
	want(t, w.as("manager").post(E+"/"+url.PathEscape("Pending@X.example")+"/verify", nil), 200)
	want(t, w.as("user").post(E+"/"+url.PathEscape("Pending@X.example")+"/verify", nil), 200)
	if len(m.sent) != 3 {
		t.Fatalf("resent: %v", m.sent)
	}
	want(t, w.as("manager").post(AU+"/"+w.users["admin"].ID+"/emails/"+url.PathEscape(w.users["admin"].Email)+"/verify", nil), 403)

	// a new primary address is unverified and mailed a link too
	r = ad.patch(AU+"/"+w.users["user"].ID, map[string]any{"email": "alan.new@x.example"})
	want(t, r, 200)
	if r.JSON["email_verified"] != false || m.sent[len(m.sent)-1] != "verify alan alan.new@x.example" {
		t.Fatalf("primary change: %s %v", r.Raw, m.sent)
	}
	// your own primary address is not edited directly (add one, verify it, make it primary)
	me := AU + "/" + w.users["admin"].ID
	wantField(t, ad.patch(me, map[string]any{"email": "me.new@x.example"}), 422, "email")
}

// Managers and up add and remove their own addresses from their admin user page, after re-authenticating (a fresh
// sign-in counts); what they add stays unverified.
func TestOwnAddressesNeedReauth(t *testing.T) {
	w := newWorld(t)
	w.env.Server.Site.Mail = true
	m := &fakeMailer{}
	w.mod.Mailer = m
	me := AU + "/" + w.users["admin"].ID + "/emails"
	ad := w.as("admin")
	fresh := true
	w.env.Server.Reauthed = func(*http.Request) bool { return fresh }

	r := ad.post(me, map[string]any{"address": "Me.Other@X.example"})
	want(t, r, 201)
	if l := r.JSON["linked_emails"].([]any)[0].(map[string]any); l["verified"] != false {
		t.Fatalf("own address verified at once: %s", r.Raw)
	}
	if len(m.sent) != 1 {
		t.Fatalf("no link mailed: %v", m.sent)
	}
	fresh = false
	wantField(t, ad.delete(me+"/"+url.PathEscape("Me.Other@X.example")), 403, "reauth")
	wantField(t, ad.post(me, map[string]any{"address": "third@x.example"}), 403, "reauth")
	fresh = true
	want(t, ad.delete(me+"/"+url.PathEscape("Me.Other@X.example")), 200)
	// someone else's need no re-authentication
	fresh = false
	want(t, ad.post(AU+"/"+w.users["user"].ID+"/emails", map[string]any{"address": "alan.alt@x.example"}), 201)
}

func TestMarkEmailVerifiedAPI(t *testing.T) {
	w := newWorld(t)
	w.env.Server.Site.Mail = true
	w.mod.Mailer = &fakeMailer{}
	E := AU + "/" + w.users["user"].ID
	want(t, w.as("admin").post(E+"/emails", map[string]any{"address": "pending@x.example"}), 201)

	r := w.as("manager").get(E)
	want(t, r, 200)
	if r.JSON["can_verify_email"] != true {
		t.Fatalf("manager on user: %s", r.Raw)
	}
	r = w.as("admin").get(AU + "/" + w.users["admin"].ID)
	if r.JSON["can_verify_email"] != false {
		t.Fatalf("own account: %s", r.Raw)
	}
	wantField(t, w.as("user").post(E+"/emails/"+url.PathEscape("pending@x.example")+"/mark-verified", nil), 422, "email")                   // their own
	want(t, w.as("user").post(AU+"/"+w.users["manager"].ID+"/emails/"+url.PathEscape(w.users["manager"].Email)+"/mark-verified", nil), 404) // cannot see others
	r = w.as("manager").post(E+"/emails/"+url.PathEscape("pending@x.example")+"/mark-verified", nil)
	want(t, r, 200)
	if l := r.JSON["linked_emails"].([]any)[0].(map[string]any); l["verified"] != true {
		t.Fatalf("marked: %s", r.Raw)
	}
	want(t, w.as("manager").post(E+"/emails/"+url.PathEscape("pending@x.example")+"/mark-verified", nil), 409)
	me := AU + "/" + w.users["admin"].ID
	wantField(t, w.as("admin").post(me+"/emails/"+url.PathEscape(w.users["admin"].Email)+"/mark-verified", nil), 422, "email")
}
