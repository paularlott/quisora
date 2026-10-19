package oidc

import "testing"

// The consent page's way back to the application: a web app's home, nothing for a native app.
func TestReturnURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://knot.example.com/auth/callback?x=1", "https://knot.example.com/"},
		{"https://knot.example.com:8443/cb", "https://knot.example.com:8443/"},
		{"http://localhost:3000/callback", "http://localhost:3000/"},
		{"http://127.0.0.1:51234/callback", ""}, // native app on a loopback IP: the port changes every time
		{"http://[::1]:51234/callback", ""},
		{"com.example.app:/oauth2redirect", ""}, // native app, custom scheme
		{"javascript:alert(1)", ""},
		{"", ""},
	} {
		if got := returnURL(tc.in); got != tc.want {
			t.Errorf("returnURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
