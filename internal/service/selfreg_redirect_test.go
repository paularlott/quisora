package service

import "testing"

// A self-registered application's redirect URIs: https, http on the loopback interface, or a private-use scheme
// named after a domain; never a fragment, credentials or an opaque URI.
func TestSelfRegRedirect(t *testing.T) {
	for ru, want := range map[string]bool{
		"https://app.example/cb":           true,
		"http://127.0.0.1:33418/callback":  true,
		"http://[::1]/callback":            true,
		"http://localhost:8080/cb":         true,
		"com.example.app:/oauth/callback":  true,
		"com.example.app://callback":       true,
		"http://app.example/cb":            false,
		"http://localhost.evil.example/cb": false,
		"https://app.example/cb#x":         false,
		"https://user:pw@app.example/cb":   false,
		"https:///cb":                      false,
		"myapp:/cb":                        false,
		"com.example.app:cb":               false,
		"com.example.app:/cb#x":            false,
		"javascript:alert(1)":              false,
		"data:text/html,x":                 false,
		"file:///etc/passwd":               false,
		"":                                 false,
	} {
		if got := selfRegRedirect(ru); got != want {
			t.Errorf("%q: %v, want %v", ru, got, want)
		}
	}
}
