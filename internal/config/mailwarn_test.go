package config

import "testing"

// Mail in clear text is warned about, unless the SMTP server is on this machine; encrypted mail and no mail are not.
func TestMailWithoutTLSIsWarnedAbout(t *testing.T) {
	for _, tc := range []struct {
		host, tls string
		warn      bool
	}{
		{"smtp.example.com", "none", true},
		{"10.0.0.5", "none", true},
		{"localhost", "none", false},
		{"127.0.0.1", "none", false},
		{"::1", "none", false},
		{"smtp.example.com", "starttls", false},
		{"", "none", false},
	} {
		cfg := &Config{}
		cfg.Mail = Mail{SMTPHost: tc.host, TLS: tc.tls}
		if w := cfg.MailWarnings(); len(w) > 1 || (len(w) == 1) != tc.warn {
			t.Errorf("%s tls=%s: warnings %v", tc.host, tc.tls, w)
		}
	}
}
