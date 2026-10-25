package app

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
)

// Connections off this machine without TLS that verifies the server are warned about; local ones and verified ones
// are not.
func TestTransportWarnings(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*config.Config)
		want string // "" = no warning
	}{
		{"badger", func(c *config.Config) {}, ""},
		{"postgres local", func(c *config.Config) {
			c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", "postgres://u:p@localhost:5432/q?sslmode=disable"
		}, ""},
		{"postgres plain", func(c *config.Config) {
			c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", "postgres://u:p@db.example.com/q?sslmode=disable"
		}, "not encrypted"},
		{"postgres require", func(c *config.Config) {
			c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", "postgres://u:p@db.example.com/q?sslmode=require"
		}, "not verified"},
		{"postgres verify-full", func(c *config.Config) {
			c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", "postgres://u:p@db.example.com/q?sslmode=verify-full"
		}, ""},
		{"mysql plain", func(c *config.Config) {
			c.Storage.Backend, c.Storage.MySQL.DSN = "mysql", "u:p@tcp(db.example.com:3306)/q"
		}, "not encrypted"},
		{"mysql ca file", func(c *config.Config) {
			c.Storage.Backend, c.Storage.MySQL.DSN, c.Storage.MySQL.CAFile = "mysql", "u:p@tcp(db.example.com:3306)/q", "/ca.pem"
		}, ""},
		{"mariadb skip-verify", func(c *config.Config) {
			c.Storage.Backend, c.Storage.MariaDB.DSN = "mariadb", "u:p@tcp(db.example.com:3306)/q?tls=skip-verify"
		}, "not verified"},
		{"mysql local", func(c *config.Config) {
			c.Storage.Backend, c.Storage.MySQL.DSN = "mysql", "u:p@tcp(127.0.0.1:3306)/q"
		}, ""},
		{"smtp password without tls", func(c *config.Config) {
			c.Mail.SMTPHost, c.Mail.TLS, c.Mail.Password = "smtp.example.com", "none", "pw"
		}, "SMTP password"},
		{"smtp local without tls", func(c *config.Config) {
			c.Mail.SMTPHost, c.Mail.TLS, c.Mail.Password = "127.0.0.1", "none", "pw"
		}, ""},
	} {
		c := config.Default()
		tc.set(c)
		got := strings.Join(transportWarnings(c), "; ")
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
}
