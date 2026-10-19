package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/paularlott/quisora/internal/config"
)

// Connections to the database and the mail server carry secrets (credentials, sealed records, password-reset links):
// off the local machine they should use TLS that verifies the server. Nothing is refused, so local and development
// set-ups keep working; each weak connection is a warning at start-up.

// caPool reads a PEM CA file into a pool of its own (nil for "").
func caPool(file, setting string) (*x509.CertPool, error) {
	if file == "" {
		return nil, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", setting, err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no PEM certificate in %s", setting, file)
	}
	return p, nil
}

// valkeyTLS builds the TLS configuration of a Valkey connection from storage.valkey (nil: the defaults).
func valkeyTLS(v config.Valkey) (*tls.Config, error) {
	if v.CAFile == "" && v.ServerName == "" && v.CertFile == "" && v.KeyFile == "" {
		return nil, nil
	}
	t := &tls.Config{ServerName: v.ServerName, MinVersion: tls.VersionTLS12}
	pool, err := caPool(v.CAFile, "storage.valkey.ca_file")
	if err != nil {
		return nil, err
	}
	t.RootCAs = pool
	if v.CertFile != "" || v.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(v.CertFile, v.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("storage.valkey.cert_file / key_file: %w", err)
		}
		t.Certificates = []tls.Certificate{cert}
	}
	return t, nil
}

// local reports whether host is this machine (a loopback name or address, or a Unix socket path).
func local(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "" || host == "localhost" || strings.HasPrefix(host, "/") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// transportWarnings lists the connections that leave this machine without TLS that verifies the server.
func transportWarnings(c *config.Config) []string {
	var out []string
	st := c.Storage
	switch st.Backend {
	case "postgres":
		pc, err := pgx.ParseConfig(st.Postgres.DSN)
		if err != nil || local(pc.Host) {
			break
		}
		switch {
		case pc.TLSConfig == nil:
			out = append(out, "storage.postgres: the connection to "+pc.Host+" is not encrypted (sslmode=verify-full)")
		// verify-ca (a chain check, VerifyPeerCertificate) and require with a CA file (which gets one, see sqlstore)
		// verify the server; require alone does not.
		case pc.TLSConfig.InsecureSkipVerify && pc.TLSConfig.VerifyPeerCertificate == nil && st.Postgres.CAFile == "" ||
			len(pc.Fallbacks) > 0 && pc.Fallbacks[0].TLSConfig == nil:
			out = append(out, "storage.postgres: the server's certificate is not verified, or plain text is allowed "+
				"(use sslmode=verify-full, with storage.postgres.ca_file or sslrootcert for a private CA)")
		}
	case "mysql", "mariadb":
		dsn, caFile := st.MySQL.DSN, st.MySQL.CAFile
		if st.Backend == "mariadb" {
			dsn, caFile = st.MariaDB.DSN, st.MariaDB.CAFile
		}
		mc, err := mysql.ParseDSN(dsn)
		if err != nil || mc.Net == "unix" {
			break
		}
		host, _, _ := net.SplitHostPort(mc.Addr)
		if local(host) {
			break
		}
		switch {
		case mc.TLS == nil && caFile == "":
			out = append(out, "storage."+st.Backend+": the connection to "+host+" is not encrypted (tls=true in the DSN, "+
				"or storage."+st.Backend+".ca_file for a private CA)")
		case mc.TLS != nil && mc.TLS.InsecureSkipVerify:
			out = append(out, "storage."+st.Backend+": the server's certificate is not verified, or plain text is allowed "+
				"(tls=true in the DSN, or storage."+st.Backend+".ca_file)")
		}
	case "valkey":
		for _, a := range st.Valkey.Addrs {
			host, _, err := net.SplitHostPort(a)
			if err != nil {
				host = a
			}
			if !st.Valkey.TLS && !local(host) {
				out = append(out, "storage.valkey: the connection to "+host+" is not encrypted (storage.valkey.tls)")
				break
			}
		}
	}
	if m := c.Mail; m.SMTPHost != "" && m.TLS == "none" && m.Password != "" && !local(m.SMTPHost) {
		out = append(out, "mail: the SMTP password is sent to "+m.SMTPHost+" without TLS (mail.tls = starttls or tls)")
	}
	return out
}
