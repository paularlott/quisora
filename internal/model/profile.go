package model

import (
	"strings"
	"time"

	_ "time/tzdata" // ValidTimeZone does not depend on the host's zone files (distroless images have none)

	"golang.org/x/text/language"
)

// LocaleOption is a language tag offered in the language autocompleter, with its English name.
type LocaleOption struct {
	Tag  string `json:"tag"`
	Name string `json:"name"`
}

// NormalizeLocale returns the canonical BCP 47 form of a language tag ("en_gb" and "EN-GB" become "en-GB"), or
// ok false when s is not a well-formed tag. "" stays "" (no language set).
func NormalizeLocale(s string) (string, bool) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "_", "-"))
	if s == "" {
		return "", true
	}
	if len(s) > 35 {
		return "", false
	}
	t, err := language.Parse(s)
	if err != nil {
		return "", false
	}
	return t.String(), true
}

// ValidTimeZone reports whether s is an IANA time zone name ("" means none). The time zone database is embedded in
// the binary, so this does not depend on the host.
func ValidTimeZone(s string) bool {
	if s == "" {
		return true
	}
	if s == "Local" || len(s) > 64 || strings.ContainsAny(s, " .\\") {
		return false
	}
	_, err := time.LoadLocation(s)
	return err == nil
}

// The user types offered in the console. SCIM clients may send others (Entra ID sends "Member" and "Guest"), so
// any short value is kept.
var UserTypes = []string{"employee", "contractor", "guest", "service"}

// Work holds the SCIM enterprise extension of a user (RFC 7643 §4.3): directory details that identity providers
// such as Entra ID and Okta send and applications use for directory pages, approvals and reporting.
type Work struct {
	Title          string `msgpack:"ti,omitempty" json:"title,omitempty"`
	Department     string `msgpack:"de,omitempty" json:"department,omitempty"`
	Organization   string `msgpack:"or,omitempty" json:"organization,omitempty"`
	Division       string `msgpack:"di,omitempty" json:"division,omitempty"`
	CostCenter     string `msgpack:"cc,omitempty" json:"cost_center,omitempty"`
	EmployeeNumber string `msgpack:"en,omitempty" json:"employee_number,omitempty"`
	// ManagerID is the id of another user of the same organization.
	ManagerID string `msgpack:"mg,omitempty" json:"manager_id,omitempty"`
}

// Empty reports whether no work detail is set.
func (w Work) Empty() bool { return w == Work{} }

// Enabled reports whether the user may sign in and use tokens at now: active, and not past their end date.
func (u *User) Enabled(now time.Time) bool {
	return u.Active && (u.ValidUntil == nil || now.Before(*u.ValidUntil))
}
