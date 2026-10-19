package loadtest

import (
	"encoding/json"
	"fmt"
	"os"
)

// Data is the file `seed` writes and `run` reads: what a load generator needs to build valid requests.
type Data struct {
	Orgs     int    `json:"orgs"`
	Users    int    `json:"users"`
	Password string `json:"password"`
	// APIToken is a personal API token of the primary org's super admin (scopes admin and scim).
	APIToken string        `json:"api_token"`
	Samples  []OrgSample   `json:"samples"`
	Grants   []GrantSample `json:"grants"`
}

// OrgSample is one organization with its seeded OAuth clients.
type OrgSample struct {
	Org      string `json:"org"`
	OrgID    string `json:"org_id"`
	WebID    string `json:"web_client_id"`
	WebSec   string `json:"web_client_secret"`
	CCID     string `json:"cc_client_id,omitempty"`
	CCSecret string `json:"cc_client_secret,omitempty"`
	// Tenants of the org: "default" (holds the web and service clients) and "apps".
	Tenants []TenantSample `json:"tenants,omitempty"`
}

// TenantSample is a seeded tenant.
type TenantSample struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// GrantSample is a ready-to-use refresh token.
type GrantSample struct {
	Token    string `json:"token"`
	Org      string `json:"org"`
	ClientID string `json:"client_id"`
	Secret   string `json:"client_secret"`
	Groups   bool   `json:"groups"`
}

// LoadData reads a seed data file.
func LoadData(path string) (*Data, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if d.Orgs < 1 || d.Users < 1 {
		return nil, fmt.Errorf("%s: not a loadtest data file", path)
	}
	return &d, nil
}

// Save writes the data file (0600: it holds client secrets and a token).
func (d *Data) Save(path string) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
