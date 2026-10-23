package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/paularlott/quisora/internal/config"
)

// serviceAccount reads op:// references with a 1Password service account. It is set by the onepassword build tag
// (onepassword_sdk.go): the 1Password SDK is large and calls 1Password's servers, so only builds that ask for it
// link it.
var serviceAccount func(ctx context.Context, token string) (opReader, error)

func newOnePassword(ctx context.Context, c config.OnePassword) (opReader, error) {
	sa, err := credential(c.ServiceAccountToken, c.ServiceAccountTokenFile, "secrets.onepassword.service_account_token_file")
	if err != nil {
		return nil, err
	}
	switch {
	case sa != "" && c.ConnectURL != "":
		return nil, fmt.Errorf("1Password: configure Connect (connect_url) or a service account, not both")
	case sa != "":
		if serviceAccount == nil {
			return nil, fmt.Errorf("1Password service accounts need a build with the onepassword tag " +
				"(go build -tags onepassword); this one reads 1Password through Connect only")
		}
		return serviceAccount(ctx, sa)
	case c.ConnectURL == "":
		return nil, errNotConfigured("1Password", "secrets.onepassword.connect_url (or a service account token)")
	}
	u, err := url.Parse(c.ConnectURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("secrets.onepassword.connect_url must be an http(s) URL")
	}
	token, err := credential(c.ConnectToken, c.ConnectTokenFile, "secrets.onepassword.connect_token_file")
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("1Password Connect needs an access token (secrets.onepassword.connect_token or connect_token_file)")
	}
	hc, err := httpClient(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("secrets.onepassword.ca_file: %w", err)
	}
	return &connect{addr: strings.TrimRight(c.ConnectURL, "/"), token: token, hc: hc}, nil
}

// opRef is a parsed op://vault/item[/section]/field reference.
type opRef struct{ vault, item, section, field string }

func parseOpRef(ref string) (opRef, error) {
	parts := strings.Split(strings.TrimPrefix(ref, "op://"), "/")
	for _, p := range parts {
		if p == "" {
			parts = nil
			break
		}
	}
	switch len(parts) {
	case 3:
		return opRef{vault: parts[0], item: parts[1], field: parts[2]}, nil
	case 4:
		return opRef{vault: parts[0], item: parts[1], section: parts[2], field: parts[3]}, nil
	}
	return opRef{}, fmt.Errorf("a 1Password reference is op://<vault>/<item>/<field> or op://<vault>/<item>/<section>/<field>")
}

// connect reads items through a 1Password Connect server.
type connect struct {
	addr, token string
	hc          *http.Client
}

var opID = regexp.MustCompile(`^[a-z0-9]{26}$`) // a 1Password vault or item id

type connectItem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Sections []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	} `json:"sections"`
	Fields []struct {
		ID      string `json:"id"`
		Label   string `json:"label"`
		Purpose string `json:"purpose"`
		Value   string `json:"value"`
		Section *struct {
			ID string `json:"id"`
		} `json:"section"`
	} `json:"fields"`
}

func (c *connect) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("1Password Connect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		return fmt.Errorf("1Password Connect answered %s %s", resp.Status, e.Message)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// find returns the id of the one entry of list named name (or name itself when it is an id).
func (c *connect) find(ctx context.Context, path, attr, name, what string) (string, error) {
	if opID.MatchString(name) {
		return name, nil
	}
	var list []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Title string `json:"title"`
	}
	filter := url.QueryEscape(attr + ` eq "` + strings.ReplaceAll(name, `"`, `\"`) + `"`)
	if err := c.get(ctx, path+"?filter="+filter, &list); err != nil {
		return "", err
	}
	var ids []string
	for _, e := range list {
		if e.Name == name || e.Title == name {
			ids = append(ids, e.ID)
		}
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("no %s %q", what, name)
	case 1:
		return ids[0], nil
	}
	return "", fmt.Errorf("%d %ss are called %q: use its id", len(ids), what, name)
}

func (c *connect) read(ctx context.Context, ref string) (string, error) {
	r, err := parseOpRef(ref)
	if err != nil {
		return "", err
	}
	vaultID, err := c.find(ctx, "/v1/vaults", "name", r.vault, "vault")
	if err != nil {
		return "", err
	}
	items := "/v1/vaults/" + url.PathEscape(vaultID) + "/items"
	itemID, err := c.find(ctx, items, "title", r.item, "item")
	if err != nil {
		return "", err
	}
	var item connectItem
	if err := c.get(ctx, items+"/"+url.PathEscape(itemID), &item); err != nil {
		return "", err
	}
	section := ""
	if r.section != "" {
		for _, s := range item.Sections {
			if strings.EqualFold(s.Label, r.section) || s.ID == r.section {
				section = s.ID
			}
		}
		if section == "" {
			return "", fmt.Errorf("item %q has no section %q", r.item, r.section)
		}
	}
	for _, f := range item.Fields {
		if section != "" && (f.Section == nil || f.Section.ID != section) {
			continue
		}
		if strings.EqualFold(f.Label, r.field) || f.ID == r.field || strings.EqualFold(f.Purpose, r.field) {
			return f.Value, nil
		}
	}
	return "", fmt.Errorf("item %q has no field %q", r.item, r.field)
}
