package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/paularlott/quisora/internal/config"
)

// vaultClient reads Vault KV secrets with a token, given or from an AppRole sign-in.
type vaultClient struct {
	addr, token, namespace string
	hc                     *http.Client
}

func newVault(ctx context.Context, c config.Vault) (*vaultClient, error) {
	if c.Address == "" {
		return nil, errNotConfigured("Vault", "secrets.vault.address")
	}
	u, err := url.Parse(c.Address)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("secrets.vault.address must be an http(s) URL")
	}
	hc, err := httpClient(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("secrets.vault.ca_file: %w", err)
	}
	v := &vaultClient{addr: strings.TrimRight(c.Address, "/"), namespace: c.Namespace, hc: hc}
	if v.token, err = credential(c.Token, c.TokenFile, "secrets.vault.token_file"); err != nil {
		return nil, err
	}
	if v.token == "" {
		secret, err := credential(c.SecretID, c.SecretIDFile, "secrets.vault.secret_id_file")
		if err != nil {
			return nil, err
		}
		if c.RoleID == "" || secret == "" {
			return nil, fmt.Errorf("Vault needs a token (secrets.vault.token or token_file) or AppRole (role_id and secret_id)")
		}
		mount := c.AppRoleMount
		if mount == "" {
			mount = "approle"
		}
		if v.token, err = v.appRole(ctx, mount, c.RoleID, secret); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (v *vaultClient) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.addr+"/v1/"+strings.TrimLeft(path, "/"), rd)
	if err != nil {
		return err
	}
	if v.token != "" {
		req.Header.Set("X-Vault-Token", v.token)
	}
	if v.namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return fmt.Errorf("Vault: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		return fmt.Errorf("Vault answered %s %s", resp.Status, strings.Join(e.Errors, "; "))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func (v *vaultClient) appRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := v.do(ctx, http.MethodPost, "auth/"+strings.Trim(mount, "/")+"/login",
		map[string]string{"role_id": roleID, "secret_id": secretID}, &out); err != nil {
		return "", fmt.Errorf("AppRole sign-in: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", fmt.Errorf("AppRole sign-in: Vault returned no token")
	}
	return out.Auth.ClientToken, nil
}

// read resolves "<path>#<field>": the secret at path, KV version 1 or 2 (the field is looked for in data, or in
// data.data for version 2), field "value" when none is named.
func (v *vaultClient) read(ctx context.Context, ref string) (string, error) {
	path, field, _ := strings.Cut(ref, "#")
	if path = strings.Trim(path, "/"); path == "" {
		return "", fmt.Errorf("a Vault reference is vault://<path>#<field>")
	}
	if field == "" {
		field = "value"
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := v.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return "", err
	}
	data := out.Data
	if nested, ok := data["data"].(map[string]any); ok {
		if _, meta := data["metadata"]; meta { // KV version 2
			data = nested
		}
	}
	val, ok := data[field]
	if !ok {
		return "", fmt.Errorf("no field %q at %s", field, path)
	}
	s, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("field %q at %s is not a string", field, path)
	}
	return s, nil
}
