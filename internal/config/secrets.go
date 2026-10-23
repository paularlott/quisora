package config

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// Secrets configures the secret stores a secret setting may name instead of holding its value (internal/secrets):
// "op://vault/item/field" reads 1Password, "vault://path#field" reads HashiCorp Vault. Every other value is the value
// itself, as before. The stores' own credentials are given here, in this file or a file they name, or the environment.
type Secrets struct {
	Vault       Vault       `toml:"vault" flag:"vault"`
	OnePassword OnePassword `toml:"onepassword" flag:"onepassword"`
}

// Vault is a HashiCorp Vault (or OpenBao) server and how to sign in to it: a token, or AppRole.
type Vault struct {
	Address      string `toml:"address" flag:"address" usage:"HashiCorp Vault address (https://vault:8200) for vault:// references in secret settings"`
	Token        string `toml:"token" flag:"token" secret:"true" usage:"Vault token (or token_file, or AppRole: role_id and secret_id)"`
	TokenFile    string `toml:"token_file" flag:"token-file" usage:"File holding the Vault token (its first line)"`
	RoleID       string `toml:"role_id" flag:"role-id" usage:"Vault AppRole role id (signs in at auth/<approle_mount>/login)"`
	SecretID     string `toml:"secret_id" flag:"secret-id" secret:"true" usage:"Vault AppRole secret id (or secret_id_file)"`
	SecretIDFile string `toml:"secret_id_file" flag:"secret-id-file" usage:"File holding the Vault AppRole secret id (its first line)"`
	AppRoleMount string `toml:"approle_mount" flag:"approle-mount" usage:"Mount path of Vault's AppRole auth method (default approle)"`
	Namespace    string `toml:"namespace" flag:"namespace" usage:"Vault Enterprise namespace"`
	CAFile       string `toml:"ca_file" flag:"ca-file" usage:"PEM CA certificates Vault's TLS certificate is verified against (a private CA)"`
}

// OnePassword is a 1Password Connect server, or a 1Password service account (builds with the onepassword tag).
type OnePassword struct {
	ConnectURL              string `toml:"connect_url" flag:"connect-url" usage:"1Password Connect server (https://op-connect:8080) for op:// references in secret settings"`
	ConnectToken            string `toml:"connect_token" flag:"connect-token" secret:"true" usage:"1Password Connect access token (or connect_token_file)"`
	ConnectTokenFile        string `toml:"connect_token_file" flag:"connect-token-file" usage:"File holding the 1Password Connect access token (its first line)"`
	ServiceAccountToken     string `toml:"service_account_token" flag:"service-account-token" secret:"true" usage:"1Password service account token, instead of Connect (needs a build with the onepassword tag; calls 1Password's servers)"`
	ServiceAccountTokenFile string `toml:"service_account_token_file" flag:"service-account-token-file" usage:"File holding the 1Password service account token (its first line)"`
	CAFile                  string `toml:"ca_file" flag:"ca-file" usage:"PEM CA certificates the Connect server's TLS certificate is verified against (a private CA)"`
}

// IsSecretRef reports whether v names a value in a secret store rather than being the value.
func IsSecretRef(v string) bool {
	return strings.HasPrefix(v, "op://") || strings.HasPrefix(v, "vault://")
}

// ResolveSecrets replaces every reference held by a secret setting (secret:"true", outside [secrets]) with the
// value resolve reads for it; only the settings named in paths (TOML paths), or all of them when paths is empty. A
// list setting drops the references that read empty (previous keys kept in a store while no rotation runs). The
// values stay in memory: nothing is written back.
func (c *Config) ResolveSecrets(ctx context.Context, resolve func(ctx context.Context, ref string) (string, error),
	paths ...string) error {
	for _, s := range settings(c) {
		if !s.Secret || strings.HasPrefix(s.Path, "secrets.") || len(paths) > 0 && !slices.Contains(paths, s.Path) {
			continue
		}
		one := func(v string) (string, error) {
			if !IsSecretRef(v) {
				return v, nil
			}
			got, err := resolve(ctx, v)
			if err != nil {
				return "", fmt.Errorf("%s: %w", s.Path, err)
			}
			return got, nil
		}
		switch f := s.field; f.Kind() {
		case reflect.String:
			v, err := one(f.String())
			if err != nil {
				return err
			}
			f.SetString(v)
		case reflect.Slice: // an empty value drops out: "previous keys" kept in a store when no rotation runs
			kept := reflect.MakeSlice(f.Type(), 0, f.Len())
			for i := range f.Len() {
				v, err := one(f.Index(i).String())
				if err != nil {
					return err
				}
				if v != "" {
					kept = reflect.Append(kept, reflect.ValueOf(v))
				}
			}
			f.Set(kept)
		}
	}
	return nil
}

// HasSecretRefs reports whether any secret setting names a secret store.
func (c *Config) HasSecretRefs() bool {
	found := false
	_ = c.ResolveSecrets(context.Background(), func(_ context.Context, ref string) (string, error) {
		found = true
		return ref, nil
	})
	return found
}
