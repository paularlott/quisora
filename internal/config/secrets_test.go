package config

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSecretRefs(t *testing.T) {
	for v, want := range map[string]bool{"op://v/i/f": true, "vault://p#f": true, "plain": false, "": false, " op://x": false} {
		if IsSecretRef(v) != want {
			t.Errorf("IsSecretRef(%q)", v)
		}
	}
	c := Default()
	if c.HasSecretRefs() {
		t.Fatal("defaults hold no references")
	}
	c.Server.MasterKey = "vault://secret/data/q#master"
	c.Server.PreviousMasterKeys = []string{"vault://secret/data/q#prev1", "op://v/i/prev2", "literal"}
	c.Cluster.Key = "op://v/i/cluster"
	c.Secrets.Vault.Token = "vault://not/resolved#here" // the stores' own credentials are never resolved
	if !c.HasSecretRefs() {
		t.Fatal("references not found")
	}
	values := map[string]string{"vault://secret/data/q#master": key(1), "vault://secret/data/q#prev1": "", "op://v/i/prev2": key(2),
		"op://v/i/cluster": key(3)}
	var asked []string
	resolve := func(_ context.Context, ref string) (string, error) {
		asked = append(asked, ref)
		return values[ref], nil
	}
	// only the named setting
	if err := c.ResolveSecrets(context.Background(), resolve, "cluster.key"); err != nil || c.Cluster.Key != key(3) ||
		c.Server.MasterKey != "vault://secret/data/q#master" || len(asked) != 1 {
		t.Fatalf("selective: %v %v %q", err, asked, c.Server.MasterKey)
	}
	// all of them; empty list entries drop out, literals stay
	if err := c.ResolveSecrets(context.Background(), resolve); err != nil {
		t.Fatal(err)
	}
	if c.Server.MasterKey != key(1) || !slices.Equal(c.Server.PreviousMasterKeys, []string{key(2), "literal"}) ||
		c.Secrets.Vault.Token != "vault://not/resolved#here" {
		t.Fatalf("resolved: %q %q %q", c.Server.MasterKey, c.Server.PreviousMasterKeys, c.Secrets.Vault.Token)
	}
	// an error names the setting
	c.Server.MasterKey = "op://bad"
	boom := errors.New("boom")
	err := c.ResolveSecrets(context.Background(), func(context.Context, string) (string, error) { return "", boom })
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "server.master_key") {
		t.Fatalf("%v", err)
	}
	c.Server.MasterKey = key(1)
	c.Server.PreviousMasterKeys = []string{"vault://x#y"}
	err = c.ResolveSecrets(context.Background(), func(context.Context, string) (string, error) { return "", boom })
	if !errors.Is(err, boom) {
		t.Fatalf("list entry error: %v", err)
	}
}
