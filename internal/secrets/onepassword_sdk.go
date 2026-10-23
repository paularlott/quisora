//go:build onepassword

package secrets

import (
	"context"

	sdk "github.com/1password/onepassword-sdk-go"
	"github.com/paularlott/quisora/internal/build"
)

// Builds with the onepassword tag read op:// references with a 1Password service account, through 1Password's SDK
// (which calls 1Password's servers).
func init() {
	serviceAccount = func(ctx context.Context, token string) (opReader, error) {
		c, err := sdk.NewClient(ctx, sdk.WithServiceAccountToken(token), sdk.WithIntegrationInfo("Quisora", build.Version))
		if err != nil {
			return nil, err
		}
		return sdkReader{c}, nil
	}
}

type sdkReader struct{ c *sdk.Client }

func (r sdkReader) read(ctx context.Context, ref string) (string, error) {
	if _, err := parseOpRef(ref); err != nil {
		return "", err
	}
	return r.c.Secrets().Resolve(ctx, ref)
}
